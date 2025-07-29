import os
import shutil
import re
from pathlib import Path
from typing import List, Optional, Tuple
from git import Repo, InvalidGitRepositoryError

from gen_testcases import generate_junit_vulnerability_test
from gen_commitHistory import gpt_commit_one_file_with_support


class VulnerabilityProjectBuilder:
    """Builds Maven projects with vulnerability test cases and commit history."""
    
    POM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.example</groupId>
    <artifactId>{artifact_id}</artifactId>
    <version>1.0-SNAPSHOT</version>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    
    <dependencies>
        <!-- Testing -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-api</artifactId>
            <version>5.7.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter-engine</artifactId>
            <version>5.7.2</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>3.12.4</version>
            <scope>test</scope>
        </dependency>
        
        <!-- Web -->
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>4.0.1</version>
            <scope>provided</scope>
        </dependency>
        
        <!-- Utilities -->
        <dependency>
            <groupId>javax.mail</groupId>
            <artifactId>mail</artifactId>
            <version>1.4.7</version>
        </dependency>
        <dependency>
            <groupId>commons-codec</groupId>
            <artifactId>commons-codec</artifactId>
            <version>1.15</version>
        </dependency>
        <dependency>
            <groupId>commons-lang</groupId>
            <artifactId>commons-lang</artifactId>
            <version>2.6</version>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-dependency-plugin</artifactId>
                <version>3.2.0</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>2.22.2</version>
            </plugin>
        </plugins>
    </build>
</project>"""

    WORKFLOW_TEMPLATE = """name: Java CI

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4
    
    - name: Set up JDK 21
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
    
    - name: Build with Maven
      run: mvn clean compile
      working-directory: {project_name}
      env:
        ADD: "en-US%0d%0aSet-Cookie:evil=1"
    
    - name: Run tests
      run: mvn test
      working-directory: {project_name}
      env:
        ADD: "en-US%0d%0aSet-Cookie:evil=1"
"""

    def __init__(self):
        self.repo = None
    
    def parse_package_from_java(self, java_code: str) -> Optional[str]:
        """Extract package declaration from Java source."""
        match = re.search(r'package\s+([a-zA-Z0-9_.]+);', java_code)
        return match.group(1) if match else None
    
    def copy_java_file_to_package(self, java_file: str, src_root: str) -> str:
        """Copy Java file to its package directory."""
        with open(java_file, "r") as f:
            code = f.read()
        
        package = self.parse_package_from_java(code)
        filename = os.path.basename(java_file)
        
        if package:
            package_path = os.path.join(src_root, *package.split('.'))
            os.makedirs(package_path, exist_ok=True)
            dst_file = os.path.join(package_path, filename)
        else:
            os.makedirs(src_root, exist_ok=True)
            dst_file = os.path.join(src_root, filename)
        
        shutil.copy(java_file, dst_file)
        return dst_file
    
    def copy_package_companions(self, main_file: str, src_root: str) -> List[str]:
        """Copy other Java files from the same directory as main file."""
        copied_files = []
        main_dir = os.path.dirname(main_file)
        main_path = os.path.abspath(main_file)
        
        # Only process files in immediate directory
        for item in os.listdir(main_dir):
            item_path = os.path.join(main_dir, item)
            
            if (os.path.isfile(item_path) and 
                item.endswith(".java") and 
                os.path.abspath(item_path) != main_path):
                
                dst_file = self.copy_java_file_to_package(item_path, src_root)
                copied_files.append(dst_file)
        
        return copied_files
    
    def create_project_structure(self, root_dir: str) -> Tuple[str, str]:
        """Create Maven project directory structure."""
        src_main = os.path.join(root_dir, "src", "main", "java")
        src_test = os.path.join(root_dir, "src", "test", "java")
        os.makedirs(src_main, exist_ok=True)
        os.makedirs(src_test, exist_ok=True)
        return src_main, src_test
    
    def create_pom_file(self, project_dir: str, artifact_id: str):
        """Create Maven pom.xml file."""
        pom_path = os.path.join(project_dir, "pom.xml")
        pom_content = self.POM_TEMPLATE.format(artifact_id=artifact_id)
        
        with open(pom_path, "w") as f:
            f.write(pom_content)
        
        return pom_path
    
    def create_github_workflow(self, repo_dir: str, project_name: str) -> str:
        """Create GitHub Actions workflow file."""
        workflow_dir = os.path.join(repo_dir, ".github", "workflows")
        os.makedirs(workflow_dir, exist_ok=True)
        
        workflow_path = os.path.join(workflow_dir, f"maven-build-{project_name}.yml")
        workflow_content = self.WORKFLOW_TEMPLATE.format(project_name=project_name)
        
        with open(workflow_path, "w") as f:
            f.write(workflow_content)
        
        return workflow_path
    
    def initialize_repository(self, repo_dir: str) -> Repo:
        """Initialize or load Git repository."""
        try:
            repo = Repo(repo_dir)
            print(f"Using existing repository at {repo_dir}")
        except InvalidGitRepositoryError:
            repo = Repo.init(repo_dir)
            print(f"Initialized new repository at {repo_dir}")
        
        self.repo = repo
        return repo
    
    def build_project(self, commit_repository_dir: str, project_name: str,
                     main_java_file: str, support_java_dir: str,
                     api_key: str, test_generator_model: str,
                     commit_history_model: str):
        """Build complete Maven project with tests and commit history."""
        
        # Set up directories
        project_dir = os.path.join(commit_repository_dir, project_name)
        src_main, src_test = self.create_project_structure(project_dir)
        
        # Initialize repository
        repo = self.initialize_repository(commit_repository_dir)
        
        # Copy main file (but don't commit yet)
        new_main_file = self.copy_java_file_to_package(main_java_file, src_main)
        print(f"Copied main file to {new_main_file}")
        
        # Copy companion files from main directory
        companion_files = self.copy_package_companions(main_java_file, src_main)
        print(f"Copied {len(companion_files)} companion files")
        
        # Copy support files
        support_files = []
        if os.path.exists(support_java_dir):
            for root, _, files in os.walk(support_java_dir):
                for fname in files:
                    if fname.endswith(".java"):
                        src_path = os.path.join(root, fname)
                        dst_file = self.copy_java_file_to_package(src_path, src_main)
                        support_files.append(dst_file)
        print(f"Copied {len(support_files)} support files")
        
        # Create pom.xml
        pom_path = self.create_pom_file(project_dir, project_name)
        
        # Generate test file
        print("Generating JUnit test...")
        temp_test_dir = "./_temp_generated_tests"
        generated_test = generate_junit_vulnerability_test(
            main_java_file=main_java_file,
            support_java_dir=support_java_dir,
            output_test_dir=temp_test_dir,
            api_key=api_key,
            model=test_generator_model
        )
        
        # Move test to proper location
        if generated_test:
            with open(generated_test, "r") as f:
                test_code = f.read()
            
            test_package = self.parse_package_from_java(test_code)
            if test_package:
                test_dst_dir = os.path.join(src_test, *test_package.split('.'))
            else:
                test_dst_dir = src_test
            
            os.makedirs(test_dst_dir, exist_ok=True)
            final_test_path = os.path.join(test_dst_dir, os.path.basename(generated_test))
            shutil.move(generated_test, final_test_path)
            print(f"Test file moved to {final_test_path}")
        
        # Create GitHub workflow
        workflow_path = self.create_github_workflow(commit_repository_dir, project_name)
        
        # Commit initial setup (everything except main file)
        files_to_commit = []
        
        # Add all files except main
        files_to_commit.extend([os.path.relpath(f, commit_repository_dir) 
                               for f in support_files])
        files_to_commit.extend([os.path.relpath(f, commit_repository_dir) 
                               for f in companion_files])
        files_to_commit.append(os.path.relpath(pom_path, commit_repository_dir))
        files_to_commit.append(os.path.relpath(workflow_path, commit_repository_dir))
        
        if generated_test:
            files_to_commit.append(os.path.relpath(final_test_path, commit_repository_dir))
        
        repo.git.add(files_to_commit)
        repo.index.commit("Initial project setup")
        print("Committed initial project structure")
        
        # Generate commit history for main file
        print("\nGenerating commit history...")
        gpt_commit_one_file_with_support(
            main_java_file=new_main_file,
            support_dir=src_main,
            repo_root_dir=commit_repository_dir,
            src_base_dir=project_dir,
            api_key=api_key,
            model=commit_history_model
        )
        
        print("\nProject build completed successfully")


def vcc_intro(commit_repository_dir: str, project_name: str, main_java_file: str,
         support_java_dir: str, api_key: str, 
         test_generator_model: str = "gpt-4o-mini",
         commit_history_model: str = "gpt-4o-mini"):
    """Main entry point for project building."""
    builder = VulnerabilityProjectBuilder()
    builder.build_project(
        commit_repository_dir=commit_repository_dir,
        project_name=project_name,
        main_java_file=main_java_file,
        support_java_dir=support_java_dir,
        api_key=api_key,
        test_generator_model=test_generator_model,
        commit_history_model=commit_history_model
    )


if __name__ == "__main__":
    # Example usage
    vcc_intro(
        commit_repository_dir="/Users/vlopes/Desktop/git-projects/repo-for-test",
        project_name="CWE835_Infinite_Loop__do_true_01",
        main_java_file="CWE835_Infinite_Loop/CWE835_Infinite_Loop__do_true_01.java",
        support_java_dir="./support_files",
        api_key="your-api-key-here"
    )