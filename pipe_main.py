import os
import json
import glob
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from vcc_intro import vcc_intro as run_commit_builder
from gen_patch import patch_all_findings


@dataclass
class PipelineStats:
    """Track pipeline execution statistics."""
    total_testcases: int = 0
    commit_history_success: int = 0
    commit_history_failed: int = 0
    cwe_analysis_success: int = 0
    cwe_analysis_failed: int = 0
    patch_success: int = 0
    patch_failed: int = 0


@dataclass
class PipelineConfig:
    """Pipeline configuration settings."""
    parsed_juliet_dir: str
    commit_repo_dir: str
    openai_api_key: str
    s2e_project_dir: str
    test_model: str = "gpt-4o-mini"
    commit_model: str = "gpt-4o-mini"
    patch_model: str = "gpt-4o-mini"
    java_home: Optional[str] = None


class VulnerabilityPipeline:
    """Manages the complete vulnerability lifecycle pipeline."""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.stats = PipelineStats()
        self._setup_java_environment()
    
    def _setup_java_environment(self):
        """Configure Java environment if not already set."""
        if not self.config.java_home:
            self.config.java_home = self._detect_java11()
    
    def _detect_java11(self) -> Optional[str]:
        """Detect Java 11 installation on macOS."""
        try:
            result = subprocess.run(
                ["/usr/libexec/java_home", "-v", "11"],
                capture_output=True, 
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def find_testcase_directories(self) -> List[str]:
        """Locate all testcase directories in the parsed Juliet dataset."""
        pattern = os.path.join(self.config.parsed_juliet_dir, "testcase-*")
        testcase_dirs = glob.glob(pattern)
        # Sort numerically by testcase number
        testcase_dirs.sort(key=lambda x: int(x.split("-")[-1]))
        return testcase_dirs
    
    def find_main_java_file(self, testcase_dir: str) -> Optional[str]:
        """Find the primary Java file in a testcase directory."""
        testcases_path = os.path.join(testcase_dir, "testcases")
        
        for root, _, files in os.walk(testcases_path):
            for file in files:
                if file.endswith(".java"):
                    return os.path.join(root, file)
        return None
    
    def run_commit_history_generation(self, testcase_dir: str, 
                                    testcase_num: int) -> bool:
        """Generate commit history for a testcase."""
        print(f"\n{'='*60}")
        print(f"Step 1: Generating commit history for testcase-{testcase_num}")
        print(f"{'='*60}")
        
        try:
            main_java_file = self.find_main_java_file(testcase_dir)
            if not main_java_file:
                print(f"Error: No Java file found in {testcase_dir}")
                self.stats.commit_history_failed += 1
                return False

            project_name = f"testcase-{testcase_num}-commits"
            support_dir = os.path.join(testcase_dir, "testcasesupport")
            
            # Run commit builder
            run_commit_builder(
                commit_repository_dir=self.config.commit_repo_dir,
                project_name=project_name,
                main_java_file=main_java_file,
                support_java_dir=support_dir,
                api_key=self.config.openai_api_key,
                test_generator_model=self.config.test_model,
                commit_history_model=self.config.commit_model
            )
            
            print(f"✅ Commit history generated successfully")
            self.stats.commit_history_success += 1
            return True
            
        except Exception as e:
            print(f"Error: Failed to generate commit history: {e}")
            self.stats.commit_history_failed += 1
            return False

    def compile_project(self, project_path: str) -> bool:
        """Compile Maven project with dependencies."""
        print(f"Compiling project: {project_path}")
        
        try:
            env = self._get_java_environment()
            
            # Run Maven compile and dependency resolution
            result = subprocess.run(
                ["mvn", "clean", "compile", "dependency:copy-dependencies", "-DskipTests"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=180,
                env=env
            )
            
            if result.returncode == 0:
                self._verify_compilation(project_path)
                return True
            else:
                print(f"Compilation failed (exit code: {result.returncode})")
                if result.stderr:
                    print(f"Error output:\n{result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("Compilation timed out")
            return False
        except Exception as e:
            print(f"Compilation error: {e}")
            return False
    
    def _get_java_environment(self) -> Dict[str, str]:
        """Get environment variables with Java configuration."""
        env = os.environ.copy()
        if self.config.java_home:
            env['JAVA_HOME'] = self.config.java_home
            env['PATH'] = f"{self.config.java_home}/bin:{env.get('PATH', '')}"
            print(f"Using Java: {self.config.java_home}")
        return env
    
    def _verify_compilation(self, project_path: str):
        """Verify compilation results."""
        target_classes = os.path.join(project_path, "target", "classes")
        if os.path.exists(target_classes):
            class_count = sum(1 for root, _, files in os.walk(target_classes) 
                            for f in files if f.endswith('.class'))
            print(f"Generated {class_count} class files")
            
            # Check dependencies
            deps_dir = os.path.join(project_path, "target", "dependency")
            if os.path.exists(deps_dir):
                jar_count = len([f for f in os.listdir(deps_dir) if f.endswith('.jar')])
                print(f"Copied {jar_count} dependency JARs")

    def run_cwe_analysis(self, testcase_dir: str, 
                        testcase_num: int) -> Tuple[bool, Optional[str]]:
        """Run CWE vulnerability analysis on generated code."""
        print(f"\n{'='*60}")
        print(f"Step 2: Running CWE analysis for testcase-{testcase_num}")
        print(f"{'='*60}")
        
        try:
            project_name = f"testcase-{testcase_num}-commits"
            project_path = os.path.join(self.config.commit_repo_dir, project_name)
            
            if not os.path.exists(project_path):
                print(f"Error: Project not found: {project_path}")
                self.stats.cwe_analysis_failed += 1
                return False, None
            
            # Compile project first
            if not self.compile_project(project_path):
                print("Failed to compile project")
                self.stats.cwe_analysis_failed += 1
                return False, None
            
            # Run analysis
            findings_file = self._run_s2e_scanner(project_path, testcase_num)
            
            if findings_file and os.path.exists(findings_file):
                self._print_findings_summary(findings_file)
                self.stats.cwe_analysis_success += 1
                return True, findings_file
            else:
                print("CWE analysis failed")
                self.stats.cwe_analysis_failed += 1
                return False, None
                
        except Exception as e:
            print(f"Analysis error: {e}")
            self.stats.cwe_analysis_failed += 1
            return False, None

    def _run_s2e_scanner(self, project_path: str, testcase_num: int) -> Optional[str]:
        """Execute S2E vulnerability scanner."""
        print("Running S2E scanner...")
        
        # Find main Java file
        main_java_file = self._find_project_main_file(project_path)
        if not main_java_file:
            print("Error: No main Java file found")
            return None
        
        # Set up scanner paths
        scanner_config = self._get_scanner_config(project_path, main_java_file)
        findings_file = os.path.join(project_path, f"findings-{testcase_num}.json")
        
        # Build scanner command
        args = [
            main_java_file,
            scanner_config['pattern_file'],
            scanner_config['support_dir'],
            scanner_config['class_dir'],
            scanner_config['jar_dir'],
            scanner_config['exclusions_file'],
            findings_file
        ]
        
        cmd = [
            "mvn", "exec:java",
            f"-Dexec.mainClass=s2e.Main",
            f"-Dexec.args={' '.join(args)}",
            "-q"
        ]
        
        # Run scanner
        try:
            result = subprocess.run(
                cmd,
                cwd=self.config.s2e_project_dir,
                capture_output=True,
                text=True,
                timeout=300,
                env=self._get_java_environment()
            )
            
            if result.returncode == 0 and os.path.exists(findings_file):
                print("✅ Analysis completed successfully")
                return findings_file
            else:
                print(f"Scanner failed (exit code: {result.returncode})")
                if result.stderr:
                    print(f"Error: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("Scanner timed out")
            return None
        except Exception as e:
            print(f"Scanner error: {e}")
            return None

    def _get_scanner_config(self, project_path: str, main_file: str) -> Dict[str, str]:
        """Get S2E scanner configuration paths."""
        compiled_classes = os.path.join(project_path, "target", "classes")
        
        # Determine class directory from package structure
        java_rel_path = os.path.relpath(
            main_file, 
            os.path.join(project_path, "src/main/java")
        )
        package_dir = os.path.dirname(java_rel_path)
        class_dir = os.path.join(compiled_classes, package_dir)
        
        # Support files directory
        support_dir = os.path.join(compiled_classes, "testcasesupport")
        if not os.path.exists(support_dir):
            support_dir = os.path.join(project_path, "src/main/java/testcasesupport")
        
        return {
            'pattern_file': "/Users/vlopes/Desktop/git-projects/Patch-Vul/src/main/resources/cwe-patterns.json",
            'exclusions_file': "/Users/vlopes/Desktop/git-projects/Patch-Vul/src/main/resources/exclusions.txt",
            'jar_dir': "/Users/vlopes/Desktop/Java/lib/",
            'class_dir': class_dir,
            'support_dir': support_dir
        }

    def _find_project_main_file(self, project_path: str) -> Optional[str]:
        """Find main Java file in Maven project."""
        src_main_java = os.path.join(project_path, "src", "main", "java")
        
        for root, dirs, files in os.walk(src_main_java):
            if "testcasesupport" in root:
                continue
            for file in files:
                if file.endswith(".java"):
                    return os.path.join(root, file)
        return None

    def _print_findings_summary(self, findings_file: str):
        """Print summary of vulnerability findings."""
        try:
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            
            print(f"Found {len(findings)} vulnerabilities:")
            for i, finding in enumerate(findings[:3], 1):
                cwe = finding.get('cwe', 'Unknown')
                line = finding.get('line', '?')
                print(f"  {i}. {cwe} at line {line}")
            
            if len(findings) > 3:
                print(f"  ... and {len(findings) - 3} more")
        except:
            pass

    def run_patch_generation(self, findings_file: str, testcase_num: int) -> bool:
        """Generate security patches for identified vulnerabilities."""
        print(f"\n{'='*60}")
        print(f"Step 3: Generating patches for testcase-{testcase_num}")
        print(f"{'='*60}")
        
        try:
            project_name = f"testcase-{testcase_num}-commits"
            commit_repo = os.path.join(self.config.commit_repo_dir, project_name)
            
            patch_all_findings(
                findings_path=findings_file,
                api_key=self.config.openai_api_key,
                commit_repo=commit_repo,
                model=self.config.patch_model
            )
            
            print("✅ Patches generated successfully")
            self.stats.patch_success += 1
            return True
            
        except Exception as e:
            print(f"Patch generation failed: {e}")
            self.stats.patch_failed += 1
            return False

    def process_single_testcase(self, testcase_dir: str, 
                              testcase_num: int) -> List[str]:
        """Process a single testcase through the complete pipeline."""
        print(f"\n🚀 Processing testcase-{testcase_num}")
        print(f"Directory: {testcase_dir}")
        
        completed_steps = []
        
        # Step 1: Generate commit history
        if self.run_commit_history_generation(testcase_dir, testcase_num):
            completed_steps.append("commit_history")
        else:
            return completed_steps
        
        # Step 2: Run CWE analysis
        success, findings_file = self.run_cwe_analysis(testcase_dir, testcase_num)
        if success and findings_file:
            completed_steps.append("cwe_analysis")
        else:
            return completed_steps
        
        # Step 3: Generate patches
        if self.run_patch_generation(findings_file, testcase_num):
            completed_steps.append("patch_generation")
        
        return completed_steps

    def run_pipeline(self, start_testcase: Optional[int] = None, 
                    end_testcase: Optional[int] = None):
        """Execute the complete pipeline on specified testcases."""
        print("Starting Vulnerability Lifecycle Pipeline")
        print(f"Source: {self.config.parsed_juliet_dir}")
        print(f"Output: {self.config.commit_repo_dir}")
        
        # Find testcases
        testcase_dirs = self.find_testcase_directories()
        if not testcase_dirs:
            print("Error: No testcase directories found")
            return
        
        # Apply range filter
        if start_testcase is not None or end_testcase is not None:
            testcase_dirs = self._filter_testcase_range(
                testcase_dirs, start_testcase, end_testcase
            )
        
        self.stats.total_testcases = len(testcase_dirs)
        print(f"Processing {len(testcase_dirs)} testcases")
        
        # Process each testcase
        for i, testcase_dir in enumerate(testcase_dirs, 1):
            testcase_num = int(testcase_dir.split("-")[-1])
            print(f"\nProgress: {i}/{len(testcase_dirs)}")
            
            try:
                completed = self.process_single_testcase(testcase_dir, testcase_num)
                print(f"Completed: {completed}")
                
            except KeyboardInterrupt:
                print("\nPipeline interrupted by user")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                continue
        
        self.print_summary()

    def _filter_testcase_range(self, testcase_dirs: List[str], 
                             start: Optional[int], end: Optional[int]) -> List[str]:
        """Filter testcases by numeric range."""
        filtered = []
        for testcase_dir in testcase_dirs:
            num = int(testcase_dir.split("-")[-1])
            if start is not None and num < start:
                continue
            if end is not None and num > end:
                continue
            filtered.append(testcase_dir)
        return filtered

    def print_summary(self):
        """Print execution summary statistics."""
        print(f"\n{'='*60}")
        print("PIPELINE EXECUTION SUMMARY")
        print(f"{'='*60}")
        print(f"Total testcases: {self.stats.total_testcases}")
        
        print(f"\nCommit History Generation:")
        print(f"  Success: {self.stats.commit_history_success}")
        print(f"  Failed: {self.stats.commit_history_failed}")
        
        print(f"\nCWE Analysis:")
        print(f"  Success: {self.stats.cwe_analysis_success}")
        print(f"  Failed: {self.stats.cwe_analysis_failed}")
        
        print(f"\nPatch Generation:")
        print(f"  Success: {self.stats.patch_success}")
        print(f"  Failed: {self.stats.patch_failed}")


def main():
    """Main entry point."""
    config = PipelineConfig(
        parsed_juliet_dir="/Users/vlopes/Desktop/parsed-juliet",
        commit_repo_dir="/Users/vlopes/Desktop/git-projects/repo-for-test",
        openai_api_key="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",
        s2e_project_dir="/Users/vlopes/Desktop/git-projects/Patch-Vul"
    )
    
    pipeline = VulnerabilityPipeline(config)
    pipeline.run_pipeline()


if __name__ == "__main__":
    main()