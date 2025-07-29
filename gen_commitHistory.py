import os
import re
from typing import List, Tuple, Optional
from openai import OpenAI
from git import Repo, InvalidGitRepositoryError


class CommitHistoryGenerator:
    """Generates realistic commit history for Java files using GPT."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
    
    def parse_package_from_java(self, java_code: str) -> Optional[str]:
        """Extract package declaration from Java source code."""
        match = re.search(r'package\s+([a-zA-Z0-9_.]+);', java_code)
        return match.group(1) if match else None
    
    def ensure_package_directory(self, base_path: str, package: str) -> str:
        """Create and return the directory path for a Java package."""
        if package:
            package_path = os.path.join(base_path, *(package.split('.')))
        else:
            package_path = base_path
        os.makedirs(package_path, exist_ok=True)
        return package_path
    
    def is_complete_java_file(self, code_snippet: str) -> bool:
        """Check if code snippet contains a complete Java class definition."""
        # Remove comments and imports to check for class definition
        cleaned = re.sub(r"(?s)/\*.*?\*/", "", code_snippet)
        cleaned = re.sub(r"//.*", "", cleaned)
        cleaned = re.sub(r"^\s*(package|import)[^;]+;\s*", "", cleaned, flags=re.MULTILINE)
        return re.search(r'\bclass\s+\w+', cleaned) is not None
    
    def gather_support_files(self, support_dir: str) -> List[Tuple[str, str]]:
        """Collect all Java support files from the given directory."""
        support_files = []
        if not os.path.exists(support_dir):
            return support_files
            
        for root, _, files in os.walk(support_dir):
            for filename in files:
                if filename.endswith('.java'):
                    filepath = os.path.join(root, filename)
                    relative_path = os.path.relpath(filepath, support_dir)
                    with open(filepath, "r") as f:
                        support_files.append((relative_path, f.read()))
        return support_files
    
    def build_gpt_prompt(self, main_code: str, support_files: List[Tuple[str, str]]) -> str:
        """Construct the prompt for GPT to generate commit history."""
        support_content = ""
        for filename, code in support_files:
            support_content += f"\n- {filename}\n```\n{code}\n```\n"
        
        return f"""You are an experienced Java developer. Create a realistic commit history for the given Java class.

REQUIREMENTS:
1. Each commit must contain COMPLETE, VALID, COMPILABLE Java code
2. Output the ENTIRE Java file at each step, not just code snippets
3. Ensure proper Java syntax with all braces, semicolons, and class structure
4. Every commit should compile successfully with the provided support files

Split the development into logical commits (start with signatures, then implement methods).

Target Java class:
```java
{main_code}
```

Support classes:
{support_content}

Generate 3-5 commits with complete, valid Java code for each step."""
    
    def parse_gpt_response(self, response_text: str) -> List[Tuple[str, str]]:
        """Extract commit messages and code from GPT response."""
        # Try to parse structured commits first
        pattern = r"(?:^|\n)#+?\s*Commit\s+(\d+):\s*(.*?)\n+```(?:java)?\n(.*?)```"
        commits = []
        
        for match in re.finditer(pattern, response_text, re.DOTALL | re.IGNORECASE):
            num, msg, code = match.groups()
            msg = msg.strip() if msg else f"Step {num}"
            # Clean up message if it contains code artifacts
            if msg.startswith("```") or msg.startswith("/*") or not msg:
                msg = f"Step {num}"
            commits.append((msg, code.strip()))
        
        # Fallback: extract any Java code blocks
        if not commits:
            blocks = re.findall(r"```java(.*?)```", response_text, re.DOTALL)
            commits = [(f"Step {i+1}", block.strip()) for i, block in enumerate(blocks)]
        
        # Last resort: treat entire response as code
        if not commits:
            commits = [("Initial implementation", response_text.strip())]
        
        return commits
    
    def generate_commits(self, main_java_file: str, support_dir: str, 
                        repo_root: str, src_base: str) -> bool:
        """Generate commit history for a Java file."""
        # Validate inputs
        if not os.path.isfile(main_java_file):
            print(f"Error: Main Java file not found: {main_java_file}")
            return False
        
        # Gather context
        support_files = self.gather_support_files(support_dir)
        print(f"Found {len(support_files)} support files")
        
        # Initialize repository
        repo = self._init_repository(repo_root)
        if not repo:
            return False
        
        # Read main file and build prompt
        with open(main_java_file, "r") as f:
            main_code = f.read()
        
        prompt = self.build_gpt_prompt(main_code, support_files)
        
        # Get GPT response
        print("Generating commit history...")
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a helpful developer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            response_text = response.choices[0].message.content
        except Exception as e:
            print(f"Error calling GPT: {e}")
            return False
        
        # Parse and apply commits
        commits = self.parse_gpt_response(response_text)
        if not commits:
            print("No commits could be parsed from response")
            return False
        
        print(f"Creating {len(commits)} commits")
        return self._apply_commits(commits, main_java_file, repo, src_base)
    
    def _init_repository(self, repo_root: str) -> Optional[Repo]:
        """Initialize or load Git repository."""
        if not os.path.exists(repo_root):
            os.makedirs(repo_root)
        
        try:
            repo = Repo(repo_root)
            print(f"Using existing repository at {repo_root}")
        except InvalidGitRepositoryError:
            repo = Repo.init(repo_root)
            print(f"Initialized new repository at {repo_root}")
        
        # Create initial commit if needed
        if not repo.head.is_valid():
            placeholder = os.path.join(repo_root, "placeholder.txt")
            with open(placeholder, "w") as f:
                f.write("Initial placeholder\n")
            repo.git.add(placeholder)
            repo.index.commit("Initial commit")
        
        return repo
    
    def _apply_commits(self, commits: List[Tuple[str, str]], main_file: str, 
                      repo: Repo, src_base: str) -> bool:
        """Apply parsed commits to the repository."""
        # Determine output location based on package
        out_base = os.path.join(src_base, "src", "main", "java")
        
        with open(main_file, "r") as f:
            original_code = f.read()
        
        package = self.parse_package_from_java(original_code)
        package_dir = self.ensure_package_directory(out_base, package)
        filename = os.path.basename(main_file)
        output_path = os.path.join(package_dir, filename)
        
        # Apply each commit
        current_code = ""
        for idx, (message, code) in enumerate(commits, 1):
            print(f"Commit {idx}: {message[:60]}...")
            
            # Update code content
            if self.is_complete_java_file(code) or idx == 1:
                current_code = code
            else:
                # Append to existing code if it's a fragment
                current_code += "\n\n" + code
            
            # Write file
            with open(output_path, "w") as f:
                f.write(current_code)
            
            # Commit changes
            commit_msg = f"{package or 'src'}/{filename}: {message}"
            relative_path = os.path.relpath(output_path, repo.working_dir)
            repo.git.add(relative_path)
            repo.index.commit(commit_msg)
            
            # Try to push if remote exists
            try:
                origin = repo.remote(name='origin')
                origin.push()
                print("Pushed to remote")
            except ValueError:
                pass  # No remote configured
            except Exception as e:
                print(f"Push failed: {e}")
        
        print(f"\nSuccessfully created {len(commits)} commits")
        return True


def gpt_commit_one_file_with_support(main_java_file: str, support_dir: str,
                                    repo_root_dir: str, src_base_dir: str,
                                    api_key: str, model: str = "gpt-4o-mini"):
    """Legacy function wrapper for backward compatibility."""
    generator = CommitHistoryGenerator(api_key, model)
    return generator.generate_commits(main_java_file, support_dir, 
                                    repo_root_dir, src_base_dir)