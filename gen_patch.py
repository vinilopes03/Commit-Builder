import json
import os
import re
import subprocess
from typing import Dict, List, Any, Optional
from openai import OpenAI


class VulnerabilityPatcher:
    """Generates security patches for identified vulnerabilities using GPT."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
    
    def load_findings(self, findings_path: str) -> List[Dict[str, Any]]:
        """Load vulnerability findings from JSON file."""
        if not os.path.exists(findings_path):
            raise FileNotFoundError(f"Findings file not found: {findings_path}")
        
        with open(findings_path) as f:
            return json.load(f)
    
    def extract_code_from_response(self, response: str) -> str:
        """Extract Java code from GPT response."""
        # Try to find code within markdown fences
        match = re.search(r"```(?:java)?\n(.*?)```", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Otherwise return the entire response
        return response.strip()
    
    def generate_patch(self, file_path: str, vuln_line: int, cwe_id: str) -> str:
        """Generate a security patch for the given vulnerability."""
        # Read the vulnerable code
        with open(file_path, 'r') as f:
            code = f.read()
        
        prompt = f"""You are a secure Java developer. Fix the vulnerability in this code.

Vulnerability: {cwe_id} on line {vuln_line}

Requirements:
- Fix ONLY the security vulnerability
- Make minimal changes to the code
- Preserve all existing functionality
- Ensure the fix is correct and complete

Java code:
{code}

Output ONLY the fully patched Java code, no explanations."""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        
        patched_code = response.choices[0].message.content
        return self.extract_code_from_response(patched_code)
    
    def apply_patch(self, file_path: str, patched_code: str) -> None:
        """Write the patched code to the file."""
        with open(file_path, "w") as f:
            f.write(patched_code)
        print(f"✅ Patched: {file_path}")
    
    def commit_and_push(self, repo_dir: str, cwe_id: str, file_path: str) -> bool:
        """Commit and push the patch to the repository."""
        file_name = os.path.basename(file_path)
        commit_msg = f"Security patch: {cwe_id} in {file_name}"
        
        try:
            # Stage changes
            subprocess.run(['git', 'add', '-A'], cwd=repo_dir, check=True)
            
            # Commit
            subprocess.run(['git', 'commit', '-m', commit_msg], 
                         cwd=repo_dir, check=True)
            
            # Push
            subprocess.run(['git', 'push'], cwd=repo_dir, check=True)
            
            print(f"✅ Committed and pushed: {commit_msg}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Git operation failed: {e}")
            return False
    
    def patch_all_findings(self, findings_path: str, commit_repo: str) -> Dict[str, int]:
        """Process all findings and generate patches."""
        findings = self.load_findings(findings_path)
        
        if not findings:
            print("No vulnerabilities found to patch")
            return {"total": 0, "patched": 0, "failed": 0}
        
        stats = {"total": len(findings), "patched": 0, "failed": 0}
        
        for finding in findings:
            # Extract finding details (support multiple field names)
            file_path = (finding.get("file_path") or 
                        finding.get("filepath") or 
                        finding.get("path") or 
                        finding.get("filePath"))
            
            vuln_line = finding.get("line") or finding.get("line_number")
            cwe_id = (finding.get("cwe_id") or 
                     finding.get("cweId") or 
                     finding.get("cwe"))
            
            if not all([file_path, vuln_line, cwe_id]):
                print(f"⚠️  Skipping incomplete finding: {finding}")
                stats["failed"] += 1
                continue
            
            print(f"\n🔧 Patching {cwe_id} in {file_path} (line {vuln_line})")
            
            try:
                # Generate and apply patch
                patched_code = self.generate_patch(file_path, vuln_line, cwe_id)
                self.apply_patch(file_path, patched_code)
                
                # Commit changes
                if self.commit_and_push(commit_repo, cwe_id, file_path):
                    stats["patched"] += 1
                else:
                    stats["failed"] += 1
                    
            except Exception as e:
                print(f"❌ Failed to patch: {e}")
                stats["failed"] += 1
        
        # Print summary
        print(f"\n📊 Patching Summary:")
        print(f"   Total findings: {stats['total']}")
        print(f"   Successfully patched: {stats['patched']}")
        print(f"   Failed: {stats['failed']}")
        
        return stats


def patch_all_findings(findings_path: str, api_key: str, commit_repo: str, 
                      model: str = "gpt-4o-mini") -> None:
    """Legacy function wrapper for backward compatibility."""
    patcher = VulnerabilityPatcher(api_key, model)
    patcher.patch_all_findings(findings_path, commit_repo)


if __name__ == "__main__":
    # Configuration
    config = {
        "api_key": "your-api-key-here",
        "findings_json": "/path/to/findings.json",
        "commit_repo": "/path/to/repo",
        "model": "gpt-4o-mini"
    }
    
    patcher = VulnerabilityPatcher(config["api_key"], config["model"])
    patcher.patch_all_findings(config["findings_json"], config["commit_repo"])