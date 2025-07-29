#!/usr/bin/env python3
"""
GitHub Repository Size Checker
Fetches repository size and other statistics using the GitHub API
"""

import requests
import json
import sys
import re
from datetime import datetime


def format_bytes(bytes_size):
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def get_repo_info(owner, repo, token=None):
    """Fetch repository information from GitHub API"""
    url = f"https://api.github.com/repos/{owner}/{repo}"
    
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Add authentication token if provided
    if token:
        headers["Authorization"] = f"token {token}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"\nError: Repository '{owner}/{repo}' not found!")
            print("\nPossible reasons:")
            print("1. The repository name is case-sensitive. Check the exact capitalization.")
            print("2. The repository might be private (use a token with appropriate permissions).")
            print("3. The repository might have been renamed or deleted.")
            print(f"\nTried URL: {url}")
            
            # Try to search for similar repos
            search_url = f"https://api.github.com/search/repositories?q={repo}+user:{owner}"
            try:
                search_response = requests.get(search_url, headers=headers)
                if search_response.status_code == 200:
                    results = search_response.json()
                    if results['total_count'] > 0:
                        print("\nDid you mean one of these?")
                        for item in results['items'][:5]:
                            print(f"  - {item['full_name']}")
            except:
                pass
        else:
            print(f"Error fetching repository data: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching repository data: {e}")
        return None


def get_repo_stats(owner, repo, token=None):
    """Fetch additional repository statistics"""
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    
    if token:
        headers["Authorization"] = f"token {token}"
    
    stats = {
        "commits": 0,
        "contributors": 0,
        "files": 0,
        "lines": 0
    }
    
    # Get commit count from contributors endpoint
    try:
        # Get default branch first
        repo_url = f"https://api.github.com/repos/{owner}/{repo}"
        repo_response = requests.get(repo_url, headers=headers)
        if repo_response.status_code == 200:
            default_branch = repo_response.json().get('default_branch', 'main')
            
            # Get commit count
            commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits?sha={default_branch}&per_page=1"
            commits_response = requests.get(commits_url, headers=headers)
            if commits_response.status_code == 200 and 'Link' in commits_response.headers:
                # Parse the Link header to get total pages (commits)
                link_header = commits_response.headers['Link']
                if 'last' in link_header:
                    import re
                    match = re.search(r'page=(\d+)>; rel="last"', link_header)
                    if match:
                        stats["commits"] = int(match.group(1))
            
            # Get contributors count
            contrib_url = f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=1&anon=true"
            contrib_response = requests.get(contrib_url, headers=headers)
            if contrib_response.status_code == 200 and 'Link' in contrib_response.headers:
                link_header = contrib_response.headers['Link']
                if 'last' in link_header:
                    match = re.search(r'page=(\d+)>; rel="last"', link_header)
                    if match:
                        stats["contributors"] = int(match.group(1))
                elif contrib_response.json():
                    stats["contributors"] = len(contrib_response.json())
    except:
        pass
    
    # Get file count and lines of code using tree API
    try:
        # Get the default branch SHA
        branch_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{default_branch}"
        branch_response = requests.get(branch_url, headers=headers)
        
        if branch_response.status_code == 200:
            tree_sha = branch_response.json()['commit']['sha']
            
            # Get repository tree (all files)
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=true"
            tree_response = requests.get(tree_url, headers=headers)
            
            if tree_response.status_code == 200:
                tree_data = tree_response.json()
                if 'tree' in tree_data:
                    files = [item for item in tree_data['tree'] if item['type'] == 'blob']
                    stats["files"] = len(files)
                    
                    # Note: Getting actual line count would require fetching each file
                    # which is rate-limit intensive. We'll estimate based on size.
                    print("  Note: Line count is estimated based on repository size")
    except:
        pass
    
    return stats


def get_repo_languages(owner, repo, token=None):
    """Fetch language statistics for the repository"""
    url = f"https://api.github.com/repos/{owner}/{repo}/languages"
    
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    
    if token:
        headers["Authorization"] = f"token {token}"
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching language data: {e}")
        return None


def list_user_repos(owner, token=None):
    """List all repositories for a given owner/organization"""
    page = 1
    all_repos = []
    
    headers = {
        "Accept": "application/vnd.github.v3+json"
    }
    
    if token:
        headers["Authorization"] = f"token {token}"
    
    print(f"\nFetching repositories for {owner}...\n")
    
    while True:
        url = f"https://api.github.com/users/{owner}/repos?per_page=100&page={page}"
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            repos = response.json()
            
            if not repos:
                break
                
            all_repos.extend(repos)
            page += 1
            
            if len(repos) < 100:
                break
                
        except requests.exceptions.RequestException as e:
            print(f"Error fetching repositories: {e}")
            return
    
    if not all_repos:
        print(f"No repositories found for {owner}")
        return
    
    print(f"Found {len(all_repos)} repositories:\n")
    
    # Sort by name
    all_repos.sort(key=lambda x: x['name'].lower())
    
    for repo in all_repos:
        size_str = f"{repo['size']:,} KB" if repo['size'] > 0 else "Empty"
        private_str = " (Private)" if repo.get('private', False) else ""
        print(f"  {repo['name']:<40} {size_str:>15}{private_str}")
    
    print(f"\nTotal: {len(all_repos)} repositories")


def display_repo_info(repo_data, languages_data, stats_data=None):
    """Display repository information in a formatted way"""
    if not repo_data:
        return
    
    print("\n" + "="*50)
    print(f"Repository: {repo_data['full_name']}")
    print("="*50)
    
    # Basic info
    print(f"\nDescription: {repo_data.get('description', 'No description')}")
    print(f"Created: {datetime.strptime(repo_data['created_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d')}")
    print(f"Last Updated: {datetime.strptime(repo_data['updated_at'], '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d')}")
    
    # Size information
    size_kb = repo_data.get('size', 0)
    size_bytes = size_kb * 1024
    print(f"\nRepository Size: {size_kb:,} KB ({format_bytes(size_bytes)})")
    
    # Additional statistics
    if stats_data:
        print(f"\nCode Statistics:")
        print(f"  Files: {stats_data['files']:,}" if stats_data['files'] > 0 else "  Files: N/A")
        print(f"  Commits: {stats_data['commits']:,}" if stats_data['commits'] > 0 else "  Commits: N/A")
        print(f"  Contributors: {stats_data['contributors']:,}" if stats_data['contributors'] > 0 else "  Contributors: N/A")
        
        # Estimate lines of code based on average file size
        if stats_data['files'] > 0 and size_kb > 0:
            avg_file_size = size_kb / stats_data['files']
            # Rough estimate: 1 KB ≈ 25-40 lines of code
            estimated_lines = int(size_kb * 30)
            print(f"  Estimated Lines: ~{estimated_lines:,}")
    
    # Statistics
    print(f"\nRepository Stats:")
    print(f"  Stars: {repo_data.get('stargazers_count', 0):,}")
    print(f"  Forks: {repo_data.get('forks_count', 0):,}")
    print(f"  Open Issues: {repo_data.get('open_issues_count', 0):,}")
    print(f"  Watchers: {repo_data.get('watchers_count', 0):,}")
    
    # Language breakdown
    if languages_data:
        print("\nLanguage Breakdown:")
        total_bytes = sum(languages_data.values())
        for lang, bytes_count in sorted(languages_data.items(), key=lambda x: x[1], reverse=True):
            percentage = (bytes_count / total_bytes) * 100 if total_bytes > 0 else 0
            print(f"  {lang}: {percentage:.1f}% ({format_bytes(bytes_count)})")
    
    # Additional info
    print(f"\nAdditional Info:")
    print(f"  Default Branch: {repo_data.get('default_branch', 'N/A')}")
    print(f"  License: {repo_data.get('license', {}).get('name', 'No license') if repo_data.get('license') else 'No license'}")
    print(f"  Private: {'Yes' if repo_data.get('private', False) else 'No'}")
    print(f"  Archived: {'Yes' if repo_data.get('archived', False) else 'No'}")
    
    if repo_data.get('fork', False):
        print(f"  Fork of: {repo_data.get('parent', {}).get('full_name', 'Unknown')}")
    
    # Topics/Tags
    if repo_data.get('topics'):
        print(f"  Topics: {', '.join(repo_data['topics'])}")


def main():
    """Main function to run the script"""
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python github_repo_size.py <owner/repo> [token]")
        print("Example: python github_repo_size.py facebook/react")
        print("\nNote: Providing a GitHub token is optional but recommended to avoid rate limits")
        print("\nOptions:")
        print("  --debug    Show debug information")
        print("  --list     List all repositories for the owner")
        sys.exit(1)
    
    # Check if listing repos
    if "--list" in sys.argv and len(sys.argv) >= 2:
        owner = sys.argv[1]
        token = None
        for i, arg in enumerate(sys.argv):
            if arg not in ["--list", "--debug", owner] and i > 0:
                token = arg
                break
        
        list_user_repos(owner, token)
        sys.exit(0)
    
    # Parse repository argument
    repo_arg = sys.argv[1]
    if '/' not in repo_arg:
        print("Error: Repository must be in format 'owner/repo'")
        sys.exit(1)
    
    owner, repo = repo_arg.split('/', 1)
    
    # Optional token
    token = None
    for i, arg in enumerate(sys.argv[2:], 2):
        if not arg.startswith("--"):
            token = arg
            break
    
    print(f"Fetching information for {owner}/{repo}...")
    
    # Debug mode flag
    debug = "--debug" in sys.argv
    if debug:
        print(f"Debug: Using API endpoint https://api.github.com/repos/{owner}/{repo}")
        if token:
            print("Debug: Using authentication token")
    
    # Fetch repository data
    repo_data = get_repo_info(owner, repo, token)
    if not repo_data:
        sys.exit(1)
    
    languages_data = get_repo_languages(owner, repo, token)
    
    # Fetch additional statistics
    print("Fetching additional statistics...")
    stats_data = get_repo_stats(owner, repo, token)
    
    # Display results
    display_repo_info(repo_data, languages_data, stats_data)
    
    # Rate limit info
    if repo_data:
        print("\n" + "-"*50)
        print("Note: GitHub API has rate limits.")
        print("- Without authentication: 60 requests/hour")
        print("- With authentication: 5,000 requests/hour")
        if not token:
            print("\nTip: Provide a GitHub token as second argument to increase rate limit")


if __name__ == "__main__":
    main()