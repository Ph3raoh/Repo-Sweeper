#!/usr/bin/env python3
"""
Repo-Sweeper: A tool to scan GitHub repositories for sensitive data,
notify owners, and suggest fixes via pull requests.
"""

import argparse
import re
import os
from github import Github
from git import Repo
import requests

# Sensitive data patterns (basic examples)
SENSITIVE_PATTERNS = {
    'api_key': re.compile(r'(?i)(api[_-]?key|apikey|sk-)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    'password': re.compile(r'(?i)(password|passwd|pwd)[=:]\s*["\']?([^\s\'"]{8,})["\']?'),
    'secret': re.compile(r'(?i)(secret|token)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    'aws_access_key': re.compile(r'(?i)(AKIA[0-9A-Z]{16})'),
    'aws_secret_key': re.compile(r'(?i)([a-zA-Z0-9+/]{40})'),  # Simplified
}

def scan_file_content(content, file_path):
    """
    Scan file content for sensitive data patterns.
    Returns list of findings: (line_number, line, pattern_type, match)
    """
    findings = []
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        for pattern_type, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(line)
            if matches:
                findings.append((i, line.strip(), pattern_type, matches))
    return findings

def scan_repository(repo_url, github_token):
    """
    Scan a GitHub repository for sensitive data.
    """
    # Authenticate with GitHub
    g = Github(github_token)
    
    # Parse repo URL to get owner/repo
    # Assuming URL like https://github.com/owner/repo
    parts = repo_url.rstrip('/').split('/')
    owner = parts[-2]
    repo_name = parts[-1]
    
    repo = g.get_repo(f"{owner}/{repo_name}")
    
    findings = []
    
    # Get all files in the repo (simplified, only master branch)
    contents = repo.get_contents("", ref="main")
    # If main doesn't exist, try master
    if not contents:
        contents = repo.get_contents("", ref="master")
    
    def get_contents_recursive(contents):
        files = []
        for content in contents:
            if content.type == "file":
                files.append(content)
            elif content.type == "dir":
                sub_contents = repo.get_contents(content.path, ref="main")
                if not sub_contents:
                    sub_contents = repo.get_contents(content.path, ref="master")
                files.extend(get_contents_recursive(sub_contents))
        return files
    
    all_files = get_contents_recursive(contents)
    
    for file in all_files:
        if file.size > 1000000:  # Skip large files
            continue
        try:
            content = file.decoded_content.decode('utf-8')
            file_findings = scan_file_content(content, file.path)
            if file_findings:
                findings.append((file.path, file_findings))
        except:
            continue  # Skip binary or decode errors
    
    return findings, owner, repo_name, repo

def create_issue(repo, findings):
    """
    Create a GitHub issue with findings.
    """
    title = "Potential Sensitive Data Found"
    body = "The following sensitive data patterns were detected in your repository:\n\n"
    for file_path, file_findings in findings:
        body += f"**{file_path}**\n"
        for line_num, line, pattern_type, matches in file_findings:
            body += f"- Line {line_num}: {pattern_type.upper()} detected in: `{line}`\n"
        body += "\n"
    body += "Please review and remove any sensitive information.\n"
    
    issue = repo.create_issue(title=title, body=body)
    return issue

def suggest_fix(repo, findings, github_token):
    """
    Attempt to fix by creating a branch and PR with redactions.
    This is simplified and may not be perfect.
    """
    # Clone the repo locally (assuming we have access)
    # This is tricky without permissions, so perhaps just suggest manual fixes for now.
    # For full implementation, need to fork or have write access.
    
    # For now, create a PR with a comment suggesting fixes.
    title = "Proposed Fixes for Sensitive Data"
    body = "This PR proposes to remove detected sensitive data.\n\nChanges:\n"
    for file_path, file_findings in findings:
        body += f"- {file_path}: Redact sensitive lines\n"
    
    # To create PR, need to create branch first.
    # This requires write access or forking.
    # Assume the token has access.
    
    # Create a new branch
    base_branch = repo.get_branch("main") or repo.get_branch("master")
    new_branch_name = "fix-sensitive-data"
    ref = repo.create_git_ref(ref=f"refs/heads/{new_branch_name}", sha=base_branch.commit.sha)
    
    # For simplicity, since editing files via API is complex, just create the issue and PR with instructions.
    pr = repo.create_pull(title=title, body=body, head=new_branch_name, base=base_branch.name)
    
    # Note: Actual file changes would require updating files via API or local clone.
    # For now, this is a placeholder.
    
    return pr

def main():
    parser = argparse.ArgumentParser(description="Scan GitHub repos for sensitive data.")
    parser.add_argument("repo_url", help="GitHub repository URL")
    parser.add_argument("--token", required=True, help="GitHub personal access token")
    parser.add_argument("--fix", action="store_true", help="Attempt to create PR with fixes")
    
    args = parser.parse_args()
    
    findings, owner, repo_name, repo = scan_repository(args.repo_url, args.token)
    
    if findings:
        print(f"Found sensitive data in {len(findings)} files.")
        issue = create_issue(repo, findings)
        print(f"Created issue: {issue.html_url}")
        
        if args.fix:
            pr = suggest_fix(repo, findings, args.token)
            print(f"Created PR: {pr.html_url}")
    else:
        print("No sensitive data found.")

if __name__ == "__main__":
    main()
