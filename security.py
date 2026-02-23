#!/usr/bin/env python3
"""
Security script for Repo-Sweeper: Scan the app's own code for sensitive data, respecting .gitignore.
"""

import os
import re
import fnmatch

# Sensitive data patterns (same as Rust version)
SENSITIVE_PATTERNS = {
    'api_key': re.compile(r'(?i)(api[_-]?key|apikey|sk-)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    'password': re.compile(r'(?i)(password|passwd|pwd)[=:]\s*["\']?([^\s\'"]{8,})["\']?'),
    'secret': re.compile(r'(?i)(secret|token)[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?'),
    'aws_access_key': re.compile(r'(?i)(AKIA[0-9A-Z]{16})'),
    'aws_secret_key': re.compile(r'(?i)([a-zA-Z0-9+/]{40})'),
}

def load_gitignore(root_dir):
    gitignore_path = os.path.join(root_dir, '.gitignore')
    if not os.path.exists(gitignore_path):
        return []
    with open(gitignore_path, 'r') as f:
        patterns = []
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    return patterns

def is_ignored(path, gitignore_patterns, root_dir):
    rel_path = os.path.relpath(path, root_dir)
    for pattern in gitignore_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
            return True
    return False

def scan_file_content(content, file_path):
    findings = []
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        for pattern_type, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(line)
            if matches:
                findings.append((i, line.strip(), pattern_type, matches))
    return findings

def scan_directory(root_dir):
    gitignore_patterns = load_gitignore(root_dir)
    findings = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Modify dirnames in place to skip ignored dirs
        dirnames[:] = [d for d in dirnames if not is_ignored(os.path.join(dirpath, d), gitignore_patterns, root_dir)]
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if is_ignored(file_path, gitignore_patterns, root_dir):
                continue
            if os.path.getsize(file_path) > 1000000:  # Skip large files
                continue
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                file_findings = scan_file_content(content, file_path)
                if file_findings:
                    findings.append((file_path, file_findings))
            except (UnicodeDecodeError, OSError):
                continue  # Skip binary or unreadable files
    return findings

if __name__ == "__main__":
    root_dir = os.getcwd()
    findings = scan_directory(root_dir)
    if findings:
        print(f"Found sensitive data in {len(findings)} files:")
        for file_path, file_findings in findings:
            print(f"**{file_path}**")
            for line_num, line, pattern_type, matches in file_findings:
                print(f"- Line {line_num}: {pattern_type.upper()} detected in: `{line}`")
    else:
        print("No sensitive data found in the app's code.")
