# Repo-Sweeper

Repo-Sweeper is a tool to scan GitHub repositories for sensitive data such as API keys, passwords, and secrets. It notifies repository owners via GitHub issues and can attempt to create pull requests with suggested fixes.

## Features

- Scans repository files for common sensitive data patterns
- Creates GitHub issues to notify owners
- Optionally creates pull requests with proposed fixes (redaction)

## Installation

1. Ensure Rust is installed (https://rustup.rs/).
2. Clone the repository:
   ```bash
   git clone https://github.com/Ph3raoh/Repo-Sweeper.git
   cd Repo-Sweeper
   ```
3. Build the Rust app:
   ```bash
   cargo build --release
   ```

## Usage

```bash
./target/release/repo-sweeper https://github.com/owner/repo --token YOUR_GITHUB_TOKEN [--fix]
```

- `repo_url`: The GitHub repository URL to scan.
- `--token`: Your GitHub personal access token.
- `--fix`: Optional flag to attempt creating a PR with fixes.

## Security Script

The `security.py` Python script scans the app's own code for sensitive data, respecting `.gitignore`.

Run it with:
```bash
python security.py
```

## Patterns Detected

- API Keys (e.g., starting with `sk-`)
- Passwords
- Secrets/Tokens
- AWS Access/Secret Keys (basic detection)

## Note

Fix functionality is implemented and may require manual review. Ensure the token has write access to the repository for creating PRs.

## License

MIT License
