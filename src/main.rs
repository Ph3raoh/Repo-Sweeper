use clap::Parser;
use octocrab::Octocrab;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;
use git2::Repository;

#[derive(Parser)]
#[command(name = "repo-sweeper")]
#[command(about = "Scan GitHub repos for sensitive data")]
struct Args {
    #[arg(help = "GitHub repository URL")]
    repo_url: String,

    #[arg(long, help = "GitHub personal access token")]
    token: String,

    #[arg(long, help = "Attempt to create PR with fixes")]
    fix: bool,
}

#[derive(Debug)]
struct Finding {
    line_num: usize,
    line: String,
    pattern_type: String,
    matches: Vec<String>,
}

fn get_sensitive_patterns() -> HashMap<&'static str, Regex> {
    let mut patterns = HashMap::new();
    patterns.insert("api_key", Regex::new(r"(?i)(api[_-]?key|apikey|sk-)[=:]\s*[""]?([a-zA-Z0-9_-]{20,})[""]?").unwrap());
    patterns.insert("password", Regex::new(r"(?i)(password|passwd|pwd)[=:]\s*[""]?([^\s'""]{8,})[""]?").unwrap());
    patterns.insert("secret", Regex::new(r"(?i)(secret|token)[=:]\s*[""]?([a-zA-Z0-9_-]{20,})[""]?").unwrap());
    patterns.insert("aws_access_key", Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap());
    patterns.insert("aws_secret_key", Regex::new(r"(?i)([a-zA-Z0-9+/]{40})").unwrap());
    patterns
}

fn scan_file_content(content: &str, file_path: &str) -> Vec<Finding> {
    let patterns = get_sensitive_patterns();
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        for (pattern_type, pattern) in &patterns {
            if let Some(captures) = pattern.captures(line) {
                let matches: Vec<String> = captures.iter().skip(1).filter_map(|m| m.map(|m| m.as_str().to_string())).collect();
                if !matches.is_empty() {
                    findings.push(Finding {
                        line_num: i + 1,
                        line: line.to_string(),
                        pattern_type: pattern_type.to_string(),
                        matches,
                    });
                }
            }
        }
    }
    findings
}

async fn scan_repository(repo_url: &str, token: &str) -> Result<(Vec<(String, Vec<Finding>)>, String, String, octocrab::models::Repository), Box<dyn std::error::Error>> {
    let octocrab = Octocrab::builder().personal_token(token.to_string()).build()?;
    let parts: Vec<&str> = repo_url.trim_end_matches('/').split('/').collect();
    let owner = parts[parts.len() - 2];
    let repo_name = parts[parts.len() - 1];
    let repo = octocrab.repos(owner, repo_name).get().await?;
    let mut contents = octocrab.repos(owner, repo_name).get_content().send().await?;
    let mut all_files = Vec::new();

    fn get_contents_recursive(octocrab: &Octocrab, owner: &str, repo_name: &str, path: &str, files: &mut Vec<octocrab::models::repos::Content>) -> Result<(), Box<dyn std::error::Error>> {
        let contents = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                octocrab.repos(owner, repo_name).get_content().path(path).send().await
            })
        })?;
        for item in contents.items {
            if item.r#type == "file" {
                files.push(item);
            } else if item.r#type == "dir" {
                get_contents_recursive(octocrab, owner, repo_name, &item.path, files)?;
            }
        }
        Ok(())
    }

    get_contents_recursive(&octocrab, owner, repo_name, "", &mut all_files)?;

    let mut findings = Vec::new();
    for file in all_files {
        if file.size > 1000000 { continue; }
        if let Some(content) = file.content {
            let decoded = base64::decode(content)?;
            let text = String::from_utf8(decoded)?;
            let file_findings = scan_file_content(&text, &file.path);
            if !file_findings.is_empty() {
                findings.push((file.path, file_findings));
            }
        }
    }

    Ok((findings, owner.to_string(), repo_name.to_string(), repo))
}

async fn create_issue(octocrab: &Octocrab, owner: &str, repo_name: &str, findings: &[(String, Vec<Finding>)]) -> Result<octocrab::models::issues::Issue, Box<dyn std::error::Error>> {
    let title = "Potential Sensitive Data Found";
    let mut body = "The following sensitive data patterns were detected:\n\n".to_string();
    for (file_path, file_findings) in findings {
        body.push_str(&format!("**{}**\n", file_path));
        for finding in file_findings {
            body.push_str(&format!("- Line {}: {} detected in: `{}`\n", finding.line_num, finding.pattern_type, finding.line));
        }
        body.push_str("\n");
    }
    body.push_str("Please review and remove any sensitive information.\n");

    let issue = octocrab.issues(owner, repo_name).create(title).body(&body).send().await?;
    Ok(issue)
}

async fn suggest_fix(octocrab: &Octocrab, owner: &str, repo_name: &str, findings: &[(String, Vec<Finding>)], token: &str) -> Result<Option<octocrab::models::pulls::PullRequest>, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let clone_url = format!("https://{}@github.com/{}/{}.git", token, owner, repo_name);
    let repo = Repository::clone(&clone_url, temp_dir.path())?;

    // Create branch
    let head_commit = repo.head()?.peel_to_commit()?;
    let new_branch_name = "fix-sensitive-data";
    let mut branch = repo.branch(new_branch_name, &head_commit, false)?;
    let branch_ref = branch.get();
    repo.checkout_tree(&head_commit.as_object(), None)?;
    repo.set_head(branch_ref.name().unwrap())?;

    // Apply fixes
    let patterns = get_sensitive_patterns();
    let mut changed = false;
    for (file_path, file_findings) in findings {
        let full_path = temp_dir.path().join(file_path);
        if full_path.exists() {
            let content = fs::read_to_string(&full_path)?;
            let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            for finding in file_findings {
                if finding.line_num <= lines.len() {
                    let line = &mut lines[finding.line_num - 1];
                    for match_str in &finding.matches {
                        *line = line.replace(match_str, "[REDACTED]");
                    }
                    changed = true;
                }
            }
            if changed {
                fs::write(&full_path, lines.join("\n"))?;
            }
        }
    }

    if changed {
        let mut index = repo.index()?;
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = git2::Signature::now("Repo-Sweeper", "bot@example.com")?;
        let commit = repo.commit(Some("HEAD"), &sig, &sig, "Redact sensitive data", &tree, &[&head_commit])?;
        let remote = repo.find_remote("origin")?;
        remote.push(&[&format!("refs/heads/{}", new_branch_name)], None)?;

        let pr = octocrab.pulls(owner, repo_name).create("Proposed Fixes for Sensitive Data", &format!("{}:{}", owner, new_branch_name), "main").body("This PR redacts detected sensitive data.").send().await?;
        Ok(Some(pr))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let (findings, owner, repo_name, repo) = scan_repository(&args.repo_url, &args.token).await?;

    if !findings.is_empty() {
        println!("Found sensitive data in {} files.", findings.len());
        let octocrab = Octocrab::builder().personal_token(args.token).build()?;
        let issue = create_issue(&octocrab, &owner, &repo_name, &findings).await?;
        println!("Created issue: {}", issue.html_url);

        if args.fix {
            match suggest_fix(&octocrab, &owner, &repo_name, &findings, &args.token).await? {
                Some(pr) => println!("Created PR: {}", pr.html_url),
                None => println!("No changes made, PR not created."),
            }
        }
    } else {
        println!("No sensitive data found.");
    }

    Ok(())
}
