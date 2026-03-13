//! GitHub issue auto-reporter for signing errors.
//!
//! Automatically creates GitHub issues when signing errors occur,
//! using the `gh` CLI tool. Includes deduplication to prevent
//! flooding the issue tracker with identical errors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use sha2::{Digest, Sha256};

/// Automatic GitHub issue reporter.
pub struct GitHubIssueReporter {
    /// GitHub repository in "owner/repo" format.
    repo: String,
    /// Deduplication window in seconds.
    dedup_window_secs: u64,
    /// Recent error hashes with their creation time (for dedup).
    recent_errors: Mutex<HashMap<String, Instant>>,
}

impl GitHubIssueReporter {
    /// Create a new reporter for the given repository.
    pub fn new(repo: String, dedup_window_secs: u64) -> Self {
        Self {
            repo,
            dedup_window_secs,
            recent_errors: Mutex::new(HashMap::new()),
        }
    }

    /// Report a signing error as a GitHub issue.
    ///
    /// Returns `true` if an issue was created, `false` if deduplicated or failed.
    pub async fn report_signing_error(
        &self,
        error_type: &str,
        error_message: &str,
        filename: Option<&str>,
        file_size: Option<u64>,
    ) -> bool {
        let error_hash = hex::encode(Sha256::digest(
            format!("{}:{}", error_type, error_message).as_bytes(),
        ));

        // Check deduplication
        {
            let mut recent = match self.recent_errors.lock() {
                Ok(r) => r,
                Err(_) => return false,
            };

            // Clean up expired entries
            let cutoff = Instant::now();
            recent.retain(|_, created_at| {
                cutoff.duration_since(*created_at).as_secs() < self.dedup_window_secs
            });

            // Check if this error was already reported recently
            if recent.contains_key(&error_hash) {
                tracing::debug!(
                    error_type,
                    "Skipping duplicate GitHub issue (within dedup window)"
                );
                return false;
            }

            recent.insert(error_hash, Instant::now());
        }

        // Build issue title and body — sanitize inputs for CLI safety
        let safe_error_type: String = error_type
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '-' || *c == '.')
            .take(100)
            .collect();
        let title = format!("[auto] Signing error: {}", safe_error_type);
        let file_info = match (filename, file_size) {
            (Some(name), Some(size)) => format!("- **File:** {} ({} bytes)\n", name, size),
            (Some(name), None) => format!("- **File:** {}\n", name),
            _ => String::new(),
        };

        // Sanitize error_message: escape backticks to prevent markdown code-block breakout
        let safe_error_message = error_message.replace('`', "'");
        let body = format!(
            "## Automated Signing Error Report\n\n\
             - **Error type:** {safe_error_type}\n\
             - **Timestamp:** {timestamp}\n\
             {file_info}\
             \n### Error Message\n\n\
             ```\n{safe_error_message}\n```\n\n\
             ---\n\
             *This issue was automatically created by Code Signing Service.*",
            timestamp = chrono::Utc::now().to_rfc3339(),
        );

        // Create issue via gh CLI
        let result = tokio::process::Command::new("gh")
            .arg("issue")
            .arg("create")
            .arg("--repo")
            .arg(&self.repo)
            .arg("--title")
            .arg(&title)
            .arg("--body")
            .arg(&body)
            .arg("--label")
            .arg("auto-reported,signing-error")
            .output()
            .await;

        match result {
            Ok(output) => {
                if output.status.success() {
                    tracing::info!(error_type, "Created GitHub issue for signing error");
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        error_type,
                        stderr = %stderr,
                        "Failed to create GitHub issue"
                    );
                    false
                }
            }
            Err(e) => {
                tracing::warn!(
                    error_type,
                    error = %e,
                    "Failed to execute gh CLI"
                );
                false
            }
        }
    }

    /// Create a GitHub issue from a user-submitted report.
    pub async fn create_user_report(
        &self,
        title: &str,
        body: &str,
        reporter: Option<&str>,
    ) -> Result<String, String> {
        let full_body = format!(
            "{body}\n\n---\n\
             *Reported by: {}*\n\
             *Submitted via Code Signing Service issue reporter.*",
            reporter.unwrap_or("anonymous"),
        );

        let output = tokio::process::Command::new("gh")
            .arg("issue")
            .arg("create")
            .arg("--repo")
            .arg(&self.repo)
            .arg("--title")
            .arg(title)
            .arg("--body")
            .arg(&full_body)
            .arg("--label")
            .arg("user-reported")
            .output()
            .await
            .map_err(|e| format!("Failed to execute gh CLI: {e}"))?;

        if output.status.success() {
            let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(url)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("gh issue create failed: {stderr}"))
        }
    }
}
