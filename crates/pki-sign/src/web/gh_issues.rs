//! GitHub issue auto-reporter for signing errors.
//!
//! Automatically creates GitHub issues when signing errors occur,
//! using the `gh` CLI tool. Includes deduplication to prevent
//! flooding the issue tracker with identical errors.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use sha2::{Digest, Sha256};

/// Argv-safety caps for values passed to `gh issue create`.
///
/// `gh` has no `--` terminator for its flag/value pairs, so a value starting
/// with `-` is parsed as an option flag. A title of `--label release-block`
/// or `--body-file /etc/passwd` would mutate the issue or exfiltrate files.
/// These caps also bound the DoS surface of unbounded JSON bodies.
const GH_TITLE_MAX: usize = 256;
const GH_BODY_MAX: usize = 64 * 1024;
const GH_REPORTER_MAX: usize = 128;

/// Sanitize a value destined for a `gh` argv flag.
///
/// - Strips leading `-` / whitespace so the value can never be parsed as a flag.
/// - Truncates at `max` bytes on a char boundary.
/// - Returns `None` if the value is empty after stripping.
pub(crate) fn sanitize_gh_arg(value: &str, max: usize) -> Option<String> {
    let stripped = value.trim_start_matches(|c: char| c == '-' || c.is_whitespace());
    if stripped.is_empty() {
        return None;
    }
    let mut end = stripped.len().min(max);
    while !stripped.is_char_boundary(end) {
        end -= 1;
    }
    Some(stripped[..end].to_string())
}

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
             *This issue was automatically created by PKI Signing Service.*",
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
        let safe_title = sanitize_gh_arg(title, GH_TITLE_MAX)
            .ok_or_else(|| "title is empty or contains only leading dashes".to_string())?;
        let safe_body = sanitize_gh_arg(body, GH_BODY_MAX)
            .ok_or_else(|| "body is empty or contains only leading dashes".to_string())?;
        let safe_reporter = reporter
            .and_then(|r| sanitize_gh_arg(r, GH_REPORTER_MAX))
            .unwrap_or_else(|| "anonymous".to_string());

        let full_body = format!(
            "{safe_body}\n\n---\n\
             *Reported by: {safe_reporter}*\n\
             *Submitted via PKI Signing Service issue reporter.*",
        );

        let output = tokio::process::Command::new("gh")
            .arg("issue")
            .arg("create")
            .arg("--repo")
            .arg(&self.repo)
            .arg("--title")
            .arg(&safe_title)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reporter_new() {
        let reporter = GitHubIssueReporter::new("owner/repo".to_string(), 300);
        assert_eq!(reporter.repo, "owner/repo");
        assert_eq!(reporter.dedup_window_secs, 300);
        assert!(reporter.recent_errors.lock().unwrap().is_empty());
    }

    #[test]
    fn test_dedup_hash_deterministic() {
        let hash1 = hex::encode(Sha256::digest(
            format!("{}:{}", "TestError", "something broke").as_bytes(),
        ));
        let hash2 = hex::encode(Sha256::digest(
            format!("{}:{}", "TestError", "something broke").as_bytes(),
        ));
        assert_eq!(hash1, hash2, "Same input must produce same hash");
    }

    #[test]
    fn test_dedup_different_errors_produce_different_hashes() {
        let hash1 = hex::encode(Sha256::digest(
            format!("{}:{}", "ErrorA", "message1").as_bytes(),
        ));
        let hash2 = hex::encode(Sha256::digest(
            format!("{}:{}", "ErrorB", "message2").as_bytes(),
        ));
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_dedup_same_type_different_message() {
        let hash1 = hex::encode(Sha256::digest(
            format!("{}:{}", "SignError", "file A").as_bytes(),
        ));
        let hash2 = hex::encode(Sha256::digest(
            format!("{}:{}", "SignError", "file B").as_bytes(),
        ));
        assert_ne!(
            hash1, hash2,
            "Same error type with different messages must produce different hashes"
        );
    }

    #[test]
    fn test_dedup_entry_inserted_and_found() {
        let reporter = GitHubIssueReporter::new("owner/repo".to_string(), 300);
        let hash = hex::encode(Sha256::digest(b"TestError:broke" as &[u8]));
        reporter
            .recent_errors
            .lock()
            .unwrap()
            .insert(hash.clone(), Instant::now());
        assert!(reporter.recent_errors.lock().unwrap().contains_key(&hash));
    }

    #[test]
    fn test_sanitize_error_type_strips_special_chars() {
        let malicious = "error$(whoami)&&rm -rf /";
        let safe: String = malicious
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '-' || *c == '.')
            .take(100)
            .collect();
        assert_eq!(safe, "errorwhoamirm -rf ");
        assert!(!safe.contains('$'));
        assert!(!safe.contains('('));
        assert!(!safe.contains('&'));
    }

    #[test]
    fn test_sanitize_error_type_truncates_at_100() {
        let long_input = "A".repeat(200);
        let safe: String = long_input
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '_' || *c == '-' || *c == '.')
            .take(100)
            .collect();
        assert_eq!(safe.len(), 100);
    }

    #[test]
    fn test_sanitize_error_message_escapes_backticks() {
        let msg = "error in `fn main()` at ```block```";
        let safe = msg.replace('`', "'");
        assert!(!safe.contains('`'));
        assert_eq!(safe, "error in 'fn main()' at '''block'''");
    }

    #[test]
    fn test_file_info_both_name_and_size() {
        let info = match (Some("test.exe"), Some(1024u64)) {
            (Some(name), Some(size)) => format!("- **File:** {} ({} bytes)\n", name, size),
            (Some(name), None) => format!("- **File:** {}\n", name),
            _ => String::new(),
        };
        assert_eq!(info, "- **File:** test.exe (1024 bytes)\n");
    }

    #[test]
    fn test_file_info_name_only() {
        let info = match (Some("test.exe"), None::<u64>) {
            (Some(name), Some(size)) => format!("- **File:** {} ({} bytes)\n", name, size),
            (Some(name), None) => format!("- **File:** {}\n", name),
            _ => String::new(),
        };
        assert_eq!(info, "- **File:** test.exe\n");
    }

    #[test]
    fn test_file_info_none() {
        let info: String = match (None::<&str>, None::<u64>) {
            (Some(name), Some(size)) => format!("- **File:** {} ({} bytes)\n", name, size),
            (Some(name), None) => format!("- **File:** {}\n", name),
            _ => String::new(),
        };
        assert!(info.is_empty());
    }

    #[test]
    fn test_title_format() {
        let safe_type = "InvalidPe";
        let title = format!("[auto] Signing error: {}", safe_type);
        assert_eq!(title, "[auto] Signing error: InvalidPe");
    }

    #[test]
    fn test_sanitize_gh_arg_rejects_leading_dash() {
        // SecOps HIGH — title starting with -- would be parsed as flag by gh CLI.
        assert_eq!(
            sanitize_gh_arg("--label release-block", 256),
            Some("label release-block".to_string()),
        );
        assert_eq!(
            sanitize_gh_arg("-body-file /etc/passwd", 256),
            Some("body-file /etc/passwd".to_string()),
        );
        // Leading whitespace + dashes both stripped.
        assert_eq!(
            sanitize_gh_arg("   -- inject", 256),
            Some("inject".to_string()),
        );
    }

    #[test]
    fn test_sanitize_gh_arg_returns_none_when_all_dashes() {
        assert_eq!(sanitize_gh_arg("---", 256), None);
        assert_eq!(sanitize_gh_arg("", 256), None);
        assert_eq!(sanitize_gh_arg("   ", 256), None);
    }

    #[test]
    fn test_sanitize_gh_arg_preserves_normal_input() {
        assert_eq!(
            sanitize_gh_arg("Normal title with dashes - inline", 256),
            Some("Normal title with dashes - inline".to_string()),
        );
    }

    #[test]
    fn test_sanitize_gh_arg_truncates_at_max() {
        let long = "a".repeat(500);
        let out = sanitize_gh_arg(&long, 256).unwrap();
        assert_eq!(out.len(), 256);
    }

    #[test]
    fn test_sanitize_gh_arg_respects_char_boundary() {
        // Truncation must not split a multi-byte UTF-8 char.
        let mixed = format!("{}é", "a".repeat(254));
        let out = sanitize_gh_arg(&mixed, 255).unwrap();
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn test_dedup_window_retention() {
        let reporter = GitHubIssueReporter::new("owner/repo".to_string(), 3600);
        let hash = hex::encode(Sha256::digest(b"err:msg" as &[u8]));
        reporter
            .recent_errors
            .lock()
            .unwrap()
            .insert(hash.clone(), Instant::now());

        // Simulate cleanup: entries within window should be retained
        let cutoff = Instant::now();
        let recent = reporter.recent_errors.lock().unwrap();
        let retained: Vec<_> = recent
            .iter()
            .filter(|(_, created_at)| cutoff.duration_since(**created_at).as_secs() < 3600)
            .collect();
        assert_eq!(retained.len(), 1);
    }
}
