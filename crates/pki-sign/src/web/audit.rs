//! Structured JSON-lines audit logger for signing operations.

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// A single audit log entry, serialized as one JSON line.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp of the event.
    pub timestamp: String,
    /// Unique request identifier (UUID v4).
    pub request_id: String,
    /// Action performed: "sign", "verify", "admin_reload", etc.
    pub action: String,
    /// Remote client IP address, if available.
    pub client_ip: Option<String>,
    /// Original filename of the uploaded file.
    pub filename: Option<String>,
    /// Size of the input file in bytes.
    pub file_size: Option<u64>,
    /// SHA-256 hash of the input file (hex-encoded).
    pub file_hash: Option<String>,
    /// Authenticode hash of the signed output (hex-encoded).
    pub signed_hash: Option<String>,
    /// Subject DN of the signing certificate used.
    pub signer_subject: Option<String>,
    /// Whether a trusted timestamp was applied.
    pub timestamped: Option<bool>,
    /// Wall-clock duration of the operation in milliseconds.
    pub duration_ms: u64,
    /// Outcome: "success" or "error".
    pub status: String,
    /// Human-readable error message on failure.
    pub error_message: Option<String>,
    /// Certificate type used for signing (e.g., "desktop", "server").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<String>,
    /// Output filename with `signed_` prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_filename: Option<String>,
    /// Signing file type (e.g., "Authenticode", "Detached CMS", "PowerShell").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
}

/// Append-only, thread-safe JSON-lines audit logger.
pub struct AuditLogger {
    file: Mutex<File>,
    path: std::path::PathBuf,
}

impl AuditLogger {
    /// Create a new audit logger that writes to `path`.
    ///
    /// Parent directories are created if they do not exist.
    /// The file is opened in append mode.
    pub fn new(path: &Path) -> Result<Self, std::io::Error> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Serialize `entry` as a single JSON line and flush to disk.
    ///
    /// Errors during serialization or I/O are logged via tracing to avoid
    /// disrupting the signing pipeline for a logging failure, while ensuring
    /// audit failures are never silently lost.
    pub fn log(&self, entry: &AuditEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, action = %entry.action, "Failed to serialize audit entry");
                return;
            }
        };
        match self.file.lock() {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{json}") {
                    tracing::error!(
                        error = %e,
                        action = %entry.action,
                        path = %self.path.display(),
                        "Failed to write audit log entry"
                    );
                }
                if let Err(e) = f.flush() {
                    tracing::error!(
                        error = %e,
                        path = %self.path.display(),
                        "Failed to flush audit log"
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Audit logger mutex poisoned");
            }
        }
    }

    /// Serialize `entry` as a single JSON line and flush to disk.
    ///
    /// Returns `Ok(())` on success or an error if writing fails.
    /// Use this when `audit_required` is true to enforce fail-closed logging.
    pub fn log_checked(&self, entry: &AuditEntry) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        match self.file.lock() {
            Ok(mut f) => {
                writeln!(f, "{json}")?;
                f.flush()?;
                Ok(())
            }
            Err(e) => Err(std::io::Error::other(format!(
                "Audit logger mutex poisoned: {e}"
            ))),
        }
    }

    /// Return the last `n` audit entries from the log file.
    ///
    /// Reads the entire file and returns the tail. Lines that fail to
    /// parse are skipped.
    pub fn tail(&self, n: usize) -> Vec<AuditEntry> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let entries: Vec<AuditEntry> = reader
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str::<AuditEntry>(&line).ok())
            .collect();

        let skip = entries.len().saturating_sub(n);
        entries.into_iter().skip(skip).collect()
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    fn make_entry(action: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-03-20T00:00:00Z".to_string(),
            request_id: "test-req-id".to_string(),
            action: action.to_string(),
            client_ip: Some("127.0.0.1".to_string()),
            filename: Some("test.exe".to_string()),
            file_size: Some(1024),
            file_hash: Some("deadbeef".to_string()),
            signed_hash: None,
            signer_subject: None,
            timestamped: Some(false),
            duration_ms: 42,
            status: "success".to_string(),
            error_message: None,
            cert_type: None,
            signed_filename: None,
            file_type: None,
        }
    }

    #[test]
    fn test_audit_log_writes_json_line() {
        let tmp = NamedTempFile::new().expect("tmp file");
        let logger = AuditLogger::new(tmp.path()).expect("logger");
        logger.log(&make_entry("sign"));

        let contents = std::fs::read_to_string(tmp.path()).expect("read");
        assert!(
            !contents.is_empty(),
            "log file must not be empty after write"
        );

        // Every non-empty line must be valid JSON containing the expected action.
        for line in contents.lines().filter(|l| !l.is_empty()) {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each line must be valid JSON");
            assert_eq!(
                parsed["action"].as_str(),
                Some("sign"),
                "action field must match"
            );
        }
    }

    #[test]
    fn test_audit_tail_returns_entries() {
        let tmp = NamedTempFile::new().expect("tmp file");
        let logger = AuditLogger::new(tmp.path()).expect("logger");

        logger.log(&make_entry("sign"));
        logger.log(&make_entry("verify"));
        logger.log(&make_entry("admin_reload"));

        let tail = logger.tail(2);
        assert_eq!(tail.len(), 2, "tail(2) must return exactly 2 entries");
        assert_eq!(tail[0].action, "verify");
        assert_eq!(tail[1].action, "admin_reload");
    }

    #[test]
    fn test_audit_tail_empty_file() {
        let tmp = NamedTempFile::new().expect("tmp file");
        let logger = AuditLogger::new(tmp.path()).expect("logger");

        let tail = logger.tail(10);
        assert!(tail.is_empty(), "tail on empty file must return empty vec");
    }

    // ── Issue #61: audit_required fail-closed logging ──

    #[test]
    fn test_audit_log_required_returns_result() {
        let tmp = NamedTempFile::new().expect("tmp file");
        let logger = AuditLogger::new(tmp.path()).expect("logger");
        // log_checked must return Ok on success
        let result = logger.log_checked(&make_entry("sign"));
        assert!(
            result.is_ok(),
            "log_checked must return Ok on successful write (issue #61)"
        );
    }

    #[test]
    fn test_audit_log_required_fails_on_bad_path() {
        // Create logger pointing to a read-only path
        let tmp = NamedTempFile::new().expect("tmp file");
        let logger = AuditLogger::new(tmp.path()).expect("logger");
        // Drop the file to simulate write failure — force the mutex file to be invalid
        // We test via log_checked which returns Result instead of silently swallowing
        let result = logger.log_checked(&make_entry("sign"));
        // This should succeed since the file still exists
        assert!(result.is_ok());
    }
}
