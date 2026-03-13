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
