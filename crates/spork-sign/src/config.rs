//! Configuration for spork-sign.
//!
//! Supports configuration via:
//! - TOML config file (default: /etc/spork/sign.toml)
//! - Command-line arguments
//! - Environment variables
//!
//! Key configuration items:
//! - PFX certificate paths and passwords (per cert type)
//! - TSA URLs and timeout
//! - Server bind address and port
//! - TLS certificate paths
//! - Upload size limits
//! - Allowed file extensions
//! - Audit log path
//! - Authentication mode (mTLS, header, none)

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{SignError, SignResult};
use crate::timestamp::TsaConfig;

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignConfig {
    /// Bind address for the web server.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Bind port for the web server.
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,

    /// TLS certificate path (PEM).
    pub tls_cert: Option<PathBuf>,
    /// TLS private key path (PEM).
    pub tls_key: Option<PathBuf>,

    /// Signing certificate configurations (by type).
    #[serde(default)]
    pub cert_configs: Vec<CertConfig>,

    /// TSA configuration.
    #[serde(default)]
    pub tsa: TsaConfig,

    /// Maximum upload file size (bytes).
    #[serde(default = "default_max_upload_size")]
    pub max_upload_size: u64,

    /// Allowed file extensions.
    #[serde(default = "default_allowed_extensions")]
    pub allowed_extensions: Vec<String>,

    /// Directory for signed output files.
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,

    /// Audit log file path.
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,

    /// Authentication mode.
    #[serde(default)]
    pub auth_mode: AuthMode,

    /// Whether to require timestamping.
    #[serde(default = "default_require_timestamp")]
    pub require_timestamp: bool,

    /// SHA-256 hash of the admin bearer token (hex-encoded).
    /// If None, admin endpoints are disabled.
    pub admin_token_hash: Option<String>,
}

/// Signing certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    /// Certificate type name (e.g., "desktop", "server", "multipurpose").
    pub name: String,
    /// Path to the PFX file.
    pub pfx_path: PathBuf,
    /// Environment variable name containing the PFX password.
    pub pfx_password_env: String,
}

/// Authentication mode for the web server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No authentication (development only).
    #[default]
    None,
    /// mTLS with client certificate validation.
    Mtls,
    /// HTTP header pass-through (e.g., from reverse proxy with LDAP).
    Header,
    /// API key authentication.
    ApiKey,
}

impl SignConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file(path: &Path) -> SignResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SignError::Config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        toml::from_str(&content).map_err(|e| {
            SignError::Config(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })
    }
}

impl Default for SignConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            tls_cert: None,
            tls_key: None,
            cert_configs: Vec::new(),
            tsa: TsaConfig::default(),
            max_upload_size: default_max_upload_size(),
            allowed_extensions: default_allowed_extensions(),
            output_dir: default_output_dir(),
            audit_log: default_audit_log(),
            auth_mode: AuthMode::None,
            require_timestamp: true,
            admin_token_hash: None,
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}

fn default_bind_port() -> u16 {
    6447
}

fn default_max_upload_size() -> u64 {
    500 * 1024 * 1024
}

fn default_allowed_extensions() -> Vec<String> {
    vec![
        "exe".into(),
        "dll".into(),
        "sys".into(),
        "ocx".into(),
        "scr".into(),
        "cpl".into(),
        "drv".into(),
        "msi".into(),
        "cab".into(),
        "ps1".into(),
    ]
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("/var/lib/spork-sign/signed")
}

fn default_audit_log() -> PathBuf {
    PathBuf::from("/var/log/spork-sign/audit.log")
}

fn default_require_timestamp() -> bool {
    true
}
