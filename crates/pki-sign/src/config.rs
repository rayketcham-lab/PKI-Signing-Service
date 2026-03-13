//! Configuration for pki-sign.
//!
//! Supports configuration via:
//! - TOML config file (default: /etc/pki/sign.toml)
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
//! - LDAP header pass-through configuration
//! - GitHub issue reporter configuration

use std::collections::HashMap;
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

    /// LDAP header pass-through configuration.
    #[serde(default)]
    pub ldap: LdapConfig,

    /// GitHub issue reporter configuration.
    #[serde(default)]
    pub github: GitHubConfig,

    /// Development mode.
    ///
    /// When enabled, LDAP authentication is bypassed and all functionality
    /// is accessible without restrictions.
    /// When disabled (production mode), LDAP is enforced, pages are read-only,
    /// and admin functions are disabled for non-admin users.
    #[serde(default)]
    pub dev_mode: bool,
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

/// LDAP header pass-through configuration.
///
/// When enabled, the reverse proxy authenticates users via LDAP and passes
/// user information through HTTP headers. This module extracts that info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// Whether LDAP header auth is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Header containing the authenticated username.
    #[serde(default = "default_user_header")]
    pub user_header: String,
    /// Header containing the user's groups.
    #[serde(default = "default_groups_header")]
    pub groups_header: String,
    /// Header containing the user's email.
    #[serde(default = "default_email_header")]
    pub email_header: String,
    /// Header containing the user's display name.
    #[serde(default = "default_display_name_header")]
    pub display_name_header: String,
    /// Group DN that grants admin access.
    #[serde(default)]
    pub admin_group: String,
    /// Mapping of certificate name → group DN required to use that cert.
    #[serde(default)]
    pub cert_groups: HashMap<String, String>,
    /// Delimiter for multiple groups in the groups header.
    #[serde(default = "default_groups_delimiter")]
    pub groups_delimiter: String,
    /// Trusted reverse proxy IP addresses/CIDRs.
    ///
    /// When non-empty, LDAP header authentication is only accepted from
    /// requests originating from these addresses. Requests from other IPs
    /// will have LDAP auth headers stripped/ignored (returns 404).
    /// Supports IPv4 and IPv6 addresses (CIDR notation not yet supported).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            user_header: default_user_header(),
            groups_header: default_groups_header(),
            email_header: default_email_header(),
            display_name_header: default_display_name_header(),
            admin_group: String::new(),
            cert_groups: HashMap::new(),
            groups_delimiter: default_groups_delimiter(),
            trusted_proxies: Vec::new(),
        }
    }
}

/// GitHub issue reporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// Whether GitHub issue reporting is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// GitHub repository (owner/name format).
    #[serde(default = "default_github_repo")]
    pub repo: String,
    /// Automatically create issues on signing errors.
    #[serde(default)]
    pub auto_issue_on_error: bool,
    /// Deduplication window in seconds (prevent duplicate issues for same error).
    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            repo: default_github_repo(),
            auto_issue_on_error: false,
            dedup_window_secs: default_dedup_window(),
        }
    }
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
            ldap: LdapConfig::default(),
            github: GitHubConfig::default(),
            dev_mode: false,
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
    PathBuf::from("/var/lib/pki-sign/signed")
}

fn default_audit_log() -> PathBuf {
    PathBuf::from("/var/log/pki-sign/audit.log")
}

fn default_require_timestamp() -> bool {
    true
}

fn default_user_header() -> String {
    "X-Remote-User".into()
}

fn default_groups_header() -> String {
    "X-Remote-Groups".into()
}

fn default_email_header() -> String {
    "X-Remote-Email".into()
}

fn default_display_name_header() -> String {
    "X-Remote-Display-Name".into()
}

fn default_groups_delimiter() -> String {
    ";".into()
}

fn default_github_repo() -> String {
    "rayketcham-lab/pki-sign".into()
}

fn default_dedup_window() -> u64 {
    3600
}
