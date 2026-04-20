//! # pki-sign — Pure Rust Code Signing Engine
//!
//! A standalone code signing service that signs Windows PE executables,
//! DLLs, drivers, MSI installers, and PowerShell scripts using
//! Microsoft Authenticode. Supports detached CMS/PKCS#7 signing for
//! arbitrary files. No external tools required — all signing
//! logic is implemented in pure Rust.
//!
//! ## Features
//!
//! - **PE Authenticode signing** — EXE, DLL, SYS, OCX, SCR, CPL, DRV
//! - **Detached CMS signing** — Sign any file with a `.p7s` detached signature
//! - **PowerShell signing** — PS1 scripts with Base64 PKCS#7 blocks
//! - **MSI/CAB signing** — Windows Installer packages
//! - **RFC 3161 timestamping** — Counter-signatures for long-term validity
//! - **Signature verification** — Validate existing Authenticode and detached signatures
//! - **PFX/PKCS#12 support** — Load signing credentials from .pfx files
//! - **Web service mode** — axum HTTP server for Code Signing as a Service
//! - **LDAP authentication** — Header-based auth via reverse proxy
//! - **Certificate management** — Admin API for cert listing and management
//! - **CLI mode** — Command-line signing without a server
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
//! │  Web Server  │────▶│    Signer     │────▶│  Timestamper │
//! │  (axum)      │     │ (orchestrator)│     │  (RFC 3161)  │
//! └─────────────┘     └──────┬───────┘     └─────────────┘
//!                            │
//!                    ┌───────┴───────┐
//!                    │               │
//!               ┌────▼───┐    ┌─────▼─────┐
//!               │   PE   │    │  PKCS#7   │
//!               │ Parser │    │  Builder  │
//!               └────────┘    └───────────┘
//! ```

pub mod cab;
pub mod config;
#[cfg(feature = "demo")]
pub mod demo;
pub mod error;
pub mod msi;
pub mod pe;
pub mod pkcs7;
pub mod powershell;
pub mod signer;
pub mod timestamp;
pub mod tsa_http;
pub mod tsa_server;
pub mod verifier;
pub mod web;

pub use error::{SignError, SignResult};
