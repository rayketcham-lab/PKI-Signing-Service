//! # spork-sign — Pure Rust Authenticode Code Signing Service
//!
//! A standalone code signing service that signs Windows PE executables,
//! DLLs, drivers, MSI installers, and PowerShell scripts using
//! Microsoft Authenticode. No external tools required — all signing
//! logic is implemented in pure Rust.
//!
//! ## Features
//!
//! - **PE Authenticode signing** — EXE, DLL, SYS, OCX, SCR, CPL, DRV
//! - **PowerShell signing** — PS1 scripts with Base64 PKCS#7 blocks
//! - **MSI/CAB signing** — Windows Installer packages
//! - **RFC 3161 timestamping** — Counter-signatures for long-term validity
//! - **Signature verification** — Validate existing Authenticode signatures
//! - **PFX/PKCS#12 support** — Load signing credentials from .pfx files
//! - **Web service mode** — axum HTTP server for Code Signing as a Service
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

// Allow dead code during scaffolding phase — stubs will be implemented in Phases 2-4
#![allow(dead_code, unused_imports, unused_variables)]

pub mod config;
pub mod crypto;
pub mod error;
pub mod ers;
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
