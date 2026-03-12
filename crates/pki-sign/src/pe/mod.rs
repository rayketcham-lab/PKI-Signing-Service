//! PE/COFF file parsing and Authenticode hash computation.
//!
//! This module handles:
//! - Parsing PE headers to locate the checksum, certificate table, and sections
//! - Computing the Authenticode PE hash (SHA-256/384/512) which excludes:
//!   - The PE checksum field (4 bytes at PE + 0x58)
//!   - The Certificate Table directory entry (8 bytes)
//!   - All data beyond the end of the last section (existing signatures)
//! - Embedding WIN_CERTIFICATE structures into the PE certificate table
//! - Updating PE headers after signature insertion

pub mod authenticode;
pub mod embed;
pub mod parser;

pub use authenticode::{compute_authenticode_hash, compute_authenticode_hash_with};
pub use embed::embed_signature;
pub use parser::PeInfo;
