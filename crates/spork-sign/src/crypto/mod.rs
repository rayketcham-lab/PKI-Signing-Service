//! Standalone cryptographic primitives for spork-sign.
//!
//! These modules replace the spork-core and spork-common dependencies
//! with self-contained implementations using the same underlying crates.

pub mod hkdf;
pub mod rsa_oaep;
