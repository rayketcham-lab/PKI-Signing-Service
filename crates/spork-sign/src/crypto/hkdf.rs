//! Key Derivation Functions -- RFC 5869 (HKDF)
//!
//! Provides HKDF-Extract and HKDF-Expand per RFC 5869 for deriving
//! cryptographic key material from input keying material (IKM).

use sha2::{Sha256, Sha384, Sha512};

use crate::error::{SignError, SignResult};

/// HKDF hash algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfHash {
    /// HKDF with HMAC-SHA-256 (32-byte output)
    Sha256,
    /// HKDF with HMAC-SHA-384 (48-byte output)
    Sha384,
    /// HKDF with HMAC-SHA-512 (64-byte output)
    Sha512,
}

impl HkdfHash {
    /// Maximum output length for this hash (255 * HashLen per RFC 5869 §2.3).
    pub fn max_output_len(self) -> usize {
        match self {
            Self::Sha256 => 255 * 32,
            Self::Sha384 => 255 * 48,
            Self::Sha512 => 255 * 64,
        }
    }

    /// Hash output length in bytes.
    pub fn hash_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// One-shot HKDF: Extract-then-Expand in a single call.
///
/// Convenience function that combines RFC 5869 §2.2 (Extract) and §2.3 (Expand).
///
/// # Parameters
///
/// - `hash` -- Hash function to use (SHA-256, SHA-384, or SHA-512)
/// - `salt` -- Optional salt value (can be empty)
/// - `ikm` -- Input keying material
/// - `info` -- Context and application-specific information
/// - `okm_len` -- Desired output key material length in bytes
///
/// # Errors
///
/// Returns an error if `okm_len` exceeds 255 * HashLen.
pub fn hkdf_derive(
    hash: HkdfHash,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> SignResult<Vec<u8>> {
    if okm_len > hash.max_output_len() {
        return Err(SignError::Internal(format!(
            "HKDF output length {} exceeds maximum {} (RFC 5869 §2.3)",
            okm_len,
            hash.max_output_len()
        )));
    }

    let mut okm = vec![0u8; okm_len];

    match hash {
        HkdfHash::Sha256 => {
            let hk =
                hkdf::Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
            hk.expand(info, &mut okm)
                .map_err(|_| SignError::Internal("HKDF-Expand failed".to_string()))?;
        }
        HkdfHash::Sha384 => {
            let hk =
                hkdf::Hkdf::<Sha384>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
            hk.expand(info, &mut okm)
                .map_err(|_| SignError::Internal("HKDF-Expand failed".to_string()))?;
        }
        HkdfHash::Sha512 => {
            let hk =
                hkdf::Hkdf::<Sha512>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
            hk.expand(info, &mut okm)
                .map_err(|_| SignError::Internal("HKDF-Expand failed".to_string()))?;
        }
    }

    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_derive() {
        let ikm = b"master key material";
        let salt = b"random salt";
        let info = b"encryption key v1";

        let key1 = hkdf_derive(HkdfHash::Sha256, salt, ikm, info, 32).unwrap();
        let key2 = hkdf_derive(HkdfHash::Sha256, salt, ikm, info, 32).unwrap();
        assert_eq!(key1, key2); // Deterministic

        let key3 = hkdf_derive(HkdfHash::Sha256, salt, ikm, b"different context", 32).unwrap();
        assert_ne!(key1, key3); // Different info produces different key
    }

    #[test]
    fn test_hkdf_output_too_long() {
        let result = hkdf_derive(HkdfHash::Sha256, b"s", b"ikm", b"info", 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_sha384_derive() {
        let key = hkdf_derive(HkdfHash::Sha384, b"salt", b"ikm", b"info", 48).unwrap();
        assert_eq!(key.len(), 48);
    }

    #[test]
    fn test_hkdf_sha512_derive() {
        let key = hkdf_derive(HkdfHash::Sha512, b"salt", b"ikm", b"info", 64).unwrap();
        assert_eq!(key.len(), 64);
    }
}
