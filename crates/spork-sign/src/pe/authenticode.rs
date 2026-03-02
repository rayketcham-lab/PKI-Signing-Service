//! Authenticode PE hash computation.
//!
//! Computes the hash of a PE file according to the Microsoft
//! Authenticode specification. Supports SHA-256, SHA-384, and SHA-512.
//! The hash excludes:
//!
//! 1. The PE checksum field (4 bytes)
//! 2. The Certificate Table directory entry (8 bytes: RVA + size)
//! 3. All data beyond the "end of image" (existing certificate data)
//!
//! This is the hash that gets signed and embedded in the CMS SignedData
//! as the SPC_INDIRECT_DATA content.
//!
//! Reference: Microsoft PE Authenticode specification
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode>

use sha2::{Digest, Sha256, Sha384, Sha512};

use super::parser::PeInfo;
use crate::error::{SignError, SignResult};
use crate::pkcs7::builder::DigestAlgorithm;

/// Compute the Authenticode PE image hash using the specified digest algorithm.
///
/// The hash covers the entire file EXCEPT:
/// - The CheckSum field (4 bytes at `pe_info.checksum_offset`)
/// - The Certificate Table directory entry (8 bytes at `pe_info.cert_table_offset`)
/// - Any data beyond `pe_info.end_of_image` (existing signatures)
///
/// Per the Authenticode specification, SHA-256 is the standard algorithm.
/// SHA-384 and SHA-512 are supported for environments requiring stronger digests.
pub fn compute_authenticode_hash_with(
    data: &[u8],
    pe_info: &PeInfo,
    digest_alg: DigestAlgorithm,
) -> SignResult<Vec<u8>> {
    if data.len() < pe_info.end_of_image {
        return Err(SignError::Hash(
            "File shorter than computed end of image".into(),
        ));
    }

    // Build the list of byte ranges to hash (excluding checksum + cert table)
    let exclusions = [(pe_info.checksum_offset, 4), (pe_info.cert_table_offset, 8)];

    // Feed byte ranges into a hasher, supporting SHA-2 and SHA-3 families
    macro_rules! hash_with {
        ($hasher_type:ty) => {{
            let mut hasher = <$hasher_type>::new();
            feed_authenticode_ranges(&mut hasher, data, pe_info, &exclusions);
            Ok(hasher.finalize().to_vec())
        }};
    }

    match digest_alg {
        DigestAlgorithm::Sha256 => hash_with!(Sha256),
        DigestAlgorithm::Sha384 => hash_with!(Sha384),
        DigestAlgorithm::Sha512 => hash_with!(Sha512),
        DigestAlgorithm::Sha3_256 => hash_with!(sha3::Sha3_256),
        DigestAlgorithm::Sha3_384 => hash_with!(sha3::Sha3_384),
        DigestAlgorithm::Sha3_512 => hash_with!(sha3::Sha3_512),
    }
}

/// Feed the Authenticode hash ranges into a Digest hasher, skipping excluded regions.
fn feed_authenticode_ranges(
    hasher: &mut impl Digest,
    data: &[u8],
    pe_info: &PeInfo,
    exclusions: &[(usize, usize)],
) {
    let mut pos = 0;
    for &(exc_start, exc_len) in exclusions {
        if exc_start > pe_info.end_of_image {
            break;
        }
        if pos < exc_start {
            hasher.update(&data[pos..exc_start]);
        }
        pos = exc_start + exc_len;
    }

    if pos < pe_info.end_of_image {
        hasher.update(&data[pos..pe_info.end_of_image]);
    }
}

/// Compute the Authenticode PE image hash (SHA-256).
///
/// Convenience wrapper for the most common case.
pub fn compute_authenticode_hash(data: &[u8], pe_info: &PeInfo) -> SignResult<Vec<u8>> {
    compute_authenticode_hash_with(data, pe_info, DigestAlgorithm::Sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7::builder::DigestAlgorithm;

    fn make_pe_info(
        checksum_offset: usize,
        cert_table_offset: usize,
        end_of_image: usize,
    ) -> PeInfo {
        PeInfo {
            pe_offset: 0,
            is_pe32_plus: false,
            checksum_offset,
            cert_table_offset,
            cert_table_rva: 0,
            cert_table_size: 0,
            end_of_image,
            file_size: end_of_image,
            sections: vec![],
            size_of_optional_header: 0,
            number_of_rva_and_sizes: 16,
        }
    }

    #[test]
    fn test_hash_excludes_regions() {
        let pe_info = make_pe_info(10, 20, 50);
        let data = vec![0xAA; 60];
        let hash = compute_authenticode_hash(&data, &pe_info).unwrap();

        // Hash should be deterministic for same input
        let hash2 = compute_authenticode_hash(&data, &pe_info).unwrap();
        assert_eq!(hash, hash2);

        // Hash should be 32 bytes (SHA-256)
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_hash_changes_with_content() {
        let pe_info = make_pe_info(10, 20, 50);

        let data_a = vec![0xAA; 60];
        let data_b = vec![0xBB; 60];

        let hash_a = compute_authenticode_hash(&data_a, &pe_info).unwrap();
        let hash_b = compute_authenticode_hash(&data_b, &pe_info).unwrap();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_ignores_checksum_changes() {
        let pe_info = make_pe_info(10, 20, 50);

        let mut data_a = vec![0xAA; 60];
        let mut data_b = data_a.clone();

        // Modify only the checksum region (bytes 10-13)
        data_a[10] = 0x00;
        data_b[10] = 0xFF;
        data_b[11] = 0xFF;
        data_b[12] = 0xFF;
        data_b[13] = 0xFF;

        let hash_a = compute_authenticode_hash(&data_a, &pe_info).unwrap();
        let hash_b = compute_authenticode_hash(&data_b, &pe_info).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_ignores_cert_table_changes() {
        let pe_info = make_pe_info(10, 20, 50);

        let data_a = vec![0xAA; 60];
        let mut data_b = data_a.clone();

        // Modify only the cert table region (bytes 20-27)
        for byte in &mut data_b[20..28] {
            *byte = 0xFF;
        }

        let hash_a = compute_authenticode_hash(&data_a, &pe_info).unwrap();
        let hash_b = compute_authenticode_hash(&data_b, &pe_info).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_ignores_data_beyond_end_of_image() {
        let pe_info = make_pe_info(10, 20, 50);

        let data_a = vec![0xAA; 100];
        let mut data_b = data_a.clone();

        // Modify bytes beyond end_of_image (50+)
        for byte in &mut data_b[50..100] {
            *byte = 0xFF;
        }

        let hash_a = compute_authenticode_hash(&data_a, &pe_info).unwrap();
        let hash_b = compute_authenticode_hash(&data_b, &pe_info).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_rejects_short_file() {
        let pe_info = make_pe_info(10, 20, 100);
        let data = vec![0xAA; 50]; // shorter than end_of_image
        assert!(compute_authenticode_hash(&data, &pe_info).is_err());
    }

    #[test]
    fn test_hash_sensitive_to_non_excluded_regions() {
        let pe_info = make_pe_info(10, 20, 50);

        let data_a = vec![0xAA; 60];
        let mut data_b = data_a.clone();

        // Modify byte 5 (inside hashed region, before checksum)
        data_b[5] = 0xFF;

        let hash_a = compute_authenticode_hash(&data_a, &pe_info).unwrap();
        let hash_b = compute_authenticode_hash(&data_b, &pe_info).unwrap();
        assert_ne!(hash_a, hash_b);
    }

    // ─── Multi-digest tests (SHA-384, SHA-512) ───

    #[test]
    fn test_sha384_authenticode_hash() {
        let pe_info = make_pe_info(10, 20, 50);
        let data = vec![0xAA; 60];
        let hash =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha384).unwrap();
        // SHA-384 produces 48 bytes
        assert_eq!(hash.len(), 48);

        // Deterministic
        let hash2 =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha384).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sha512_authenticode_hash() {
        let pe_info = make_pe_info(10, 20, 50);
        let data = vec![0xAA; 60];
        let hash =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha512).unwrap();
        // SHA-512 produces 64 bytes
        assert_eq!(hash.len(), 64);

        // Deterministic
        let hash2 =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha512).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_algorithms_produce_different_hashes() {
        let pe_info = make_pe_info(10, 20, 50);
        let data = vec![0xAA; 60];

        let sha256 =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha256).unwrap();
        let sha384 =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha384).unwrap();
        let sha512 =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha512).unwrap();

        // Different lengths
        assert_eq!(sha256.len(), 32);
        assert_eq!(sha384.len(), 48);
        assert_eq!(sha512.len(), 64);

        // Different content (comparing first 32 bytes)
        assert_ne!(&sha256[..], &sha384[..32]);
        assert_ne!(&sha256[..], &sha512[..32]);
    }

    #[test]
    fn test_sha384_excludes_same_regions() {
        let pe_info = make_pe_info(10, 20, 50);

        let mut data_a = vec![0xAA; 60];
        let mut data_b = data_a.clone();

        // Modify checksum region — should be excluded
        data_a[10] = 0x00;
        data_b[10] = 0xFF;

        let hash_a =
            compute_authenticode_hash_with(&data_a, &pe_info, DigestAlgorithm::Sha384).unwrap();
        let hash_b =
            compute_authenticode_hash_with(&data_b, &pe_info, DigestAlgorithm::Sha384).unwrap();
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_sha256_wrapper_matches_with_function() {
        let pe_info = make_pe_info(10, 20, 50);
        let data = vec![0xAA; 60];

        let from_wrapper = compute_authenticode_hash(&data, &pe_info).unwrap();
        let from_with =
            compute_authenticode_hash_with(&data, &pe_info, DigestAlgorithm::Sha256).unwrap();
        assert_eq!(from_wrapper, from_with);
    }
}
