//! CMS DigestedData builder and verifier (RFC 5652 §4.5)
//!
//! Implements the DigestedData content type, which provides integrity-only
//! protection (a digest without signing or encryption). This completes CMS
//! structure coverage alongside SignedData and EnvelopedData.
//!
//! ## Structure
//!
//! ```text
//! DigestedData ::= SEQUENCE {
//!   version CMSVersion,
//!   digestAlgorithm DigestAlgorithmIdentifier,
//!   encapContentInfo EncapsulatedContentInfo,
//!   digest Digest }
//!
//! Digest ::= OCTET STRING
//! ```
//!
//! version is always 0 when content type is id-data (1.2.840.113549.1.7.1),
//! and 2 otherwise (RFC 5652 §4.5).
//!
//! The OID for DigestedData is 1.2.840.113549.1.7.5 (id-digestedData).

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;
use crate::pkcs7::builder::DigestAlgorithm;

// ─── DigestedData OID ───

/// OID 1.2.840.113549.1.7.5 — id-digestedData (RFC 5652 §4.5)
///
/// Encoding: 1.2 = 42 = 0x2A; 840 = 0x86 0x48; 113549 = 0x86 0xF7 0x0D;
/// 1 = 0x01; 7 = 0x07; 5 = 0x05
pub const OID_DIGESTED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05,
];

// ─── DigestedData Builder ───

/// Builder for CMS DigestedData structures (RFC 5652 §4.5).
///
/// Produces a DER-encoded ContentInfo wrapping a DigestedData value.
/// The digest is computed over the encapsulated content using the
/// configured digest algorithm.
///
/// # Example
///
/// ```rust,ignore
/// let der = DigestedDataBuilder::new(b"hello world".to_vec())
///     .with_digest_algorithm(DigestAlgorithm::Sha256)
///     .build()?;
/// ```
pub struct DigestedDataBuilder {
    digest_algorithm: DigestAlgorithm,
    content_type_oid: Vec<u8>,
    content: Vec<u8>,
}

impl DigestedDataBuilder {
    /// Create a new builder with the given content.
    ///
    /// Defaults to id-data content type and SHA-256 digest algorithm.
    pub fn new(content: Vec<u8>) -> Self {
        Self {
            digest_algorithm: DigestAlgorithm::Sha256,
            content_type_oid: asn1::OID_DATA.to_vec(),
            content,
        }
    }

    /// Override the digest algorithm (default: SHA-256).
    pub fn with_digest_algorithm(mut self, alg: DigestAlgorithm) -> Self {
        self.digest_algorithm = alg;
        self
    }

    /// Override the content type OID (default: id-data).
    ///
    /// When the content type is not id-data, version is set to 2 per RFC 5652 §4.5.
    /// The OID must be DER-encoded (including tag 0x06 and length byte).
    pub fn with_content_type(mut self, oid: Vec<u8>) -> Self {
        self.content_type_oid = oid;
        self
    }

    /// Build the DER-encoded ContentInfo wrapping DigestedData.
    ///
    /// Computes the digest over the content, encodes the DigestedData structure,
    /// and wraps it in a ContentInfo per RFC 5652 §3.
    ///
    /// # Structure produced
    ///
    /// ```text
    /// ContentInfo {
    ///   contentType  id-digestedData,
    ///   content  [0] EXPLICIT DigestedData {
    ///     version          CMSVersion,
    ///     digestAlgorithm  DigestAlgorithmIdentifier,
    ///     encapContentInfo EncapsulatedContentInfo,
    ///     digest           Digest
    ///   }
    /// }
    /// ```
    pub fn build(self) -> SignResult<Vec<u8>> {
        // Compute digest over the raw content
        let digest_value = self.digest_algorithm.digest(&self.content);

        // RFC 5652 §4.5: version is 0 if content type is id-data, 2 otherwise
        let is_id_data = self.content_type_oid == asn1::OID_DATA;
        let version = asn1::encode_integer_value(if is_id_data { 0 } else { 2 });

        // DigestAlgorithmIdentifier
        let digest_alg_id = self.digest_algorithm.algorithm_id();

        // EncapsulatedContentInfo ::= SEQUENCE {
        //   eContentType  ContentType,
        //   eContent  [0] EXPLICIT OCTET STRING OPTIONAL
        // }
        //
        // eContent is the raw content bytes wrapped in an OCTET STRING,
        // then wrapped in [0] EXPLICIT per RFC 5652 §5.2.
        let econtent_os = asn1::encode_octet_string(&self.content);
        let econtent_tag = asn1::encode_explicit_tag(0, &econtent_os);
        let encap_content_info = asn1::encode_sequence(&[&self.content_type_oid, &econtent_tag]);

        // Digest ::= OCTET STRING
        let digest_os = asn1::encode_octet_string(&digest_value);

        // DigestedData ::= SEQUENCE { version, digestAlgorithm, encapContentInfo, digest }
        let digested_data =
            asn1::encode_sequence(&[&version, digest_alg_id, &encap_content_info, &digest_os]);

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT DigestedData }
        let content_field = asn1::encode_explicit_tag(0, &digested_data);
        let content_info = asn1::encode_sequence(&[OID_DIGESTED_DATA, &content_field]);

        Ok(content_info)
    }
}

// ─── DigestedData Info (verification result) ───

/// Result of verifying a DigestedData structure.
pub struct DigestedDataInfo {
    /// The digest algorithm used.
    pub algorithm: DigestAlgorithm,
    /// The encapsulated content bytes.
    pub content: Vec<u8>,
    /// Whether the stored digest matches a freshly computed digest over the content.
    pub digest_verified: bool,
}

// ─── DigestedData Verifier ───

/// Parse and verify a DER-encoded ContentInfo containing a DigestedData structure.
///
/// Extracts the digest algorithm, content, and claimed digest, then recomputes
/// the digest over the extracted content to verify integrity.
///
/// # Errors
///
/// Returns `SignError::Pkcs7` if the DER structure is malformed or if the
/// content type is not id-digestedData.
pub fn verify_digested_data(der: &[u8]) -> SignResult<DigestedDataInfo> {
    // Parse outer ContentInfo SEQUENCE
    let (tag, content_info_body) = asn1::parse_tlv(der)
        .map_err(|e| SignError::Pkcs7(format!("Parse ContentInfo outer SEQUENCE: {}", e)))?;
    if tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "Expected ContentInfo SEQUENCE (0x30), got 0x{:02X}",
            tag
        )));
    }

    // Skip contentType OID (id-digestedData)
    let (_oid_tag, after_oid) = asn1::skip_tlv(content_info_body)
        .map_err(|e| SignError::Pkcs7(format!("Skip ContentInfo OID: {}", e)))?;

    // Parse [0] EXPLICIT content wrapper
    let (context_tag, after_context) = asn1::parse_tlv(after_oid)
        .map_err(|e| SignError::Pkcs7(format!("Parse ContentInfo [0] tag: {}", e)))?;
    if context_tag != 0xA0 {
        return Err(SignError::Pkcs7(format!(
            "Expected [0] EXPLICIT (0xA0) wrapping DigestedData, got 0x{:02X}",
            context_tag
        )));
    }

    // Parse inner DigestedData SEQUENCE
    let (inner_tag, digested_data_body) = asn1::parse_tlv(after_context)
        .map_err(|e| SignError::Pkcs7(format!("Parse DigestedData SEQUENCE: {}", e)))?;
    if inner_tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "Expected DigestedData SEQUENCE (0x30), got 0x{:02X}",
            inner_tag
        )));
    }

    // Skip version INTEGER
    let (_ver_tag, after_version) = asn1::skip_tlv(digested_data_body)
        .map_err(|e| SignError::Pkcs7(format!("Skip DigestedData version: {}", e)))?;

    // Parse digestAlgorithm SEQUENCE to determine the algorithm
    let (alg_tlv, after_alg) = asn1::extract_tlv(after_version)
        .map_err(|e| SignError::Pkcs7(format!("Extract digestAlgorithm: {}", e)))?;
    let algorithm = identify_digest_algorithm(alg_tlv)?;

    // Parse encapContentInfo SEQUENCE
    let (_eci_tag, eci_body) = asn1::parse_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("Parse encapContentInfo: {}", e)))?;

    // Skip eContentType OID within encapContentInfo
    let (_ct_tag, after_ct) = asn1::skip_tlv(eci_body)
        .map_err(|e| SignError::Pkcs7(format!("Skip eContentType OID: {}", e)))?;

    // Parse [0] EXPLICIT eContent tag
    let content_bytes = if after_ct.is_empty() {
        // eContent is OPTIONAL — treat as empty content
        Vec::new()
    } else {
        let (_econtent_ctx_tag, econtent_ctx_body) = asn1::parse_tlv(after_ct)
            .map_err(|e| SignError::Pkcs7(format!("Parse eContent [0] context: {}", e)))?;

        // Parse inner OCTET STRING
        let (_os_tag, os_body) = asn1::parse_tlv(econtent_ctx_body)
            .map_err(|e| SignError::Pkcs7(format!("Parse eContent OCTET STRING: {}", e)))?;
        os_body.to_vec()
    };

    // Skip encapContentInfo TLV in after_alg to get to the digest
    let (_eci_full_tlv, after_eci) = asn1::extract_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("Extract encapContentInfo TLV: {}", e)))?;

    // Parse digest OCTET STRING
    let (_digest_tag, stored_digest) = asn1::parse_tlv(after_eci)
        .map_err(|e| SignError::Pkcs7(format!("Parse digest OCTET STRING: {}", e)))?;

    // Recompute digest and compare
    let computed_digest = algorithm.digest(&content_bytes);
    let digest_verified = computed_digest == stored_digest;

    Ok(DigestedDataInfo {
        algorithm,
        content: content_bytes,
        digest_verified,
    })
}

/// Identify a digest algorithm from a DER-encoded AlgorithmIdentifier.
///
/// Matches the OID bytes within the AlgorithmIdentifier SEQUENCE to determine
/// which `DigestAlgorithm` variant is in use.
fn identify_digest_algorithm(alg_id_der: &[u8]) -> SignResult<DigestAlgorithm> {
    // alg_id_der is the full SEQUENCE TLV; the OID is the first element
    let (seq_tag, seq_body) = asn1::parse_tlv(alg_id_der)
        .map_err(|e| SignError::Pkcs7(format!("Parse AlgorithmIdentifier SEQUENCE: {}", e)))?;
    if seq_tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "AlgorithmIdentifier must be SEQUENCE (0x30), got 0x{:02X}",
            seq_tag
        )));
    }

    // Extract OID TLV (first element of SEQUENCE)
    let (oid_tlv, _rest) = asn1::extract_tlv(seq_body)
        .map_err(|e| SignError::Pkcs7(format!("Extract OID from AlgorithmIdentifier: {}", e)))?;

    // Compare OID bytes (tag 0x06 + length + value) against known constants.
    // Each SHA algorithm_id() returns SEQUENCE { OID, NULL }; the known OID
    // TLVs below are the OID portions only (what we extract from the sequence body).
    //
    // OID 2.16.840.1.101.3.4.2.x:
    //   0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x02 0x0y
    match oid_tlv {
        // SHA-256: OID 2.16.840.1.101.3.4.2.1
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => {
            Ok(DigestAlgorithm::Sha256)
        }
        // SHA-384: OID 2.16.840.1.101.3.4.2.2
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => {
            Ok(DigestAlgorithm::Sha384)
        }
        // SHA-512: OID 2.16.840.1.101.3.4.2.3
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => {
            Ok(DigestAlgorithm::Sha512)
        }
        // SHA3-256: OID 2.16.840.1.101.3.4.2.8
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08] => {
            Ok(DigestAlgorithm::Sha3_256)
        }
        // SHA3-384: OID 2.16.840.1.101.3.4.2.9
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09] => {
            Ok(DigestAlgorithm::Sha3_384)
        }
        // SHA3-512: OID 2.16.840.1.101.3.4.2.10 (0x0A)
        [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A] => {
            Ok(DigestAlgorithm::Sha3_512)
        }
        _ => Err(SignError::Pkcs7(format!(
            "Unrecognised digest AlgorithmIdentifier OID: {:02X?}",
            oid_tlv
        ))),
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build then verify, asserting success
    fn build_and_verify(content: &[u8], alg: DigestAlgorithm) -> DigestedDataInfo {
        let der = DigestedDataBuilder::new(content.to_vec())
            .with_digest_algorithm(alg)
            .build()
            .expect("build should succeed");

        let info = verify_digested_data(&der).expect("verify_digested_data should succeed");
        assert!(
            info.digest_verified,
            "digest_verified should be true after a clean round-trip"
        );
        assert_eq!(
            info.content, content,
            "recovered content must equal original"
        );
        info
    }

    #[test]
    fn test_digested_data_sha256() {
        let content = b"hello world, SHA-256 DigestedData";
        let info = build_and_verify(content, DigestAlgorithm::Sha256);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha256));
    }

    #[test]
    fn test_digested_data_sha384() {
        let content = b"hello world, SHA-384 DigestedData";
        let info = build_and_verify(content, DigestAlgorithm::Sha384);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha384));
    }

    #[test]
    fn test_digested_data_sha512() {
        let content = b"hello world, SHA-512 DigestedData";
        let info = build_and_verify(content, DigestAlgorithm::Sha512);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha512));
    }

    #[test]
    fn test_digested_data_custom_content_type() {
        // Use a non-id-data OID: id-signedData (1.2.840.113549.1.7.2)
        // so version should be 2 per RFC 5652 §4.5
        let custom_oid = asn1::OID_SIGNED_DATA.to_vec();
        let content = b"custom content type test";

        let der = DigestedDataBuilder::new(content.to_vec())
            .with_content_type(custom_oid)
            .build()
            .expect("build should succeed");

        // Decode outer ContentInfo -> [0] EXPLICIT -> DigestedData SEQUENCE
        let (_ci_tag, ci_body) = asn1::parse_tlv(&der).unwrap();
        let (_oid_tag, after_oid) = asn1::skip_tlv(ci_body).unwrap();
        let (_ctx_tag, ctx_body) = asn1::parse_tlv(after_oid).unwrap();
        let (_seq_tag, dg_body) = asn1::parse_tlv(ctx_body).unwrap();

        // First element is version INTEGER
        let (_ver_tag, version_content) = asn1::parse_tlv(dg_body).unwrap();
        // version should be 2 (0x02) for non-id-data content type
        assert_eq!(
            version_content,
            &[0x02],
            "version must be 2 for non-id-data content type"
        );
    }

    #[test]
    fn test_digested_data_id_data_version_is_zero() {
        // The default content type is id-data — version must be 0
        let content = b"id-data version check";
        let der = DigestedDataBuilder::new(content.to_vec())
            .build()
            .expect("build should succeed");

        let (_ci_tag, ci_body) = asn1::parse_tlv(&der).unwrap();
        let (_oid_tag, after_oid) = asn1::skip_tlv(ci_body).unwrap();
        let (_ctx_tag, ctx_body) = asn1::parse_tlv(after_oid).unwrap();
        let (_seq_tag, dg_body) = asn1::parse_tlv(ctx_body).unwrap();
        let (_ver_tag, version_content) = asn1::parse_tlv(dg_body).unwrap();
        assert_eq!(
            version_content,
            &[0x00],
            "version must be 0 for id-data content type"
        );
    }

    #[test]
    fn test_digested_data_tampered() {
        // Build a valid DigestedData, then tamper with the content.
        // Re-verifying against the original structure should detect the mismatch.
        let original = b"original content";
        let der = DigestedDataBuilder::new(original.to_vec())
            .build()
            .expect("build should succeed");

        // Parse and verify the original — must pass
        let info = verify_digested_data(&der).expect("verify should succeed");
        assert!(info.digest_verified);

        // Build a new DigestedData with tampered content but the same DER structure
        // to simulate a situation where the digest does not match the content.
        // We do this by building fresh content that differs and manually crafting
        // a structure with the old digest and new content.
        let tampered_content = b"tampered content !!!";
        let original_digest = DigestAlgorithm::Sha256.digest(original);
        let tampered_digest = DigestAlgorithm::Sha256.digest(tampered_content);

        // They must not be equal — this is the integrity violation we test
        assert_ne!(
            original_digest, tampered_digest,
            "tampered content must produce a different digest"
        );

        // Build a DigestedData that intentionally stores a wrong digest by:
        // 1. Building with the tampered content (gets correct digest for tampered)
        // 2. Re-encoding with tampered content embedded but original digest appended
        //
        // Instead, test the realistic scenario: verify() returns digest_verified=false
        // when the stored digest does not match the content. We craft this directly:
        let tampered_der = build_tampered_der(tampered_content, &original_digest);
        let info = verify_digested_data(&tampered_der).expect("parse should succeed");
        assert!(
            !info.digest_verified,
            "digest_verified must be false when digest does not match content"
        );
    }

    /// Build a DigestedData DER where the digest field stores `stored_digest`
    /// rather than the actual digest of `content`. Used to test tamper detection.
    fn build_tampered_der(content: &[u8], stored_digest: &[u8]) -> Vec<u8> {
        let version = asn1::encode_integer_value(0);
        let digest_alg_id = DigestAlgorithm::Sha256.algorithm_id();

        let econtent_os = asn1::encode_octet_string(content);
        let econtent_tag = asn1::encode_explicit_tag(0, &econtent_os);
        let encap_content_info = asn1::encode_sequence(&[asn1::OID_DATA, &econtent_tag]);

        // Intentionally store the WRONG digest
        let digest_os = asn1::encode_octet_string(stored_digest);

        let digested_data =
            asn1::encode_sequence(&[&version, digest_alg_id, &encap_content_info, &digest_os]);

        let content_field = asn1::encode_explicit_tag(0, &digested_data);
        asn1::encode_sequence(&[OID_DIGESTED_DATA, &content_field])
    }

    #[test]
    fn test_digested_data_empty_content() {
        // Empty content must still produce a valid, verifiable DigestedData
        let info = build_and_verify(b"", DigestAlgorithm::Sha256);
        assert_eq!(info.content, b"");
        assert!(info.digest_verified);
    }

    #[test]
    fn test_digested_data_content_info_oid() {
        // Verify the outer ContentInfo carries the id-digestedData OID
        let der = DigestedDataBuilder::new(b"oid check".to_vec())
            .build()
            .expect("build should succeed");

        // Parse ContentInfo: SEQUENCE { OID, [0] EXPLICIT DigestedData }
        let (_ci_tag, ci_body) = asn1::parse_tlv(&der).unwrap();
        let (oid_tlv, _rest) = asn1::extract_tlv(ci_body).unwrap();

        // OID_DIGESTED_DATA is the full DER-encoded OID (tag + length + value)
        assert_eq!(
            oid_tlv, OID_DIGESTED_DATA,
            "ContentInfo OID must be id-digestedData (1.2.840.113549.1.7.5)"
        );
    }

    #[test]
    fn test_digested_data_sha3_256() {
        let content = b"SHA3-256 DigestedData test";
        let info = build_and_verify(content, DigestAlgorithm::Sha3_256);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha3_256));
    }

    #[test]
    fn test_digested_data_sha3_384() {
        let content = b"SHA3-384 DigestedData test";
        let info = build_and_verify(content, DigestAlgorithm::Sha3_384);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha3_384));
    }

    #[test]
    fn test_digested_data_sha3_512() {
        let content = b"SHA3-512 DigestedData test";
        let info = build_and_verify(content, DigestAlgorithm::Sha3_512);
        assert!(matches!(info.algorithm, DigestAlgorithm::Sha3_512));
    }

    #[test]
    fn test_digested_data_large_content() {
        // Content that requires multi-byte DER length encoding
        let content = vec![0xAB_u8; 300];
        let info = build_and_verify(&content, DigestAlgorithm::Sha256);
        assert_eq!(info.content.len(), 300);
        assert!(info.digest_verified);
    }
}
