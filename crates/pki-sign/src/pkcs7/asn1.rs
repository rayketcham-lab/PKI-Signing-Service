//! Low-level ASN.1 DER encoding utilities for PKCS#7 construction.
//!
//! Hand-rolled DER encoding for precise control over Authenticode's
//! non-standard structures (SPC_INDIRECT_DATA, etc.).
//!
//! This module provides:
//! - DER length encoding
//! - Tag-Length-Value construction (SEQUENCE, SET, OCTET STRING, etc.)
//! - OID constants for Authenticode
//! - TLV parsing for certificate field extraction

use chrono::Utc;

// ─── OID Constants (DER-encoded, including tag + length) ───

/// OID 1.2.840.113549.1.7.2 — id-signedData
pub const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];

/// OID 1.2.840.113549.1.7.1 — id-data
pub const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
];

/// OID 1.3.6.1.4.1.311.2.1.4 — SPC_INDIRECT_DATA_OBJID
pub const OID_SPC_INDIRECT_DATA: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
];

/// OID 1.3.6.1.4.1.311.2.1.15 — SPC_PE_IMAGE_DATAOBJ
pub const OID_SPC_PE_IMAGE_DATAOBJ: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F,
];

/// OID 1.3.6.1.4.1.311.2.1.30 — SPC_SIPINFO_OBJID (SIP-based signatures)
pub const OID_SPC_SIPINFO: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x1E,
];

/// OID 1.3.6.1.4.1.311.2.1.12 — SPC_SP_OPUS_INFO_OBJID
pub const OID_SPC_SP_OPUS_INFO: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C,
];

/// OID 1.2.840.113549.1.9.3 — id-contentType
pub const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];

/// OID 1.2.840.113549.1.9.4 — id-messageDigest
pub const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];

/// OID 1.2.840.113549.1.9.5 — id-signingTime
pub const OID_SIGNING_TIME: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
];

/// OID 1.2.840.113549.1.9.16.2.14 — id-aa-timeStampToken
pub const OID_TIMESTAMP_TOKEN: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
];

/// OID 1.2.840.113549.1.9.6 — id-counterSignature (RFC 5652 §11.4)
pub const OID_COUNTER_SIGNATURE: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06,
];

/// OID 1.2.840.113549.1.9.16.2.4 — id-smime-aa-contentHint (RFC 2634 §2.9)
pub const OID_CONTENT_HINTS: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x04,
];

/// OID 1.2.840.113549.1.9.16.2.47 — id-smime-aa-signingCertificateV2 (RFC 5035)
pub const OID_ESS_CERT_ID_V2: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// OID 1.2.840.113549.1.9.52 — id-aa-CMSAlgorithmProtection (RFC 8933)
///
/// Encoding: 1.2 = 42 = 0x2A; 840 = 0x86 0x48; 113549 = 0x86 0xF7 0x0D;
/// 1.9.52 → arc 1 = 0x01, arc 9 = 0x09, arc 52 = 0x34
pub const OID_CMS_ALGORITHM_PROTECTION: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x34,
];

// ─── S/MIME OIDs ───

/// OID 1.2.840.113549.1.7.3 — id-envelopedData (RFC 5652 §6)
pub const OID_ENVELOPED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
];

/// OID 1.2.840.113549.1.7.5 — id-digestedData (RFC 5652 §4.5)
///
/// Encoding: 1.2 = 42 = 0x2A; 840 = 0x86 0x48; 113549 = 0x86 0xF7 0x0D;
/// 1 = 0x01; 7 = 0x07; 5 = 0x05
pub const OID_DIGESTED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05,
];

/// OID 2.16.840.1.101.3.4.1.2 — id-aes128-CBC (NIST AES)
///
/// Encoding: 2.16 = 96 = 0x60; 840 = 0x86 0x48; 1 = 0x01; 101 = 0x65; 3 = 0x03; 4 = 0x04; 1 = 0x01; 2 = 0x02
pub const OID_AES128_CBC: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02,
];

/// OID 2.16.840.1.101.3.4.1.42 — id-aes256-CBC (NIST AES)
///
/// arc 42 = 0x2A
pub const OID_AES256_CBC: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A,
];

/// OID 2.16.840.1.101.3.4.1.6 — id-aes128-GCM (RFC 5084)
pub const OID_AES128_GCM: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06,
];

/// OID 2.16.840.1.101.3.4.1.46 — id-aes256-GCM (RFC 5084)
///
/// arc 46 = 0x2E
pub const OID_AES256_GCM: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E,
];

/// OID 1.2.840.113549.1.9.16.13.3 — id-ori-kem (RFC 9629 §3)
///
/// Encoding: 1.2 = 0x2A; 840 = 0x86 0x48; 113549 = 0x86 0xF7 0x0D;
/// 1.9.16.13.3 → 0x01 0x09 0x10 0x0D 0x03
pub const OID_ORI_KEM: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x0D, 0x03,
];

/// OID 1.2.840.113549.1.9.16.3.28 — id-alg-hkdf-with-sha256 (RFC 8619 §3)
///
/// Encoding: 1.2 = 0x2A; 840 = 0x86 0x48; 113549 = 0x86 0xF7 0x0D;
/// 1.9.16.3.28 → 0x01 0x09 0x10 0x03 0x1C
pub const OID_HKDF_SHA256: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1C,
];

/// OID 1.2.840.113549.1.9.16.3.29 — id-alg-hkdf-with-sha384 (RFC 8619 §3)
pub const OID_HKDF_SHA384: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1D,
];

/// OID 1.2.840.113549.1.9.16.3.30 — id-alg-hkdf-with-sha512 (RFC 8619 §3)
pub const OID_HKDF_SHA512: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x1E,
];

/// OID 1.3.132.1.12 — id-ecDH (RFC 5480, ECDH key agreement)
///
/// Encoding: 1.3 = 43 = 0x2B; 132 = 0x84 0x04; 1 = 0x01; 12 = 0x0C
pub const OID_EC_DH: &[u8] = &[0x06, 0x05, 0x2B, 0x84, 0x04, 0x01, 0x0C];

/// OID 2.16.840.1.101.3.4.1.5 — id-aes128-wrap (RFC 3394, AES Key Wrap)
pub const OID_AES128_WRAP: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05,
];

/// OID 2.16.840.1.101.3.4.1.45 — id-aes256-wrap (RFC 3394, AES Key Wrap)
///
/// arc 45 = 0x2D
pub const OID_AES256_WRAP: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D,
];

/// OID 1.2.840.113549.1.9.16.2.1 — id-smime-aa-receiptRequest (RFC 2634 §2.7)
/// Note: OID_ESS_CERT_ID_V2 (.47) is already defined above.
pub const OID_ESS_RECEIPT_REQUEST: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x01,
];

/// OID 1.2.840.113549.1.9.16.2.2 — id-smime-aa-securityLabel (RFC 2634 §3.7)
pub const OID_ESS_SECURITY_LABEL: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x02,
];

/// OID 1.2.840.113549.1.9.16.2.3 — id-smime-aa-mlExpansionHistory (RFC 2634 §4.2)
pub const OID_ESS_ML_EXPANSION_HISTORY: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x03,
];

/// OID 1.2.840.113549.1.9.15 — smimeCapabilities (RFC 8551 §2.5.2)
pub const OID_SMIME_CAPABILITIES: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F,
];

/// OID 1.2.840.113549.1.9.16.1.2 — id-smime-ct-receipt (RFC 2634 §2)
pub const OID_SMIME_CT_RECEIPT: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x02,
];

/// OID 1.2.840.113549.1.9.16.1.4 — id-smime-ct-TSTInfo (RFC 3161 §2.4.2, RFC 3852)
pub const OID_SMIME_CT_TST_INFO: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// OID 1.2.840.113549.1.9.16.3.5 — id-alg-ESDH (RFC 2631, ephemeral-static ECDH for S/MIME)
/// Note: pkcs-9-at-smimeCapabilities (.21) is the same as OID_SMIME_CAPABILITIES above.
pub const OID_SMIME_ALG_ESDH: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x05,
];

/// Build a DER-encoded AlgorithmIdentifier for AES-CBC with a 16-byte IV.
///
/// AES-CBC AlgorithmIdentifier ::= SEQUENCE { OID, OCTET STRING (iv) }
/// The IV is included as the parameters field.
pub fn aes_cbc_algorithm_id(oid_bytes: &[u8], iv: &[u8; 16]) -> Vec<u8> {
    // IV as OCTET STRING
    let iv_os = encode_octet_string(iv);
    let mut content = oid_bytes.to_vec();
    content.extend_from_slice(&iv_os);
    encode_sequence(&[&content])
}

/// Build a DER-encoded AlgorithmIdentifier for AES-GCM with nonce and optional ICVlen.
///
/// GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }
/// Per RFC 5084 §3.2.
pub fn aes_gcm_algorithm_id(oid_bytes: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    // GCMParameters SEQUENCE { OCTET STRING (nonce), [optionally INTEGER icvlen] }
    // When ICVlen == 12 (default), it SHOULD be omitted per RFC 5084 §3.2
    let nonce_os = encode_octet_string(nonce);
    let gcm_params = encode_sequence(&[&nonce_os]);
    let mut content = oid_bytes.to_vec();
    content.extend_from_slice(&gcm_params);
    encode_sequence(&[&content])
}

// ─── AlgorithmIdentifier Constants ───

/// AlgorithmIdentifier for SHA-256: SEQUENCE { OID sha256, NULL }
pub const SHA256_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID sha256
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for SHA-384: SEQUENCE { OID sha384, NULL }
/// OID 2.16.840.1.101.3.4.2.2
pub const SHA384_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, // OID sha384
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for SHA-512: SEQUENCE { OID sha512, NULL }
/// OID 2.16.840.1.101.3.4.2.3
pub const SHA512_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, // OID sha512
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for SHA3-256: SEQUENCE { OID sha3-256, NULL }
/// OID 2.16.840.1.101.3.4.2.8 (FIPS 202)
pub const SHA3_256_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, // OID sha3-256
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for SHA3-384: SEQUENCE { OID sha3-384, NULL }
/// OID 2.16.840.1.101.3.4.2.9 (FIPS 202)
pub const SHA3_384_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, // OID sha3-384
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for SHA3-512: SEQUENCE { OID sha3-512, NULL }
/// OID 2.16.840.1.101.3.4.2.10 (FIPS 202)
pub const SHA3_512_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A, // OID sha3-512
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1): SEQUENCE { OID, NULL }
///
/// Used as the signatureAlgorithm in Authenticode SignerInfo, where the
/// digest algorithm is specified separately in the digestAlgorithm field.
/// This matches osslsigncode and Windows Authenticode behavior.
pub const RSA_ENCRYPTION_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // OID rsaEncryption
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for sha256WithRSAEncryption: SEQUENCE { OID, NULL }
pub const SHA256_WITH_RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, // OID sha256WithRSA
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for sha384WithRSAEncryption: SEQUENCE { OID, NULL }
/// OID 1.2.840.113549.1.1.12
pub const SHA384_WITH_RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, // OID sha384WithRSA
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for sha512WithRSAEncryption: SEQUENCE { OID, NULL }
/// OID 1.2.840.113549.1.1.13
pub const SHA512_WITH_RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0D, // SEQUENCE, length 13
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, // OID sha512WithRSA
    0x05, 0x00, // NULL
];

/// AlgorithmIdentifier for ecdsa-with-SHA256 (1.2.840.10045.4.3.2): SEQUENCE { OID }
///
/// Per RFC 5480, ECDSA AlgorithmIdentifiers MUST omit the parameters field.
pub const ECDSA_WITH_SHA256_ALGORITHM_ID: [u8; 12] = [
    0x30, 0x0A, // SEQUENCE, length 10
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, // OID ecdsa-with-SHA256
];

/// AlgorithmIdentifier for ecdsa-with-SHA384 (1.2.840.10045.4.3.3): SEQUENCE { OID }
pub const ECDSA_WITH_SHA384_ALGORITHM_ID: [u8; 12] = [
    0x30, 0x0A, // SEQUENCE, length 10
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, // OID ecdsa-with-SHA384
];

/// AlgorithmIdentifier for ecdsa-with-SHA512 (1.2.840.10045.4.3.4): SEQUENCE { OID }
pub const ECDSA_WITH_SHA512_ALGORITHM_ID: [u8; 12] = [
    0x30, 0x0A, // SEQUENCE, length 10
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04, // OID ecdsa-with-SHA512
];

/// AlgorithmIdentifier for Ed25519 (1.3.101.112): SEQUENCE { OID }
///
/// Per RFC 8410 §3, EdDSA AlgorithmIdentifiers MUST NOT include parameters.
pub const ED25519_ALGORITHM_ID: [u8; 7] = [
    0x30, 0x05, // SEQUENCE, length 5
    0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112
];

/// AlgorithmIdentifier for RSASSA-PSS (1.2.840.113549.1.1.10) with SHA-256 parameters.
///
/// RSASSA-PSS-params ::= SEQUENCE {
///   hashAlgorithm    [0] sha-256,
///   maskGenAlgorithm [1] mgf1SHA256,
///   saltLength       [2] INTEGER 32
/// }
///
/// This is the full DER encoding of AlgorithmIdentifier { id-RSASSA-PSS, params }.
pub const RSASSA_PSS_SHA256_ALGORITHM_ID: [u8; 67] = [
    0x30, 0x41, // SEQUENCE (65 bytes)
    // OID: id-RSASSA-PSS (1.2.840.113549.1.1.10)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
    // RSASSA-PSS-params SEQUENCE
    0x30, 0x34, // SEQUENCE (52 bytes)
    // [0] hashAlgorithm: sha-256
    0xA0, 0x0F, // [0] EXPLICIT (15 bytes)
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    // [1] maskGenAlgorithm: mgf1(sha-256)
    0xA1, 0x1C, // [1] EXPLICIT (28 bytes)
    0x30, 0x1A, // SEQUENCE (26 bytes)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, // OID mgf1
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    // [2] saltLength: 32
    0xA2, 0x03, // [2] EXPLICIT (3 bytes)
    0x02, 0x01, 0x20, // INTEGER 32
];

/// AlgorithmIdentifier for RSASSA-PSS with SHA-384 parameters (RFC 4055).
///
/// hashAlgorithm: SHA-384, maskGenAlgorithm: mgf1(SHA-384), saltLength: 48
pub const RSASSA_PSS_SHA384_ALGORITHM_ID: [u8; 67] = [
    0x30, 0x41, // SEQUENCE (65 bytes)
    // OID: id-RSASSA-PSS (1.2.840.113549.1.1.10)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
    // RSASSA-PSS-params SEQUENCE
    0x30, 0x34, // SEQUENCE (52 bytes)
    // [0] hashAlgorithm: sha-384
    0xA0, 0x0F, // [0] EXPLICIT (15 bytes)
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    // [1] maskGenAlgorithm: mgf1(sha-384)
    0xA1, 0x1C, // [1] EXPLICIT (28 bytes)
    0x30, 0x1A, // SEQUENCE (26 bytes)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, // OID mgf1
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    // [2] saltLength: 48
    0xA2, 0x03, // [2] EXPLICIT (3 bytes)
    0x02, 0x01, 0x30, // INTEGER 48
];

/// AlgorithmIdentifier for RSASSA-PSS with SHA-512 parameters (RFC 4055).
///
/// hashAlgorithm: SHA-512, maskGenAlgorithm: mgf1(SHA-512), saltLength: 64
pub const RSASSA_PSS_SHA512_ALGORITHM_ID: [u8; 67] = [
    0x30, 0x41, // SEQUENCE (65 bytes)
    // OID: id-RSASSA-PSS (1.2.840.113549.1.1.10)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
    // RSASSA-PSS-params SEQUENCE
    0x30, 0x34, // SEQUENCE (52 bytes)
    // [0] hashAlgorithm: sha-512
    0xA0, 0x0F, // [0] EXPLICIT (15 bytes)
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
    // [1] maskGenAlgorithm: mgf1(sha-512)
    0xA1, 0x1C, // [1] EXPLICIT (28 bytes)
    0x30, 0x1A, // SEQUENCE (26 bytes)
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, // OID mgf1
    0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
    // [2] saltLength: 64
    0xA2, 0x03, // [2] EXPLICIT (3 bytes)
    0x02, 0x01, 0x40, // INTEGER 64
];

/// AlgorithmIdentifier for ML-DSA-44 (2.16.840.1.101.3.4.3.17): SEQUENCE { OID }
///
/// Per RFC 9882 §3, ML-DSA AlgorithmIdentifiers MUST NOT include parameters.
pub const ML_DSA_44_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
];

/// AlgorithmIdentifier for ML-DSA-65 (2.16.840.1.101.3.4.3.18): SEQUENCE { OID }
pub const ML_DSA_65_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];

/// AlgorithmIdentifier for ML-DSA-87 (2.16.840.1.101.3.4.3.19): SEQUENCE { OID }
pub const ML_DSA_87_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
];

/// AlgorithmIdentifier for SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20): SEQUENCE { OID }
///
/// Per RFC 9909, SLH-DSA AlgorithmIdentifiers MUST NOT include parameters.
pub const SLH_DSA_SHA2_128S_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
];

/// AlgorithmIdentifier for SLH-DSA-SHA2-192s (2.16.840.1.101.3.4.3.22): SEQUENCE { OID }
pub const SLH_DSA_SHA2_192S_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16,
];

/// AlgorithmIdentifier for SLH-DSA-SHA2-256s (2.16.840.1.101.3.4.3.24): SEQUENCE { OID }
pub const SLH_DSA_SHA2_256S_ALGORITHM_ID: [u8; 13] = [
    0x30, 0x0B, // SEQUENCE, length 11
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18,
];

// ─── DER Encoding Functions ───

/// Encode a DER length.
///
/// | Length Range | Encoding |
/// |-------------|----------|
/// | 0-127       | Single byte |
/// | 128-255     | 0x81 + 1 byte |
/// | 256-65535   | 0x82 + 2 bytes (big-endian) |
/// | 65536+      | 0x83 + 3 bytes (big-endian) |
pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Encode a DER SEQUENCE from concatenated content parts.
pub fn encode_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

/// Encode a DER SET from pre-encoded content.
pub fn encode_set(content: &[u8]) -> Vec<u8> {
    let mut result = vec![0x31]; // SET tag
    result.extend(encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encode a DER SET OF with proper lexicographic ordering (X.690 Section 11.6).
///
/// Takes a slice of individually DER-encoded elements, sorts them by their
/// complete DER encoding in lexicographic order, then wraps in a SET tag.
/// This is required for signed attributes per RFC 5652 Section 5.3.
pub fn encode_set_of(elements: &[&[u8]]) -> Vec<u8> {
    let mut sorted: Vec<&[u8]> = elements.to_vec();
    sorted.sort();
    let total_len: usize = sorted.iter().map(|e| e.len()).sum();
    let mut result = vec![0x31]; // SET tag
    result.extend(encode_length(total_len));
    for elem in &sorted {
        result.extend_from_slice(elem);
    }
    result
}

/// Encode an OCTET STRING.
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend(encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

/// Encode a small positive INTEGER value.
pub fn encode_integer_value(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let mut bytes = Vec::new();
    let mut v = value;
    while v > 0 {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
    }
    bytes.reverse();
    // Add leading zero if high bit set (ASN.1 INTEGER is signed)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    let mut result = vec![0x02]; // INTEGER tag
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Encode a context-specific [tag] IMPLICIT wrapper.
///
/// Replaces the universal tag with 0xA0 | tag_number.
pub fn encode_implicit_tag(tag_number: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | tag_number;
    let mut result = vec![tag];
    result.extend(encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encode a context-specific [tag] EXPLICIT wrapper.
///
/// Wraps the content in a constructed context tag.
pub fn encode_explicit_tag(tag_number: u8, content: &[u8]) -> Vec<u8> {
    let tag = 0xA0 | tag_number;
    let mut result = vec![tag];
    result.extend(encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encode the current UTC time as ASN.1 UTCTime.
///
/// Format: YYMMDDHHmmSSZ (13 bytes)
pub fn encode_utc_time_now() -> Vec<u8> {
    let now = Utc::now();
    encode_utc_time(now)
}

/// Encode a specific UTC time as ASN.1 UTCTime or GeneralizedTime.
///
/// Per RFC 5280 §4.1.2.5: UTCTime (tag 0x17) is used for years 1950-2049,
/// GeneralizedTime (tag 0x18) for years 2050 and beyond.
/// UTCTime format: YYMMDDHHmmSSZ (13 bytes)
/// GeneralizedTime format: YYYYMMDDHHmmSSZ (15 bytes)
pub fn encode_utc_time(time: chrono::DateTime<Utc>) -> Vec<u8> {
    let year = time.format("%Y").to_string().parse::<i32>().unwrap_or(2026);
    if year >= 2050 {
        // RFC 5280 §4.1.2.5.2: GeneralizedTime for years >= 2050
        let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
        let time_bytes = time_str.as_bytes();
        let mut result = vec![0x18]; // GeneralizedTime tag
        result.extend(encode_length(time_bytes.len()));
        result.extend_from_slice(time_bytes);
        result
    } else {
        // RFC 5280 §4.1.2.5.1: UTCTime for years 1950-2049
        let time_str = time.format("%y%m%d%H%M%SZ").to_string();
        let time_bytes = time_str.as_bytes();
        let mut result = vec![0x17]; // UTCTime tag
        result.extend(encode_length(time_bytes.len()));
        result.extend_from_slice(time_bytes);
        result
    }
}

/// Encode a UTF8String value.
pub fn encode_utf8_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = vec![0x0C]; // UTF8String tag
    result.extend(encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    result
}

// ─── DER Parsing Functions (for certificate field extraction) ───

/// Validate that DER data uses definite-length encoding per RFC 5652 §10.1.
///
/// DER requires definite-length encoding: length byte 0x80 (indefinite form)
/// is forbidden. Also rejects non-canonical length encoding where a shorter
/// form could represent the same length (e.g., 0x81 0x7F for length 127).
pub fn validate_der_definite_length(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 2 {
        return Ok(()); // too short to contain invalid encoding
    }
    let len_byte = data[1];
    if len_byte == 0x80 {
        return Err("indefinite-length encoding forbidden in DER (RFC 5652 §10.1)");
    }
    // Check for non-canonical long-form encoding
    if len_byte & 0x80 != 0 {
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes == 1 && data.len() > 2 && data[2] < 128 {
            return Err("non-canonical DER length: value < 128 must use short form");
        }
        if num_bytes > 1 && data.len() > 2 && data[2] == 0 {
            return Err("non-canonical DER length: leading zero in long-form");
        }
    }
    Ok(())
}

/// Parse a DER TLV, returning (content, remaining_after_content).
///
/// This extracts the content bytes of the first TLV element,
/// and returns the remaining bytes after the entire TLV.
pub fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8]), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let tag = data[0];
    let (content_len, header_len) = decode_length(&data[1..])?;
    let total = header_len + content_len;
    if 1 + total > data.len() {
        return Err("TLV extends beyond input");
    }
    let content = &data[1 + header_len..1 + total];
    Ok((tag, content))
}

/// Skip a TLV element, returning (tag, remaining bytes after it).
pub fn skip_tlv(data: &[u8]) -> Result<(u8, &[u8]), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let tag = data[0];
    let (content_len, header_len) = decode_length(&data[1..])?;
    let total = 1 + header_len + content_len;
    if total > data.len() {
        return Err("TLV extends beyond input");
    }
    Ok((tag, &data[total..]))
}

/// Extract a complete TLV (tag + length + value bytes) as a slice.
///
/// Returns (tlv_bytes, remaining_bytes).
pub fn extract_tlv(data: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let (content_len, header_len) = decode_length(&data[1..])?;
    let total = 1 + header_len + content_len;
    if total > data.len() {
        return Err("TLV extends beyond input");
    }
    Ok((&data[..total], &data[total..]))
}

/// Decode a DER length field, returning (length_value, number_of_length_bytes).
fn decode_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("missing length byte");
    }
    if data[0] < 128 {
        Ok((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 3 {
            return Err("unsupported length encoding");
        }
        if 1 + num_bytes > data.len() {
            return Err("length bytes truncated");
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_short() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(1), vec![0x01]);
        assert_eq!(encode_length(127), vec![0x7F]);
    }

    #[test]
    fn test_encode_length_medium() {
        assert_eq!(encode_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_length(255), vec![0x81, 0xFF]);
    }

    #[test]
    fn test_encode_length_long() {
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_length(65535), vec![0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode_integer_value(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(encode_integer_value(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(encode_integer_value(127), vec![0x02, 0x01, 0x7F]);
        // 128 has high bit set → needs leading 0x00
        assert_eq!(encode_integer_value(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(encode_integer_value(256), vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_sequence() {
        let inner = vec![0x02, 0x01, 0x01]; // INTEGER 1
        let seq = encode_sequence(&[&inner]);
        assert_eq!(seq, vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_encode_set() {
        let inner = vec![0x02, 0x01, 0x42]; // INTEGER 0x42
        let set = encode_set(&inner);
        assert_eq!(set, vec![0x31, 0x03, 0x02, 0x01, 0x42]);
    }

    #[test]
    fn test_encode_octet_string() {
        let data = vec![0xDE, 0xAD];
        let os = encode_octet_string(&data);
        assert_eq!(os, vec![0x04, 0x02, 0xDE, 0xAD]);
    }

    #[test]
    fn test_implicit_tag() {
        let content = vec![0x01, 0x02, 0x03];
        let tagged = encode_implicit_tag(0, &content);
        assert_eq!(tagged, vec![0xA0, 0x03, 0x01, 0x02, 0x03]);

        let tagged1 = encode_implicit_tag(1, &content);
        assert_eq!(tagged1, vec![0xA1, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_utc_time_format() {
        let t = encode_utc_time_now();
        assert_eq!(t[0], 0x17); // UTCTime tag
        assert_eq!(t[1], 13); // Always 13 bytes for YYMMDDHHmmSSZ
                              // Last byte should be 'Z'
        assert_eq!(t[t.len() - 1], b'Z');
    }

    #[test]
    fn test_parse_tlv_roundtrip() {
        let data = encode_sequence(&[&encode_integer_value(42)]);
        let (tag, content) = parse_tlv(&data).unwrap();
        assert_eq!(tag, 0x30);
        // Content should be the INTEGER
        assert_eq!(content, &[0x02, 0x01, 0x2A]);
    }

    #[test]
    fn test_extract_tlv() {
        let int1 = encode_integer_value(1);
        let int2 = encode_integer_value(2);
        let mut combined = int1.clone();
        combined.extend(&int2);

        let (extracted, remaining) = extract_tlv(&combined).unwrap();
        assert_eq!(extracted, int1.as_slice());
        assert_eq!(remaining, int2.as_slice());
    }

    #[test]
    fn test_skip_tlv() {
        let int1 = encode_integer_value(1);
        let int2 = encode_integer_value(2);
        let mut combined = int1.clone();
        combined.extend(&int2);

        let (tag, remaining) = skip_tlv(&combined).unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(remaining, int2.as_slice());
    }

    #[test]
    fn test_oid_signed_data_correct() {
        // 1.2.840.113549.1.7.2
        assert_eq!(OID_SIGNED_DATA[0], 0x06); // OID tag
        assert_eq!(OID_SIGNED_DATA[1], 0x09); // length 9
    }

    #[test]
    fn test_oid_spc_indirect_data_correct() {
        // 1.3.6.1.4.1.311.2.1.4
        assert_eq!(OID_SPC_INDIRECT_DATA[0], 0x06); // OID tag
        assert_eq!(OID_SPC_INDIRECT_DATA[1], 0x0A); // length 10
    }

    #[test]
    fn test_sha256_algorithm_id() {
        assert_eq!(SHA256_ALGORITHM_ID[0], 0x30); // SEQUENCE
        assert_eq!(SHA256_ALGORITHM_ID[1], 0x0D); // length 13
        assert_eq!(SHA256_ALGORITHM_ID[2], 0x06); // OID tag
    }

    #[test]
    fn test_sha384_algorithm_id() {
        assert_eq!(SHA384_ALGORITHM_ID[0], 0x30);
        assert_eq!(SHA384_ALGORITHM_ID[1], 0x0D); // length 13
                                                  // OID sha384: 2.16.840.1.101.3.4.2.2 — last byte is 0x02
        assert_eq!(SHA384_ALGORITHM_ID[12], 0x02);
    }

    #[test]
    fn test_sha512_algorithm_id() {
        assert_eq!(SHA512_ALGORITHM_ID[0], 0x30);
        assert_eq!(SHA512_ALGORITHM_ID[1], 0x0D); // length 13
                                                  // OID sha512: 2.16.840.1.101.3.4.2.3 — last byte is 0x03
        assert_eq!(SHA512_ALGORITHM_ID[12], 0x03);
    }

    #[test]
    fn test_sha384_with_rsa_algorithm_id() {
        assert_eq!(SHA384_WITH_RSA_ALGORITHM_ID[0], 0x30);
        // OID 1.2.840.113549.1.1.12 — last byte is 0x0C
        assert_eq!(SHA384_WITH_RSA_ALGORITHM_ID[12], 0x0C);
    }

    #[test]
    fn test_sha512_with_rsa_algorithm_id() {
        assert_eq!(SHA512_WITH_RSA_ALGORITHM_ID[0], 0x30);
        // OID 1.2.840.113549.1.1.13 — last byte is 0x0D
        assert_eq!(SHA512_WITH_RSA_ALGORITHM_ID[12], 0x0D);
    }

    #[test]
    fn test_ecdsa_sha384_algorithm_id() {
        assert_eq!(ECDSA_WITH_SHA384_ALGORITHM_ID[0], 0x30);
        assert_eq!(ECDSA_WITH_SHA384_ALGORITHM_ID[1], 0x0A); // length 10
                                                             // OID ecdsa-with-SHA384: last byte 0x03
        assert_eq!(ECDSA_WITH_SHA384_ALGORITHM_ID[11], 0x03);
    }

    #[test]
    fn test_ecdsa_sha512_algorithm_id() {
        assert_eq!(ECDSA_WITH_SHA512_ALGORITHM_ID[0], 0x30);
        assert_eq!(ECDSA_WITH_SHA512_ALGORITHM_ID[1], 0x0A); // length 10
                                                             // OID ecdsa-with-SHA512: last byte 0x04
        assert_eq!(ECDSA_WITH_SHA512_ALGORITHM_ID[11], 0x04);
    }

    #[test]
    fn test_ed25519_algorithm_id() {
        // SEQUENCE { OID 1.3.101.112 } — no parameters per RFC 8410
        assert_eq!(ED25519_ALGORITHM_ID[0], 0x30); // SEQUENCE
        assert_eq!(ED25519_ALGORITHM_ID[1], 0x05); // length 5
        assert_eq!(ED25519_ALGORITHM_ID[2], 0x06); // OID tag
        assert_eq!(ED25519_ALGORITHM_ID[3], 0x03); // OID length 3
                                                   // OID bytes: 2B 65 70 = 1.3.101.112
        assert_eq!(ED25519_ALGORITHM_ID[4], 0x2B);
        assert_eq!(ED25519_ALGORITHM_ID[5], 0x65);
        assert_eq!(ED25519_ALGORITHM_ID[6], 0x70);
    }

    #[test]
    fn test_rsassa_pss_sha256_algorithm_id() {
        // Outer: SEQUENCE { OID id-RSASSA-PSS, RSASSA-PSS-params }
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[0], 0x30); // SEQUENCE
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[1], 0x41); // length 65
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[2], 0x06); // OID tag
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[3], 0x09); // OID length 9
                                                             // Last OID byte: 0x0A = id-RSASSA-PSS (1.2.840.113549.1.1.10)
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[12], 0x0A);
        // RSASSA-PSS-params SEQUENCE follows
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[13], 0x30); // inner SEQUENCE
        assert_eq!(RSASSA_PSS_SHA256_ALGORITHM_ID[14], 0x34); // length 52
                                                              // Salt length should be 32 (0x20) — last meaningful byte
        assert_eq!(
            RSASSA_PSS_SHA256_ALGORITHM_ID[RSASSA_PSS_SHA256_ALGORITHM_ID.len() - 1],
            0x20
        );
    }

    #[test]
    fn test_rsassa_pss_sha384_algorithm_id() {
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[0], 0x30);
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[1], 0x41); // length 65
                                                             // OID: id-RSASSA-PSS
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[12], 0x0A);
        // Inner params SEQUENCE
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[13], 0x30);
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[14], 0x34); // length 52
                                                              // Hash OID last byte at index 29: 0x02 = SHA-384 (2.16.840.1.101.3.4.2.2)
        assert_eq!(RSASSA_PSS_SHA384_ALGORITHM_ID[29], 0x02);
        // Salt length: 48 (0x30)
        assert_eq!(
            RSASSA_PSS_SHA384_ALGORITHM_ID[RSASSA_PSS_SHA384_ALGORITHM_ID.len() - 1],
            0x30
        );
    }

    #[test]
    fn test_rsassa_pss_sha512_algorithm_id() {
        assert_eq!(RSASSA_PSS_SHA512_ALGORITHM_ID[0], 0x30);
        assert_eq!(RSASSA_PSS_SHA512_ALGORITHM_ID[1], 0x41); // length 65
                                                             // OID: id-RSASSA-PSS
        assert_eq!(RSASSA_PSS_SHA512_ALGORITHM_ID[12], 0x0A);
        // Hash OID last byte at index 29: 0x03 = SHA-512 (2.16.840.1.101.3.4.2.3)
        assert_eq!(RSASSA_PSS_SHA512_ALGORITHM_ID[29], 0x03);
        // Salt length: 64 (0x40)
        assert_eq!(
            RSASSA_PSS_SHA512_ALGORITHM_ID[RSASSA_PSS_SHA512_ALGORITHM_ID.len() - 1],
            0x40
        );
    }

    #[test]
    fn test_ml_dsa_44_algorithm_id() {
        assert_eq!(ML_DSA_44_ALGORITHM_ID[0], 0x30); // SEQUENCE
        assert_eq!(ML_DSA_44_ALGORITHM_ID[1], 0x0B); // length 11
        assert_eq!(ML_DSA_44_ALGORITHM_ID[2], 0x06); // OID tag
        assert_eq!(ML_DSA_44_ALGORITHM_ID[3], 0x09); // OID length 9
                                                     // OID 2.16.840.1.101.3.4.3.17 — last byte 0x11
        assert_eq!(ML_DSA_44_ALGORITHM_ID[12], 0x11);
    }

    #[test]
    fn test_ml_dsa_65_algorithm_id() {
        assert_eq!(ML_DSA_65_ALGORITHM_ID[0], 0x30);
        assert_eq!(ML_DSA_65_ALGORITHM_ID[1], 0x0B);
        // OID 2.16.840.1.101.3.4.3.18 — last byte 0x12
        assert_eq!(ML_DSA_65_ALGORITHM_ID[12], 0x12);
    }

    #[test]
    fn test_ml_dsa_87_algorithm_id() {
        assert_eq!(ML_DSA_87_ALGORITHM_ID[0], 0x30);
        assert_eq!(ML_DSA_87_ALGORITHM_ID[1], 0x0B);
        // OID 2.16.840.1.101.3.4.3.19 — last byte 0x13
        assert_eq!(ML_DSA_87_ALGORITHM_ID[12], 0x13);
    }

    #[test]
    fn test_slh_dsa_sha2_128s_algorithm_id() {
        assert_eq!(SLH_DSA_SHA2_128S_ALGORITHM_ID[0], 0x30);
        assert_eq!(SLH_DSA_SHA2_128S_ALGORITHM_ID[1], 0x0B);
        // OID 2.16.840.1.101.3.4.3.20 — last byte 0x14
        assert_eq!(SLH_DSA_SHA2_128S_ALGORITHM_ID[12], 0x14);
    }

    #[test]
    fn test_slh_dsa_sha2_192s_algorithm_id() {
        assert_eq!(SLH_DSA_SHA2_192S_ALGORITHM_ID[0], 0x30);
        assert_eq!(SLH_DSA_SHA2_192S_ALGORITHM_ID[1], 0x0B);
        // OID 2.16.840.1.101.3.4.3.22 — last byte 0x16
        assert_eq!(SLH_DSA_SHA2_192S_ALGORITHM_ID[12], 0x16);
    }

    #[test]
    fn test_slh_dsa_sha2_256s_algorithm_id() {
        assert_eq!(SLH_DSA_SHA2_256S_ALGORITHM_ID[0], 0x30);
        assert_eq!(SLH_DSA_SHA2_256S_ALGORITHM_ID[1], 0x0B);
        // OID 2.16.840.1.101.3.4.3.24 — last byte 0x18
        assert_eq!(SLH_DSA_SHA2_256S_ALGORITHM_ID[12], 0x18);
    }

    #[test]
    fn test_pqc_algorithm_ids_no_parameters() {
        // RFC 9882/9909: PQC AlgorithmIdentifiers MUST NOT include parameters.
        // Total length should be 13 bytes: 2 (SEQUENCE wrapper) + 2 (OID tag+len) + 9 (OID value)
        assert_eq!(ML_DSA_44_ALGORITHM_ID.len(), 13);
        assert_eq!(ML_DSA_65_ALGORITHM_ID.len(), 13);
        assert_eq!(ML_DSA_87_ALGORITHM_ID.len(), 13);
        assert_eq!(SLH_DSA_SHA2_128S_ALGORITHM_ID.len(), 13);
        assert_eq!(SLH_DSA_SHA2_192S_ALGORITHM_ID.len(), 13);
        assert_eq!(SLH_DSA_SHA2_256S_ALGORITHM_ID.len(), 13);
        // Ed25519 also has no parameters but shorter OID (3 bytes vs 9)
        assert_eq!(ED25519_ALGORITHM_ID.len(), 7);
    }

    #[test]
    fn test_encode_set_of_ordering() {
        // Three elements: 0x02 0x01 0x03, 0x02 0x01 0x01, 0x02 0x01 0x02
        let a = &[0x02u8, 0x01, 0x03] as &[u8]; // INTEGER 3
        let b = &[0x02u8, 0x01, 0x01] as &[u8]; // INTEGER 1
        let c = &[0x02u8, 0x01, 0x02] as &[u8]; // INTEGER 2
        let set = encode_set_of(&[a, b, c]);
        // Should be sorted: INT 1, INT 2, INT 3
        assert_eq!(
            set,
            vec![
                0x31, 0x09, // SET, length 9
                0x02, 0x01, 0x01, // INTEGER 1
                0x02, 0x01, 0x02, // INTEGER 2
                0x02, 0x01, 0x03, // INTEGER 3
            ]
        );
    }

    #[test]
    fn test_encode_set_of_different_tags() {
        // OCTET STRING sorts before SEQUENCE because 0x04 < 0x30
        let oct = encode_octet_string(&[0x01]);
        let seq = encode_sequence(&[&[0x02, 0x01, 0x00]]);
        let set = encode_set_of(&[&seq, &oct]);
        // OCTET STRING (0x04...) should come before SEQUENCE (0x30...)
        assert_eq!(set[2], 0x04); // OCTET STRING tag first
    }

    #[test]
    fn test_encode_set_of_single_element() {
        let elem = &[0x02u8, 0x01, 0x05] as &[u8];
        let set = encode_set_of(&[elem]);
        assert_eq!(set, vec![0x31, 0x03, 0x02, 0x01, 0x05]);
    }

    #[test]
    fn test_encode_utc_time_specific() {
        use chrono::TimeZone;
        let time = Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).unwrap();
        let encoded = encode_utc_time(time);
        assert_eq!(encoded[0], 0x17); // UTCTime tag
        assert_eq!(encoded[1], 13);
        let time_str = std::str::from_utf8(&encoded[2..]).unwrap();
        assert_eq!(time_str, "260115103000Z");
    }

    #[test]
    fn test_encode_utc_time_year_2049_uses_utctime() {
        use chrono::TimeZone;
        let time = Utc.with_ymd_and_hms(2049, 12, 31, 23, 59, 59).unwrap();
        let encoded = encode_utc_time(time);
        assert_eq!(encoded[0], 0x17, "Year 2049 must use UTCTime (tag 0x17)");
        let time_str = std::str::from_utf8(&encoded[2..]).unwrap();
        assert_eq!(time_str, "491231235959Z");
    }

    #[test]
    fn test_encode_utc_time_year_2050_uses_generalized_time() {
        use chrono::TimeZone;
        // RFC 5280 §4.1.2.5: years >= 2050 must use GeneralizedTime
        let time = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
        let encoded = encode_utc_time(time);
        assert_eq!(
            encoded[0], 0x18,
            "Year 2050 must use GeneralizedTime (tag 0x18)"
        );
        let time_str = std::str::from_utf8(&encoded[2..]).unwrap();
        assert_eq!(time_str, "20500101000000Z");
    }

    #[test]
    fn test_encode_utc_time_year_2099_uses_generalized_time() {
        use chrono::TimeZone;
        let time = Utc.with_ymd_and_hms(2099, 6, 15, 12, 30, 45).unwrap();
        let encoded = encode_utc_time(time);
        assert_eq!(
            encoded[0], 0x18,
            "Year 2099 must use GeneralizedTime (tag 0x18)"
        );
        let time_str = std::str::from_utf8(&encoded[2..]).unwrap();
        assert_eq!(time_str, "20990615123045Z");
    }

    // ─── RFC 5652 §10.1 — DER definite-length validation ───

    #[test]
    fn test_der_definite_length_valid_short() {
        // Short form: tag + length < 128
        let data = [0x30, 0x03, 0x02, 0x01, 0x01]; // SEQUENCE { INTEGER 1 }
        assert!(validate_der_definite_length(&data).is_ok());
    }

    #[test]
    fn test_der_definite_length_valid_long() {
        // Long form: 0x81 0x80 = 128 bytes (valid)
        let data = [0x30, 0x81, 0x80];
        assert!(validate_der_definite_length(&data).is_ok());
    }

    #[test]
    fn test_der_definite_length_indefinite_rejected() {
        // Indefinite form: 0x80 is forbidden in DER
        let data = [0x30, 0x80, 0x00, 0x00]; // SEQUENCE with indefinite length
        let result = validate_der_definite_length(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("indefinite"));
    }

    #[test]
    fn test_der_definite_length_non_canonical_rejected() {
        // Non-canonical: using 0x81 0x7F for length 127 (should use short form 0x7F)
        let data = [0x30, 0x81, 0x7F];
        let result = validate_der_definite_length(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-canonical"));
    }

    #[test]
    fn test_der_definite_length_leading_zero_rejected() {
        // Non-canonical: leading zero in multi-byte length
        let data = [0x30, 0x82, 0x00, 0x80]; // 0x82 0x00 0x80 = 128, but 0x81 0x80 is shorter
        let result = validate_der_definite_length(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("leading zero"));
    }
}
