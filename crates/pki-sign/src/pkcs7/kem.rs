//! RFC 9629 — Using Key Encapsulation Mechanism (KEM) Algorithms with CMS EnvelopedData.
//!
//! Implements KEM-based key management for CMS, enabling post-quantum key transport
//! via the `OtherRecipientInfo` (ori) CHOICE in RecipientInfo (tag [3]).
//!
//! ## Flow (RFC 9629 §2)
//!
//! 1. Sender calls `KEM.Encapsulate(recipient_pubkey)` → `(shared_secret, kem_ct)`
//! 2. Build `CMSORIforKEMOtherInfo` context structure (wrap_alg, kek_len, optional ukm)
//! 3. Derive KEK via HKDF: `HKDF(ss, kek_len, CMSORIforKEMOtherInfo)` using chosen KDF
//! 4. Wrap CEK with KEK via AES Key Wrap (RFC 3394)
//! 5. Encode as `KEMRecipientInfo` inside `OtherRecipientInfo` (tag [3])
//!
//! ## ASN.1 Structures
//!
//! ```text
//! KEMRecipientInfo ::= SEQUENCE {
//!   version CMSVersion,              -- always 0
//!   rid RecipientIdentifier,
//!   kem KEMAlgorithmIdentifier,
//!   kemct OCTET STRING,
//!   kdf KeyDerivationAlgorithmIdentifier,
//!   kekLength INTEGER,
//!   wrap KeyEncryptionAlgorithmIdentifier,
//!   encryptedKey EncryptedKey
//! }
//!
//! CMSORIforKEMOtherInfo ::= SEQUENCE {
//!   wrap KeyEncryptionAlgorithmIdentifier,
//!   kekLength INTEGER (1..MAX),
//!   ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL
//! }
//! ```
//!
//! ## Key OIDs
//!
//! - `1.2.840.113549.1.9.16.13.3` — id-ori-kem
//! - `1.2.840.113549.1.9.16.3.28` — id-alg-hkdf-with-sha256
//! - `1.2.840.113549.1.9.16.3.29` — id-alg-hkdf-with-sha384
//! - `1.2.840.113549.1.9.16.3.30` — id-alg-hkdf-with-sha512

use zeroize::Zeroizing;

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;
use crate::pkcs7::ecdh::{aes_key_unwrap, aes_key_wrap, KeyWrapAlgorithm};

// ─── KDF Algorithm Selection ───

/// KDF algorithm for KEK derivation in KEM recipient (RFC 8619).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemKdf {
    /// HKDF with SHA-256 (id-alg-hkdf-with-sha256)
    HkdfSha256,
    /// HKDF with SHA-384 (id-alg-hkdf-with-sha384)
    HkdfSha384,
    /// HKDF with SHA-512 (id-alg-hkdf-with-sha512)
    HkdfSha512,
}

impl KemKdf {
    /// Return the DER-encoded AlgorithmIdentifier for this KDF.
    fn algorithm_id(&self) -> Vec<u8> {
        let oid = match self {
            KemKdf::HkdfSha256 => asn1::OID_HKDF_SHA256,
            KemKdf::HkdfSha384 => asn1::OID_HKDF_SHA384,
            KemKdf::HkdfSha512 => asn1::OID_HKDF_SHA512,
        };
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ABSENT }
        // HKDF OIDs have no parameters (RFC 8619 §3)
        asn1::encode_sequence(&[oid])
    }

    /// Map to the standalone HkdfHash enum.
    fn to_hkdf_hash(self) -> crate::crypto::hkdf::HkdfHash {
        match self {
            KemKdf::HkdfSha256 => crate::crypto::hkdf::HkdfHash::Sha256,
            KemKdf::HkdfSha384 => crate::crypto::hkdf::HkdfHash::Sha384,
            KemKdf::HkdfSha512 => crate::crypto::hkdf::HkdfHash::Sha512,
        }
    }

    /// Try to parse from a DER-encoded AlgorithmIdentifier.
    fn from_algorithm_id(der: &[u8]) -> SignResult<Self> {
        // Parse SEQUENCE { OID ... }
        let (tag, content) = asn1::parse_tlv(der)
            .map_err(|e| SignError::Pkcs7(format!("Parse KDF AlgID: {}", e)))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "Expected SEQUENCE for KDF AlgID, got 0x{:02X}",
                tag
            )));
        }
        // Extract OID bytes (tag + length + value)
        let (oid_tlv, _) = asn1::extract_tlv(content)
            .map_err(|e| SignError::Pkcs7(format!("Extract KDF OID: {}", e)))?;

        if oid_tlv == asn1::OID_HKDF_SHA256 {
            Ok(KemKdf::HkdfSha256)
        } else if oid_tlv == asn1::OID_HKDF_SHA384 {
            Ok(KemKdf::HkdfSha384)
        } else if oid_tlv == asn1::OID_HKDF_SHA512 {
            Ok(KemKdf::HkdfSha512)
        } else {
            Err(SignError::Pkcs7(format!(
                "Unknown KDF OID in KEMRecipientInfo (len={})",
                oid_tlv.len()
            )))
        }
    }
}

// ─── KEM Algorithm Trait ───

/// Trait for Key Encapsulation Mechanism algorithms.
///
/// This is a generic interface allowing plug-in of any KEM (X25519, ML-KEM, etc.)
/// for RFC 9629 support. The trait handles encapsulation (sender) and
/// decapsulation (recipient).
pub trait KemAlgorithm {
    /// DER-encoded AlgorithmIdentifier for this KEM (e.g., id-X25519, id-ML-KEM-768).
    fn algorithm_id(&self) -> Vec<u8>;

    /// Encapsulate: generate shared secret + ciphertext from recipient's public key.
    ///
    /// Returns `(shared_secret, kem_ciphertext)`.
    fn encapsulate(&self, recipient_public_key: &[u8])
        -> SignResult<(Zeroizing<Vec<u8>>, Vec<u8>)>;

    /// Decapsulate: recover shared secret from ciphertext using private key.
    fn decapsulate(&self, private_key: &[u8], kem_ct: &[u8]) -> SignResult<Zeroizing<Vec<u8>>>;
}

// ─── KEM Recipient Info ───

/// Configuration for a KEM-based recipient in EnvelopedData (RFC 9629).
pub struct KemRecipientInfo<K: KemAlgorithm> {
    /// DER-encoded certificate of the recipient.
    pub recipient_cert_der: Vec<u8>,
    /// The KEM algorithm implementation.
    pub kem: K,
    /// KDF to derive the KEK from shared secret.
    pub kdf: KemKdf,
    /// AES Key Wrap algorithm for wrapping the CEK.
    pub wrap: KeyWrapAlgorithm,
    /// Optional User Keying Material (ukm).
    pub ukm: Option<Vec<u8>>,
}

// ─── CMSORIforKEMOtherInfo (RFC 9629 §3) ───

/// Encode `CMSORIforKEMOtherInfo` — the context info fed to the KDF.
///
/// ```text
/// CMSORIforKEMOtherInfo ::= SEQUENCE {
///   wrap KeyEncryptionAlgorithmIdentifier,
///   kekLength INTEGER (1..MAX),
///   ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL
/// }
/// ```
fn encode_kem_other_info(
    wrap_alg: KeyWrapAlgorithm,
    kek_length: usize,
    ukm: Option<&[u8]>,
) -> Vec<u8> {
    let wrap_alg_id = wrap_algorithm_id(wrap_alg);
    let kek_len_int = asn1::encode_integer_value(kek_length as u32);

    if let Some(ukm_bytes) = ukm {
        let ukm_os = asn1::encode_octet_string(ukm_bytes);
        let ukm_explicit = asn1::encode_explicit_tag(0, &ukm_os);
        asn1::encode_sequence(&[&wrap_alg_id, &kek_len_int, &ukm_explicit])
    } else {
        asn1::encode_sequence(&[&wrap_alg_id, &kek_len_int])
    }
}

/// Build the DER-encoded AlgorithmIdentifier for AES Key Wrap.
fn wrap_algorithm_id(alg: KeyWrapAlgorithm) -> Vec<u8> {
    let oid = match alg {
        KeyWrapAlgorithm::Aes128 => asn1::OID_AES128_WRAP,
        KeyWrapAlgorithm::Aes256 => asn1::OID_AES256_WRAP,
    };
    // AlgorithmIdentifier ::= SEQUENCE { OID, parameters ABSENT }
    asn1::encode_sequence(&[oid])
}

// ─── KEK Derivation ───

/// Derive the Key Encryption Key (KEK) from KEM shared secret via HKDF (RFC 9629 §3).
///
/// - `ikm`: the KEM shared secret
/// - `kdf`: which HKDF variant to use
/// - `wrap_alg`: the wrap algorithm (determines KEK length)
/// - `ukm`: optional User Keying Material
fn derive_kek(
    ikm: &[u8],
    kdf: KemKdf,
    wrap_alg: KeyWrapAlgorithm,
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    let kek_len = match wrap_alg {
        KeyWrapAlgorithm::Aes128 => 16,
        KeyWrapAlgorithm::Aes256 => 32,
    };

    // info = DER-encoded CMSORIforKEMOtherInfo
    let info = encode_kem_other_info(wrap_alg, kek_len, ukm);

    // HKDF Extract-then-Expand with empty salt (RFC 9629 §3: salt is absent)
    let kek = crate::crypto::hkdf::hkdf_derive(kdf.to_hkdf_hash(), &[], ikm, &info, kek_len)?;

    Ok(Zeroizing::new(kek))
}

// ─── Build KEMRecipientInfo ───

/// Build a DER-encoded `OtherRecipientInfo` [3] for a KEM recipient.
///
/// This is the complete `RecipientInfo` CHOICE value with implicit tag [3],
/// ready to be placed in the `RecipientInfos` SET.
pub fn build_kem_recipient_info<K: KemAlgorithm>(
    recipient: &KemRecipientInfo<K>,
    cek: &[u8],
) -> SignResult<Vec<u8>> {
    // Extract issuer + serial from recipient cert for RecipientIdentifier
    let (issuer_der, serial_der) =
        crate::pkcs7::enveloped::extract_issuer_serial(&recipient.recipient_cert_der)?;

    // Step 1: KEM Encapsulate
    // Extract public key from recipient cert
    let pub_key = crate::pkcs7::enveloped::extract_spki_from_cert(&recipient.recipient_cert_der)?;
    let (shared_secret, kem_ct) = recipient.kem.encapsulate(&pub_key)?;

    // Step 2: Derive KEK via HKDF
    let kek = derive_kek(
        &shared_secret,
        recipient.kdf,
        recipient.wrap,
        recipient.ukm.as_deref(),
    )?;

    // Step 3: Wrap CEK with KEK
    let wrapped_cek = aes_key_wrap(recipient.wrap, &kek, cek)?;

    // Step 4: Encode KEMRecipientInfo SEQUENCE
    let version = asn1::encode_integer_value(0); // always 0 per RFC 9629

    // RecipientIdentifier — IssuerAndSerialNumber
    let rid = asn1::encode_sequence(&[&issuer_der, &serial_der]);

    // kem AlgorithmIdentifier
    let kem_alg_id = recipient.kem.algorithm_id();

    // kemct OCTET STRING
    let kemct = asn1::encode_octet_string(&kem_ct);

    // kdf AlgorithmIdentifier
    let kdf_alg_id = recipient.kdf.algorithm_id();

    // kekLength INTEGER
    let kek_length = match recipient.wrap {
        KeyWrapAlgorithm::Aes128 => 16u32,
        KeyWrapAlgorithm::Aes256 => 32u32,
    };
    let kek_len_int = asn1::encode_integer_value(kek_length);

    // wrap AlgorithmIdentifier
    let wrap_alg_id = wrap_algorithm_id(recipient.wrap);

    // encryptedKey OCTET STRING
    let enc_key = asn1::encode_octet_string(&wrapped_cek);

    // KEMRecipientInfo SEQUENCE
    let kem_ri = asn1::encode_sequence(&[
        &version,
        &rid,
        &kem_alg_id,
        &kemct,
        &kdf_alg_id,
        &kek_len_int,
        &wrap_alg_id,
        &enc_key,
    ]);

    // OtherRecipientInfo ::= SEQUENCE {
    //   oriType OBJECT IDENTIFIER,
    //   oriValue ANY DEFINED BY oriType
    // }
    // Wrapped in ORI SEQUENCE, then tagged [3] IMPLICIT
    let ori_seq = asn1::encode_sequence(&[asn1::OID_ORI_KEM, &kem_ri]);

    // [3] IMPLICIT — RecipientInfo CHOICE tag for OtherRecipientInfo
    let tagged = asn1::encode_implicit_tag(3, &ori_seq);

    Ok(tagged)
}

// ─── Parse KEMRecipientInfo ───

/// Parsed KEM recipient info fields from a DER-encoded OtherRecipientInfo.
#[derive(Debug)]
pub struct ParsedKemRecipientInfo {
    /// DER-encoded issuer name.
    pub issuer_der: Vec<u8>,
    /// DER-encoded serial number.
    pub serial_der: Vec<u8>,
    /// DER-encoded KEM AlgorithmIdentifier.
    pub kem_alg_id: Vec<u8>,
    /// KEM ciphertext.
    pub kem_ct: Vec<u8>,
    /// KDF used for KEK derivation.
    pub kdf: KemKdf,
    /// KEK length in bytes.
    pub kek_length: usize,
    /// Key wrap algorithm.
    pub wrap: KeyWrapAlgorithm,
    /// Wrapped (encrypted) CEK.
    pub encrypted_key: Vec<u8>,
}

/// Parse OtherRecipientInfo [3] content into KEM recipient info.
///
/// Input is the inner content after the [3] implicit tag has been stripped.
pub fn parse_kem_recipient_info(content: &[u8]) -> SignResult<ParsedKemRecipientInfo> {
    // OtherRecipientInfo SEQUENCE { oriType OID, oriValue KEMRecipientInfo }
    let (tag, ori_content) =
        asn1::parse_tlv(content).map_err(|e| SignError::Pkcs7(format!("Parse ORI: {}", e)))?;
    if tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "Expected SEQUENCE for ORI, got 0x{:02X}",
            tag
        )));
    }

    // oriType OID — must be id-ori-kem
    let (oid_tlv, after_oid) = asn1::extract_tlv(ori_content)
        .map_err(|e| SignError::Pkcs7(format!("Extract ORI OID: {}", e)))?;
    if oid_tlv != asn1::OID_ORI_KEM {
        return Err(SignError::Pkcs7(
            "OtherRecipientInfo OID is not id-ori-kem".to_string(),
        ));
    }

    // oriValue — KEMRecipientInfo SEQUENCE
    let (tag, kri_content) = asn1::parse_tlv(after_oid)
        .map_err(|e| SignError::Pkcs7(format!("Parse KEMRecipientInfo: {}", e)))?;
    if tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "Expected SEQUENCE for KEMRecipientInfo, got 0x{:02X}",
            tag
        )));
    }

    // version INTEGER (must be 0)
    let (_, after_ver) = asn1::skip_tlv(kri_content)
        .map_err(|e| SignError::Pkcs7(format!("KEM RI skip version: {}", e)))?;

    // rid — IssuerAndSerialNumber SEQUENCE
    let (_, rid_content) = asn1::parse_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("Parse KEM RID: {}", e)))?;
    let (issuer_tlv, after_issuer) = asn1::extract_tlv(rid_content)
        .map_err(|e| SignError::Pkcs7(format!("Extract KEM issuer: {}", e)))?;
    let (serial_tlv, _) = asn1::extract_tlv(after_issuer)
        .map_err(|e| SignError::Pkcs7(format!("Extract KEM serial: {}", e)))?;

    let (_, after_rid) =
        asn1::skip_tlv(after_ver).map_err(|e| SignError::Pkcs7(format!("Skip KEM RID: {}", e)))?;

    // kem AlgorithmIdentifier (full TLV)
    let (kem_alg_tlv, after_kem_alg) = asn1::extract_tlv(after_rid)
        .map_err(|e| SignError::Pkcs7(format!("Extract KEM alg: {}", e)))?;

    // kemct OCTET STRING
    let (ct_tag, ct_value) = asn1::parse_tlv(after_kem_alg)
        .map_err(|e| SignError::Pkcs7(format!("Parse kemct: {}", e)))?;
    if ct_tag != 0x04 {
        return Err(SignError::Pkcs7(format!(
            "Expected OCTET STRING for kemct, got 0x{:02X}",
            ct_tag
        )));
    }
    let (_, after_ct) = asn1::skip_tlv(after_kem_alg)
        .map_err(|e| SignError::Pkcs7(format!("Skip kemct: {}", e)))?;

    // kdf AlgorithmIdentifier
    let (kdf_alg_tlv, after_kdf) = asn1::extract_tlv(after_ct)
        .map_err(|e| SignError::Pkcs7(format!("Extract KDF alg: {}", e)))?;
    let kdf = KemKdf::from_algorithm_id(kdf_alg_tlv)?;

    // kekLength INTEGER
    let (kek_tag, kek_val) = asn1::parse_tlv(after_kdf)
        .map_err(|e| SignError::Pkcs7(format!("Parse kekLength: {}", e)))?;
    if kek_tag != 0x02 {
        return Err(SignError::Pkcs7(format!(
            "Expected INTEGER for kekLength, got 0x{:02X}",
            kek_tag
        )));
    }
    let kek_length = parse_integer_value(kek_val)?;
    let (_, after_kek_len) = asn1::skip_tlv(after_kdf)
        .map_err(|e| SignError::Pkcs7(format!("Skip kekLength: {}", e)))?;

    // wrap AlgorithmIdentifier
    let (wrap_alg_tlv, after_wrap) = asn1::extract_tlv(after_kek_len)
        .map_err(|e| SignError::Pkcs7(format!("Extract wrap alg: {}", e)))?;
    let wrap = parse_wrap_algorithm(wrap_alg_tlv)?;

    // Validate kekLength matches wrap algorithm
    let expected_kek_len = match wrap {
        KeyWrapAlgorithm::Aes128 => 16,
        KeyWrapAlgorithm::Aes256 => 32,
    };
    if kek_length != expected_kek_len {
        return Err(SignError::Pkcs7(format!(
            "kekLength {} does not match wrap algorithm (expected {})",
            kek_length, expected_kek_len
        )));
    }

    // encryptedKey OCTET STRING
    let (ek_tag, ek_value) = asn1::parse_tlv(after_wrap)
        .map_err(|e| SignError::Pkcs7(format!("Parse encryptedKey: {}", e)))?;
    if ek_tag != 0x04 {
        return Err(SignError::Pkcs7(format!(
            "Expected OCTET STRING for encryptedKey, got 0x{:02X}",
            ek_tag
        )));
    }

    Ok(ParsedKemRecipientInfo {
        issuer_der: issuer_tlv.to_vec(),
        serial_der: serial_tlv.to_vec(),
        kem_alg_id: kem_alg_tlv.to_vec(),
        kem_ct: ct_value.to_vec(),
        kdf,
        kek_length,
        wrap,
        encrypted_key: ek_value.to_vec(),
    })
}

// ─── Decrypt KEM Recipient ───

/// Decrypt the CEK from a parsed KEMRecipientInfo using the recipient's private key.
///
/// - `parsed`: the parsed KEM recipient info fields
/// - `kem`: the KEM algorithm implementation (must match the one used during encryption)
/// - `private_key_der`: the recipient's private key in DER format
/// - `ukm`: optional User Keying Material (must match what sender used)
pub fn decrypt_kem_cek<K: KemAlgorithm>(
    parsed: &ParsedKemRecipientInfo,
    kem: &K,
    private_key_der: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    // Step 1: KEM Decapsulate
    let shared_secret = kem.decapsulate(private_key_der, &parsed.kem_ct)?;

    // Step 2: Derive KEK
    let kek = derive_kek(&shared_secret, parsed.kdf, parsed.wrap, ukm)?;

    // Step 3: Unwrap CEK
    aes_key_unwrap(parsed.wrap, &kek, &parsed.encrypted_key)
}

// ─── Helpers ───

/// Parse a DER INTEGER value into usize.
fn parse_integer_value(bytes: &[u8]) -> SignResult<usize> {
    if bytes.is_empty() {
        return Err(SignError::Pkcs7("Empty INTEGER value".to_string()));
    }
    let mut val: usize = 0;
    for &b in bytes {
        val = val
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or_else(|| SignError::Pkcs7("INTEGER overflow".to_string()))?;
    }
    Ok(val)
}

/// Parse a wrap AlgorithmIdentifier to determine the KeyWrapAlgorithm.
fn parse_wrap_algorithm(der: &[u8]) -> SignResult<KeyWrapAlgorithm> {
    let (tag, content) =
        asn1::parse_tlv(der).map_err(|e| SignError::Pkcs7(format!("Parse wrap AlgID: {}", e)))?;
    if tag != 0x30 {
        return Err(SignError::Pkcs7(format!(
            "Expected SEQUENCE for wrap AlgID, got 0x{:02X}",
            tag
        )));
    }
    let (oid_tlv, _) = asn1::extract_tlv(content)
        .map_err(|e| SignError::Pkcs7(format!("Extract wrap OID: {}", e)))?;

    if oid_tlv == asn1::OID_AES128_WRAP {
        Ok(KeyWrapAlgorithm::Aes128)
    } else if oid_tlv == asn1::OID_AES256_WRAP {
        Ok(KeyWrapAlgorithm::Aes256)
    } else {
        Err(SignError::Pkcs7(
            "Unknown wrap algorithm OID in KEMRecipientInfo".to_string(),
        ))
    }
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock KEM for testing: uses a simple XOR-based "encapsulation" (NOT cryptographic).
    /// The shared secret is derived deterministically from the public key.
    struct MockKem;

    impl KemAlgorithm for MockKem {
        fn algorithm_id(&self) -> Vec<u8> {
            // Fake OID for testing: 1.2.3.4.5
            asn1::encode_sequence(&[&[0x06, 0x04, 0x2A, 0x03, 0x04, 0x05][..]])
        }

        fn encapsulate(
            &self,
            recipient_public_key: &[u8],
        ) -> SignResult<(Zeroizing<Vec<u8>>, Vec<u8>)> {
            // Mock: shared secret = SHA-256(pubkey), ciphertext = pubkey bytes
            use sha2::{Digest, Sha256};
            let ss = Sha256::digest(recipient_public_key);
            Ok((Zeroizing::new(ss.to_vec()), recipient_public_key.to_vec()))
        }

        fn decapsulate(
            &self,
            _private_key: &[u8],
            kem_ct: &[u8],
        ) -> SignResult<Zeroizing<Vec<u8>>> {
            // Mock: ciphertext IS the pubkey, so derive same shared secret
            use sha2::{Digest, Sha256};
            let ss = Sha256::digest(kem_ct);
            Ok(Zeroizing::new(ss.to_vec()))
        }
    }

    #[test]
    fn test_cms_ori_for_kem_other_info_encoding() {
        // Test basic encoding without UKM
        let info = encode_kem_other_info(KeyWrapAlgorithm::Aes256, 32, None);
        // Should be a valid SEQUENCE
        assert_eq!(info[0], 0x30);
        // Verify it parses back
        let (tag, _) = asn1::parse_tlv(&info).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_cms_ori_for_kem_other_info_with_ukm() {
        let ukm = b"test-ukm-value";
        let info = encode_kem_other_info(KeyWrapAlgorithm::Aes128, 16, Some(ukm));
        assert_eq!(info[0], 0x30);
        // With UKM the encoding should be longer
        let info_no_ukm = encode_kem_other_info(KeyWrapAlgorithm::Aes128, 16, None);
        assert!(info.len() > info_no_ukm.len());
    }

    #[test]
    fn test_kek_derivation_aes128() {
        let shared_secret = b"0123456789abcdef0123456789abcdef";
        let kek = derive_kek(
            shared_secret,
            KemKdf::HkdfSha256,
            KeyWrapAlgorithm::Aes128,
            None,
        )
        .unwrap();
        assert_eq!(kek.len(), 16);
    }

    #[test]
    fn test_kek_derivation_aes256() {
        let shared_secret = b"0123456789abcdef0123456789abcdef";
        let kek = derive_kek(
            shared_secret,
            KemKdf::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        assert_eq!(kek.len(), 32);
    }

    #[test]
    fn test_kek_derivation_with_ukm_differs() {
        let shared_secret = b"0123456789abcdef0123456789abcdef";
        let kek1 = derive_kek(
            shared_secret,
            KemKdf::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        let kek2 = derive_kek(
            shared_secret,
            KemKdf::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            Some(b"unique-ukm"),
        )
        .unwrap();
        // KEK should differ when UKM is added
        assert_ne!(*kek1, *kek2);
    }

    #[test]
    fn test_kek_derivation_different_kdf_differs() {
        let shared_secret = b"0123456789abcdef0123456789abcdef";
        let kek256 = derive_kek(
            shared_secret,
            KemKdf::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        let kek384 = derive_kek(
            shared_secret,
            KemKdf::HkdfSha384,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        assert_ne!(*kek256, *kek384);
    }

    #[test]
    fn test_kdf_algorithm_id_roundtrip() {
        for kdf in [KemKdf::HkdfSha256, KemKdf::HkdfSha384, KemKdf::HkdfSha512] {
            let alg_id = kdf.algorithm_id();
            let parsed = KemKdf::from_algorithm_id(&alg_id).unwrap();
            assert_eq!(parsed, kdf);
        }
    }

    #[test]
    fn test_wrap_algorithm_id_roundtrip() {
        for wrap in [KeyWrapAlgorithm::Aes128, KeyWrapAlgorithm::Aes256] {
            let alg_id = wrap_algorithm_id(wrap);
            let parsed = parse_wrap_algorithm(&alg_id).unwrap();
            assert_eq!(parsed, wrap);
        }
    }

    #[test]
    fn test_parse_integer_value() {
        assert_eq!(parse_integer_value(&[0x10]).unwrap(), 16);
        assert_eq!(parse_integer_value(&[0x00, 0x20]).unwrap(), 32);
        assert_eq!(parse_integer_value(&[0x01, 0x00]).unwrap(), 256);
        assert!(parse_integer_value(&[]).is_err());
    }

    #[test]
    fn test_build_and_parse_kem_recipient_info() {
        // Build a self-signed test cert for recipient identification
        let test_cert = build_test_cert();
        let _test_pub_key = vec![0x04; 65]; // fake EC point

        let recipient = KemRecipientInfo {
            recipient_cert_der: test_cert.clone(),
            kem: MockKem,
            kdf: KemKdf::HkdfSha256,
            wrap: KeyWrapAlgorithm::Aes256,
            ukm: None,
        };

        // Fake CEK (32 bytes for AES-256)
        let cek = vec![0x42u8; 32];

        let ori_der = build_kem_recipient_info(&recipient, &cek).unwrap();

        // Verify tag is [3] IMPLICIT
        assert_eq!(ori_der[0], 0xA3);

        // Parse the inner content (skip the [3] tag)
        let (_, inner) = asn1::parse_tlv(&ori_der).unwrap();
        let parsed = parse_kem_recipient_info(inner).unwrap();

        assert_eq!(parsed.kdf, KemKdf::HkdfSha256);
        assert_eq!(parsed.wrap, KeyWrapAlgorithm::Aes256);
        assert_eq!(parsed.kek_length, 32);
        // kemct should be the pubkey (MockKem behavior)
        assert!(!parsed.kem_ct.is_empty());
        assert!(!parsed.encrypted_key.is_empty());
    }

    #[test]
    fn test_kem_encrypt_decrypt_roundtrip() {
        let test_cert = build_test_cert();
        let fake_private_key = vec![0x01; 32];

        let recipient = KemRecipientInfo {
            recipient_cert_der: test_cert.clone(),
            kem: MockKem,
            kdf: KemKdf::HkdfSha256,
            wrap: KeyWrapAlgorithm::Aes256,
            ukm: None,
        };

        // Random CEK
        let cek = vec![0xAB; 32];

        let ori_der = build_kem_recipient_info(&recipient, &cek).unwrap();

        // Parse
        let (_, inner) = asn1::parse_tlv(&ori_der).unwrap();
        let parsed = parse_kem_recipient_info(inner).unwrap();

        // Decrypt
        let recovered_cek = decrypt_kem_cek(&parsed, &MockKem, &fake_private_key, None).unwrap();
        assert_eq!(&*recovered_cek, &cek);
    }

    #[test]
    fn test_kem_with_ukm_roundtrip() {
        let test_cert = build_test_cert();
        let fake_private_key = vec![0x01; 32];
        let ukm = b"session-specific-context".to_vec();

        let recipient = KemRecipientInfo {
            recipient_cert_der: test_cert.clone(),
            kem: MockKem,
            kdf: KemKdf::HkdfSha384,
            wrap: KeyWrapAlgorithm::Aes128,
            ukm: Some(ukm.clone()),
        };

        let cek = vec![0xCD; 16]; // 16 bytes for AES-128

        let ori_der = build_kem_recipient_info(&recipient, &cek).unwrap();
        let (_, inner) = asn1::parse_tlv(&ori_der).unwrap();
        let parsed = parse_kem_recipient_info(inner).unwrap();

        assert_eq!(parsed.kdf, KemKdf::HkdfSha384);
        assert_eq!(parsed.wrap, KeyWrapAlgorithm::Aes128);
        assert_eq!(parsed.kek_length, 16);

        let recovered_cek =
            decrypt_kem_cek(&parsed, &MockKem, &fake_private_key, Some(&ukm)).unwrap();
        assert_eq!(&*recovered_cek, &cek);
    }

    #[test]
    fn test_kem_wrong_ukm_fails() {
        let test_cert = build_test_cert();
        let fake_private_key = vec![0x01; 32];

        let recipient = KemRecipientInfo {
            recipient_cert_der: test_cert.clone(),
            kem: MockKem,
            kdf: KemKdf::HkdfSha256,
            wrap: KeyWrapAlgorithm::Aes256,
            ukm: Some(b"correct-ukm".to_vec()),
        };

        let cek = vec![0xEF; 32];
        let ori_der = build_kem_recipient_info(&recipient, &cek).unwrap();
        let (_, inner) = asn1::parse_tlv(&ori_der).unwrap();
        let parsed = parse_kem_recipient_info(inner).unwrap();

        // Decrypt with wrong UKM should fail (AES Key Unwrap integrity check)
        let result = decrypt_kem_cek(&parsed, &MockKem, &fake_private_key, Some(b"wrong-ukm"));
        assert!(result.is_err());
    }

    /// Build a minimal DER-encoded X.509 certificate for testing.
    ///
    /// This creates the bare minimum structure that `extract_issuer_serial` and
    /// `extract_spki_from_cert` can parse: TBSCertificate with version,
    /// serial, signature alg, issuer, validity, subject, and SPKI.
    fn build_test_cert() -> Vec<u8> {
        // Version [0] EXPLICIT INTEGER 2 (v3)
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        // Serial number
        let serial = asn1::encode_integer_value(12345);
        // Signature algorithm (SHA-256 with ECDSA — placeholder)
        let sig_alg = asn1::encode_sequence(&[&[
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
        ][..]]);
        // Issuer: SEQUENCE { SET { SEQUENCE { OID CN, UTF8String "Test" } } }
        let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // id-at-commonName
        let cn_val: &[u8] = &[0x0C, 0x04, 0x54, 0x65, 0x73, 0x74]; // UTF8String "Test"
        let cn_attr = asn1::encode_sequence(&[cn_oid, cn_val]);
        let cn_set = asn1::encode_set(&cn_attr);
        let issuer = asn1::encode_sequence(&[&cn_set]);
        // Validity: SEQUENCE { UTCTime, UTCTime }
        let not_before: &[u8] = &[
            0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x5A,
        ];
        let not_after: &[u8] = &[
            0x17, 0x0D, 0x33, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x5A,
        ];
        let validity = asn1::encode_sequence(&[not_before, not_after]);
        // Subject = same as issuer
        let subject = issuer.clone();
        // SubjectPublicKeyInfo: fake EC P-256 public key (65-byte uncompressed point)
        let ec_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // id-ecPublicKey
        let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // prime256v1
        let spki_alg = asn1::encode_sequence(&[ec_oid, p256_oid]);
        // BIT STRING wrapping 65-byte uncompressed point (0x04 prefix)
        let mut fake_point = vec![0x04u8]; // uncompressed
        fake_point.extend_from_slice(&[0xAA; 32]); // x
        fake_point.extend_from_slice(&[0xBB; 32]); // y
        let mut bit_string = vec![0x03]; // BIT STRING tag
        let bs_len = fake_point.len() + 1; // +1 for unused bits byte
        bit_string.extend(asn1::encode_length(bs_len));
        bit_string.push(0x00); // 0 unused bits
        bit_string.extend_from_slice(&fake_point);
        let spki = asn1::encode_sequence(&[&spki_alg, &bit_string]);
        // TBSCertificate
        let tbs = asn1::encode_sequence(&[
            &version, &serial, &sig_alg, &issuer, &validity, &subject, &spki,
        ]);
        // signatureAlgorithm (same as above)
        let sig_alg2 = sig_alg.clone();
        // signatureValue BIT STRING (fake)
        let mut sig_val = vec![0x03, 0x03, 0x00]; // BIT STRING, len 3, 0 unused bits
        sig_val.extend_from_slice(&[0x00, 0x00]); // fake signature
                                                  // Certificate SEQUENCE { tbs, sigAlg, sigVal }
        asn1::encode_sequence(&[&tbs, &sig_alg2, &sig_val])
    }
}
