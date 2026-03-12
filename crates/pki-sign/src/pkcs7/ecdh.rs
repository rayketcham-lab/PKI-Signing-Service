//! ECDH Key Agreement for CMS EnvelopedData (RFC 5753)
//!
//! Implements ephemeral-static ECDH key agreement per RFC 5753 §3.1:
//! - Ephemeral ECDH key generation (P-256 or P-384)
//! - Static recipient public key extraction
//! - Shared secret derivation via ECDH
//! - Key derivation via ConcatKDF (NIST SP 800-56A Rev 3 §5.8.1)
//! - AES Key Wrap per RFC 3394 (via aes-kw crate)
//!
//! The CMS KeyAgreeRecipientInfo structure is produced by:
//! 1. Generating an ephemeral key pair
//! 2. Computing ECDH shared secret with recipient's static public key
//! 3. Deriving a key-encryption key via ConcatKDF
//! 4. Wrapping the content encryption key with AES Key Wrap

use aes_kw::KekAes128;
use aes_kw::KekAes256;
use p256::ecdh::EphemeralSecret as P256EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey as P256PublicKey;
use p384::ecdh::EphemeralSecret as P384EphemeralSecret;
use p384::PublicKey as P384PublicKey;
use pkcs8::DecodePublicKey;
use rand::rngs::OsRng;
use sha2::Digest;
use zeroize::Zeroizing;

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;

/// Which EC curve to use for ECDH key agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 (secp256r1) — 128-bit security
    P256,
    /// NIST P-384 (secp384r1) — 192-bit security
    P384,
}

/// Key wrap algorithm for the key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// AES-128 Key Wrap (RFC 3394) — 16-byte KEK
    Aes128,
    /// AES-256 Key Wrap (RFC 3394) — 32-byte KEK
    Aes256,
}

impl KeyWrapAlgorithm {
    /// Return the OID bytes for the key wrap algorithm.
    pub fn oid_bytes(&self) -> &'static [u8] {
        match self {
            KeyWrapAlgorithm::Aes128 => asn1::OID_AES128_WRAP,
            KeyWrapAlgorithm::Aes256 => asn1::OID_AES256_WRAP,
        }
    }

    /// Return the key-encryption key size in bytes.
    pub fn kek_len(&self) -> usize {
        match self {
            KeyWrapAlgorithm::Aes128 => 16,
            KeyWrapAlgorithm::Aes256 => 32,
        }
    }
}

/// Result of ephemeral ECDH key generation and key wrapping.
pub struct EcdhKeyAgreementResult {
    /// DER-encoded ephemeral public key (SubjectPublicKeyInfo)
    pub ephemeral_pub_spki: Vec<u8>,
    /// Uncompressed ephemeral public key bytes (for DER encoding in KeyAgreeRecipientInfo)
    pub ephemeral_pub_uncompressed: Vec<u8>,
    /// AES-wrapped content encryption key
    pub wrapped_cek: Vec<u8>,
    /// DER-encoded key wrap AlgorithmIdentifier (for KeyEncryptionAlgorithm field)
    pub key_wrap_alg_id: Vec<u8>,
}

/// Perform ECDH key agreement and wrap the content encryption key.
///
/// This implements the CMS KeyAgreeRecipientInfo sender side (RFC 5753 §3.1):
/// 1. Generate ephemeral key pair on `curve`
/// 2. Extract recipient static public key from SPKI DER
/// 3. Compute ECDH shared secret
/// 4. Derive KEK via ConcatKDF
/// 5. Wrap `cek` with AES Key Wrap
///
/// Returns an `EcdhKeyAgreementResult` containing the ephemeral public key
/// and wrapped CEK for encoding in the KeyAgreeRecipientInfo structure.
pub fn ecdh_wrap_key(
    recipient_spki_der: &[u8],
    cek: &[u8],
    curve: EcdhCurve,
    wrap_alg: KeyWrapAlgorithm,
    ukm: Option<&[u8]>,
) -> SignResult<EcdhKeyAgreementResult> {
    match curve {
        EcdhCurve::P256 => ecdh_wrap_p256(recipient_spki_der, cek, wrap_alg, ukm),
        EcdhCurve::P384 => ecdh_wrap_p384(recipient_spki_der, cek, wrap_alg, ukm),
    }
}

fn ecdh_wrap_p256(
    recipient_spki_der: &[u8],
    cek: &[u8],
    wrap_alg: KeyWrapAlgorithm,
    ukm: Option<&[u8]>,
) -> SignResult<EcdhKeyAgreementResult> {
    // Parse recipient public key
    let recipient_pub = P256PublicKey::from_public_key_der(recipient_spki_der)
        .map_err(|e| SignError::Certificate(format!("P-256 recipient public key: {}", e)))?;

    // Generate ephemeral key pair
    let ephemeral_secret = P256EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = ephemeral_secret.public_key();

    // Compute ECDH shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
    let shared_secret_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Encode ephemeral public key
    let ephemeral_pub_bytes = ephemeral_pub.to_encoded_point(false); // uncompressed
    let ephemeral_pub_uncompressed = ephemeral_pub_bytes.as_bytes().to_vec();

    // Build ephemeral public key SPKI DER (for OtherRecipientInfo / OriginatorPublicKey)
    let ephemeral_spki = build_p256_spki(&ephemeral_pub_uncompressed)?;

    // Key wrap AlgorithmIdentifier DER
    let key_wrap_alg_id = build_key_wrap_alg_id(wrap_alg);

    // Derive KEK via ConcatKDF
    let kek_len = wrap_alg.kek_len();
    let wrap_oid_bytes = wrap_alg.oid_bytes();
    let kek = concat_kdf_sha256(
        &shared_secret_bytes,
        kek_len,
        wrap_oid_bytes,
        &ephemeral_pub_uncompressed,
        recipient_spki_der,
        ukm,
    )?;

    // Wrap CEK
    let wrapped_cek = aes_key_wrap(wrap_alg, &kek, cek)?;

    Ok(EcdhKeyAgreementResult {
        ephemeral_pub_spki: ephemeral_spki,
        ephemeral_pub_uncompressed,
        wrapped_cek,
        key_wrap_alg_id,
    })
}

fn ecdh_wrap_p384(
    recipient_spki_der: &[u8],
    cek: &[u8],
    wrap_alg: KeyWrapAlgorithm,
    ukm: Option<&[u8]>,
) -> SignResult<EcdhKeyAgreementResult> {
    // Parse recipient public key
    let recipient_pub = P384PublicKey::from_public_key_der(recipient_spki_der)
        .map_err(|e| SignError::Certificate(format!("P-384 recipient public key: {}", e)))?;

    // Generate ephemeral key pair
    let ephemeral_secret = P384EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = ephemeral_secret.public_key();

    // Compute ECDH shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);
    let shared_secret_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());

    // Encode ephemeral public key
    let ephemeral_pub_bytes = ephemeral_pub.to_encoded_point(false); // uncompressed
    let ephemeral_pub_uncompressed = ephemeral_pub_bytes.as_bytes().to_vec();

    // Build ephemeral public key SPKI DER
    let ephemeral_spki = build_p384_spki(&ephemeral_pub_uncompressed)?;

    // Key wrap AlgorithmIdentifier DER
    let key_wrap_alg_id = build_key_wrap_alg_id(wrap_alg);

    // Derive KEK via ConcatKDF using SHA-384 for P-384
    let kek_len = wrap_alg.kek_len();
    let wrap_oid_bytes = wrap_alg.oid_bytes();
    let kek = concat_kdf_sha384(
        &shared_secret_bytes,
        kek_len,
        wrap_oid_bytes,
        &ephemeral_pub_uncompressed,
        recipient_spki_der,
        ukm,
    )?;

    // Wrap CEK
    let wrapped_cek = aes_key_wrap(wrap_alg, &kek, cek)?;

    Ok(EcdhKeyAgreementResult {
        ephemeral_pub_spki: ephemeral_spki,
        ephemeral_pub_uncompressed,
        wrapped_cek,
        key_wrap_alg_id,
    })
}

/// Unwrap a CEK using ECDH key agreement (recipient side).
///
/// This implements the CMS KeyAgreeRecipientInfo recipient side (RFC 5753 §3.2):
/// 1. Parse the recipient's private key from PKCS#8 DER
/// 2. Parse the sender's ephemeral public key (uncompressed bytes)
/// 3. Compute ECDH shared secret
/// 4. Derive KEK via ConcatKDF
/// 5. Unwrap the CEK
pub fn ecdh_unwrap_key(
    recipient_priv_pkcs8: &[u8],
    ephemeral_pub_uncompressed: &[u8],
    wrapped_cek: &[u8],
    curve: EcdhCurve,
    wrap_alg: KeyWrapAlgorithm,
    recipient_spki_der: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    match curve {
        EcdhCurve::P256 => ecdh_unwrap_p256(
            recipient_priv_pkcs8,
            ephemeral_pub_uncompressed,
            wrapped_cek,
            wrap_alg,
            recipient_spki_der,
            ukm,
        ),
        EcdhCurve::P384 => ecdh_unwrap_p384(
            recipient_priv_pkcs8,
            ephemeral_pub_uncompressed,
            wrapped_cek,
            wrap_alg,
            recipient_spki_der,
            ukm,
        ),
    }
}

fn ecdh_unwrap_p256(
    recipient_priv_pkcs8: &[u8],
    ephemeral_pub_uncompressed: &[u8],
    wrapped_cek: &[u8],
    wrap_alg: KeyWrapAlgorithm,
    recipient_spki_der: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    use p256::ecdh::diffie_hellman;
    use p256::SecretKey;
    use pkcs8::DecodePrivateKey;

    let priv_key = SecretKey::from_pkcs8_der(recipient_priv_pkcs8)
        .map_err(|e| SignError::Certificate(format!("P-256 recipient private key: {}", e)))?;

    let eph_pub = P256PublicKey::from_sec1_bytes(ephemeral_pub_uncompressed)
        .map_err(|e| SignError::Certificate(format!("P-256 ephemeral public key: {}", e)))?;

    let shared = diffie_hellman(priv_key.to_nonzero_scalar(), eph_pub.as_affine());
    let shared_bytes = Zeroizing::new(shared.raw_secret_bytes().to_vec());

    let kek_len = wrap_alg.kek_len();
    let wrap_oid_bytes = wrap_alg.oid_bytes();
    let kek = concat_kdf_sha256(
        &shared_bytes,
        kek_len,
        wrap_oid_bytes,
        ephemeral_pub_uncompressed,
        recipient_spki_der,
        ukm,
    )?;

    aes_key_unwrap(wrap_alg, &kek, wrapped_cek)
}

fn ecdh_unwrap_p384(
    recipient_priv_pkcs8: &[u8],
    ephemeral_pub_uncompressed: &[u8],
    wrapped_cek: &[u8],
    wrap_alg: KeyWrapAlgorithm,
    recipient_spki_der: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    use p384::ecdh::diffie_hellman;
    use p384::SecretKey;
    use pkcs8::DecodePrivateKey;

    let priv_key = SecretKey::from_pkcs8_der(recipient_priv_pkcs8)
        .map_err(|e| SignError::Certificate(format!("P-384 recipient private key: {}", e)))?;

    let eph_pub = P384PublicKey::from_sec1_bytes(ephemeral_pub_uncompressed)
        .map_err(|e| SignError::Certificate(format!("P-384 ephemeral public key: {}", e)))?;

    let shared = diffie_hellman(priv_key.to_nonzero_scalar(), eph_pub.as_affine());
    let shared_bytes = Zeroizing::new(shared.raw_secret_bytes().to_vec());

    let kek_len = wrap_alg.kek_len();
    let wrap_oid_bytes = wrap_alg.oid_bytes();
    let kek = concat_kdf_sha384(
        &shared_bytes,
        kek_len,
        wrap_oid_bytes,
        ephemeral_pub_uncompressed,
        recipient_spki_der,
        ukm,
    )?;

    aes_key_unwrap(wrap_alg, &kek, wrapped_cek)
}

// ─── ConcatKDF (NIST SP 800-56A Rev 3 §5.8.1) ───

/// ConcatKDF with SHA-256 for use with P-256 key agreement.
///
/// otherInfo ::= AlgorithmID || PartyUInfo || PartyVInfo
/// Per RFC 5753 §2, for S/MIME:
/// - AlgorithmID = DER encoding of the key wrap OID
/// - PartyUInfo  = sender ephemeral public key (uncompressed point)
/// - PartyVInfo  = recipient public key SPKI DER
/// - UKM (optional user keying material) prepended to PartyUInfo
///
/// Z = shared secret from ECDH
/// keydatalen = kek_len * 8 (bits)
fn concat_kdf_sha256(
    z: &[u8],
    kek_len: usize,
    alg_id_oid: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    concat_kdf_generic::<sha2::Sha256>(z, kek_len, alg_id_oid, party_u_info, party_v_info, ukm)
}

/// ConcatKDF with SHA-384 for use with P-384 key agreement.
fn concat_kdf_sha384(
    z: &[u8],
    kek_len: usize,
    alg_id_oid: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    concat_kdf_generic::<sha2::Sha384>(z, kek_len, alg_id_oid, party_u_info, party_v_info, ukm)
}

/// Generic ConcatKDF implementation (NIST SP 800-56A Rev 3 §5.8.1).
///
/// For each counter value (starting at 1):
/// Hash(counter || Z || OtherInfo)
/// where OtherInfo = len(AlgID) || AlgID || len(PartyUInfo) || PartyUInfo || len(PartyVInfo) || PartyVInfo
fn concat_kdf_generic<H: Digest>(
    z: &[u8],
    kek_len: usize,
    alg_id_oid: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    let hash_len = <H as Digest>::output_size();
    let reps = kek_len.div_ceil(hash_len);

    // Build OtherInfo per RFC 5753 §2
    // Each field is: 4-byte big-endian length || data
    let mut other_info = Vec::new();

    // AlgorithmID: length-prefixed OID bytes
    let alg_id_len = alg_id_oid.len() as u32;
    other_info.extend_from_slice(&alg_id_len.to_be_bytes());
    other_info.extend_from_slice(alg_id_oid);

    // PartyUInfo: ephemeral public key (optionally prefixed with UKM)
    let u_info: Vec<u8> = if let Some(ukm_bytes) = ukm {
        let mut u = ukm_bytes.to_vec();
        u.extend_from_slice(party_u_info);
        u
    } else {
        party_u_info.to_vec()
    };
    let u_len = u_info.len() as u32;
    other_info.extend_from_slice(&u_len.to_be_bytes());
    other_info.extend_from_slice(&u_info);

    // PartyVInfo: recipient public key SPKI DER
    let v_len = party_v_info.len() as u32;
    other_info.extend_from_slice(&v_len.to_be_bytes());
    other_info.extend_from_slice(party_v_info);

    // Compute hash rounds
    let mut key_material = Zeroizing::new(Vec::with_capacity(reps * hash_len));
    for counter in 1u32..=(reps as u32) {
        let mut hasher = H::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(z);
        hasher.update(&other_info);
        let hash_out = hasher.finalize();
        key_material.extend_from_slice(&hash_out);
    }

    key_material.truncate(kek_len);
    Ok(key_material)
}

// ─── AES Key Wrap / Unwrap (RFC 3394) ───

/// Wrap a content encryption key using AES Key Wrap (RFC 3394).
pub(crate) fn aes_key_wrap(alg: KeyWrapAlgorithm, kek: &[u8], cek: &[u8]) -> SignResult<Vec<u8>> {
    match alg {
        KeyWrapAlgorithm::Aes128 => {
            let kek_arr: [u8; 16] = kek.try_into().map_err(|_| {
                SignError::Internal("AES-128 KEK must be exactly 16 bytes".to_string())
            })?;
            let kek_obj = KekAes128::from(kek_arr);
            // AES Key Wrap output is 8 bytes longer than input
            let mut out = vec![0u8; cek.len() + 8];
            kek_obj
                .wrap(cek, &mut out)
                .map_err(|e| SignError::Internal(format!("AES-128 key wrap failed: {}", e)))?;
            Ok(out)
        }
        KeyWrapAlgorithm::Aes256 => {
            let kek_arr: [u8; 32] = kek.try_into().map_err(|_| {
                SignError::Internal("AES-256 KEK must be exactly 32 bytes".to_string())
            })?;
            let kek_obj = KekAes256::from(kek_arr);
            let mut out = vec![0u8; cek.len() + 8];
            kek_obj
                .wrap(cek, &mut out)
                .map_err(|e| SignError::Internal(format!("AES-256 key wrap failed: {}", e)))?;
            Ok(out)
        }
    }
}

/// Unwrap a content encryption key using AES Key Unwrap (RFC 3394).
pub(crate) fn aes_key_unwrap(
    alg: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>> {
    match alg {
        KeyWrapAlgorithm::Aes128 => {
            let kek_arr: [u8; 16] = kek.try_into().map_err(|_| {
                SignError::Internal("AES-128 KEK must be exactly 16 bytes".to_string())
            })?;
            let kek_obj = KekAes128::from(kek_arr);
            // AES Key Unwrap output is 8 bytes shorter than input
            let mut out = vec![0u8; wrapped.len().saturating_sub(8)];
            kek_obj
                .unwrap(wrapped, &mut out)
                .map_err(|e| SignError::Internal(format!("AES-128 key unwrap failed: {}", e)))?;
            Ok(Zeroizing::new(out))
        }
        KeyWrapAlgorithm::Aes256 => {
            let kek_arr: [u8; 32] = kek.try_into().map_err(|_| {
                SignError::Internal("AES-256 KEK must be exactly 32 bytes".to_string())
            })?;
            let kek_obj = KekAes256::from(kek_arr);
            let mut out = vec![0u8; wrapped.len().saturating_sub(8)];
            kek_obj
                .unwrap(wrapped, &mut out)
                .map_err(|e| SignError::Internal(format!("AES-256 key unwrap failed: {}", e)))?;
            Ok(Zeroizing::new(out))
        }
    }
}

// ─── SPKI construction helpers ───

/// Build a SubjectPublicKeyInfo DER for a P-256 uncompressed public key point.
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm AlgorithmIdentifier { id-ecPublicKey, namedCurve prime256v1 },
///   subjectPublicKey BIT STRING (uncompressed point)
/// }
fn build_p256_spki(uncompressed_point: &[u8]) -> SignResult<Vec<u8>> {
    // AlgorithmIdentifier for P-256:
    // SEQUENCE {
    //   OID id-ecPublicKey (1.2.840.10045.2.1),
    //   OID prime256v1 (1.2.840.10045.3.1.7)
    // }
    let ec_pub_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let alg_id = asn1::encode_sequence(&[ec_pub_oid, p256_oid]);

    // BIT STRING: tag 0x03, length, 0x00 (no unused bits), point bytes
    let mut bit_string = vec![0x03];
    let bs_content_len = 1 + uncompressed_point.len();
    bit_string.extend(asn1::encode_length(bs_content_len));
    bit_string.push(0x00); // no unused bits
    bit_string.extend_from_slice(uncompressed_point);

    Ok(asn1::encode_sequence(&[&alg_id, &bit_string]))
}

/// Build a SubjectPublicKeyInfo DER for a P-384 uncompressed public key point.
fn build_p384_spki(uncompressed_point: &[u8]) -> SignResult<Vec<u8>> {
    // AlgorithmIdentifier for P-384:
    // SEQUENCE {
    //   OID id-ecPublicKey (1.2.840.10045.2.1),
    //   OID secp384r1 (1.3.132.0.34)
    // }
    let ec_pub_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let p384_oid: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
    let alg_id = asn1::encode_sequence(&[ec_pub_oid, p384_oid]);

    let mut bit_string = vec![0x03];
    let bs_content_len = 1 + uncompressed_point.len();
    bit_string.extend(asn1::encode_length(bs_content_len));
    bit_string.push(0x00);
    bit_string.extend_from_slice(uncompressed_point);

    Ok(asn1::encode_sequence(&[&alg_id, &bit_string]))
}

/// Build a DER-encoded AlgorithmIdentifier for a key wrap OID (no parameters).
fn build_key_wrap_alg_id(wrap_alg: KeyWrapAlgorithm) -> Vec<u8> {
    asn1::encode_sequence(&[wrap_alg.oid_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p384::ecdsa::SigningKey as P384SigningKey;
    use pkcs8::EncodePublicKey;

    fn generate_p256_spki() -> (Vec<u8>, Vec<u8>) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_der = verifying_key.to_public_key_der().unwrap();
        let priv_pkcs8 = {
            use pkcs8::EncodePrivateKey;
            signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec()
        };
        (spki_der.as_bytes().to_vec(), priv_pkcs8)
    }

    fn generate_p384_spki() -> (Vec<u8>, Vec<u8>) {
        let signing_key = P384SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let spki_der = verifying_key.to_public_key_der().unwrap();
        let priv_pkcs8 = {
            use pkcs8::EncodePrivateKey;
            signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec()
        };
        (spki_der.as_bytes().to_vec(), priv_pkcs8)
    }

    #[test]
    fn test_concat_kdf_sha256_deterministic() {
        // Same inputs → same output
        let z = [0u8; 32];
        let kek1 =
            concat_kdf_sha256(&z, 16, asn1::OID_AES128_WRAP, b"party-u", b"party-v", None).unwrap();
        let kek2 =
            concat_kdf_sha256(&z, 16, asn1::OID_AES128_WRAP, b"party-u", b"party-v", None).unwrap();
        assert_eq!(kek1.as_slice(), kek2.as_slice());
    }

    #[test]
    fn test_concat_kdf_sha256_different_lengths() {
        let z = [0xABu8; 32];
        let kek16 = concat_kdf_sha256(&z, 16, asn1::OID_AES128_WRAP, b"u", b"v", None).unwrap();
        let kek32 = concat_kdf_sha256(&z, 32, asn1::OID_AES256_WRAP, b"u", b"v", None).unwrap();
        assert_eq!(kek16.len(), 16);
        assert_eq!(kek32.len(), 32);
        // 16-byte result should be prefix of 32-byte result when using same OID and inputs
        // (not true here since OIDs differ, but lengths must be correct)
    }

    #[test]
    fn test_concat_kdf_sha256_with_ukm() {
        let z = [0x11u8; 32];
        let kek_no_ukm =
            concat_kdf_sha256(&z, 16, asn1::OID_AES128_WRAP, b"u", b"v", None).unwrap();
        let kek_with_ukm =
            concat_kdf_sha256(&z, 16, asn1::OID_AES128_WRAP, b"u", b"v", Some(b"ukm")).unwrap();
        assert_ne!(kek_no_ukm.as_slice(), kek_with_ukm.as_slice());
    }

    #[test]
    fn test_concat_kdf_sha384_output_length() {
        let z = [0x22u8; 48];
        let kek = concat_kdf_sha384(&z, 32, asn1::OID_AES256_WRAP, b"u", b"v", None).unwrap();
        assert_eq!(kek.len(), 32);
    }

    #[test]
    fn test_aes128_wrap_unwrap_roundtrip() {
        let kek = [0xAAu8; 16];
        let cek = [0xBBu8; 16]; // 128-bit key
        let wrapped = aes_key_wrap(KeyWrapAlgorithm::Aes128, &kek, &cek).unwrap();
        // AES Key Wrap adds 8 bytes of integrity check
        assert_eq!(wrapped.len(), 24);
        let unwrapped = aes_key_unwrap(KeyWrapAlgorithm::Aes128, &kek, &wrapped).unwrap();
        assert_eq!(unwrapped.as_slice(), &cek);
    }

    #[test]
    fn test_aes256_wrap_unwrap_roundtrip() {
        let kek = [0xCCu8; 32];
        let cek = [0xDDu8; 32]; // 256-bit key
        let wrapped = aes_key_wrap(KeyWrapAlgorithm::Aes256, &kek, &cek).unwrap();
        assert_eq!(wrapped.len(), 40);
        let unwrapped = aes_key_unwrap(KeyWrapAlgorithm::Aes256, &kek, &wrapped).unwrap();
        assert_eq!(unwrapped.as_slice(), &cek);
    }

    #[test]
    fn test_aes_wrap_wrong_kek_fails() {
        let kek = [0x11u8; 16];
        let wrong_kek = [0x22u8; 16];
        let cek = [0x33u8; 16];
        let wrapped = aes_key_wrap(KeyWrapAlgorithm::Aes128, &kek, &cek).unwrap();
        let result = aes_key_unwrap(KeyWrapAlgorithm::Aes128, &wrong_kek, &wrapped);
        assert!(result.is_err(), "Unwrap with wrong KEK should fail");
    }

    #[test]
    fn test_ecdh_p256_wrap_unwrap_roundtrip() {
        let (spki_der, priv_pkcs8) = generate_p256_spki();
        let cek = [0x42u8; 32]; // 256-bit CEK

        // Sender wraps
        let result = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();

        // Recipient unwraps
        let unwrapped = ecdh_unwrap_key(
            &priv_pkcs8,
            &result.ephemeral_pub_uncompressed,
            &result.wrapped_cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            &spki_der,
            None,
        )
        .unwrap();

        assert_eq!(unwrapped.as_slice(), &cek);
    }

    #[test]
    fn test_ecdh_p384_wrap_unwrap_roundtrip() {
        let (spki_der, priv_pkcs8) = generate_p384_spki();
        let cek = [0x55u8; 32];

        let result = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P384,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();

        let unwrapped = ecdh_unwrap_key(
            &priv_pkcs8,
            &result.ephemeral_pub_uncompressed,
            &result.wrapped_cek,
            EcdhCurve::P384,
            KeyWrapAlgorithm::Aes256,
            &spki_der,
            None,
        )
        .unwrap();

        assert_eq!(unwrapped.as_slice(), &cek);
    }

    #[test]
    fn test_ecdh_p256_with_aes128_wrap() {
        let (spki_der, priv_pkcs8) = generate_p256_spki();
        let cek = [0x77u8; 16]; // 128-bit CEK

        let result = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes128,
            None,
        )
        .unwrap();

        let unwrapped = ecdh_unwrap_key(
            &priv_pkcs8,
            &result.ephemeral_pub_uncompressed,
            &result.wrapped_cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes128,
            &spki_der,
            None,
        )
        .unwrap();

        assert_eq!(unwrapped.as_slice(), &cek);
    }

    #[test]
    fn test_ecdh_wrong_recipient_key_fails() {
        let (spki_der, _) = generate_p256_spki();
        let (_, wrong_priv) = generate_p256_spki();
        let cek = [0x88u8; 32];

        let result = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();

        let unwrap_result = ecdh_unwrap_key(
            &wrong_priv,
            &result.ephemeral_pub_uncompressed,
            &result.wrapped_cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            &spki_der,
            None,
        );

        assert!(
            unwrap_result.is_err(),
            "Unwrapping with wrong private key should fail"
        );
    }

    #[test]
    fn test_ecdh_ephemeral_keys_differ_per_call() {
        let (spki_der, _) = generate_p256_spki();
        let cek = [0x99u8; 32];

        let r1 = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();
        let r2 = ecdh_wrap_key(
            &spki_der,
            &cek,
            EcdhCurve::P256,
            KeyWrapAlgorithm::Aes256,
            None,
        )
        .unwrap();

        // Different ephemeral keys each call
        assert_ne!(r1.ephemeral_pub_uncompressed, r2.ephemeral_pub_uncompressed);
        // Different wrapped CEKs (due to different KEK derived from different shared secrets)
        assert_ne!(r1.wrapped_cek, r2.wrapped_cek);
    }

    #[test]
    fn test_build_p256_spki_structure() {
        let point = vec![0x04u8; 65]; // fake uncompressed point (0x04 prefix + 64 bytes)
        let spki = build_p256_spki(&point).unwrap();
        // Should start with SEQUENCE
        assert_eq!(spki[0], 0x30);
        // Should contain the EC OID
        assert!(spki.windows(2).any(|w| w == [0x06, 0x07]));
    }

    #[test]
    fn test_build_p384_spki_structure() {
        let point = vec![0x04u8; 97]; // fake uncompressed point for P-384
        let spki = build_p384_spki(&point).unwrap();
        assert_eq!(spki[0], 0x30);
    }
}
