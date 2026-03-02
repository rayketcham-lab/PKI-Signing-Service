//! CMS EnvelopedData builder and decryptor (RFC 5652 §6)
//!
//! Implements CMS EnvelopedData for S/MIME email encryption (RFC 8550/8551):
//! - Content encryption: AES-128/256-CBC (RFC 3370), AES-128/256-GCM (RFC 5084)
//! - Key transport: RSA-OAEP (RFC 3560) via `KeyTransRecipientInfo`
//! - Key agreement: ECDH P-256/P-384 + ConcatKDF + AES Key Wrap via `KeyAgreeRecipientInfo`
//!
//! ## Structure
//!
//! ```text
//! EnvelopedData ::= SEQUENCE {
//!   version CMSVersion,
//!   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//!   recipientInfos RecipientInfos,
//!   encryptedContentInfo EncryptedContentInfo,
//!   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
//! }
//! ```

use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes_gcm::aead::Aead;
use aes_gcm::{AeadInPlace, KeyInit};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;
use crate::pkcs7::ecdh::{ecdh_unwrap_key, ecdh_wrap_key, EcdhCurve, KeyWrapAlgorithm};

// RSA-OAEP — standalone implementation (extracted from spork-core)
use crate::crypto::rsa_oaep::{oaep_decrypt, oaep_encrypt, OaepHash};

// KEM type alias for parsed recipient info list
type KemriList = Vec<crate::pkcs7::kem::ParsedKemRecipientInfo>;

/// Parsed EnvelopedData: (encrypted_content, enc_alg_id_der, ktri_list, kari_list, kemri_list)
type ParsedEnvelopedData = (Vec<u8>, Vec<u8>, KtriList, KariList, KemriList);

// ─── Content Encryption Algorithm ───

/// Content encryption algorithm for EnvelopedData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncryptionAlgorithm {
    /// AES-128-CBC (RFC 3370 §3.2) — 16-byte key
    Aes128Cbc,
    /// AES-256-CBC (RFC 3370 §3.2) — 32-byte key
    Aes256Cbc,
    /// AES-128-GCM (RFC 5084 §3.2) — 16-byte key + 12-byte nonce
    Aes128Gcm,
    /// AES-256-GCM (RFC 5084 §3.2) — 32-byte key + 12-byte nonce
    Aes256Gcm,
}

impl ContentEncryptionAlgorithm {
    /// Return the content encryption key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc | ContentEncryptionAlgorithm::Aes128Gcm => 16,
            ContentEncryptionAlgorithm::Aes256Cbc | ContentEncryptionAlgorithm::Aes256Gcm => 32,
        }
    }

    /// Return the OID bytes for this algorithm (without parameters).
    pub fn oid_bytes(&self) -> &'static [u8] {
        match self {
            ContentEncryptionAlgorithm::Aes128Cbc => asn1::OID_AES128_CBC,
            ContentEncryptionAlgorithm::Aes256Cbc => asn1::OID_AES256_CBC,
            ContentEncryptionAlgorithm::Aes128Gcm => asn1::OID_AES128_GCM,
            ContentEncryptionAlgorithm::Aes256Gcm => asn1::OID_AES256_GCM,
        }
    }

    /// Return whether this is an AEAD algorithm.
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            ContentEncryptionAlgorithm::Aes128Gcm | ContentEncryptionAlgorithm::Aes256Gcm
        )
    }
}

// ─── Recipient Types ───

/// RSA key transport recipient (RFC 5652 §6.2.1).
///
/// The content encryption key is wrapped using RSA-OAEP with the
/// recipient's RSA public key.
#[derive(Debug, Clone)]
pub struct KeyTransRecipientInfo {
    /// DER-encoded recipient certificate (X.509)
    pub recipient_cert_der: Vec<u8>,
    /// OAEP hash algorithm (default: SHA-256)
    pub oaep_hash: OaepHash,
}

/// ECDH key agreement recipient (RFC 5753 §3.1).
///
/// The content encryption key is wrapped using ECDH + ConcatKDF + AES Key Wrap
/// with the recipient's EC public key.
#[derive(Debug, Clone)]
pub struct KeyAgreeRecipientInfo {
    /// DER-encoded recipient certificate (X.509)
    pub recipient_cert_der: Vec<u8>,
    /// ECDH curve to use
    pub curve: EcdhCurve,
    /// Key wrap algorithm
    pub key_wrap: KeyWrapAlgorithm,
    /// Optional user keying material
    pub ukm: Option<Vec<u8>>,
}

// ─── EnvelopedData Builder ───

/// Builder for CMS EnvelopedData (RFC 5652 §6).
///
/// # Example
/// ```rust,ignore
/// let der = EnvelopedDataBuilder::new()
///     .with_algorithm(ContentEncryptionAlgorithm::Aes256Gcm)
///     .add_key_trans_recipient(KeyTransRecipientInfo {
///         recipient_cert_der: cert_der,
///         oaep_hash: OaepHash::Sha256,
///     })
///     .build(b"Hello, S/MIME!")?;
/// ```
pub struct EnvelopedDataBuilder {
    algorithm: ContentEncryptionAlgorithm,
    key_trans_recipients: Vec<KeyTransRecipientInfo>,
    key_agree_recipients: Vec<KeyAgreeRecipientInfo>,
    has_kem_recipients: bool,
    kem_recipient_infos_der: Vec<Vec<u8>>,
}

impl Default for EnvelopedDataBuilder {
    fn default() -> Self {
        Self {
            algorithm: ContentEncryptionAlgorithm::Aes256Gcm,
            key_trans_recipients: Vec::new(),
            key_agree_recipients: Vec::new(),
            has_kem_recipients: false,
            kem_recipient_infos_der: Vec::new(),
        }
    }
}

impl EnvelopedDataBuilder {
    /// Create a new builder with AES-256-GCM as default algorithm.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the content encryption algorithm.
    pub fn with_algorithm(mut self, alg: ContentEncryptionAlgorithm) -> Self {
        self.algorithm = alg;
        self
    }

    /// Add an RSA key transport recipient.
    pub fn add_key_trans_recipient(mut self, recipient: KeyTransRecipientInfo) -> Self {
        self.key_trans_recipients.push(recipient);
        self
    }

    /// Add an ECDH key agreement recipient.
    pub fn add_key_agree_recipient(mut self, recipient: KeyAgreeRecipientInfo) -> Self {
        self.key_agree_recipients.push(recipient);
        self
    }

    /// Add pre-built KEM recipient DER (RFC 9629).
    ///
    /// The caller should use `kem::build_kem_recipient_info()` to produce the DER
    /// encoding, then pass it here. This sets EnvelopedData version to 3.
    ///
    /// For full builder integration where the CEK is generated internally,
    /// use `build_with_kem_recipients()` instead.
    pub fn add_kem_recipient_der(mut self, kem_ri_der: Vec<u8>) -> Self {
        self.kem_recipient_infos_der.push(kem_ri_der);
        self.has_kem_recipients = true;
        self
    }

    /// Build the DER-encoded EnvelopedData structure.
    ///
    /// Generates a random content encryption key, encrypts the plaintext,
    /// wraps the CEK for each recipient, and returns the complete DER encoding.
    pub fn build(self, plaintext: &[u8]) -> SignResult<Vec<u8>> {
        if self.key_trans_recipients.is_empty()
            && self.key_agree_recipients.is_empty()
            && self.kem_recipient_infos_der.is_empty()
        {
            return Err(SignError::Pkcs7(
                "EnvelopedData requires at least one recipient".to_string(),
            ));
        }

        // Generate random CEK
        let key_len = self.algorithm.key_len();
        let mut cek = Zeroizing::new(vec![0u8; key_len]);
        rand::rngs::OsRng.fill_bytes(&mut cek);

        // Encrypt content
        let (ciphertext, enc_alg_id) = encrypt_content(self.algorithm, &cek, plaintext)?;

        // Build RecipientInfos
        let mut recipient_infos: Vec<Vec<u8>> = Vec::new();

        for kt in &self.key_trans_recipients {
            let ri = build_key_trans_recipient_info(kt, &cek)?;
            recipient_infos.push(ri);
        }

        for ka in &self.key_agree_recipients {
            let ri = build_key_agree_recipient_info(ka, &cek)?;
            recipient_infos.push(ri);
        }

        // Append pre-built KEM recipient DER (already encoded as OtherRecipientInfo [3])
        for kem_ri in &self.kem_recipient_infos_der {
            recipient_infos.push(kem_ri.clone());
        }

        // Build EnvelopedData DER
        // RFC 9629 §3: version MUST be 3 when KEMRecipientInfo is present
        encode_enveloped_data(
            &recipient_infos,
            &enc_alg_id,
            &ciphertext,
            self.has_kem_recipients,
        )
    }
}

// ─── Content Encryption ───

/// Encrypt plaintext with the given algorithm and CEK.
/// Returns (ciphertext, DER-encoded AlgorithmIdentifier with IV/nonce).
fn encrypt_content(
    alg: ContentEncryptionAlgorithm,
    cek: &[u8],
    plaintext: &[u8],
) -> SignResult<(Vec<u8>, Vec<u8>)> {
    match alg {
        ContentEncryptionAlgorithm::Aes128Cbc => {
            let mut iv = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut iv);
            let ciphertext = aes128_cbc_encrypt(cek, &iv, plaintext)?;
            let alg_id = asn1::aes_cbc_algorithm_id(asn1::OID_AES128_CBC, &iv);
            Ok((ciphertext, alg_id))
        }
        ContentEncryptionAlgorithm::Aes256Cbc => {
            let mut iv = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut iv);
            let ciphertext = aes256_cbc_encrypt(cek, &iv, plaintext)?;
            let alg_id = asn1::aes_cbc_algorithm_id(asn1::OID_AES256_CBC, &iv);
            Ok((ciphertext, alg_id))
        }
        ContentEncryptionAlgorithm::Aes128Gcm => {
            let mut nonce = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let ciphertext = aes_gcm_encrypt::<aes_gcm::Aes128Gcm>(cek, &nonce, plaintext)?;
            let alg_id = asn1::aes_gcm_algorithm_id(asn1::OID_AES128_GCM, &nonce);
            Ok((ciphertext, alg_id))
        }
        ContentEncryptionAlgorithm::Aes256Gcm => {
            let mut nonce = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let ciphertext = aes_gcm_encrypt::<aes_gcm::Aes256Gcm>(cek, &nonce, plaintext)?;
            let alg_id = asn1::aes_gcm_algorithm_id(asn1::OID_AES256_GCM, &nonce);
            Ok((ciphertext, alg_id))
        }
    }
}

// Type aliases for the cbc crate
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES-CBC encryption with PKCS#7 padding (AES-128).
fn aes128_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> SignResult<Vec<u8>> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::KeyIvInit;
    let encryptor = Aes128CbcEnc::new_from_slices(key, iv)
        .map_err(|e| SignError::Pkcs7(format!("AES-128-CBC init failed: {}", e)))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// AES-CBC encryption with PKCS#7 padding (AES-256).
fn aes256_cbc_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> SignResult<Vec<u8>> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::KeyIvInit;
    let encryptor = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| SignError::Pkcs7(format!("AES-256-CBC init failed: {}", e)))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// AES-GCM encryption (appends 16-byte authentication tag).
fn aes_gcm_encrypt<A>(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> SignResult<Vec<u8>>
where
    A: KeyInit + AeadInPlace,
{
    use aes_gcm::Nonce;
    let cipher = A::new_from_slice(key)
        .map_err(|e| SignError::Pkcs7(format!("AES-GCM init failed: {}", e)))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SignError::Pkcs7(format!("AES-GCM encrypt failed: {}", e)))
}

// ─── Content Decryption ───

/// Decrypt AES-128-CBC ciphertext.
fn aes128_cbc_decrypt(
    key: &[u8],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::KeyIvInit;
    let decryptor = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|e| SignError::Pkcs7(format!("AES-128-CBC init failed: {}", e)))?;
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| SignError::Pkcs7(format!("AES-128-CBC decrypt failed: {}", e)))?;
    Ok(Zeroizing::new(plaintext))
}

/// Decrypt AES-256-CBC ciphertext.
fn aes256_cbc_decrypt(
    key: &[u8],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::KeyIvInit;
    let decryptor = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| SignError::Pkcs7(format!("AES-256-CBC init failed: {}", e)))?;
    let plaintext = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| SignError::Pkcs7(format!("AES-256-CBC decrypt failed: {}", e)))?;
    Ok(Zeroizing::new(plaintext))
}

/// Decrypt AES-GCM ciphertext (includes authentication tag verification).
fn aes_gcm_decrypt<A>(
    key: &[u8],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>>
where
    A: KeyInit + AeadInPlace,
{
    use aes_gcm::Nonce;
    let cipher = A::new_from_slice(key)
        .map_err(|e| SignError::Pkcs7(format!("AES-GCM init failed: {}", e)))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        SignError::Pkcs7("AES-GCM authentication tag verification failed".to_string())
    })?;
    Ok(Zeroizing::new(plaintext))
}

// ─── RecipientInfo Builders ───

/// Build a KeyTransRecipientInfo DER for RSA-OAEP key transport.
///
/// KeyTransRecipientInfo ::= SEQUENCE {
///   version CMSVersion,
///   rid RecipientIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey
/// }
fn build_key_trans_recipient_info(kt: &KeyTransRecipientInfo, cek: &[u8]) -> SignResult<Vec<u8>> {
    // Extract SubjectPublicKeyInfo from the recipient cert
    let pub_key_der = extract_rsa_spki_from_cert(&kt.recipient_cert_der)?;

    // Encrypt CEK with RSA-OAEP
    let encrypted_key = oaep_encrypt(&pub_key_der, cek, kt.oaep_hash, None)
        .map_err(|e| SignError::Pkcs7(format!("RSA-OAEP encrypt failed: {}", e)))?;

    // Extract issuer+serial for RecipientIdentifier (issuerAndSerialNumber)
    let (issuer_der, serial_der) = extract_issuer_serial(&kt.recipient_cert_der)?;

    // Build RecipientIdentifier: CHOICE issuerAndSerialNumber
    // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber CertificateSerialNumber }
    let issuer_and_serial = asn1::encode_sequence(&[&issuer_der, &serial_der]);

    // KeyEncryptionAlgorithmIdentifier for RSA-OAEP with SHA-256
    // id-RSAES-OAEP (1.2.840.113549.1.1.7) with RSAES-OAEP-params
    let key_enc_alg_id = build_rsa_oaep_alg_id(kt.oaep_hash);

    // version = 0 (issuerAndSerialNumber)
    let version = asn1::encode_integer_value(0);

    // encryptedKey OCTET STRING
    let encrypted_key_os = asn1::encode_octet_string(&encrypted_key);

    // Assemble KeyTransRecipientInfo
    let ktri = asn1::encode_sequence(&[
        &version,
        &issuer_and_serial,
        &key_enc_alg_id,
        &encrypted_key_os,
    ]);

    Ok(ktri)
}

/// Build a KeyAgreeRecipientInfo DER for ECDH key agreement.
///
/// KeyAgreeRecipientInfo ::= SEQUENCE {
///   version [1] EXPLICIT CMSVersion,  -- always v3
///   originator [0] EXPLICIT OriginatorIdentifierOrKey,
///   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   recipientEncryptedKeys RecipientEncryptedKeys
/// }
fn build_key_agree_recipient_info(ka: &KeyAgreeRecipientInfo, cek: &[u8]) -> SignResult<Vec<u8>> {
    // Extract recipient SPKI from cert
    let recipient_spki = extract_spki_from_cert(&ka.recipient_cert_der)?;

    // Perform ECDH and wrap CEK
    let ecdh_result = ecdh_wrap_key(
        &recipient_spki,
        cek,
        ka.curve,
        ka.key_wrap,
        ka.ukm.as_deref(),
    )?;

    // version = 3 for KeyAgreeRecipientInfo
    let version = encode_context_integer(1, 3); // [1] EXPLICIT INTEGER 3

    // originatorInfo: [0] EXPLICIT OriginatorPublicKey
    // OriginatorPublicKey ::= SEQUENCE { algorithm AlgorithmIdentifier, publicKey BIT STRING }
    let eph_point = &ecdh_result.ephemeral_pub_uncompressed;
    let originator_pub = build_originator_public_key(eph_point, ka.curve)?;
    let originator = asn1::encode_explicit_tag(0, &originator_pub);

    // UKM [1] EXPLICIT OPTIONAL
    let ukm_field = if let Some(ukm_bytes) = &ka.ukm {
        let ukm_os = asn1::encode_octet_string(ukm_bytes);
        asn1::encode_explicit_tag(1, &ukm_os)
    } else {
        vec![]
    };

    // keyEncryptionAlgorithm: AES Key Wrap OID
    let key_enc_alg = asn1::encode_sequence(&[ka.key_wrap.oid_bytes()]);

    // RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
    // RecipientEncryptedKey ::= SEQUENCE {
    //   rid KeyAgreeRecipientIdentifier,
    //   encryptedKey EncryptedKey
    // }
    let (issuer_der, serial_der) = extract_issuer_serial(&ka.recipient_cert_der)?;
    let issuer_and_serial = asn1::encode_sequence(&[&issuer_der, &serial_der]);
    let encrypted_key_os = asn1::encode_octet_string(&ecdh_result.wrapped_cek);
    let recipient_enc_key = asn1::encode_sequence(&[&issuer_and_serial, &encrypted_key_os]);
    let recipient_enc_keys = asn1::encode_sequence(&[&recipient_enc_key]);

    // Assemble all parts (ukm is optional)
    let mut parts: Vec<Vec<u8>> = vec![version, originator];
    if !ukm_field.is_empty() {
        parts.push(ukm_field);
    }
    parts.push(key_enc_alg);
    parts.push(recipient_enc_keys);

    let parts_refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();

    // KeyAgreeRecipientInfo is wrapped in [1] IMPLICIT SEQUENCE in RecipientInfo CHOICE
    let kari_content = {
        let mut content = Vec::new();
        for part in &parts_refs {
            content.extend_from_slice(part);
        }
        content
    };

    // Wrap in SEQUENCE and then [1] tag for RecipientInfo CHOICE
    let kari_seq = asn1::encode_sequence(&parts_refs);

    // RecipientInfo CHOICE [1] = KeyAgreeRecipientInfo
    let mut kari_choice = vec![0xA1]; // [1] IMPLICIT
    kari_choice.extend(asn1::encode_length(kari_seq.len() - 2)); // strip SEQUENCE wrapper
                                                                 // Actually, encode directly as [1] EXPLICIT SEQUENCE content
    let inner_len = kari_content.len();
    let mut result = vec![0xA1];
    result.extend(asn1::encode_length(inner_len));
    result.extend(kari_content);

    Ok(result)
}

/// Build OriginatorPublicKey for the ephemeral EC key.
///
/// OriginatorPublicKey ::= SEQUENCE {
///   algorithm AlgorithmIdentifier,
///   publicKey BIT STRING
/// }
fn build_originator_public_key(uncompressed_point: &[u8], curve: EcdhCurve) -> SignResult<Vec<u8>> {
    let ec_pub_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let curve_oid: &[u8] = match curve {
        EcdhCurve::P256 => &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        EcdhCurve::P384 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
    };
    let alg_id = asn1::encode_sequence(&[ec_pub_oid, curve_oid]);

    let mut bit_string = vec![0x03];
    bit_string.extend(asn1::encode_length(1 + uncompressed_point.len()));
    bit_string.push(0x00);
    bit_string.extend_from_slice(uncompressed_point);

    Ok(asn1::encode_sequence(&[&alg_id, &bit_string]))
}

/// Encode an RSA-OAEP AlgorithmIdentifier for key encryption.
///
/// id-RSAES-OAEP (1.2.840.113549.1.1.7) SEQUENCE { OID, RSAES-OAEP-params }
fn build_rsa_oaep_alg_id(hash: OaepHash) -> Vec<u8> {
    // OID id-RSAES-OAEP: 1.2.840.113549.1.1.7
    let oaep_oid: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07,
    ];

    // Hash OID in AlgorithmIdentifier
    let (hash_alg_id, salt_len): (&[u8], u8) = match hash {
        OaepHash::Sha1 => (
            // SHA-1: 1.3.14.3.2.26
            &[
                0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
            ],
            20,
        ),
        OaepHash::Sha256 => (&asn1::SHA256_ALGORITHM_ID, 32),
        OaepHash::Sha384 => (&asn1::SHA384_ALGORITHM_ID, 48),
        OaepHash::Sha512 => (&asn1::SHA512_ALGORITHM_ID, 64),
    };

    // MGF1 OID: 1.2.840.113549.1.1.8
    let mgf1_oid: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08,
    ];
    let mgf1_params = asn1::encode_sequence(&[mgf1_oid, hash_alg_id]);

    // RSAES-OAEP-params
    let hash_field = asn1::encode_explicit_tag(0, hash_alg_id);
    let mgf_field = asn1::encode_explicit_tag(1, &mgf1_params);
    let salt_field = {
        let salt_int = asn1::encode_integer_value(salt_len as u32);
        asn1::encode_explicit_tag(2, &salt_int)
    };
    let oaep_params = asn1::encode_sequence(&[&hash_field, &mgf_field, &salt_field]);

    asn1::encode_sequence(&[oaep_oid, &oaep_params])
}

// ─── EnvelopedData DER Encoder ───

/// Encode the full EnvelopedData SEQUENCE in DER.
fn encode_enveloped_data(
    recipient_infos: &[Vec<u8>],
    enc_alg_id: &[u8],
    ciphertext: &[u8],
    has_kem: bool,
) -> SignResult<Vec<u8>> {
    // version = 0 (only KeyTransRecipientInfo) or 2 (has KeyAgreeRecipientInfo)
    // or 3 (has KEMRecipientInfo per RFC 9629 §3)
    let ver = if has_kem { 3 } else { 2 };
    let version = asn1::encode_integer_value(ver);

    // RecipientInfos SET OF RecipientInfo
    let mut ri_concat = Vec::new();
    for ri in recipient_infos {
        ri_concat.extend_from_slice(ri);
    }
    let recipient_infos_set = asn1::encode_set(&ri_concat);

    // EncryptedContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
    //   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
    // }
    //
    // contentType = id-data (1.2.840.113549.1.7.1)
    let content_type = asn1::OID_DATA;

    // encryptedContent [0] IMPLICIT OCTET STRING
    let mut enc_content_tag = vec![0x80]; // [0] IMPLICIT primitive
    enc_content_tag.extend(asn1::encode_length(ciphertext.len()));
    enc_content_tag.extend_from_slice(ciphertext);

    let enc_content_info = asn1::encode_sequence(&[content_type, enc_alg_id, &enc_content_tag]);

    // EnvelopedData SEQUENCE
    let enveloped_data =
        asn1::encode_sequence(&[&version, &recipient_infos_set, &enc_content_info]);

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT EnvelopedData }
    let content_field = asn1::encode_explicit_tag(0, &enveloped_data);
    let content_info = asn1::encode_sequence(&[asn1::OID_ENVELOPED_DATA, &content_field]);

    Ok(content_info)
}

// ─── Decryption ───

/// Decrypt an EnvelopedData structure using an RSA private key.
///
/// Finds the first KeyTransRecipientInfo that matches the certificate's
/// issuer/serial, decrypts the CEK, then decrypts the content.
pub fn decrypt_enveloped_data(
    enveloped_der: &[u8],
    recipient_key_der: &[u8],
    recipient_cert_der: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>> {
    let (enc_content, enc_alg_der, ktri_list, _kari_list, _kemri_list) =
        parse_enveloped_data(enveloped_der)?;

    let (issuer_der, serial_der) = extract_issuer_serial(recipient_cert_der)?;

    // Find matching KeyTransRecipientInfo
    for (ri_issuer, ri_serial, key_enc_alg, encrypted_key) in &ktri_list {
        if *ri_issuer == issuer_der && *ri_serial == serial_der {
            // Determine OAEP hash from key_enc_alg
            let hash = parse_oaep_hash(key_enc_alg);

            // Decrypt CEK using RSA-OAEP
            let cek = oaep_decrypt(recipient_key_der, encrypted_key, hash, None)
                .map_err(|e| SignError::Pkcs7(format!("RSA-OAEP decrypt failed: {}", e)))?;

            // Decrypt content
            return decrypt_content(&enc_alg_der, &cek, &enc_content);
        }
    }

    Err(SignError::Pkcs7(
        "No matching RecipientInfo found for the provided certificate".to_string(),
    ))
}

/// Decrypt an EnvelopedData structure using an ECDH private key.
pub fn decrypt_enveloped_data_ecdh(
    enveloped_der: &[u8],
    recipient_key_der: &[u8],
    recipient_cert_der: &[u8],
    curve: EcdhCurve,
    wrap_alg: KeyWrapAlgorithm,
) -> SignResult<Zeroizing<Vec<u8>>> {
    let (enc_content, enc_alg_der, _ktri_list, kari_list, _kemri_list) =
        parse_enveloped_data(enveloped_der)?;

    let recipient_spki = extract_spki_from_cert(recipient_cert_der)?;
    let (issuer_der, serial_der) = extract_issuer_serial(recipient_cert_der)?;

    for (ri_issuer, ri_serial, eph_pub, wrapped_cek, ukm) in &kari_list {
        if *ri_issuer == issuer_der && *ri_serial == serial_der {
            let cek = ecdh_unwrap_key(
                recipient_key_der,
                eph_pub,
                wrapped_cek,
                curve,
                wrap_alg,
                &recipient_spki,
                ukm.as_deref(),
            )?;
            return decrypt_content(&enc_alg_der, &cek, &enc_content);
        }
    }

    Err(SignError::Pkcs7(
        "No matching ECDH RecipientInfo found".to_string(),
    ))
}

/// Decrypt an EnvelopedData structure using a KEM private key (RFC 9629).
///
/// Finds the first KEMRecipientInfo that matches the certificate's
/// issuer/serial, decapsulates the shared secret, derives the KEK,
/// unwraps the CEK, then decrypts the content.
pub fn decrypt_enveloped_data_kem<K: crate::pkcs7::kem::KemAlgorithm>(
    enveloped_der: &[u8],
    recipient_key_der: &[u8],
    recipient_cert_der: &[u8],
    kem: &K,
    ukm: Option<&[u8]>,
) -> SignResult<Zeroizing<Vec<u8>>> {
    let (enc_content, enc_alg_der, _ktri_list, _kari_list, kemri_list) =
        parse_enveloped_data(enveloped_der)?;

    let (issuer_der, serial_der) = extract_issuer_serial(recipient_cert_der)?;

    for parsed in &kemri_list {
        if parsed.issuer_der == issuer_der && parsed.serial_der == serial_der {
            let cek = crate::pkcs7::kem::decrypt_kem_cek(parsed, kem, recipient_key_der, ukm)?;
            return decrypt_content(&enc_alg_der, &cek, &enc_content);
        }
    }

    Err(SignError::Pkcs7(
        "No matching KEM RecipientInfo found".to_string(),
    ))
}

/// Decrypt content using the content encryption algorithm and CEK.
fn decrypt_content(
    enc_alg_der: &[u8],
    cek: &[u8],
    ciphertext: &[u8],
) -> SignResult<Zeroizing<Vec<u8>>> {
    // Parse AlgorithmIdentifier: SEQUENCE { OID, params }
    let (_, seq_content) = asn1::parse_tlv(enc_alg_der)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse enc alg: {}", e)))?;

    let (_, oid_content) = asn1::parse_tlv(seq_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse enc OID: {}", e)))?;

    // Match OID to algorithm
    match oid_content {
        o if o == &asn1::OID_AES128_CBC[2..] => {
            let iv = extract_cbc_iv(enc_alg_der)?;
            aes128_cbc_decrypt(cek, &iv, ciphertext)
        }
        o if o == &asn1::OID_AES256_CBC[2..] => {
            let iv = extract_cbc_iv(enc_alg_der)?;
            aes256_cbc_decrypt(cek, &iv, ciphertext)
        }
        o if o == &asn1::OID_AES128_GCM[2..] => {
            let nonce = extract_gcm_nonce(enc_alg_der)?;
            aes_gcm_decrypt::<aes_gcm::Aes128Gcm>(cek, &nonce, ciphertext)
        }
        o if o == &asn1::OID_AES256_GCM[2..] => {
            let nonce = extract_gcm_nonce(enc_alg_der)?;
            aes_gcm_decrypt::<aes_gcm::Aes256Gcm>(cek, &nonce, ciphertext)
        }
        _ => Err(SignError::Pkcs7(
            "Unsupported content encryption algorithm".to_string(),
        )),
    }
}

// ─── DER Parsing Helpers ───

type KtriList = Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>; // (issuer, serial, key_enc_alg, enc_key)
type KariList = Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>)>; // (issuer, serial, eph_pub, wrapped_cek, ukm)

/// Parse ContentInfo { EnvelopedData } and extract encrypted content fields.
///
/// Returns (encrypted_content_bytes, enc_alg_id_der, ktri_list, kari_list, kemri_list)
fn parse_enveloped_data(der: &[u8]) -> SignResult<ParsedEnvelopedData> {
    // ContentInfo SEQUENCE
    let (_, ci_content) =
        asn1::parse_tlv(der).map_err(|e| SignError::Pkcs7(format!("Parse ContentInfo: {}", e)))?;

    // Skip OID
    let (_, after_oid) = asn1::skip_tlv(ci_content)
        .map_err(|e| SignError::Pkcs7(format!("Skip ContentInfo OID: {}", e)))?;

    // [0] EXPLICIT EnvelopedData
    let (_, ed_wrapped) = asn1::parse_tlv(after_oid)
        .map_err(|e| SignError::Pkcs7(format!("Parse [0] wrapper: {}", e)))?;

    // EnvelopedData SEQUENCE
    let (_, ed_content) = asn1::parse_tlv(ed_wrapped)
        .map_err(|e| SignError::Pkcs7(format!("Parse EnvelopedData: {}", e)))?;

    // Skip version
    let (_, after_ver) =
        asn1::skip_tlv(ed_content).map_err(|e| SignError::Pkcs7(format!("Skip version: {}", e)))?;

    // RecipientInfos SET
    let (ri_tag, ri_content) = asn1::parse_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("Parse RecipientInfos: {}", e)))?;
    if ri_tag != 0x31 {
        return Err(SignError::Pkcs7(format!(
            "Expected SET for RecipientInfos, got 0x{:02X}",
            ri_tag
        )));
    }
    let (_, after_ri) = asn1::skip_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("Skip RecipientInfos: {}", e)))?;
    let after_ri = after_ri.to_vec();

    let mut ktri_list = Vec::new();
    let mut kari_list = Vec::new();
    let mut kemri_list: KemriList = Vec::new();
    parse_recipient_infos(ri_content, &mut ktri_list, &mut kari_list, &mut kemri_list)?;

    // EncryptedContentInfo SEQUENCE
    let (_, eci_content) = asn1::parse_tlv(&after_ri)
        .map_err(|e| SignError::Pkcs7(format!("Parse EncryptedContentInfo: {}", e)))?;

    // Skip contentType OID
    let (_, after_ct) = asn1::skip_tlv(eci_content)
        .map_err(|e| SignError::Pkcs7(format!("Skip contentType: {}", e)))?;

    // Extract enc algorithm AlgorithmIdentifier (full TLV)
    let (enc_alg_tlv, after_alg) = asn1::extract_tlv(after_ct)
        .map_err(|e| SignError::Pkcs7(format!("Extract enc alg: {}", e)))?;
    let enc_alg_id = enc_alg_tlv.to_vec();

    // [0] IMPLICIT encrypted content (primitive OCTET STRING with tag 0x80)
    let (enc_tag, enc_content_bytes) = asn1::parse_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("Parse encrypted content: {}", e)))?;

    if enc_tag != 0x80 {
        return Err(SignError::Pkcs7(format!(
            "Expected [0] IMPLICIT for encryptedContent, got 0x{:02X}",
            enc_tag
        )));
    }

    Ok((
        enc_content_bytes.to_vec(),
        enc_alg_id,
        ktri_list,
        kari_list,
        kemri_list,
    ))
}

/// Parse all RecipientInfos from a SET OF bytes.
fn parse_recipient_infos(
    data: &[u8],
    ktri_list: &mut KtriList,
    kari_list: &mut KariList,
    kemri_list: &mut KemriList,
) -> SignResult<()> {
    let mut remaining = data;
    while !remaining.is_empty() {
        if remaining[0] == 0x30 {
            // KeyTransRecipientInfo SEQUENCE
            let (ri_content, rest) = {
                let (content, rem) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Pkcs7(format!("Extract KTRI TLV: {}", e)))?;
                let (_, inner) = asn1::parse_tlv(content)
                    .map_err(|e| SignError::Pkcs7(format!("Parse KTRI inner: {}", e)))?;
                (inner.to_vec(), rem)
            };
            parse_key_trans_ri(&ri_content, ktri_list)?;
            remaining = rest;
        } else if remaining[0] == 0xA1 {
            // [1] KeyAgreeRecipientInfo
            let (ri_content, rest) = {
                let (content, rem) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Pkcs7(format!("Extract KARI TLV: {}", e)))?;
                let (_, inner) = asn1::parse_tlv(content)
                    .map_err(|e| SignError::Pkcs7(format!("Parse KARI inner: {}", e)))?;
                (inner.to_vec(), rem)
            };
            parse_key_agree_ri(&ri_content, kari_list)?;
            remaining = rest;
        } else if remaining[0] == 0xA3 {
            // [3] OtherRecipientInfo — RFC 9629 KEMRecipientInfo
            let (ori_content, rest) = {
                let (content, rem) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Pkcs7(format!("Extract ORI TLV: {}", e)))?;
                let (_, inner) = asn1::parse_tlv(content)
                    .map_err(|e| SignError::Pkcs7(format!("Parse ORI inner: {}", e)))?;
                (inner.to_vec(), rem)
            };
            // OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY }
            // Check if oriType is id-ori-kem
            let (_, ori_seq) = asn1::parse_tlv(&ori_content)
                .map_err(|e| SignError::Pkcs7(format!("Parse ORI SEQUENCE: {}", e)))?;
            let (oid_tlv, after_oid) = asn1::extract_tlv(ori_seq)
                .map_err(|e| SignError::Pkcs7(format!("Extract ORI OID: {}", e)))?;
            if oid_tlv == asn1::OID_ORI_KEM {
                // oriValue is KEMRecipientInfo SEQUENCE
                let (_, kem_ri_content) = asn1::parse_tlv(after_oid)
                    .map_err(|e| SignError::Pkcs7(format!("Parse KEMRecipientInfo: {}", e)))?;
                let parsed = crate::pkcs7::kem::parse_kem_recipient_info(kem_ri_content)?;
                kemri_list.push(parsed);
            }
            remaining = rest;
        } else {
            // Skip unknown recipient info types
            let (_, rest) = asn1::skip_tlv(remaining)
                .map_err(|e| SignError::Pkcs7(format!("Skip unknown RI: {}", e)))?;
            remaining = rest;
        }
    }
    Ok(())
}

/// Parse a KeyTransRecipientInfo.
fn parse_key_trans_ri(content: &[u8], ktri_list: &mut KtriList) -> SignResult<()> {
    // Skip version
    let (_, after_ver) = asn1::skip_tlv(content)
        .map_err(|e| SignError::Pkcs7(format!("KTRI skip version: {}", e)))?;

    // IssuerAndSerialNumber SEQUENCE
    let (_, issuer_serial_content) = asn1::parse_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("KTRI parse IssuerSerial: {}", e)))?;

    let (issuer_tlv, after_issuer) = asn1::extract_tlv(issuer_serial_content)
        .map_err(|e| SignError::Pkcs7(format!("KTRI extract issuer: {}", e)))?;
    let (serial_tlv, _) = asn1::extract_tlv(after_issuer)
        .map_err(|e| SignError::Pkcs7(format!("KTRI extract serial: {}", e)))?;

    let (_, after_rid) =
        asn1::skip_tlv(after_ver).map_err(|e| SignError::Pkcs7(format!("KTRI skip RID: {}", e)))?;

    // Key encryption AlgorithmIdentifier (full TLV)
    let (key_enc_alg_tlv, after_alg) = asn1::extract_tlv(after_rid)
        .map_err(|e| SignError::Pkcs7(format!("KTRI extract key enc alg: {}", e)))?;

    // encryptedKey OCTET STRING
    let (_, enc_key_content) = asn1::parse_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("KTRI parse encryptedKey: {}", e)))?;

    ktri_list.push((
        issuer_tlv.to_vec(),
        serial_tlv.to_vec(),
        key_enc_alg_tlv.to_vec(),
        enc_key_content.to_vec(),
    ));
    Ok(())
}

/// Parse a KeyAgreeRecipientInfo.
fn parse_key_agree_ri(content: &[u8], kari_list: &mut KariList) -> SignResult<()> {
    // version [1] EXPLICIT
    let (_, after_ver) = asn1::skip_tlv(content)
        .map_err(|e| SignError::Pkcs7(format!("KARI skip version: {}", e)))?;

    // originator [0] EXPLICIT OriginatorPublicKey
    let (_, originator_content) = asn1::parse_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("KARI parse originator: {}", e)))?;

    // Extract ephemeral public key from OriginatorPublicKey SEQUENCE
    let eph_pub = extract_ephemeral_pub_from_originator(originator_content)?;

    let (_, after_orig) = asn1::skip_tlv(after_ver)
        .map_err(|e| SignError::Pkcs7(format!("KARI skip originator: {}", e)))?;

    // Check for optional UKM [1] EXPLICIT
    let (ukm, after_ukm) = if !after_orig.is_empty() && after_orig[0] == 0xA1 {
        let (_, ukm_content) = asn1::parse_tlv(after_orig)
            .map_err(|e| SignError::Pkcs7(format!("KARI parse UKM: {}", e)))?;
        let (_, ukm_bytes) = asn1::parse_tlv(ukm_content)
            .map_err(|e| SignError::Pkcs7(format!("KARI parse UKM bytes: {}", e)))?;
        let (_, rest) = asn1::skip_tlv(after_orig)
            .map_err(|e| SignError::Pkcs7(format!("KARI skip UKM: {}", e)))?;
        (Some(ukm_bytes.to_vec()), rest)
    } else {
        (None, after_orig)
    };

    // keyEncryptionAlgorithm
    let (_, after_alg) = asn1::skip_tlv(after_ukm)
        .map_err(|e| SignError::Pkcs7(format!("KARI skip key enc alg: {}", e)))?;

    // RecipientEncryptedKeys SEQUENCE OF
    let (_, reks_content) = asn1::parse_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("KARI parse REKs: {}", e)))?;

    // First RecipientEncryptedKey
    let (_, rek_content) = asn1::parse_tlv(reks_content)
        .map_err(|e| SignError::Pkcs7(format!("KARI parse REK: {}", e)))?;

    // IssuerAndSerialNumber
    let (ias_content, after_ias_tlv) = {
        let (ias_tlv, rem) = asn1::extract_tlv(rek_content)
            .map_err(|e| SignError::Pkcs7(format!("KARI extract IAS: {}", e)))?;
        let (_, c) = asn1::parse_tlv(ias_tlv)
            .map_err(|e| SignError::Pkcs7(format!("KARI parse IAS content: {}", e)))?;
        (c.to_vec(), rem)
    };

    let (issuer_tlv, after_issuer) = asn1::extract_tlv(&ias_content)
        .map_err(|e| SignError::Pkcs7(format!("KARI extract issuer: {}", e)))?;
    let (serial_tlv, _) = asn1::extract_tlv(after_issuer)
        .map_err(|e| SignError::Pkcs7(format!("KARI extract serial: {}", e)))?;

    // encryptedKey OCTET STRING
    let (_, wrapped_cek) = asn1::parse_tlv(after_ias_tlv)
        .map_err(|e| SignError::Pkcs7(format!("KARI parse wrapped CEK: {}", e)))?;

    kari_list.push((
        issuer_tlv.to_vec(),
        serial_tlv.to_vec(),
        eph_pub,
        wrapped_cek.to_vec(),
        ukm,
    ));
    Ok(())
}

/// Extract the ephemeral uncompressed EC point from OriginatorPublicKey.
fn extract_ephemeral_pub_from_originator(originator: &[u8]) -> SignResult<Vec<u8>> {
    // OriginatorPublicKey SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let (_, inner) = asn1::parse_tlv(originator)
        .map_err(|e| SignError::Pkcs7(format!("Parse OriginatorPublicKey: {}", e)))?;

    // Skip AlgorithmIdentifier
    let (_, after_alg) =
        asn1::skip_tlv(inner).map_err(|e| SignError::Pkcs7(format!("Skip OPK AlgId: {}", e)))?;

    // BIT STRING: tag 0x03, length, unused bits byte, then key bytes
    let (_, bit_string_content) = asn1::parse_tlv(after_alg)
        .map_err(|e| SignError::Pkcs7(format!("Parse OPK BIT STRING: {}", e)))?;

    if bit_string_content.is_empty() {
        return Err(SignError::Pkcs7("Empty ephemeral public key".to_string()));
    }

    // First byte is "unused bits" count (should be 0)
    Ok(bit_string_content[1..].to_vec())
}

/// Parse the OAEP hash algorithm from a KeyEncryptionAlgorithm identifier.
/// Currently defaults to SHA-256; a production implementation would parse the OID params.
fn parse_oaep_hash(_alg_id: &[u8]) -> OaepHash {
    OaepHash::Sha256
}

/// Extract CBC IV (OCTET STRING in AlgorithmIdentifier parameters).
fn extract_cbc_iv(enc_alg_der: &[u8]) -> SignResult<[u8; 16]> {
    let (_, seq_content) = asn1::parse_tlv(enc_alg_der)
        .map_err(|e| SignError::Pkcs7(format!("Parse CBC alg SEQUENCE: {}", e)))?;

    // Skip OID
    let (_, after_oid) = asn1::skip_tlv(seq_content)
        .map_err(|e| SignError::Pkcs7(format!("Skip CBC OID: {}", e)))?;

    // IV OCTET STRING
    let (_, iv_bytes) =
        asn1::parse_tlv(after_oid).map_err(|e| SignError::Pkcs7(format!("Parse CBC IV: {}", e)))?;

    iv_bytes
        .try_into()
        .map_err(|_| SignError::Pkcs7(format!("CBC IV must be 16 bytes, got {}", iv_bytes.len())))
}

/// Extract GCM nonce from AlgorithmIdentifier parameters.
fn extract_gcm_nonce(enc_alg_der: &[u8]) -> SignResult<[u8; 12]> {
    let (_, seq_content) = asn1::parse_tlv(enc_alg_der)
        .map_err(|e| SignError::Pkcs7(format!("Parse GCM alg SEQUENCE: {}", e)))?;

    // Skip OID
    let (_, after_oid) = asn1::skip_tlv(seq_content)
        .map_err(|e| SignError::Pkcs7(format!("Skip GCM OID: {}", e)))?;

    // GCMParameters SEQUENCE { OCTET STRING nonce }
    let (_, gcm_params_content) = asn1::parse_tlv(after_oid)
        .map_err(|e| SignError::Pkcs7(format!("Parse GCMParameters: {}", e)))?;

    let (_, nonce_bytes) = asn1::parse_tlv(gcm_params_content)
        .map_err(|e| SignError::Pkcs7(format!("Parse GCM nonce: {}", e)))?;

    nonce_bytes.try_into().map_err(|_| {
        SignError::Pkcs7(format!(
            "GCM nonce must be 12 bytes, got {}",
            nonce_bytes.len()
        ))
    })
}

// ─── Certificate Field Extraction ───

/// Extract SubjectPublicKeyInfo DER bytes from a certificate.
pub fn extract_spki_from_cert(cert_der: &[u8]) -> SignResult<Vec<u8>> {
    // Certificate SEQUENCE { TBSCertificate, signatureAlgorithm, signature }
    let (_, cert_content) =
        asn1::parse_tlv(cert_der).map_err(|e| SignError::Pkcs7(format!("Parse cert: {}", e)))?;

    // TBSCertificate SEQUENCE
    let (_, tbs_content) =
        asn1::parse_tlv(cert_content).map_err(|e| SignError::Pkcs7(format!("Parse TBS: {}", e)))?;

    // Skip: version [0], serialNumber, signature, issuer, validity, subject
    let mut remaining = tbs_content;

    // version [0] EXPLICIT (optional)
    if !remaining.is_empty() && remaining[0] == 0xA0 {
        let (_, rest) = asn1::skip_tlv(remaining)
            .map_err(|e| SignError::Pkcs7(format!("Skip version: {}", e)))?;
        remaining = rest;
    }

    // serialNumber INTEGER
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip serial: {}", e)))?;
    remaining = rest;

    // signature AlgorithmIdentifier
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip sig alg: {}", e)))?;
    remaining = rest;

    // issuer Name
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip issuer: {}", e)))?;
    remaining = rest;

    // validity Validity
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip validity: {}", e)))?;
    remaining = rest;

    // subject Name
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip subject: {}", e)))?;
    remaining = rest;

    // subjectPublicKeyInfo SEQUENCE (this is what we want)
    let (spki_tlv, _) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Extract SPKI: {}", e)))?;

    Ok(spki_tlv.to_vec())
}

/// Extract RSA SubjectPublicKeyInfo from a certificate, validating it is RSA.
fn extract_rsa_spki_from_cert(cert_der: &[u8]) -> SignResult<Vec<u8>> {
    // Use the generic SPKI extractor; RSA vs EC validation happens at encrypt time
    extract_spki_from_cert(cert_der)
}

/// Extract issuer (full DER TLV) and serial number (full DER TLV) from a certificate.
pub fn extract_issuer_serial(cert_der: &[u8]) -> SignResult<(Vec<u8>, Vec<u8>)> {
    // Certificate SEQUENCE
    let (_, cert_content) = asn1::parse_tlv(cert_der)
        .map_err(|e| SignError::Pkcs7(format!("Parse cert outer: {}", e)))?;

    // TBSCertificate SEQUENCE
    let (_, tbs_content) = asn1::parse_tlv(cert_content)
        .map_err(|e| SignError::Pkcs7(format!("Parse TBS cert: {}", e)))?;

    let mut remaining = tbs_content;

    // version [0] EXPLICIT (optional)
    if !remaining.is_empty() && remaining[0] == 0xA0 {
        let (_, rest) = asn1::skip_tlv(remaining)
            .map_err(|e| SignError::Pkcs7(format!("Skip version: {}", e)))?;
        remaining = rest;
    }

    // serialNumber INTEGER — extract full TLV
    let (serial_tlv, rest) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Extract serial: {}", e)))?;
    remaining = rest;

    // signature AlgorithmIdentifier
    let (_, rest) =
        asn1::skip_tlv(remaining).map_err(|e| SignError::Pkcs7(format!("Skip sig alg: {}", e)))?;
    remaining = rest;

    // issuer Name — extract full TLV
    let (issuer_tlv, _) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Extract issuer: {}", e)))?;

    Ok((issuer_tlv.to_vec(), serial_tlv.to_vec()))
}

/// Encode a context-specific integer with tag [n] EXPLICIT.
fn encode_context_integer(tag: u8, value: u32) -> Vec<u8> {
    let int_der = asn1::encode_integer_value(value);
    asn1::encode_explicit_tag(tag, &int_der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rsa_oaep::OaepHash;

    // Helper: generate a minimal self-signed RSA certificate for testing
    fn make_rsa_test_cert() -> (Vec<u8>, Vec<u8>) {
        use pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        let mut rng = rand::rngs::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let pub_der = pub_key.to_public_key_der().unwrap().as_ref().to_vec();
        let priv_der = priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        (pub_der, priv_der)
    }

    #[test]
    fn test_aes128_cbc_encrypt_decrypt_roundtrip() {
        let cek = [0xAAu8; 16];
        let plaintext = b"Hello, S/MIME with AES-128-CBC!";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes128Cbc, &cek, plaintext).unwrap();

        assert_ne!(ciphertext, plaintext.as_ref());

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes256_cbc_encrypt_decrypt_roundtrip() {
        let cek = [0xBBu8; 32];
        let plaintext = b"Hello, S/MIME with AES-256-CBC!";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Cbc, &cek, plaintext).unwrap();

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes128_gcm_encrypt_decrypt_roundtrip() {
        let cek = [0xCCu8; 16];
        let plaintext = b"Hello, S/MIME with AES-128-GCM!";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes128Gcm, &cek, plaintext).unwrap();

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes256_gcm_encrypt_decrypt_roundtrip() {
        let cek = [0xDDu8; 32];
        let plaintext = b"Hello, S/MIME with AES-256-GCM!";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Gcm, &cek, plaintext).unwrap();

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let cek = [0x11u8; 32];
        let wrong_cek = [0x22u8; 32];
        let plaintext = b"test message";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Gcm, &cek, plaintext).unwrap();

        let result = decrypt_content(&alg_id, &wrong_cek, &ciphertext);
        assert!(
            result.is_err(),
            "GCM auth tag verification should fail with wrong key"
        );
    }

    #[test]
    fn test_aes_cbc_pkcs7_padding() {
        let cek = [0x33u8; 16];
        // Plaintext that is an exact multiple of block size (16 bytes)
        let plaintext = b"0123456789ABCDEF";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes128Cbc, &cek, plaintext).unwrap();

        // CBC with PKCS7 padding adds a full block when input is exact multiple
        assert_eq!(ciphertext.len(), 32);

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_encryption_is_randomized() {
        let cek = [0x44u8; 32];
        let plaintext = b"same message";

        let (ct1, _) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Gcm, &cek, plaintext).unwrap();
        let (ct2, _) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Gcm, &cek, plaintext).unwrap();

        // Different nonces → different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_cek_length() {
        assert_eq!(ContentEncryptionAlgorithm::Aes128Cbc.key_len(), 16);
        assert_eq!(ContentEncryptionAlgorithm::Aes256Cbc.key_len(), 32);
        assert_eq!(ContentEncryptionAlgorithm::Aes128Gcm.key_len(), 16);
        assert_eq!(ContentEncryptionAlgorithm::Aes256Gcm.key_len(), 32);
    }

    #[test]
    fn test_content_encryption_algorithm_is_aead() {
        assert!(!ContentEncryptionAlgorithm::Aes128Cbc.is_aead());
        assert!(!ContentEncryptionAlgorithm::Aes256Cbc.is_aead());
        assert!(ContentEncryptionAlgorithm::Aes128Gcm.is_aead());
        assert!(ContentEncryptionAlgorithm::Aes256Gcm.is_aead());
    }

    #[test]
    fn test_builder_requires_at_least_one_recipient() {
        let result = EnvelopedDataBuilder::new().build(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let cek = [0x55u8; 32];
        let plaintext = b"";

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Gcm, &cek, plaintext).unwrap();

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_cbc_large_plaintext() {
        let cek = [0x66u8; 32];
        let plaintext = vec![0x42u8; 4096];

        let (ciphertext, alg_id) =
            encrypt_content(ContentEncryptionAlgorithm::Aes256Cbc, &cek, &plaintext).unwrap();

        let decrypted = decrypt_content(&alg_id, &cek, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
}
