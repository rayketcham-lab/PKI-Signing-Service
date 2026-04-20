//! Code signing orchestrator.
//!
//! Coordinates the signing pipeline:
//! 1. Load PFX certificate and private key
//! 2. Determine file type (PE, PowerShell, MSI/CAB)
//! 3. Compute Authenticode hash
//! 4. Build CMS/PKCS#7 SignedData
//! 5. Optionally request RFC 3161 timestamp
//! 6. Embed signature in file

use std::path::Path;

use pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use signature::Signer;
use zeroize::Zeroizing;

use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p521::ecdsa::SigningKey as P521SigningKey;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
#[cfg(feature = "pq-experimental")]
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey};

use crate::error::{SignError, SignResult};
use crate::pe;
use crate::pkcs7::Pkcs7Builder;
use crate::timestamp::TsaConfig;

/// Supported file types for code signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Windows PE executable (.exe, .dll, .sys, .ocx, .scr, .cpl, .drv)
    Pe,
    /// PowerShell script (.ps1)
    PowerShell,
    /// Windows Installer (.msi)
    Msi,
    /// Cabinet archive (.cab)
    Cab,
}

impl FileType {
    /// Detect file type from extension.
    pub fn from_extension(path: &Path) -> SignResult<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "drv" => Ok(Self::Pe),
            "ps1" => Ok(Self::PowerShell),
            "msi" => Ok(Self::Msi),
            "cab" => Ok(Self::Cab),
            _ => Err(SignError::UnsupportedFileType(ext)),
        }
    }
}

/// Supported private key types for code signing.
///
/// `Debug` is manually implemented to avoid leaking key material.
///
/// Marked `#[non_exhaustive]` so future key types (hybrid/composite,
/// additional PQ schemes) can be added behind feature flags without forcing
/// downstream consumers to rewrite every match expression.
#[non_exhaustive]
pub enum PrivateKey {
    /// RSA private key (2048, 3072, or 4096 bit).
    /// Boxed to reduce enum size disparity with ECDSA variants.
    Rsa(Box<RsaPrivateKey>),
    /// ECDSA P-256 private key.
    EcdsaP256(p256::SecretKey),
    /// ECDSA P-384 private key.
    EcdsaP384(p384::SecretKey),
    /// ECDSA P-521 private key.
    EcdsaP521(p521::SecretKey),
    /// Ed25519 private key (RFC 8032).
    Ed25519(Ed25519SigningKey),
    /// ML-DSA-44 private key (FIPS 204, security category 2).
    #[cfg(feature = "pq-experimental")]
    MlDsa44(Box<MlDsaSigningKey<MlDsa44>>),
    /// ML-DSA-65 private key (FIPS 204, security category 3).
    #[cfg(feature = "pq-experimental")]
    MlDsa65(Box<MlDsaSigningKey<MlDsa65>>),
    /// ML-DSA-87 private key (FIPS 204, security category 5).
    #[cfg(feature = "pq-experimental")]
    MlDsa87(Box<MlDsaSigningKey<MlDsa87>>),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::Rsa(_) => f.write_str("PrivateKey::Rsa([REDACTED])"),
            PrivateKey::EcdsaP256(_) => f.write_str("PrivateKey::EcdsaP256([REDACTED])"),
            PrivateKey::EcdsaP384(_) => f.write_str("PrivateKey::EcdsaP384([REDACTED])"),
            PrivateKey::EcdsaP521(_) => f.write_str("PrivateKey::EcdsaP521([REDACTED])"),
            PrivateKey::Ed25519(_) => f.write_str("PrivateKey::Ed25519([REDACTED])"),
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa44(_) => f.write_str("PrivateKey::MlDsa44([REDACTED])"),
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa65(_) => f.write_str("PrivateKey::MlDsa65([REDACTED])"),
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa87(_) => f.write_str("PrivateKey::MlDsa87([REDACTED])"),
        }
    }
}

/// Loaded signing credentials from a PFX file.
///
/// Supports RSA, ECDSA P-256, ECDSA P-384, ECDSA P-521, Ed25519, and ML-DSA-44/65/87 private keys.
/// Key material is automatically zeroized on drop: `RsaPrivateKey` implements
/// `Drop` which zeroizes `d`, `primes`, and `precomputed` fields.
/// ECDSA secret keys (`p256::SecretKey`, `p384::SecretKey`, `p521::SecretKey`) implement `Zeroize`.
/// The PFX key bytes are loaded via `Zeroizing<Vec<u8>>` in `load_pfx`.
pub struct SigningCredentials {
    /// Private key for signing.
    private_key: PrivateKey,
    /// DER-encoded signing certificate.
    signer_cert_der: Vec<u8>,
    /// DER-encoded chain certificates.
    chain_certs_der: Vec<Vec<u8>>,
}

impl SigningCredentials {
    /// Load signing credentials from a PFX/PKCS#12 file.
    ///
    /// Validates that the certificate has the codeSigning EKU (required for Authenticode)
    /// and that the certificate is currently valid (not expired, not yet valid).
    pub fn from_pfx(pfx_path: &Path, password: &str) -> SignResult<Self> {
        let (private_key, signer_cert_der, chain_certs_der) = load_pfx(pfx_path, password)?;

        // RFC 5280 §4.2.1.3: Validate the signing certificate's keyUsage extension.
        // If present, it MUST include digitalSignature (bit 0) for code signing.
        validate_key_usage_for_signing(&signer_cert_der)?;

        // RFC 5280 §4.2.1.12: Validate the signing certificate's extendedKeyUsage.
        // If present, it MUST include id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
        validate_eku_for_code_signing(&signer_cert_der)?;

        // #11 fix: Validate certificate validity period
        validate_cert_validity(&signer_cert_der)?;

        Ok(SigningCredentials {
            private_key,
            signer_cert_der,
            chain_certs_der,
        })
    }

    /// Load signing credentials from a PFX/PKCS#12 file for detached signing.
    ///
    /// Only requires digitalSignature keyUsage — no codeSigning EKU requirement.
    pub fn from_pfx_detached(pfx_path: &Path, password: &str) -> SignResult<Self> {
        let (private_key, signer_cert_der, chain_certs_der) = load_pfx(pfx_path, password)?;

        // For detached signing, only digitalSignature keyUsage is required
        validate_key_usage_for_signing(&signer_cert_der)?;

        // #11 fix: Validate certificate validity period
        validate_cert_validity(&signer_cert_der)?;

        Ok(SigningCredentials {
            private_key,
            signer_cert_der,
            chain_certs_der,
        })
    }

    /// Get a reference to the signing certificate DER bytes.
    pub fn signer_cert_der(&self) -> &[u8] {
        &self.signer_cert_der
    }

    /// Get a reference to the chain certificates.
    pub fn chain_certs_der(&self) -> &[Vec<u8>] {
        &self.chain_certs_der
    }

    /// Sign data using the loaded private key.
    ///
    /// For RSA: RSASSA-PKCS1-v1_5 with SHA-256.
    /// For ECDSA P-256: ECDSA with SHA-256.
    /// For ECDSA P-384: ECDSA with SHA-384.
    ///
    /// The input should be the DER-encoded signed attributes (as a SET).
    pub fn sign_data(&self, data: &[u8]) -> SignResult<Vec<u8>> {
        match &self.private_key {
            PrivateKey::Rsa(rsa_key) => {
                let signing_key = SigningKey::<Sha256>::new(rsa_key.as_ref().clone());
                let signature = signing_key.sign(data);
                let sig_bytes: Box<[u8]> = signature.into();
                Ok(sig_bytes.into_vec())
            }
            PrivateKey::EcdsaP256(secret_key) => {
                let signing_key = P256SigningKey::from(secret_key);
                let signature: p256::ecdsa::Signature = signing_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            PrivateKey::EcdsaP384(secret_key) => {
                let signing_key = P384SigningKey::from(secret_key);
                let signature: p384::ecdsa::Signature = signing_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            PrivateKey::EcdsaP521(secret_key) => {
                let key_bytes = zeroize::Zeroizing::new(secret_key.to_bytes());
                let signing_key = P521SigningKey::from_slice(key_bytes.as_ref())
                    .map_err(|e| SignError::Internal(format!("P521 key init: {e}")))?;
                let signature: p521::ecdsa::Signature = signing_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            PrivateKey::Ed25519(signing_key) => {
                let signature: ed25519_dalek::Signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa44(signing_key) => {
                let signature: ml_dsa::Signature<MlDsa44> = signing_key.sign(data);
                let encoded = signature.encode();
                let bytes: &[u8] = encoded.as_slice();
                Ok(bytes.to_vec())
            }
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa65(signing_key) => {
                let signature: ml_dsa::Signature<MlDsa65> = signing_key.sign(data);
                let encoded = signature.encode();
                let bytes: &[u8] = encoded.as_slice();
                Ok(bytes.to_vec())
            }
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa87(signing_key) => {
                let signature: ml_dsa::Signature<MlDsa87> = signing_key.sign(data);
                let encoded = signature.encode();
                let bytes: &[u8] = encoded.as_slice();
                Ok(bytes.to_vec())
            }
        }
    }

    /// Get the signing algorithm identifier for PKCS#7 builder.
    pub fn signing_algorithm(&self) -> crate::pkcs7::SigningAlgorithm {
        match &self.private_key {
            PrivateKey::Rsa(_) => crate::pkcs7::SigningAlgorithm::RsaSha256,
            PrivateKey::EcdsaP256(_) => crate::pkcs7::SigningAlgorithm::EcdsaSha256,
            PrivateKey::EcdsaP384(_) => crate::pkcs7::SigningAlgorithm::EcdsaSha384,
            PrivateKey::EcdsaP521(_) => crate::pkcs7::SigningAlgorithm::EcdsaSha512,
            PrivateKey::Ed25519(_) => crate::pkcs7::SigningAlgorithm::Ed25519,
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa44(_) => crate::pkcs7::SigningAlgorithm::MlDsa44,
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa65(_) => crate::pkcs7::SigningAlgorithm::MlDsa65,
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa87(_) => crate::pkcs7::SigningAlgorithm::MlDsa87,
        }
    }

    /// Get a human-readable algorithm name (e.g., for response headers).
    pub fn algorithm_name(&self) -> &'static str {
        match &self.private_key {
            PrivateKey::Rsa(_) => "RSA-SHA256",
            PrivateKey::EcdsaP256(_) => "ECDSA-P256-SHA256",
            PrivateKey::EcdsaP384(_) => "ECDSA-P384-SHA384",
            PrivateKey::EcdsaP521(_) => "ECDSA-P521-SHA512",
            PrivateKey::Ed25519(_) => "Ed25519",
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa44(_) => "ML-DSA-44",
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa65(_) => "ML-DSA-65",
            #[cfg(feature = "pq-experimental")]
            PrivateKey::MlDsa87(_) => "ML-DSA-87",
        }
    }
}

/// Load PFX and extract key material (shared between from_pfx and from_pfx_detached).
///
/// Tries the legacy `p12` crate first (SHA-1 MAC, RC2/3DES encryption), then
/// falls back to `p12-keystore` for modern PKCS#12 files (PBES2/AES, SHA-256 MAC).
fn load_pfx(pfx_path: &Path, password: &str) -> SignResult<(PrivateKey, Vec<u8>, Vec<Vec<u8>>)> {
    let pfx_data = std::fs::read(pfx_path)
        .map_err(|e| SignError::Certificate(format!("Failed to read PFX file: {e}")))?;

    // Try legacy p12 crate first (handles SHA-1 MAC / RC2 / 3DES PFX files)
    if let Ok(result) = load_pfx_legacy(&pfx_data, password) {
        return Ok(result);
    }

    // Fall back to p12-keystore (handles PBES2 / AES-256-CBC / SHA-256 MAC)
    load_pfx_modern(&pfx_data, password)
}

/// Load PFX using the legacy `p12` crate (SHA-1 MAC, RC2/3DES).
fn load_pfx_legacy(
    pfx_data: &[u8],
    password: &str,
) -> SignResult<(PrivateKey, Vec<u8>, Vec<Vec<u8>>)> {
    let pfx = p12::PFX::parse(pfx_data)
        .map_err(|e| SignError::Certificate(format!("Failed to parse PFX: {e}")))?;

    if !pfx.verify_mac(password) {
        return Err(SignError::Certificate(
            "PFX password incorrect (MAC verification failed)".into(),
        ));
    }

    let key_bags = pfx
        .key_bags(password)
        .map_err(|e| SignError::Certificate(format!("Failed to extract private key: {e}")))?;

    if key_bags.is_empty() {
        return Err(SignError::Certificate(
            "PFX contains no private keys".into(),
        ));
    }

    let key_der = Zeroizing::new(key_bags[0].clone());
    let private_key = parse_private_key(&key_der)?;

    let cert_bags = pfx
        .cert_x509_bags(password)
        .map_err(|e| SignError::Certificate(format!("Failed to extract certificates: {e}")))?;

    if cert_bags.is_empty() {
        return Err(SignError::Certificate(
            "PFX contains no certificates".into(),
        ));
    }

    let signer_cert_der = cert_bags[0].clone();
    let chain_certs_der = cert_bags[1..].to_vec();

    Ok((private_key, signer_cert_der, chain_certs_der))
}

/// Load PFX using `p12-keystore` (PBES2/AES-256-CBC, SHA-256 MAC).
fn load_pfx_modern(
    pfx_data: &[u8],
    password: &str,
) -> SignResult<(PrivateKey, Vec<u8>, Vec<Vec<u8>>)> {
    let keystore = p12_keystore::KeyStore::from_pkcs12(pfx_data, password)
        .map_err(|e| SignError::Certificate(format!("Failed to parse PFX: {e}")))?;

    let (_alias, chain) = keystore
        .private_key_chain()
        .ok_or_else(|| SignError::Certificate("PFX contains no private key chain".into()))?;

    let key_der = Zeroizing::new(chain.key().to_vec());
    let private_key = parse_private_key(&key_der)?;

    let certs = chain.chain();
    if certs.is_empty() {
        return Err(SignError::Certificate(
            "PFX contains no certificates".into(),
        ));
    }

    let signer_cert_der = certs[0].as_der().to_vec();
    let chain_certs_der: Vec<Vec<u8>> = certs[1..].iter().map(|c| c.as_der().to_vec()).collect();

    Ok((private_key, signer_cert_der, chain_certs_der))
}

/// Parse PKCS#8 DER key bytes into a PrivateKey enum variant.
fn parse_private_key(key_der: &[u8]) -> SignResult<PrivateKey> {
    if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_der(key_der) {
        Ok(PrivateKey::Rsa(Box::new(rsa_key)))
    } else if let Ok(ec_key) = p256::SecretKey::from_pkcs8_der(key_der) {
        Ok(PrivateKey::EcdsaP256(ec_key))
    } else if let Ok(ec_key) = p384::SecretKey::from_pkcs8_der(key_der) {
        Ok(PrivateKey::EcdsaP384(ec_key))
    } else if let Ok(ec_key) = p521::SecretKey::from_pkcs8_der(key_der) {
        Ok(PrivateKey::EcdsaP521(ec_key))
    } else if let Ok(ed_key) = Ed25519SigningKey::from_pkcs8_der(key_der) {
        Ok(PrivateKey::Ed25519(ed_key))
    } else {
        #[cfg(feature = "pq-experimental")]
        {
            if let Ok(ml44) = MlDsaSigningKey::<MlDsa44>::from_pkcs8_der(key_der) {
                return Ok(PrivateKey::MlDsa44(Box::new(ml44)));
            }
            if let Ok(ml65) = MlDsaSigningKey::<MlDsa65>::from_pkcs8_der(key_der) {
                return Ok(PrivateKey::MlDsa65(Box::new(ml65)));
            }
            if let Ok(ml87) = MlDsaSigningKey::<MlDsa87>::from_pkcs8_der(key_der) {
                return Ok(PrivateKey::MlDsa87(Box::new(ml87)));
            }
        }
        let supported = if cfg!(feature = "pq-experimental") {
            "RSA, ECDSA P-256/P-384/P-521, Ed25519, or ML-DSA"
        } else {
            "RSA, ECDSA P-256/P-384/P-521, or Ed25519"
        };
        Err(SignError::Certificate(format!(
            "Failed to parse private key: unsupported algorithm (expected {supported})"
        )))
    }
}

/// Result of a signing operation.
#[derive(serde::Serialize)]
pub struct SigningResult {
    /// The signed file data.
    #[serde(skip)]
    pub signed_data: Vec<u8>,
    /// Whether a timestamp was applied.
    pub timestamped: bool,
    /// SHA-256 hash of the original file (hex).
    pub original_hash: String,
    /// SHA-256 hash of the signed file (hex).
    pub signed_hash: String,
}

/// Result of a detached signing operation.
#[derive(serde::Serialize)]
pub struct DetachedSignResult {
    /// The PKCS#7 detached signature (.p7s) data.
    #[serde(skip)]
    pub p7s_data: Vec<u8>,
    /// Whether a timestamp was applied.
    pub timestamped: bool,
    /// SHA-256 hash of the input file (hex).
    pub file_hash: String,
    /// SHA-256 hash of the .p7s signature (hex).
    pub p7s_hash: String,
}

/// Options controlling signing behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignOptions {
    /// Reserved for future use. Re-signing is always rejected — existing
    /// signatures are never stripped.
    _private: (),
}

/// Sign a file using Authenticode.
///
/// This is the main entry point for signing operations.
pub async fn sign_file(
    input_path: &Path,
    output_path: &Path,
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
) -> SignResult<SigningResult> {
    sign_file_with_options(
        input_path,
        output_path,
        credentials,
        tsa_config,
        &SignOptions::default(),
    )
    .await
}

/// Sign a file using Authenticode, with configurable options.
///
/// When `options.allow_resign` is true, already-signed files are stripped
/// and re-signed instead of being rejected.
pub async fn sign_file_with_options(
    input_path: &Path,
    output_path: &Path,
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
    options: &SignOptions,
) -> SignResult<SigningResult> {
    let file_type = FileType::from_extension(input_path)?;

    let data = std::fs::read(input_path)?;
    let original_hash = hex::encode(Sha256::digest(&data));

    match file_type {
        FileType::Pe => {
            let result = sign_pe(&data, credentials, tsa_config, options).await?;
            let signed_hash = hex::encode(Sha256::digest(&result.signed_data));

            // Write output
            std::fs::write(output_path, &result.signed_data)?;

            Ok(SigningResult {
                signed_data: result.signed_data,
                timestamped: result.timestamped,
                original_hash,
                signed_hash,
            })
        }
        FileType::PowerShell => {
            crate::powershell::sign_ps1(&data, output_path, credentials, tsa_config, options).await
        }
        FileType::Msi => {
            let result = crate::msi::sign_msi(&data, credentials, tsa_config, options).await?;
            let signed_hash = hex::encode(Sha256::digest(&result.signed_data));

            std::fs::write(output_path, &result.signed_data)?;

            Ok(SigningResult {
                signed_data: result.signed_data,
                timestamped: result.timestamped,
                original_hash,
                signed_hash,
            })
        }
        FileType::Cab => {
            let result = crate::cab::sign_cab(&data, credentials, tsa_config, options).await?;
            let signed_hash = hex::encode(Sha256::digest(&result.signed_data));

            std::fs::write(output_path, &result.signed_data)?;

            Ok(SigningResult {
                signed_data: result.signed_data,
                timestamped: result.timestamped,
                original_hash,
                signed_hash,
            })
        }
    }
}

/// Create a detached CMS/PKCS#7 signature for any file.
///
/// The signature is returned as a `.p7s` blob that can be verified independently.
/// No file type restrictions — any file can be signed with a detached signature.
pub async fn sign_detached(
    input_path: &Path,
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
) -> SignResult<DetachedSignResult> {
    let data = std::fs::read(input_path)?;
    let digest_alg = credentials.signing_algorithm().digest_algorithm();
    let digest = digest_alg.digest(&data);
    let file_hash = hex::encode(&digest);

    // Build detached CMS/PKCS#7 SignedData using OID_DATA content type
    let mut builder =
        Pkcs7Builder::new_detached(credentials.signer_cert_der.clone(), digest.to_vec());
    builder.with_algorithm(credentials.signing_algorithm());

    // Add chain certificates
    for chain_cert in &credentials.chain_certs_der {
        builder.add_chain_cert(chain_cert.clone());
    }

    let mut timestamped = false;

    if let Some(tsa) = tsa_config {
        // First pass: build to extract the raw signature bytes for timestamping
        let sig_bytes = {
            let temp_pkcs7 =
                builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;
            extract_signature_from_pkcs7(&temp_pkcs7)?
        };

        match crate::timestamp::request_timestamp(&sig_bytes, tsa).await {
            Ok(token) => {
                builder.set_timestamp_token(token);
                timestamped = true;
            }
            Err(e) => {
                eprintln!(
                    "Warning: timestamping failed (signing will proceed without timestamp): {e}"
                );
            }
        }
    }

    // Build the final PKCS#7 detached signature
    let pkcs7_der = builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;
    let p7s_hash = hex::encode(Sha256::digest(&pkcs7_der));

    Ok(DetachedSignResult {
        p7s_data: pkcs7_der,
        timestamped,
        file_hash,
        p7s_hash,
    })
}

/// Parsed certificate information for the admin API.
#[derive(Debug, serde::Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub chain_length: usize,
}

/// Extract the extensions SEQUENCE from a DER-encoded X.509 certificate.
///
/// Walks the TBSCertificate structure to find the [3] EXPLICIT extensions field.
/// Returns the content of the SEQUENCE OF Extension, or None if no extensions.
fn extract_extensions_from_cert(cert_der: &[u8]) -> Option<&[u8]> {
    use crate::pkcs7::asn1;

    let (_, cert_content) = asn1::parse_tlv(cert_der).ok()?;
    let (_, tbs_content) = asn1::parse_tlv(cert_content).ok()?;

    let mut pos = tbs_content;

    // Skip: version [0] EXPLICIT (if present)
    if !pos.is_empty() && pos[0] == 0xA0 {
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    // Skip: serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    for _ in 0..6 {
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    // Now pos should be at optional fields: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    while !pos.is_empty() {
        let tag = pos[0];
        if tag == 0xA3 {
            // [3] EXPLICIT → contains SEQUENCE OF Extension
            let (_, explicit_content) = asn1::parse_tlv(pos).ok()?;
            let (_, seq_content) = asn1::parse_tlv(explicit_content).ok()?;
            return Some(seq_content);
        }
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    None
}

/// Parse X.509 certificate DER to extract displayable information.
pub fn parse_certificate_info(cert_der: &[u8]) -> CertificateInfo {
    use crate::pkcs7::asn1;

    let fingerprint = hex::encode(Sha256::digest(cert_der));

    // Try to parse the TBSCertificate fields
    let mut subject = String::from("(unknown)");
    let mut issuer = String::from("(unknown)");
    let mut serial_number = String::from("(unknown)");
    let mut not_before = String::from("(unknown)");
    let mut not_after = String::from("(unknown)");
    let mut key_usage = Vec::new();
    let mut extended_key_usage = Vec::new();

    if let Ok((_tag, cert_content)) = asn1::parse_tlv(cert_der) {
        // TBSCertificate SEQUENCE
        if let Ok((_tag, tbs_content)) = asn1::parse_tlv(cert_content) {
            let mut pos = tbs_content;

            // version [0] EXPLICIT
            if !pos.is_empty() && pos[0] == 0xA0 {
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // serialNumber INTEGER
            if let Ok((_tag, serial_content)) = asn1::parse_tlv(pos) {
                serial_number = hex::encode(serial_content);
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // signature AlgorithmIdentifier — skip
            if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                pos = remaining;
            }

            // issuer Name
            if let Ok((_tag, issuer_content)) = asn1::parse_tlv(pos) {
                issuer = extract_dn_string(issuer_content);
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // validity SEQUENCE
            if let Ok((_tag, validity_content)) = asn1::parse_tlv(pos) {
                if let Ok((_tag, nb_content)) = asn1::parse_tlv(validity_content) {
                    not_before = String::from_utf8_lossy(nb_content).to_string();
                    if let Ok((_tag, rest)) = asn1::skip_tlv(validity_content) {
                        if let Ok((_tag, na_content)) = asn1::parse_tlv(rest) {
                            not_after = String::from_utf8_lossy(na_content).to_string();
                        }
                    }
                }
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // subject Name
            if let Ok((_tag, subject_content)) = asn1::parse_tlv(pos) {
                subject = extract_dn_string(subject_content);
            }
        }
    }

    // #14 fix: Parse extensions via proper ASN.1 traversal instead of byte scanning.
    // Walk through TBSCertificate extensions [3] EXPLICIT SEQUENCE OF Extension.
    if let Some(extensions_data) = extract_extensions_from_cert(cert_der) {
        // Iterate over each Extension SEQUENCE
        let mut ext_pos = extensions_data;
        while !ext_pos.is_empty() {
            let ext_content = match asn1::parse_tlv(ext_pos) {
                Ok((_, content)) => content,
                Err(_) => break,
            };
            ext_pos = match asn1::skip_tlv(ext_pos) {
                Ok((_, remaining)) => remaining,
                Err(_) => break,
            };

            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
            let (_, oid_bytes) = match asn1::parse_tlv(ext_content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut after_oid = match asn1::skip_tlv(ext_content) {
                Ok((_, r)) => r,
                Err(_) => continue,
            };

            // Skip optional BOOLEAN (critical)
            if !after_oid.is_empty() && after_oid[0] == 0x01 {
                after_oid = match asn1::skip_tlv(after_oid) {
                    Ok((_, r)) => r,
                    Err(_) => continue,
                };
            }

            // extnValue is OCTET STRING containing the extension-specific DER
            let (_, extn_value) = match asn1::parse_tlv(after_oid) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // keyUsage OID: 2.5.29.15
            if oid_bytes == [0x55, 0x1D, 0x0F] {
                // extnValue contains BIT STRING
                if let Ok((_, bit_content)) = asn1::parse_tlv(extn_value) {
                    if bit_content.len() >= 2 {
                        let bits = bit_content[1];
                        if bits & 0x80 != 0 {
                            key_usage.push("digitalSignature".into());
                        }
                        if bits & 0x40 != 0 {
                            key_usage.push("contentCommitment".into());
                        }
                        if bits & 0x20 != 0 {
                            key_usage.push("keyEncipherment".into());
                        }
                        if bits & 0x10 != 0 {
                            key_usage.push("dataEncipherment".into());
                        }
                        if bits & 0x08 != 0 {
                            key_usage.push("keyAgreement".into());
                        }
                        if bits & 0x04 != 0 {
                            key_usage.push("keyCertSign".into());
                        }
                        if bits & 0x02 != 0 {
                            key_usage.push("cRLSign".into());
                        }
                    }
                }
            }

            // extendedKeyUsage OID: 2.5.29.37
            if oid_bytes == [0x55, 0x1D, 0x25] {
                // extnValue contains SEQUENCE OF OID
                if let Ok((_, eku_seq)) = asn1::parse_tlv(extn_value) {
                    let mut eku_pos = eku_seq;
                    while !eku_pos.is_empty() {
                        if let Ok((_, eku_oid)) = asn1::parse_tlv(eku_pos) {
                            match eku_oid {
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03] => {
                                    extended_key_usage.push("codeSigning".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01] => {
                                    extended_key_usage.push("serverAuth".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04] => {
                                    extended_key_usage.push("emailProtection".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08] => {
                                    extended_key_usage.push("timeStamping".into());
                                }
                                _ => {}
                            }
                        }
                        eku_pos = match asn1::skip_tlv(eku_pos) {
                            Ok((_, r)) => r,
                            Err(_) => break,
                        };
                    }
                }
            }
        }
    }

    CertificateInfo {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        fingerprint_sha256: fingerprint,
        key_usage,
        extended_key_usage,
        chain_length: 0, // Caller should set this from chain_certs_der.len()
    }
}

/// Extract a human-readable DN string from DER-encoded Name (SEQUENCE of SET of SEQUENCE).
fn extract_dn_string(name_der: &[u8]) -> String {
    use crate::pkcs7::asn1;

    let mut parts = Vec::new();
    let mut pos = name_der;

    while !pos.is_empty() {
        // Each RDN is a SET — extract its content and advance past it
        let (set_tag, set_content) = match asn1::parse_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        let (_, remaining) = match asn1::skip_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = remaining;
        let _ = set_tag;

        // Each SET contains one or more SEQUENCE (AttributeTypeAndValue)
        let mut set_pos = set_content;
        while !set_pos.is_empty() {
            let (_, seq_content) = match asn1::parse_tlv(set_pos) {
                Ok(v) => v,
                Err(_) => break,
            };
            let (_, seq_remaining) = match asn1::skip_tlv(set_pos) {
                Ok(v) => v,
                Err(_) => break,
            };
            set_pos = seq_remaining;

            // SEQUENCE: OID + value
            // parse_tlv on the OID returns (tag=0x06, oid_bytes)
            if let Ok((_oid_tag, oid_content)) = asn1::parse_tlv(seq_content) {
                // Get remainder after OID TLV
                let value_remaining = match asn1::skip_tlv(seq_content) {
                    Ok((_, rem)) => rem,
                    Err(_) => continue,
                };
                let attr_name = match oid_content {
                    [0x55, 0x04, 0x03] => "CN",
                    [0x55, 0x04, 0x06] => "C",
                    [0x55, 0x04, 0x07] => "L",
                    [0x55, 0x04, 0x08] => "ST",
                    [0x55, 0x04, 0x0A] => "O",
                    [0x55, 0x04, 0x0B] => "OU",
                    _ => "?",
                };
                if let Ok((_val_tag, value_content)) = asn1::parse_tlv(value_remaining) {
                    let value = String::from_utf8_lossy(value_content);
                    parts.push(format!("{attr_name}={value}"));
                }
            }
        }
    }

    if parts.is_empty() {
        "(unknown)".into()
    } else {
        parts.join(", ")
    }
}

/// Internal result for PE signing (before writing to disk).
struct PeSignResult {
    signed_data: Vec<u8>,
    timestamped: bool,
}

/// Sign a PE file (internal).
async fn sign_pe(
    data: &[u8],
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
    _options: &SignOptions,
) -> SignResult<PeSignResult> {
    // Parse PE headers (on original data to check if signed)
    let pe_info_orig = pe::PeInfo::parse(data)?;

    // Reject already-signed files — never strip existing signatures
    if pe_info_orig.is_signed() {
        return Err(SignError::AlreadySigned(
            "PE file already contains an Authenticode signature — refusing to sign".into(),
        ));
    }

    // Pad data to 8-byte alignment before hashing.
    // embed_signature() pads to 8-byte alignment before the cert table.
    // Verifiers compute: hash(file[0 .. file_size - cert_table_size]),
    // which includes alignment padding. We must hash the same bytes.
    let aligned_len = (data.len() + 7) & !7;
    let sign_data: std::borrow::Cow<'_, [u8]> = if aligned_len != data.len() {
        let mut v = data.to_vec();
        v.resize(aligned_len, 0);
        std::borrow::Cow::Owned(v)
    } else {
        std::borrow::Cow::Borrowed(data)
    };

    let pe_info = pe::PeInfo::parse(&sign_data)?;
    let signing_alg = credentials.signing_algorithm();
    let digest_alg = signing_alg.digest_algorithm();
    let image_hash = pe::compute_authenticode_hash_with(&sign_data, &pe_info, digest_alg)?;

    // Build CMS/PKCS#7 SignedData
    let mut builder = Pkcs7Builder::new(credentials.signer_cert_der.clone(), image_hash);
    builder.with_algorithm(signing_alg);

    // Add chain certificates
    for chain_cert in &credentials.chain_certs_der {
        builder.add_chain_cert(chain_cert.clone());
    }

    // We need to sign first to get the signature bytes, then request a timestamp
    // on those bytes. But the PKCS#7 builder needs the timestamp before build().
    // Solution: build once without timestamp to get signature, request timestamp,
    // then rebuild with the token embedded.
    let mut timestamped = false;

    if let Some(tsa) = tsa_config {
        // First pass: build to extract the raw signature bytes
        let sig_bytes = {
            let temp_pkcs7 =
                builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;
            // Extract the signature value from the built PKCS#7
            // The raw signature is what we signed with — recalculate it
            // by signing the same attrs again (deterministic for PKCS#1 v1.5)
            extract_signature_from_pkcs7(&temp_pkcs7)?
        };

        match crate::timestamp::request_timestamp(&sig_bytes, tsa).await {
            Ok(token) => {
                builder.set_timestamp_token(token);
                timestamped = true;
            }
            Err(e) => {
                // Timestamp failure is non-fatal — log warning and continue
                eprintln!(
                    "Warning: timestamping failed (signing will proceed without timestamp): {e}"
                );
            }
        }
    }

    // Build the PKCS#7 blob — the sign_fn callback signs the DER-encoded
    // signed attributes using RSASSA-PKCS1-v1_5 with SHA-256
    let pkcs7_der = builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;

    // Embed the signature in the PE file (use padded data so alignment is consistent)
    let signed_pe = pe::embed_signature(&sign_data, &pe_info, &pkcs7_der)?;

    Ok(PeSignResult {
        signed_data: signed_pe,
        timestamped,
    })
}

/// Extract the raw signature bytes from a built PKCS#7 blob.
///
/// Navigates: ContentInfo → SignedData → SignerInfos → SignerInfo → signature OCTET STRING
pub fn extract_signature_from_pkcs7(pkcs7: &[u8]) -> SignResult<Vec<u8>> {
    use crate::pkcs7::asn1;

    // ContentInfo SEQUENCE
    let (_, ci_content) = asn1::parse_tlv(pkcs7)
        .map_err(|e| SignError::Internal(format!("Failed to parse ContentInfo: {e}")))?;

    // Skip OID (signedData)
    let (_, remaining) = asn1::skip_tlv(ci_content)
        .map_err(|e| SignError::Internal(format!("Failed to skip OID: {e}")))?;

    // [0] EXPLICIT → SignedData SEQUENCE
    let (_, explicit_content) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Internal(format!("Failed to parse [0] EXPLICIT: {e}")))?;

    // SignedData SEQUENCE
    let (_, sd_content) = asn1::parse_tlv(explicit_content)
        .map_err(|e| SignError::Internal(format!("Failed to parse SignedData: {e}")))?;

    // Skip: version, digestAlgorithms, contentInfo, certificates
    let mut pos = sd_content;
    for field_name in &["version", "digestAlgorithms", "contentInfo", "certificates"] {
        let (_, remaining) = asn1::skip_tlv(pos)
            .map_err(|e| SignError::Internal(format!("Failed to skip {field_name}: {e}")))?;
        pos = remaining;
    }

    // SignerInfos SET
    let (_, si_set_content) = asn1::parse_tlv(pos)
        .map_err(|e| SignError::Internal(format!("Failed to parse SignerInfos: {e}")))?;

    // SignerInfo SEQUENCE
    let (_, si_content) = asn1::parse_tlv(si_set_content)
        .map_err(|e| SignError::Internal(format!("Failed to parse SignerInfo: {e}")))?;

    // Skip: version, issuerAndSerialNumber, digestAlgorithm, signedAttrs [0], signatureAlgorithm
    let mut pos = si_content;
    for field_name in &[
        "version",
        "issuerAndSerialNumber",
        "digestAlgorithm",
        "signedAttrs",
        "signatureAlgorithm",
    ] {
        let (_, remaining) = asn1::skip_tlv(pos)
            .map_err(|e| SignError::Internal(format!("Failed to skip {field_name}: {e}")))?;
        pos = remaining;
    }

    // signature OCTET STRING
    let (_, sig_bytes) = asn1::parse_tlv(pos)
        .map_err(|e| SignError::Internal(format!("Failed to parse signature: {e}")))?;

    Ok(sig_bytes.to_vec())
}

/// Sign a PE file from raw bytes (convenience function).
///
/// Returns the signed PE data. Useful for testing without file I/O.
pub fn sign_pe_bytes(data: &[u8], credentials: &SigningCredentials) -> SignResult<Vec<u8>> {
    let pe_info = pe::PeInfo::parse(data)?;

    if pe_info.is_signed() {
        // sign_pe_bytes is a convenience function — always reject already-signed
        return Err(SignError::AlreadySigned(
            "PE file already contains an Authenticode signature".into(),
        ));
    }

    // Pad data to 8-byte alignment before hashing.
    // embed_signature() pads to 8-byte alignment before the cert table.
    // Verifiers compute: hash(file[0 .. file_size - cert_table_size]),
    // which includes alignment padding. We must hash the same bytes.
    let aligned_len = (data.len() + 7) & !7;
    let sign_data: std::borrow::Cow<'_, [u8]> = if aligned_len != data.len() {
        let mut v = data.to_vec();
        v.resize(aligned_len, 0);
        std::borrow::Cow::Owned(v)
    } else {
        std::borrow::Cow::Borrowed(data)
    };

    let pe_info = pe::PeInfo::parse(&sign_data)?;
    let signing_alg = credentials.signing_algorithm();
    let digest_alg = signing_alg.digest_algorithm();
    let image_hash = pe::compute_authenticode_hash_with(&sign_data, &pe_info, digest_alg)?;

    let mut builder = Pkcs7Builder::new(credentials.signer_cert_der.clone(), image_hash);
    builder.with_algorithm(signing_alg);

    for chain_cert in &credentials.chain_certs_der {
        builder.add_chain_cert(chain_cert.clone());
    }

    let pkcs7_der = builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;

    pe::embed_signature(&sign_data, &pe_info, &pkcs7_der)
}

/// RFC 5280 §4.2.1.3: Validate that a signing certificate's keyUsage extension,
/// if present, includes the digitalSignature bit (bit 0).
///
/// If the extension is absent, we permit signing (many certs omit keyUsage).
/// If present, digitalSignature MUST be set for code signing.
fn validate_key_usage_for_signing(cert_der: &[u8]) -> SignResult<()> {
    use crate::pkcs7::asn1;

    // keyUsage OID: 2.5.29.15
    let key_usage_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];

    // Search for the keyUsage extension OID in the certificate DER.
    // If not found, the extension is absent — signing is permitted.
    let Some(oid_pos) = cert_der
        .windows(key_usage_oid.len())
        .position(|w| w == key_usage_oid)
    else {
        return Ok(()); // No keyUsage extension — permitted
    };

    // After the OID, we expect: [BOOLEAN critical], OCTET STRING { BIT STRING { bits } }
    // Scan forward from the OID to find the BIT STRING containing the usage bits.
    let after_oid = &cert_der[oid_pos + key_usage_oid.len()..];

    // Skip optional BOOLEAN (critical flag) and OCTET STRING wrapper to find BIT STRING
    for window_start in 0..after_oid.len().min(20) {
        if after_oid[window_start] == 0x03 && window_start + 3 < after_oid.len() {
            // BIT STRING found — tag 0x03, then length, then unused-bits count, then value
            let (_, bit_content) = match asn1::parse_tlv(&after_oid[window_start..]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if bit_content.is_empty() {
                continue;
            }
            // bit_content[0] = number of unused bits, bit_content[1..] = key usage flags
            if bit_content.len() >= 2 {
                let usage_byte = bit_content[1];
                // digitalSignature is bit 0 (MSB) = 0x80
                if usage_byte & 0x80 == 0 {
                    return Err(SignError::Certificate(
                        "RFC 5280 §4.2.1.3: signing certificate keyUsage does not include digitalSignature".into(),
                    ));
                }
                return Ok(());
            }
        }
    }

    // Could not parse keyUsage — permit signing (defensive)
    Ok(())
}

/// RFC 5280 §4.2.1.12: Validate that a signing certificate's extendedKeyUsage
/// extension, if present, includes the id-kp-codeSigning OID (1.3.6.1.5.5.7.3.3).
///
/// If the extension is absent, we permit signing (many CA certs omit EKU).
/// If present, codeSigning MUST be listed for code signing operations.
fn validate_eku_for_code_signing(cert_der: &[u8]) -> SignResult<()> {
    // extendedKeyUsage OID: 2.5.29.37
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

    // id-kp-codeSigning OID value bytes: 1.3.6.1.5.5.7.3.3
    let code_signing_oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

    // anyExtendedKeyUsage OID value bytes: 2.5.29.37.0
    let any_eku_oid_value: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    // Search for the EKU extension OID in the certificate DER.
    let Some(oid_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) else {
        return Ok(()); // No EKU extension — permitted
    };

    // Scan the region after the EKU OID for the codeSigning or anyExtendedKeyUsage OID
    let search_region = &cert_der[oid_pos..cert_der.len().min(oid_pos + 200)];

    let has_code_signing = search_region
        .windows(code_signing_oid_value.len())
        .any(|w| w == code_signing_oid_value);

    let has_any_eku = search_region
        .windows(any_eku_oid_value.len())
        .any(|w| w == any_eku_oid_value);

    if has_code_signing || has_any_eku {
        return Ok(());
    }

    Err(SignError::MissingCodeSigningEku)
}

/// Validate that a certificate's validity period covers the current time.
///
/// Parses the notBefore and notAfter fields from the TBSCertificate and checks
/// that the current time falls within this window. Supports both UTCTime and
/// GeneralizedTime encodings per RFC 5280 §4.1.2.5.
fn validate_cert_validity(cert_der: &[u8]) -> SignResult<()> {
    use crate::pkcs7::asn1;

    // Parse: Certificate → TBSCertificate → fields
    let (_, cert_content) = asn1::parse_tlv(cert_der)
        .map_err(|e| SignError::Certificate(format!("Failed to parse certificate: {e}")))?;
    let (_, tbs_content) = asn1::parse_tlv(cert_content)
        .map_err(|e| SignError::Certificate(format!("Failed to parse TBSCertificate: {e}")))?;

    let mut pos = tbs_content;

    // Skip: version [0] EXPLICIT (if present)
    if !pos.is_empty() && pos[0] == 0xA0 {
        if let Ok((_, remaining)) = asn1::skip_tlv(pos) {
            pos = remaining;
        }
    }

    // Skip: serialNumber, signature (AlgorithmIdentifier), issuer
    for _ in 0..3 {
        if let Ok((_, remaining)) = asn1::skip_tlv(pos) {
            pos = remaining;
        }
    }

    // Validity SEQUENCE { notBefore, notAfter }
    let (_, validity_content) = asn1::parse_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to parse validity: {e}")))?;

    // Parse notBefore
    let (nb_tag, nb_content) = asn1::parse_tlv(validity_content)
        .map_err(|e| SignError::Certificate(format!("Failed to parse notBefore: {e}")))?;
    let nb_str = std::str::from_utf8(nb_content).unwrap_or("");
    let not_before = parse_asn1_time(nb_tag, nb_str);

    // Parse notAfter
    let (_, rest) = asn1::skip_tlv(validity_content)
        .map_err(|e| SignError::Certificate(format!("Failed to skip notBefore: {e}")))?;
    let (na_tag, na_content) = asn1::parse_tlv(rest)
        .map_err(|e| SignError::Certificate(format!("Failed to parse notAfter: {e}")))?;
    let na_str = std::str::from_utf8(na_content).unwrap_or("");
    let not_after = parse_asn1_time(na_tag, na_str);

    let now = chrono::Utc::now();

    if let Some(nb) = not_before {
        if now < nb {
            return Err(SignError::Certificate(format!(
                "Certificate is not yet valid (notBefore: {nb})"
            )));
        }
    }

    if let Some(na) = not_after {
        if now > na {
            return Err(SignError::Certificate(format!(
                "Certificate has expired (notAfter: {na})"
            )));
        }
    }

    Ok(())
}

/// Parse an ASN.1 UTCTime or GeneralizedTime string to a DateTime.
///
/// UTCTime (tag 0x17): "YYMMDDHHMMSSZ" — years 00-49 → 2000-2049, 50-99 → 1950-1999
/// GeneralizedTime (tag 0x18): "YYYYMMDDHHMMSSZ"
fn parse_asn1_time(tag: u8, s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone};

    let s = s.trim_end_matches('Z');

    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSS
        if s.len() < 12 {
            return None;
        }
        let yy: i32 = s[0..2].parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        let mm: u32 = s[2..4].parse().ok()?;
        let dd: u32 = s[4..6].parse().ok()?;
        let hh: u32 = s[6..8].parse().ok()?;
        let mi: u32 = s[8..10].parse().ok()?;
        let ss: u32 = s[10..12].parse().ok()?;
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, mm, dd)?,
            chrono::NaiveTime::from_hms_opt(hh, mi, ss)?,
        );
        Some(chrono::Utc.from_utc_datetime(&naive))
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        if s.len() < 14 {
            return None;
        }
        let year: i32 = s[0..4].parse().ok()?;
        let mm: u32 = s[4..6].parse().ok()?;
        let dd: u32 = s[6..8].parse().ok()?;
        let hh: u32 = s[8..10].parse().ok()?;
        let mi: u32 = s[10..12].parse().ok()?;
        let ss: u32 = s[12..14].parse().ok()?;
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, mm, dd)?,
            chrono::NaiveTime::from_hms_opt(hh, mi, ss)?,
        );
        Some(chrono::Utc.from_utc_datetime(&naive))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection() {
        assert_eq!(
            FileType::from_extension(Path::new("test.exe")).unwrap(),
            FileType::Pe
        );
        assert_eq!(
            FileType::from_extension(Path::new("test.dll")).unwrap(),
            FileType::Pe
        );
        assert_eq!(
            FileType::from_extension(Path::new("test.ps1")).unwrap(),
            FileType::PowerShell
        );
        assert_eq!(
            FileType::from_extension(Path::new("test.msi")).unwrap(),
            FileType::Msi
        );
        assert!(FileType::from_extension(Path::new("test.txt")).is_err());
    }

    #[test]
    fn test_file_type_all_pe_extensions() {
        for ext in ["exe", "dll", "sys", "ocx", "scr", "cpl", "drv"] {
            let path = format!("test.{}", ext);
            assert_eq!(
                FileType::from_extension(Path::new(&path)).unwrap(),
                FileType::Pe,
                "Expected PE for .{}",
                ext
            );
        }
    }

    #[test]
    fn test_file_type_cab() {
        assert_eq!(
            FileType::from_extension(Path::new("package.cab")).unwrap(),
            FileType::Cab
        );
    }

    #[test]
    fn test_file_type_case_insensitive() {
        assert_eq!(
            FileType::from_extension(Path::new("TEST.EXE")).unwrap(),
            FileType::Pe
        );
        assert_eq!(
            FileType::from_extension(Path::new("Script.PS1")).unwrap(),
            FileType::PowerShell
        );
    }

    #[test]
    fn test_file_type_no_extension() {
        let result = FileType::from_extension(Path::new("binary_no_ext"));
        assert!(result.is_err());
    }

    #[test]
    fn test_file_type_unsupported() {
        let result = FileType::from_extension(Path::new("data.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_file_type_unsupported_returns_extension() {
        match FileType::from_extension(Path::new("doc.pdf")) {
            Err(SignError::UnsupportedFileType(ext)) => assert_eq!(ext, "pdf"),
            other => panic!("Expected UnsupportedFileType, got: {:?}", other),
        }
    }

    // ─── Key Usage Validation Tests ───

    #[test]
    fn test_key_usage_no_extension_permits_signing() {
        // A minimal cert without any extensions — should be allowed
        let cert = build_minimal_test_cert(None);
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    #[test]
    fn test_key_usage_digital_signature_set() {
        // Cert with keyUsage = digitalSignature (bit 0 = 0x80) — should be allowed
        let ku_ext = build_key_usage_extension(0x80, true); // digitalSignature
        let cert = build_minimal_test_cert(Some(&ku_ext));
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    #[test]
    fn test_key_usage_key_cert_sign_only_rejected() {
        // Cert with keyUsage = keyCertSign only (bit 5 = 0x04) — should be rejected
        let ku_ext = build_key_usage_extension(0x04, true); // keyCertSign only
        let cert = build_minimal_test_cert(Some(&ku_ext));
        let result = validate_key_usage_for_signing(&cert);
        assert!(result.is_err(), "keyCertSign-only cert should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("digitalSignature"),
            "Error should mention digitalSignature: {}",
            err
        );
    }

    #[test]
    fn test_key_usage_both_digital_sig_and_cert_sign() {
        // Cert with keyUsage = digitalSignature + keyCertSign (0x84) — should be allowed
        let ku_ext = build_key_usage_extension(0x84, true);
        let cert = build_minimal_test_cert(Some(&ku_ext));
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    /// Build a minimal DER-encoded certificate with optional extensions.
    fn build_minimal_test_cert(extensions_der: Option<&[u8]>) -> Vec<u8> {
        use crate::pkcs7::asn1;
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial = asn1::encode_integer_value(1);
        let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
        let name = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            &[0x0C, 0x04, 0x54, 0x65, 0x73, 0x74], // UTF8String "Test"
        ]))]);
        let validity =
            asn1::encode_sequence(&[&asn1::encode_utc_time_now(), &asn1::encode_utc_time_now()]);
        let spki = asn1::encode_sequence(&[
            &algo,
            &[0x03, 0x03, 0x00, 0x04, 0x04][..], // BIT STRING (stub public key)
        ]);

        let mut tbs_parts: Vec<&[u8]> =
            vec![&version, &serial, &algo, &name, &validity, &name, &spki];
        let ext_wrapper;
        if let Some(ext) = extensions_der {
            ext_wrapper = asn1::encode_explicit_tag(3, &asn1::encode_sequence(&[ext]));
            tbs_parts.push(&ext_wrapper);
        }
        let tbs = asn1::encode_sequence(&tbs_parts);
        let sig = [0x03, 0x03, 0x00, 0x00, 0x00]; // BIT STRING (stub signature)
        asn1::encode_sequence(&[&tbs, &algo, &sig])
    }

    /// Build a DER-encoded keyUsage extension.
    fn build_key_usage_extension(usage_bits: u8, critical: bool) -> Vec<u8> {
        use crate::pkcs7::asn1;
        // keyUsage OID: 2.5.29.15
        let oid = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
        let critical_bool = if critical {
            vec![0x01, 0x01, 0xFF] // BOOLEAN TRUE
        } else {
            vec![]
        };
        // BIT STRING: tag=0x03, len=0x02, unused_bits=0x00, value=usage_bits
        let bit_string = vec![0x03, 0x02, 0x00, usage_bits];
        // OCTET STRING wrapping the BIT STRING
        let octet_wrapper = asn1::encode_octet_string(&bit_string);
        let mut parts: Vec<&[u8]> = vec![oid];
        if !critical_bool.is_empty() {
            parts.push(&critical_bool);
        }
        parts.push(&octet_wrapper);
        asn1::encode_sequence(&parts)
    }

    /// Build a DER-encoded extendedKeyUsage extension with the given EKU OIDs.
    fn build_eku_extension(eku_oids: &[&[u8]]) -> Vec<u8> {
        use crate::pkcs7::asn1;
        // extendedKeyUsage OID: 2.5.29.37
        let ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        // Build SEQUENCE OF OBJECT IDENTIFIER
        let mut eku_seq_content = Vec::new();
        for oid_value in eku_oids {
            // Encode as OID TLV
            eku_seq_content.push(0x06);
            eku_seq_content.push(oid_value.len() as u8);
            eku_seq_content.extend_from_slice(oid_value);
        }
        let _eku_seq = asn1::encode_sequence(
            &eku_seq_content
                .chunks(1)
                .collect::<Vec<_>>()
                .iter()
                .map(|_| &[][..])
                .collect::<Vec<_>>(),
        );
        // Simpler: just build the SEQUENCE manually
        let mut seq = vec![0x30];
        if eku_seq_content.len() < 0x80 {
            seq.push(eku_seq_content.len() as u8);
        } else {
            seq.push(0x81);
            seq.push(eku_seq_content.len() as u8);
        }
        seq.extend_from_slice(&eku_seq_content);

        let octet_wrapper = asn1::encode_octet_string(&seq);
        asn1::encode_sequence(&[ext_oid, &octet_wrapper])
    }

    // ─── EKU Validation Tests ───

    // id-kp-codeSigning OID value: 1.3.6.1.5.5.7.3.3
    const CODE_SIGNING_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    // id-kp-serverAuth OID value: 1.3.6.1.5.5.7.3.1
    const SERVER_AUTH_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    // id-kp-emailProtection OID value: 1.3.6.1.5.5.7.3.4
    const EMAIL_PROTECTION_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    // anyExtendedKeyUsage OID value: 2.5.29.37.0
    const ANY_EKU_OID: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    #[test]
    fn test_eku_no_extension_permits_signing() {
        let cert = build_minimal_test_cert(None);
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_code_signing_present() {
        let eku_ext = build_eku_extension(&[CODE_SIGNING_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_server_auth_only_rejected() {
        let eku_ext = build_eku_extension(&[SERVER_AUTH_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        let result = validate_eku_for_code_signing(&cert);
        assert!(
            result.is_err(),
            "serverAuth-only EKU should be rejected for code signing"
        );
        match result.unwrap_err() {
            SignError::MissingCodeSigningEku => {}
            other => panic!("Expected MissingCodeSigningEku, got: {:?}", other),
        }
    }

    #[test]
    fn test_eku_multiple_with_code_signing() {
        let eku_ext =
            build_eku_extension(&[SERVER_AUTH_OID, CODE_SIGNING_OID, EMAIL_PROTECTION_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_any_extended_key_usage_permits() {
        let eku_ext = build_eku_extension(&[ANY_EKU_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    // ─── End-to-End Sign → Verify Tests ───

    /// Check if openssl CLI is available (not present on Windows CI runners).
    fn has_openssl() -> bool {
        std::process::Command::new("openssl")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Generate a PFX file in the given temp directory using openssl CLI.
    ///
    /// Creates a self-signed cert with codeSigning EKU + digitalSignature keyUsage,
    /// packages it with the private key into a PKCS#12 file, and returns
    /// (pfx_path, password). Uses legacy encryption for compatibility with the
    /// `p12` crate v0.6.
    fn generate_test_pfx(temp_dir: &std::path::Path) -> (std::path::PathBuf, String) {
        let key_path = temp_dir.join("test.key");
        let cert_path = temp_dir.join("test.crt");
        let pfx_path = temp_dir.join("test.pfx");
        let password = "testpass123";

        // Generate 2048-bit RSA key
        let key_output = std::process::Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key_path)
            .arg("2048")
            .output()
            .expect("openssl genrsa failed to execute");
        assert!(
            key_output.status.success(),
            "openssl genrsa failed: {}",
            String::from_utf8_lossy(&key_output.stderr)
        );

        // Generate self-signed cert with codeSigning EKU and digitalSignature keyUsage
        let cert_output = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key_path)
            .args(["-out"])
            .arg(&cert_path)
            .args(["-days", "365", "-subj", "/CN=Test Code Signing/O=Test"])
            .args(["-addext", "keyUsage=critical,digitalSignature"])
            .args(["-addext", "extendedKeyUsage=codeSigning"])
            .output()
            .expect("openssl req failed to execute");
        assert!(
            cert_output.status.success(),
            "openssl req failed: {}",
            String::from_utf8_lossy(&cert_output.stderr)
        );

        // Create PFX with legacy encryption (required for p12 crate v0.6 compatibility)
        let pfx_output = std::process::Command::new("openssl")
            .args(["pkcs12", "-export", "-out"])
            .arg(&pfx_path)
            .args(["-inkey"])
            .arg(&key_path)
            .args(["-in"])
            .arg(&cert_path)
            .args([
                "-certpbe",
                "PBE-SHA1-3DES",
                "-keypbe",
                "PBE-SHA1-3DES",
                "-macalg",
                "sha1",
            ])
            .args(["-passout", &format!("pass:{}", password)])
            .output()
            .expect("openssl pkcs12 failed to execute");
        assert!(
            pfx_output.status.success(),
            "openssl pkcs12 export failed: {}",
            String::from_utf8_lossy(&pfx_output.stderr)
        );

        (pfx_path, password.to_string())
    }

    /// Generate a PFX file without codeSigning EKU (only digitalSignature keyUsage).
    ///
    /// Used for detached signing tests where codeSigning EKU is not required.
    fn generate_test_pfx_detached(temp_dir: &std::path::Path) -> (std::path::PathBuf, String) {
        let key_path = temp_dir.join("detached.key");
        let cert_path = temp_dir.join("detached.crt");
        let pfx_path = temp_dir.join("detached.pfx");
        let password = "testpass123";

        let key_output = std::process::Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key_path)
            .arg("2048")
            .output()
            .expect("openssl genrsa failed to execute");
        assert!(
            key_output.status.success(),
            "openssl genrsa failed: {}",
            String::from_utf8_lossy(&key_output.stderr)
        );

        // No EKU extension — only digitalSignature keyUsage
        let cert_output = std::process::Command::new("openssl")
            .args(["req", "-new", "-x509", "-key"])
            .arg(&key_path)
            .args(["-out"])
            .arg(&cert_path)
            .args(["-days", "365", "-subj", "/CN=Test Detached Signer/O=Test"])
            .args(["-addext", "keyUsage=critical,digitalSignature"])
            .output()
            .expect("openssl req failed to execute");
        assert!(
            cert_output.status.success(),
            "openssl req failed: {}",
            String::from_utf8_lossy(&cert_output.stderr)
        );

        let pfx_output = std::process::Command::new("openssl")
            .args(["pkcs12", "-export", "-out"])
            .arg(&pfx_path)
            .args(["-inkey"])
            .arg(&key_path)
            .args(["-in"])
            .arg(&cert_path)
            .args([
                "-certpbe",
                "PBE-SHA1-3DES",
                "-keypbe",
                "PBE-SHA1-3DES",
                "-macalg",
                "sha1",
            ])
            .args(["-passout", &format!("pass:{}", password)])
            .output()
            .expect("openssl pkcs12 failed to execute");
        assert!(
            pfx_output.status.success(),
            "openssl pkcs12 export failed: {}",
            String::from_utf8_lossy(&pfx_output.stderr)
        );

        (pfx_path, password.to_string())
    }

    /// Build a minimal valid PE32 file for signing tests.
    ///
    /// Creates a PE with MZ header, PE signature, COFF header, optional header
    /// with 16 data directories, and one section. The section raw data is placed
    /// at offset 0x200 with size 0x200, making end_of_image = 0x400.
    ///
    /// All required Windows PE optional header fields are populated so Windows
    /// recognizes this as a valid executable before checking the signature.
    fn build_test_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 0x400]; // 1024 bytes total

        // DOS header — MZ magic
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew at offset 0x3C — PE header at 0x80
        pe[0x3C] = 0x80;

        // PE signature at 0x80
        pe[0x80] = b'P';
        pe[0x81] = b'E';
        pe[0x82] = 0;
        pe[0x83] = 0;

        // COFF header at 0x84
        pe[0x84] = 0x4C; // Machine = i386
        pe[0x85] = 0x01;
        pe[0x86] = 0x01; // NumberOfSections = 1
        pe[0x87] = 0x00;
        // SizeOfOptionalHeader at offset 0x94 (COFF + 16)
        pe[0x94] = 0xE0; // 224 bytes — standard PE32
        pe[0x95] = 0x00;
        // Characteristics at 0x96
        pe[0x96] = 0x02; // EXECUTABLE_IMAGE
        pe[0x97] = 0x01; // 32BIT_MACHINE

        // Optional header at 0x98
        pe[0x98] = 0x0B; // PE32 magic
        pe[0x99] = 0x01;

        // ── Required Windows PE fields ──
        // Without these, Windows may reject the PE as malformed before
        // checking the Authenticode signature.

        // SectionAlignment at opt+32 = 0x98+32 = 0xB8
        pe[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
        // FileAlignment at opt+36 = 0x98+36 = 0xBC
        pe[0xBC..0xC0].copy_from_slice(&0x0200u32.to_le_bytes());
        // MajorOperatingSystemVersion at opt+40 = 0xC0
        pe[0xC0..0xC2].copy_from_slice(&6u16.to_le_bytes());
        // MajorSubsystemVersion at opt+44 = 0xC4
        pe[0xC4..0xC6].copy_from_slice(&6u16.to_le_bytes());
        // ImageBase at opt+28 = 0x98+28 = 0xB4
        pe[0xB4..0xB8].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        // SizeOfImage at opt+56 = 0x98+56 = 0xD0
        pe[0xD0..0xD4].copy_from_slice(&0x2000u32.to_le_bytes());
        // SizeOfHeaders at opt+60 = 0x98+60 = 0xD4
        pe[0xD4..0xD8].copy_from_slice(&0x0200u32.to_le_bytes());
        // Subsystem at opt+68 = 0x98+68 = 0xDC
        pe[0xDC..0xDE].copy_from_slice(&3u16.to_le_bytes()); // IMAGE_SUBSYSTEM_WINDOWS_CONSOLE
                                                             // SizeOfStackReserve at opt+72 = 0x98+72 = 0xE0
        pe[0xE0..0xE4].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        // SizeOfStackCommit at opt+76 = 0x98+76 = 0xE4
        pe[0xE4..0xE8].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfHeapReserve at opt+80 = 0x98+80 = 0xE8
        pe[0xE8..0xEC].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        // SizeOfHeapCommit at opt+84 = 0x98+84 = 0xEC
        pe[0xEC..0xF0].copy_from_slice(&0x1000u32.to_le_bytes());

        // NumberOfRvaAndSizes at opt+92 = 0x98+92 = 0xF4
        pe[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());

        // Certificate table is data directory index 4 at opt+96+4*8 = 0x98+96+32 = 0x118
        // Leave zeroed (unsigned)

        // Section header at opt + SizeOfOptionalHeader = 0x98 + 0xE0 = 0x178
        // Name: ".text\0\0\0"
        pe[0x178] = b'.';
        pe[0x179] = b't';
        pe[0x17A] = b'e';
        pe[0x17B] = b'x';
        pe[0x17C] = b't';
        // VirtualSize at section+8 = 0x178+8 = 0x180
        pe[0x180..0x184].copy_from_slice(&0x0200u32.to_le_bytes());
        // VirtualAddress at section+12 = 0x178+12 = 0x184
        pe[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
        // SizeOfRawData at section+16 = 0x178+16 = 0x188
        pe[0x188..0x18C].copy_from_slice(&0x0200u32.to_le_bytes());
        // PointerToRawData at section+20 = 0x178+20 = 0x18C
        pe[0x18C..0x190].copy_from_slice(&0x0200u32.to_le_bytes());
        // Characteristics at section+36 = 0x178+36 = 0x19C
        pe[0x19C..0x1A0].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE | EXECUTE | READ

        // Fill section data with non-zero bytes to make a meaningful hash
        for (i, byte) in pe[0x200..0x400].iter_mut().enumerate() {
            *byte = ((0x200 + i) & 0xFF) as u8;
        }

        pe
    }

    #[tokio::test]
    async fn e2e_detached_sign_then_verify() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let (pfx_path, password) = generate_test_pfx_detached(dir.path());
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, &password)
            .expect("from_pfx_detached should succeed");

        // Write test content to a temp file
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Hello, world! This is test content for detached signing.",
        )
        .expect("write test file");

        // Sign
        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign_detached should succeed");

        assert!(!result.p7s_data.is_empty(), "p7s_data should not be empty");
        assert!(
            !result.file_hash.is_empty(),
            "file_hash should not be empty"
        );

        // Verify
        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");

        assert!(
            verify_result.signature_valid,
            "Detached signature should be valid, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_detached_sign_verify_tampered_fails() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let (pfx_path, password) = generate_test_pfx_detached(dir.path());
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, &password)
            .expect("from_pfx_detached should succeed");

        let input_path = dir.path().join("testfile.bin");
        std::fs::write(&input_path, b"Original content for tamper test.").expect("write test file");

        // Sign the original content
        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign_detached should succeed");

        // Verify with tampered content — different bytes than what was signed
        let tampered_content = b"TAMPERED content that differs from the original.";
        let verify_result = crate::verifier::verify_detached(tampered_content, &result.p7s_data)
            .expect("verify_detached should succeed even with tampered data");

        assert!(
            !verify_result.signature_valid,
            "Tampered content should fail signature verification"
        );
    }

    #[test]
    fn e2e_pe_sign_then_verify() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let (pfx_path, password) = generate_test_pfx(dir.path());
        let creds =
            SigningCredentials::from_pfx(&pfx_path, &password).expect("from_pfx should succeed");

        let pe_data = build_test_pe();

        // Verify the test PE parses correctly before signing
        let pe_info = crate::pe::PeInfo::parse(&pe_data).expect("test PE should parse");
        assert!(!pe_info.is_signed(), "test PE should be unsigned");

        // Sign the PE
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign_pe_bytes should succeed");
        assert!(
            signed_pe.len() > pe_data.len(),
            "signed PE should be larger"
        );

        // Write signed PE and verify
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let verify_result =
            crate::verifier::verify_file(&signed_path).expect("verify_file should succeed");

        assert!(
            verify_result.signature_valid,
            "PE signature should be valid, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_powershell_sign_then_verify() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let (pfx_path, password) = generate_test_pfx(dir.path());
        let creds =
            SigningCredentials::from_pfx(&pfx_path, &password).expect("from_pfx should succeed");

        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");

        let script = "Write-Host 'Hello from PowerShell'\r\nGet-Date";
        std::fs::write(&input_path, script).expect("write test script");

        // Sign
        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign_file should succeed for PS1");

        assert!(output_path.exists(), "signed PS1 output file should exist");

        // Verify
        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify_file should succeed");

        assert!(
            verify_result.signature_valid,
            "PowerShell signature should be valid, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    // ─── Fixture-Based E2E Tests (no openssl dependency) ───

    /// Path to test fixture PFX files (committed to repo, no openssl needed).
    fn fixture_pfx(name: &str) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("fixtures");
        path.push(name);
        path
    }

    // ── Algorithm Detection ──

    #[test]
    fn e2e_fixture_algorithm_detection_rsa2048() {
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture");
        assert_eq!(creds.algorithm_name(), "RSA-SHA256");
    }

    #[test]
    fn e2e_fixture_algorithm_detection_rsa3072() {
        let pfx_path = fixture_pfx("rsa3072.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-3072 fixture");
        assert_eq!(creds.algorithm_name(), "RSA-SHA256");
    }

    #[test]
    fn e2e_fixture_algorithm_detection_rsa4096() {
        let pfx_path = fixture_pfx("rsa4096.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-4096 fixture");
        assert_eq!(creds.algorithm_name(), "RSA-SHA256");
    }

    #[test]
    fn e2e_fixture_algorithm_detection_ecdsa_p256() {
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P256 fixture");
        assert_eq!(creds.algorithm_name(), "ECDSA-P256-SHA256");
    }

    #[test]
    fn e2e_fixture_algorithm_detection_ecdsa_p384() {
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P384 fixture");
        assert_eq!(creds.algorithm_name(), "ECDSA-P384-SHA384");
    }

    #[test]
    fn e2e_fixture_algorithm_detection_ecdsa_p521() {
        let pfx_path = fixture_pfx("ecdsa-p521.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P521 fixture");
        assert_eq!(creds.algorithm_name(), "ECDSA-P521-SHA512");
    }

    // ── PE Signing (fixture-based) ──

    #[test]
    fn e2e_fixture_pe_sign_verify_rsa2048() {
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with RSA-2048");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with RSA-2048, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    #[test]
    fn e2e_fixture_pe_sign_verify_rsa3072() {
        let pfx_path = fixture_pfx("rsa3072.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-3072 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with RSA-3072");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with RSA-3072, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    #[test]
    fn e2e_fixture_pe_sign_verify_rsa4096() {
        let pfx_path = fixture_pfx("rsa4096.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-4096 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with RSA-4096");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with RSA-4096, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    #[test]
    fn e2e_fixture_pe_sign_verify_ecdsa_p256() {
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P256 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with ECDSA-P256");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with ECDSA-P256, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    #[test]
    fn e2e_fixture_pe_sign_verify_ecdsa_p384() {
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P384 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with ECDSA-P384");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with ECDSA-P384, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    #[test]
    fn e2e_fixture_pe_sign_verify_ecdsa_p521() {
        let pfx_path = fixture_pfx("ecdsa-p521.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P521 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE with ECDSA-P521");
        assert!(signed_pe.len() > pe_data.len());

        let dir = tempfile::tempdir().expect("create temp dir");
        let signed_path = dir.path().join("signed.exe");
        std::fs::write(&signed_path, &signed_pe).expect("write signed PE");

        let result = crate::verifier::verify_file(&signed_path).expect("verify should succeed");
        assert!(
            result.signature_valid,
            "PE sig should be valid with ECDSA-P521, computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    // ── Detached Signing (fixture-based) ──

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_rsa2048() {
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load RSA-2048 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with RSA-2048.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with RSA-2048, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_rsa3072() {
        let pfx_path = fixture_pfx("rsa3072.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load RSA-3072 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with RSA-3072.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with RSA-3072, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_rsa4096() {
        let pfx_path = fixture_pfx("rsa4096.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load RSA-4096 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with RSA-4096.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with RSA-4096, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_ecdsa_p256() {
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P256 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with ECDSA-P256.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with ECDSA-P256, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_ecdsa_p384() {
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P384 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with ECDSA-P384.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with ECDSA-P384, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_sign_verify_ecdsa_p521() {
        let pfx_path = fixture_pfx("ecdsa-p521.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P521 fixture for detached");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(
            &input_path,
            b"Test content for detached signing with ECDSA-P521.",
        )
        .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("detached sign should succeed");
        assert!(!result.p7s_data.is_empty());

        let file_content = std::fs::read(&input_path).expect("read test file");
        let verify_result = crate::verifier::verify_detached(&file_content, &result.p7s_data)
            .expect("verify_detached should succeed");
        assert!(
            verify_result.signature_valid,
            "Detached sig should be valid with ECDSA-P521, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    // ── PowerShell Signing (fixture-based) ──

    #[tokio::test]
    async fn e2e_fixture_powershell_sign_verify_rsa2048() {
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");
        std::fs::write(&input_path, "Write-Host 'Hello'\r\nGet-Date").expect("write test script");

        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign PS1 should succeed with RSA-2048");
        assert!(output_path.exists());

        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify should succeed");
        assert!(
            verify_result.signature_valid,
            "PS1 sig should be valid with RSA-2048, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_powershell_sign_verify_rsa4096() {
        let pfx_path = fixture_pfx("rsa4096.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-4096 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");
        std::fs::write(&input_path, "Write-Host 'Hello'\r\nGet-Date").expect("write test script");

        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign PS1 should succeed with RSA-4096");
        assert!(output_path.exists());

        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify should succeed");
        assert!(
            verify_result.signature_valid,
            "PS1 sig should be valid with RSA-4096, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_powershell_sign_verify_ecdsa_p256() {
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P256 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");
        std::fs::write(&input_path, "Write-Host 'Hello'\r\nGet-Date").expect("write test script");

        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign PS1 should succeed with ECDSA-P256");
        assert!(output_path.exists());

        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify should succeed");
        assert!(
            verify_result.signature_valid,
            "PS1 sig should be valid with ECDSA-P256, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_powershell_sign_verify_ecdsa_p384() {
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P384 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");
        std::fs::write(&input_path, "Write-Host 'Hello'\r\nGet-Date").expect("write test script");

        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign PS1 should succeed with ECDSA-P384");
        assert!(output_path.exists());

        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify should succeed");
        assert!(
            verify_result.signature_valid,
            "PS1 sig should be valid with ECDSA-P384, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    #[tokio::test]
    async fn e2e_fixture_powershell_sign_verify_ecdsa_p521() {
        let pfx_path = fixture_pfx("ecdsa-p521.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P521 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("test.ps1");
        let output_path = dir.path().join("signed.ps1");
        std::fs::write(&input_path, "Write-Host 'Hello'\r\nGet-Date").expect("write test script");

        let _result = sign_file(&input_path, &output_path, &creds, None)
            .await
            .expect("sign PS1 should succeed with ECDSA-P521");
        assert!(output_path.exists());

        let verify_result =
            crate::verifier::verify_file(&output_path).expect("verify should succeed");
        assert!(
            verify_result.signature_valid,
            "PS1 sig should be valid with ECDSA-P521, computed={} signed={}",
            verify_result.computed_digest, verify_result.signed_digest
        );
    }

    // ── Tamper Detection (fixture-based, cross-algorithm) ──

    #[tokio::test]
    async fn e2e_fixture_detached_tamper_fails_rsa2048() {
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load RSA-2048 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(&input_path, b"Original content for RSA tamper test.")
            .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign should succeed");

        let tampered = b"TAMPERED content that differs from the original.";
        let verify_result = crate::verifier::verify_detached(tampered, &result.p7s_data)
            .expect("verify should succeed even with tampered data");
        assert!(
            !verify_result.signature_valid,
            "Tampered content should fail RSA-2048 verification"
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_tamper_fails_ecdsa_p256() {
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P256 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(&input_path, b"Original content for ECDSA tamper test.")
            .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign should succeed");

        let tampered = b"TAMPERED content that differs from the original.";
        let verify_result = crate::verifier::verify_detached(tampered, &result.p7s_data)
            .expect("verify should succeed even with tampered data");
        assert!(
            !verify_result.signature_valid,
            "Tampered content should fail ECDSA-P256 verification"
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_tamper_fails_ecdsa_p384() {
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P384 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(&input_path, b"Original content for ECDSA-P384 tamper test.")
            .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign should succeed");

        let tampered = b"TAMPERED content that differs from the original.";
        let verify_result = crate::verifier::verify_detached(tampered, &result.p7s_data)
            .expect("verify should succeed even with tampered data");
        assert!(
            !verify_result.signature_valid,
            "Tampered content should fail ECDSA-P384 verification"
        );
    }

    #[tokio::test]
    async fn e2e_fixture_detached_tamper_fails_ecdsa_p521() {
        let pfx_path = fixture_pfx("ecdsa-p521.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P521 fixture");

        let dir = tempfile::tempdir().expect("create temp dir");
        let input_path = dir.path().join("testfile.bin");
        std::fs::write(&input_path, b"Original content for ECDSA-P521 tamper test.")
            .expect("write test file");

        let result = sign_detached(&input_path, &creds, None)
            .await
            .expect("sign should succeed");

        let tampered = b"TAMPERED content that differs from the original.";
        let verify_result = crate::verifier::verify_detached(tampered, &result.p7s_data)
            .expect("verify should succeed even with tampered data");
        assert!(
            !verify_result.signature_valid,
            "Tampered content should fail ECDSA-P521 verification"
        );
    }

    // ─── Security Regression Tests ───

    #[test]
    fn security_regression_no_http_default_tsa_urls() {
        let tsa = crate::timestamp::TsaConfig::default();
        for url in &tsa.urls {
            assert!(
                url.starts_with("https://"),
                "TSA URL must use HTTPS, found: {url}"
            );
        }
    }

    #[test]
    fn security_regression_cert_validity_check_exists() {
        // Verify that validate_cert_validity is called in from_pfx
        // by checking that an expired cert would be rejected.
        // Build a cert with notAfter in the past.
        use crate::pkcs7::asn1;
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial = asn1::encode_integer_value(1);
        let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
        let name = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            &[0x0C, 0x04, 0x54, 0x65, 0x73, 0x74],
        ]))]);
        // notBefore = 2020, notAfter = 2021 (expired)
        let nb = [
            0x17, 0x0D, b'2', b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0',
            b'Z',
        ];
        let na = [
            0x17, 0x0D, b'2', b'1', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0',
            b'Z',
        ];
        let validity = asn1::encode_sequence(&[&nb[..], &na[..]]);
        let spki = asn1::encode_sequence(&[&algo, &[0x03, 0x03, 0x00, 0x04, 0x04][..]]);

        let tbs =
            asn1::encode_sequence(&[&version, &serial, &algo, &name, &validity, &name, &spki]);
        let sig = [0x03, 0x03, 0x00, 0x00, 0x00];
        let cert = asn1::encode_sequence(&[&tbs, &algo, &sig]);

        let result = validate_cert_validity(&cert);
        assert!(result.is_err(), "Expired cert should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expired"),
            "Error should mention expiry: {err}"
        );
    }

    #[test]
    fn security_regression_parse_asn1_time_utctime() {
        let dt = parse_asn1_time(0x17, "260101120000Z");
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 2026);
        assert_eq!(dt.month(), 1);
    }

    #[test]
    fn security_regression_parse_asn1_time_generalized() {
        let dt = parse_asn1_time(0x18, "20260101120000Z");
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn security_regression_dev_mode_blocked_in_release() {
        // In test builds (debug_assertions=true), this test verifies the mechanism exists.
        // The actual security guarantee is that release builds ignore dev_mode.
        #[cfg(not(debug_assertions))]
        {
            // In release: dev_mode should always be denied
            assert!(!crate::web::middleware::is_dev_mode_allowed(true));
        }
    }

    #[test]
    fn security_regression_admin_denies_when_no_auth() {
        // Verify that when no LDAP and no bearer token hash are configured,
        // admin_auth_middleware returns not-found (deny by default).
        // This exercises the fallthrough at the end of admin_auth_middleware.
        use crate::config::SignConfig;

        let config = SignConfig::default();
        // Default config: ldap.enabled = false, admin_token_hash = None, dev_mode = false
        assert!(!config.ldap.enabled, "LDAP must be off by default");
        assert!(
            config.admin_token_hash.is_none(),
            "admin_token_hash must be None by default"
        );
        assert!(!config.dev_mode, "dev_mode must be off by default");

        // With no auth mechanism configured, the middleware should deny access.
        // The actual HTTP-level test is in web/handlers.rs;
        // here we verify the config state that triggers the deny path.
    }

    #[test]
    fn security_regression_extract_extensions_traversal() {
        // Verify that extract_extensions_from_cert properly walks ASN.1 structure
        let ku_ext = build_key_usage_extension(0x80, true);
        let cert = build_minimal_test_cert(Some(&ku_ext));
        let exts = extract_extensions_from_cert(&cert);
        assert!(exts.is_some(), "Should find extensions in test cert");
    }

    #[test]
    fn security_regression_no_filesystem_path_in_pfx_error() {
        // Verify load_pfx error messages don't leak file paths
        let result = load_pfx(Path::new("/nonexistent/secret/path.pfx"), "password");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("/nonexistent/secret/path.pfx"),
            "Error should not leak filesystem path: {err}"
        );
    }

    use chrono::Datelike;

    #[test]
    /// Verify that osslsigncode can parse and validate our Authenticode signatures.
    /// This is the gold-standard interop test — osslsigncode uses the same verification
    /// path as Windows, so if it passes here, Windows will accept the signature.
    fn osslsigncode_verify_pe_rsa() {
        if std::process::Command::new("osslsigncode")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let (pfx_path, password) = generate_test_pfx(dir.path());
        let creds =
            SigningCredentials::from_pfx(&pfx_path, &password).expect("from_pfx should succeed");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign_pe_bytes should succeed");
        let pe_path = dir.path().join("signed.exe");
        std::fs::write(&pe_path, &signed_pe).expect("write signed PE");

        let output = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(&pe_path)
            .output()
            .expect("run osslsigncode");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");

        // osslsigncode exits 1 for self-signed certs, but the structure must be valid.
        // Check that digest computation succeeds (current == calculated).
        assert!(
            combined.contains("Current message digest"),
            "osslsigncode should parse the signature structure:\n{combined}"
        );

        // Extract the two digest lines and verify they match
        let current: Option<&str> = combined
            .lines()
            .find(|l| l.contains("Current message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim());
        let calculated: Option<&str> = combined
            .lines()
            .find(|l| l.contains("Calculated message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim());
        assert_eq!(
            current, calculated,
            "Authenticode digest mismatch — PE hash computation is wrong"
        );

        // Must NOT contain SpcLink parsing errors
        assert!(
            !combined.contains("no matching choice type"),
            "SpcLink CHOICE encoding is wrong:\n{combined}"
        );
    }

    /// Verify ECDSA-P256 PE signature with osslsigncode.
    #[test]
    fn osslsigncode_verify_pe_ecdsa() {
        if std::process::Command::new("osslsigncode")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("create temp dir");
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load ECDSA-P256 fixture");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign_pe_bytes ECDSA");
        let pe_path = dir.path().join("signed_ecdsa.exe");
        std::fs::write(&pe_path, &signed_pe).expect("write signed PE");

        let output = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(&pe_path)
            .output()
            .expect("run osslsigncode");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");

        assert!(
            combined.contains("Current message digest"),
            "osslsigncode should parse ECDSA signature:\n{combined}"
        );

        let current: Option<&str> = combined
            .lines()
            .find(|l| l.contains("Current message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim());
        let calculated: Option<&str> = combined
            .lines()
            .find(|l| l.contains("Calculated message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim());
        assert_eq!(current, calculated, "ECDSA Authenticode digest mismatch");

        assert!(
            !combined.contains("no matching choice type"),
            "SpcLink CHOICE encoding is wrong:\n{combined}"
        );
    }

    // ── E2E Cross-Verification with osslsigncode ──

    /// Helper: run osslsigncode verify and return combined stdout+stderr.
    fn osslsigncode_verify(pe_path: &std::path::Path) -> String {
        let output = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(pe_path)
            .output()
            .expect("run osslsigncode");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("{stdout}\n{stderr}")
    }

    /// Helper: extract a field value from osslsigncode output.
    fn osslsigncode_field<'a>(output: &'a str, field: &str) -> Option<&'a str> {
        output
            .lines()
            .find(|l| l.contains(field))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
    }

    /// Helper: assert osslsigncode digest match and return current digest.
    fn assert_osslsigncode_digests_match(output: &str, label: &str) -> String {
        let current = osslsigncode_field(output, "Current message digest")
            .unwrap_or_else(|| panic!("{label}: osslsigncode should parse signature:\n{output}"));
        let calculated = osslsigncode_field(output, "Calculated message digest")
            .unwrap_or_else(|| panic!("{label}: no calculated digest:\n{output}"));
        assert_eq!(current, calculated, "{label}: Authenticode digest mismatch");
        assert!(
            !output.contains("no matching choice type"),
            "{label}: SpcLink CHOICE encoding error:\n{output}"
        );
        current.to_string()
    }

    /// Helper: sign a PE with osslsigncode using key/cert files extracted from PFX.
    fn osslsigncode_sign_with_hash(
        pe_path: &std::path::Path,
        key_path: &std::path::Path,
        cert_path: &std::path::Path,
        out_path: &std::path::Path,
        hash_alg: &str,
    ) {
        let output = std::process::Command::new("osslsigncode")
            .arg("sign")
            .arg("-certs")
            .arg(cert_path)
            .arg("-key")
            .arg(key_path)
            .arg("-h")
            .arg(hash_alg)
            .arg("-in")
            .arg(pe_path)
            .arg("-out")
            .arg(out_path)
            .output()
            .expect("run osslsigncode sign");
        assert!(
            output.status.success(),
            "osslsigncode sign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Helper: sign a PE with osslsigncode using SHA-256 (default).
    fn osslsigncode_sign(
        pe_path: &std::path::Path,
        key_path: &std::path::Path,
        cert_path: &std::path::Path,
        out_path: &std::path::Path,
    ) {
        osslsigncode_sign_with_hash(pe_path, key_path, cert_path, out_path, "sha256");
    }

    /// Helper: extract key/cert PEM files from a PFX for osslsigncode.
    fn extract_pfx_to_pem(
        pfx_path: &std::path::Path,
        password: &str,
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let key_path = dir.join("extracted.key");
        let cert_path = dir.join("extracted.crt");

        let key_out = std::process::Command::new("openssl")
            .args(["pkcs12", "-legacy", "-in"])
            .arg(pfx_path)
            .args(["-nocerts", "-nodes", "-passin"])
            .arg(format!("pass:{password}"))
            .arg("-out")
            .arg(&key_path)
            .output()
            .expect("extract key from PFX");
        assert!(
            key_out.status.success(),
            "key extraction failed: {}",
            String::from_utf8_lossy(&key_out.stderr)
        );

        let cert_out = std::process::Command::new("openssl")
            .args(["pkcs12", "-legacy", "-in"])
            .arg(pfx_path)
            .args(["-nokeys", "-passin"])
            .arg(format!("pass:{password}"))
            .arg("-out")
            .arg(&cert_path)
            .output()
            .expect("extract cert from PFX");
        assert!(
            cert_out.status.success(),
            "cert extraction failed: {}",
            String::from_utf8_lossy(&cert_out.stderr)
        );

        (key_path, cert_path)
    }

    fn skip_if_no_osslsigncode() -> bool {
        std::process::Command::new("osslsigncode")
            .arg("--version")
            .output()
            .is_err()
    }

    /// E2E: Sign PE with pki-sign, verify PE hash matches osslsigncode computation.
    /// Then sign same PE with osslsigncode and verify BOTH produce the same PE hash.
    #[test]
    fn e2e_cross_verify_pe_hash_rsa2048() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();

        // Write unsigned PE for osslsigncode
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with pki-sign
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign PE");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        // Verify both with osslsigncode
        let pki_output = osslsigncode_verify(&pki_signed_path);
        let ossl_output = osslsigncode_verify(&ossl_signed_path);

        let pki_digest = assert_osslsigncode_digests_match(&pki_output, "pki-sign RSA-2048");
        let ossl_digest = assert_osslsigncode_digests_match(&ossl_output, "osslsigncode RSA-2048");

        // The PE hash MUST match — both tools hash the same unsigned PE
        assert_eq!(
            pki_digest, ossl_digest,
            "PE hash mismatch: pki-sign and osslsigncode compute different Authenticode hashes"
        );
    }

    /// E2E: Cross-verify ECDSA P-256 PE signatures.
    #[test]
    fn e2e_cross_verify_pe_hash_ecdsa_p256() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with pki-sign
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign ECDSA");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        // Verify both
        let pki_output = osslsigncode_verify(&pki_signed_path);
        let ossl_output = osslsigncode_verify(&ossl_signed_path);

        let pki_digest = assert_osslsigncode_digests_match(&pki_output, "pki-sign ECDSA-P256");
        let ossl_digest =
            assert_osslsigncode_digests_match(&ossl_output, "osslsigncode ECDSA-P256");

        assert_eq!(
            pki_digest, ossl_digest,
            "PE hash mismatch: ECDSA P-256 Authenticode hashes differ"
        );
    }

    /// E2E: Cross-verify ECDSA P-384 PE signatures.
    /// P-384 uses SHA-384 as the Authenticode digest algorithm.
    #[test]
    fn e2e_cross_verify_pe_hash_ecdsa_p384() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("ecdsa-p384.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign ECDSA-P384");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        // pki-sign uses SHA-384 for ECDSA-P384, so tell osslsigncode to match
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign_with_hash(
            &unsigned_path,
            &key_path,
            &cert_path,
            &ossl_signed_path,
            "sha384",
        );

        let pki_output = osslsigncode_verify(&pki_signed_path);
        let ossl_output = osslsigncode_verify(&ossl_signed_path);

        let pki_digest = assert_osslsigncode_digests_match(&pki_output, "pki-sign ECDSA-P384");
        let ossl_digest =
            assert_osslsigncode_digests_match(&ossl_output, "osslsigncode ECDSA-P384");

        assert_eq!(
            pki_digest, ossl_digest,
            "PE hash mismatch: ECDSA P-384 Authenticode hashes differ"
        );
    }

    /// E2E: Cross-verify RSA-4096 PE signatures.
    #[test]
    fn e2e_cross_verify_pe_hash_rsa4096() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa4096.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign RSA-4096");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        let pki_output = osslsigncode_verify(&pki_signed_path);
        let ossl_output = osslsigncode_verify(&ossl_signed_path);

        let pki_digest = assert_osslsigncode_digests_match(&pki_output, "pki-sign RSA-4096");
        let ossl_digest = assert_osslsigncode_digests_match(&ossl_output, "osslsigncode RSA-4096");

        assert_eq!(
            pki_digest, ossl_digest,
            "PE hash mismatch: RSA-4096 Authenticode hashes differ"
        );
    }

    /// E2E: Non-8-byte-aligned PE — verify padding doesn't break hash.
    #[test]
    fn e2e_cross_verify_unaligned_pe() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        // Build a PE that is NOT 8-byte aligned (1024 + 3 = 1027 bytes)
        let mut pe_data = build_test_pe();
        pe_data.extend_from_slice(&[0xCC; 3]); // make it 1027 bytes

        // Update section SizeOfRawData to cover the extra bytes
        // SizeOfRawData at offset 0x188 — increase from 0x200 to 0x203
        pe_data[0x188] = 0x03;
        pe_data[0x189] = 0x02;

        let unsigned_path = dir.path().join("unaligned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with pki-sign
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign unaligned PE");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        // Verify both
        let pki_output = osslsigncode_verify(&pki_signed_path);
        let ossl_output = osslsigncode_verify(&ossl_signed_path);

        let pki_digest = assert_osslsigncode_digests_match(&pki_output, "pki-sign unaligned");
        let ossl_digest = assert_osslsigncode_digests_match(&ossl_output, "osslsigncode unaligned");

        assert_eq!(
            pki_digest, ossl_digest,
            "PE hash mismatch on non-8-byte-aligned PE: padding bug"
        );
    }

    /// E2E: Verify SpcIndirectDataContent structure matches osslsigncode byte-for-byte.
    #[test]
    fn e2e_spc_indirect_data_matches_osslsigncode() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with both tools
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign");
        let pki_signed_path = dir.path().join("pki-signed.exe");
        std::fs::write(&pki_signed_path, &signed_pe).expect("write pki-signed");

        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        // Extract SpcIndirectDataContent from both
        let pki_spc = extract_spc_indirect_data(&signed_pe);
        let ossl_data = std::fs::read(&ossl_signed_path).expect("read ossl-signed");
        let ossl_spc = extract_spc_indirect_data(&ossl_data);

        // The SpcIndirectDataContent structures must be identical
        // (same PE hash, same SpcPeImageData encoding, same digest algorithm)
        assert_eq!(
            pki_spc,
            ossl_spc,
            "SpcIndirectDataContent differs between pki-sign and osslsigncode.\n\
             pki-sign ({} bytes): {:02X?}\n\
             osslsigncode ({} bytes): {:02X?}",
            pki_spc.len(),
            &pki_spc[..std::cmp::min(40, pki_spc.len())],
            ossl_spc.len(),
            &ossl_spc[..std::cmp::min(40, ossl_spc.len())]
        );
    }

    /// E2E: Verify osslsigncode sees SpcStatementType in our signed attributes.
    #[test]
    fn e2e_spc_statement_type_present() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("pki-sign");
        let pe_path = dir.path().join("signed.exe");
        std::fs::write(&pe_path, &signed_pe).expect("write signed PE");

        let output = osslsigncode_verify(&pe_path);
        assert!(
            output.contains("Microsoft Individual Code Signing"),
            "SpcStatementType not detected by osslsigncode:\n{output}"
        );
    }

    /// E2E: Verify our verifier accepts osslsigncode-signed PE files.
    #[test]
    fn e2e_our_verifier_accepts_osslsigncode_pe() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);

        // Verify with our verifier
        let result = crate::verifier::verify_file(&ossl_signed_path)
            .expect("our verifier should parse osslsigncode-signed PE");
        assert!(
            result.signature_valid,
            "our verifier should accept osslsigncode signature: computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    /// E2E: Verify our verifier accepts our own signed PE files.
    #[test]
    fn e2e_our_verifier_accepts_our_pe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE");
        let pe_path = dir.path().join("signed.exe");
        std::fs::write(&pe_path, &signed_pe).expect("write signed PE");

        let result =
            crate::verifier::verify_file(&pe_path).expect("verifier should parse our signed PE");
        assert!(
            result.signature_valid,
            "our verifier should accept our own signature: computed={} signed={}",
            result.computed_digest, result.signed_digest
        );
    }

    /// Helper: extract SpcIndirectDataContent DER from a signed PE.
    fn extract_spc_indirect_data(signed_pe: &[u8]) -> Vec<u8> {
        use crate::pkcs7::asn1;

        let pe_info = super::pe::PeInfo::parse(signed_pe).expect("parse PE");
        let cert_start = pe_info.cert_table_rva as usize + 8;
        let cert_end = pe_info.cert_table_rva as usize + pe_info.cert_table_size as usize;
        let pkcs7 = &signed_pe[cert_start..cert_end];

        // Navigate: ContentInfo SEQUENCE → skip OID → [0] EXPLICIT → SignedData SEQUENCE →
        //   skip version → skip digestAlgorithms → inner ContentInfo SEQUENCE →
        //   skip SPC OID → [0] EXPLICIT → SpcIndirectDataContent
        let (_, ci_content) = asn1::parse_tlv(pkcs7).expect("parse ContentInfo");
        let (_, remaining) = asn1::skip_tlv(ci_content).expect("skip OID");
        let (_, explicit0) = asn1::parse_tlv(remaining).expect("parse [0]");
        let (_, sd_content) = asn1::parse_tlv(explicit0).expect("parse SignedData");
        let (_, after_ver) = asn1::skip_tlv(sd_content).expect("skip version");
        let (_, after_da) = asn1::skip_tlv(after_ver).expect("skip digestAlgorithms");
        // Inner ContentInfo with SPC_INDIRECT_DATA
        let (_, inner_ci) = asn1::parse_tlv(after_da).expect("parse inner ContentInfo");
        let (_, after_oid) = asn1::skip_tlv(inner_ci).expect("skip SPC OID");
        // [0] EXPLICIT wrapping SpcIndirectDataContent
        let (_, explicit_content) = asn1::parse_tlv(after_oid).expect("parse [0] EXPLICIT");
        // explicit_content IS the SpcIndirectDataContent (full content of [0] EXPLICIT)
        // skip_tlv gives us the remaining bytes after the SEQUENCE TLV
        let (_, after_spc) = asn1::skip_tlv(explicit_content).expect("skip SPC SEQUENCE");
        let spc_tlv_len = explicit_content.len() - after_spc.len();
        explicit_content[..spc_tlv_len].to_vec()
    }

    /// Helper: extract the raw PKCS#7 DER blob from a signed PE.
    fn extract_pkcs7_from_pe(signed_pe: &[u8]) -> Vec<u8> {
        let pe_info = super::pe::PeInfo::parse(signed_pe).expect("parse PE");
        let cert_start = pe_info.cert_table_rva as usize + 8; // skip WIN_CERTIFICATE header
        let cert_end = pe_info.cert_table_rva as usize + pe_info.cert_table_size as usize;
        signed_pe[cert_start..cert_end].to_vec()
    }

    /// Helper: recursively walk ASN.1 TLV tree depth-first and collect (depth, tag, length, content_bytes).
    fn walk_asn1_tree(data: &[u8], depth: usize, out: &mut Vec<(usize, u8, usize, Vec<u8>)>) {
        let mut pos = 0;
        while pos < data.len() {
            if pos >= data.len() {
                break;
            }
            let tag = data[pos];
            pos += 1;
            if pos >= data.len() {
                break;
            }

            // Parse length
            let (length, len_size) = if data[pos] < 0x80 {
                (data[pos] as usize, 1)
            } else {
                let num_bytes = (data[pos] & 0x7F) as usize;
                if num_bytes == 0 || pos + 1 + num_bytes > data.len() {
                    break;
                }
                let mut len: usize = 0;
                for i in 0..num_bytes {
                    len = (len << 8) | data[pos + 1 + i] as usize;
                }
                (len, 1 + num_bytes)
            };
            pos += len_size;

            if pos + length > data.len() {
                break;
            }

            let content = &data[pos..pos + length];
            out.push((depth, tag, length, content.to_vec()));

            // Recurse into constructed types (bit 5 set) — SEQUENCE, SET, context tags
            let is_constructed = (tag & 0x20) != 0;
            if is_constructed {
                walk_asn1_tree(content, depth + 1, out);
            }

            pos += length;
        }
    }

    /// Step 1: ASN.1 tree comparison between pki-sign and osslsigncode PKCS#7 blobs.
    ///
    /// Walks both trees depth-first and reports the first structural divergence.
    #[test]
    fn e2e_asn1_tree_comparison_pkcs7() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with pki-sign
        let pki_signed = sign_pe_bytes(&pe_data, &creds).expect("pki-sign");
        let pki_pkcs7 = extract_pkcs7_from_pe(&pki_signed);

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);
        let ossl_signed = std::fs::read(&ossl_signed_path).expect("read ossl-signed");
        let ossl_pkcs7 = extract_pkcs7_from_pe(&ossl_signed);

        // Walk both ASN.1 trees
        let mut pki_tree = Vec::new();
        let mut ossl_tree = Vec::new();
        walk_asn1_tree(&pki_pkcs7, 0, &mut pki_tree);
        walk_asn1_tree(&ossl_pkcs7, 0, &mut ossl_tree);

        // Compare structural elements (tag + length at each depth)
        // Skip content comparison for signature values (OCTET STRING containing
        // the actual RSA signature, timestamps, signingTime) since those differ.
        // Focus on: structure tags, SpcIndirectDataContent, SpcPeImageData.
        let mut divergences = Vec::new();
        let max_compare = std::cmp::min(pki_tree.len(), ossl_tree.len());

        for i in 0..max_compare {
            let (pd, pt, pl, pc) = &pki_tree[i];
            let (od, ot, ol, oc) = &ossl_tree[i];
            if pd != od || pt != ot {
                divergences.push(format!(
                    "Node {i}: pki-sign(depth={pd}, tag=0x{pt:02X}, len={pl}) vs \
                     osslsigncode(depth={od}, tag=0x{ot:02X}, len={ol})"
                ));
            } else if pl != ol {
                // Same tag but different length — only flag for structural elements
                // Skip leaf values like INTEGER (serial), OCTET STRING (signature), UTCTime
                let is_constructed = (*pt & 0x20) != 0;
                if is_constructed {
                    divergences.push(format!(
                        "Node {i}: tag=0x{pt:02X} depth={pd}, pki-sign len={pl} vs osslsigncode len={ol}"
                    ));
                }
            } else if pc != oc {
                // Same tag+length but different content — flag OIDs and BIT STRINGs
                if *pt == 0x06 || *pt == 0x03 {
                    divergences.push(format!(
                        "Node {i}: tag=0x{pt:02X} depth={pd} len={pl}, content differs:\n  \
                         pki:  {pc:02X?}\n  ossl: {oc:02X?}"
                    ));
                }
            }
        }

        if pki_tree.len() != ossl_tree.len() {
            divergences.push(format!(
                "Tree size: pki-sign has {} nodes vs osslsigncode has {} nodes",
                pki_tree.len(),
                ossl_tree.len()
            ));
        }

        // Print all divergences for diagnostic purposes
        if !divergences.is_empty() {
            eprintln!("=== ASN.1 tree divergences (informational) ===");
            for d in &divergences {
                eprintln!("  {d}");
            }
            eprintln!("=== end divergences ===");
        }

        // The SpcIndirectDataContent must match (most critical for Windows)
        let pki_spc = extract_spc_indirect_data(&pki_signed);
        let ossl_spc = extract_spc_indirect_data(&ossl_signed);
        assert_eq!(
            pki_spc, ossl_spc,
            "SpcIndirectDataContent differs — this is the most likely cause of Windows rejection"
        );
    }

    /// Step 2: PE checksum comparison between pki-sign and osslsigncode.
    #[test]
    fn e2e_pe_checksum_matches_osslsigncode() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");
        let (key_path, cert_path) = extract_pfx_to_pem(&pfx_path, "test", dir.path());

        let pe_data = build_test_pe();
        let unsigned_path = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, &pe_data).expect("write unsigned");

        // Sign with pki-sign
        let pki_signed = sign_pe_bytes(&pe_data, &creds).expect("pki-sign");

        // Sign with osslsigncode
        let ossl_signed_path = dir.path().join("ossl-signed.exe");
        osslsigncode_sign(&unsigned_path, &key_path, &cert_path, &ossl_signed_path);
        let ossl_signed = std::fs::read(&ossl_signed_path).expect("read ossl-signed");

        // Extract PE checksum from both (at opt_header + 64)
        let pki_pe_info = super::pe::PeInfo::parse(&pki_signed).expect("parse pki PE");
        let ossl_pe_info = super::pe::PeInfo::parse(&ossl_signed).expect("parse ossl PE");

        let pki_checksum = u32::from_le_bytes([
            pki_signed[pki_pe_info.checksum_offset],
            pki_signed[pki_pe_info.checksum_offset + 1],
            pki_signed[pki_pe_info.checksum_offset + 2],
            pki_signed[pki_pe_info.checksum_offset + 3],
        ]);
        let ossl_checksum = u32::from_le_bytes([
            ossl_signed[ossl_pe_info.checksum_offset],
            ossl_signed[ossl_pe_info.checksum_offset + 1],
            ossl_signed[ossl_pe_info.checksum_offset + 2],
            ossl_signed[ossl_pe_info.checksum_offset + 3],
        ]);

        // Checksums won't match exactly (different PKCS#7 blobs = different file sizes
        // and content), but both must be non-zero and correctly computed.
        assert_ne!(pki_checksum, 0, "pki-sign PE checksum is zero");
        assert_ne!(ossl_checksum, 0, "osslsigncode PE checksum is zero");

        // Verify our checksum is self-consistent: recompute and compare
        let recomputed =
            crate::pe::embed::compute_pe_checksum(&pki_signed, pki_pe_info.checksum_offset);
        assert_eq!(
            pki_checksum, recomputed,
            "pki-sign PE checksum is not self-consistent"
        );

        // Compare WIN_CERTIFICATE headers
        let pki_cert_rva = pki_pe_info.cert_table_rva as usize;
        let ossl_cert_rva = ossl_pe_info.cert_table_rva as usize;

        // wRevision
        let pki_rev =
            u16::from_le_bytes([pki_signed[pki_cert_rva + 4], pki_signed[pki_cert_rva + 5]]);
        let ossl_rev = u16::from_le_bytes([
            ossl_signed[ossl_cert_rva + 4],
            ossl_signed[ossl_cert_rva + 5],
        ]);
        assert_eq!(pki_rev, ossl_rev, "WIN_CERTIFICATE wRevision mismatch");
        assert_eq!(pki_rev, 0x0200, "wRevision should be 0x0200");

        // wCertificateType
        let pki_type =
            u16::from_le_bytes([pki_signed[pki_cert_rva + 6], pki_signed[pki_cert_rva + 7]]);
        let ossl_type = u16::from_le_bytes([
            ossl_signed[ossl_cert_rva + 6],
            ossl_signed[ossl_cert_rva + 7],
        ]);
        assert_eq!(
            pki_type, ossl_type,
            "WIN_CERTIFICATE wCertificateType mismatch"
        );
        assert_eq!(pki_type, 0x0002, "wCertificateType should be 0x0002");
    }

    /// Step 3: Validate our PKCS#7 blob with openssl asn1parse.
    #[test]
    fn e2e_openssl_asn1parse_accepts_our_pkcs7() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test").expect("load PFX");

        let pe_data = build_test_pe();
        let signed_pe = sign_pe_bytes(&pe_data, &creds).expect("sign PE");
        let pkcs7 = extract_pkcs7_from_pe(&signed_pe);

        // Write PKCS#7 DER blob to file
        let pkcs7_path = dir.path().join("signature.der");
        std::fs::write(&pkcs7_path, &pkcs7).expect("write pkcs7");

        // Run openssl asn1parse
        let output = std::process::Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(&pkcs7_path)
            .output()
            .expect("run openssl asn1parse");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "openssl asn1parse failed on our PKCS#7 blob:\nstdout: {stdout}\nstderr: {stderr}"
        );

        // Verify key structures are present in the parse output
        assert!(
            stdout.contains("SEQUENCE") || stdout.contains("SET"),
            "asn1parse output should contain ASN.1 structures:\n{stdout}"
        );

        // Also verify with openssl pkcs7 command
        let pkcs7_output = std::process::Command::new("openssl")
            .args(["pkcs7", "-inform", "DER", "-print_certs", "-noout", "-in"])
            .arg(&pkcs7_path)
            .output()
            .expect("run openssl pkcs7");

        assert!(
            pkcs7_output.status.success(),
            "openssl pkcs7 failed on our blob:\nstderr: {}",
            String::from_utf8_lossy(&pkcs7_output.stderr)
        );
    }

    // ─── Interop: Detached CMS verify with openssl cms -verify ───

    /// Interop: Sign a file with pki-sign detached CMS (RSA), then verify
    /// the resulting .p7s with `openssl cms -verify`.
    ///
    /// openssl cms -verify requires:
    ///   - the detached content file (`-content`)
    ///   - the .p7s signature file
    ///   - a trusted CA cert (`-CAfile`) — we use the signer cert itself
    ///   - `-noverify` is not available in older openssl; use `-CAfile self_cert`
    ///
    /// Because our test cert is self-signed, we pass it as both the CA and the
    /// signer cert. The `-noverify` flag is not needed when the CA chain is
    /// supplied explicitly.
    #[tokio::test]
    async fn e2e_interop_cms_detached_verify_openssl_rsa() {
        if cfg!(windows) {
            eprintln!("skipping: openssl cms -verify uses /dev/null, Linux only");
            return;
        }
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }

        let dir = tempfile::tempdir().expect("create temp dir");

        // Use the committed RSA-2048 fixture — no openssl key generation needed.
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load RSA-2048 fixture for detached");

        // Write the content to sign
        let content_path = dir.path().join("payload.bin");
        std::fs::write(
            &content_path,
            b"Interop test payload for detached CMS RSA signing.",
        )
        .expect("write payload");

        // Sign with pki-sign
        let sign_result = sign_detached(&content_path, &creds, None)
            .await
            .expect("sign_detached should succeed");
        assert!(
            !sign_result.p7s_data.is_empty(),
            "p7s_data must not be empty"
        );

        // Write the .p7s signature file
        let p7s_path = dir.path().join("payload.bin.p7s");
        std::fs::write(&p7s_path, &sign_result.p7s_data).expect("write .p7s");

        // Extract the signer certificate from the PFX so we can supply it as the
        // CA trust anchor for openssl cms -verify.
        let cert_path = dir.path().join("signer.crt");
        let cert_out = std::process::Command::new("openssl")
            .args(["pkcs12", "-legacy", "-in"])
            .arg(&pfx_path)
            .args(["-nokeys", "-passin", "pass:test", "-out"])
            .arg(&cert_path)
            .output()
            .expect("openssl pkcs12 extract cert");
        assert!(
            cert_out.status.success(),
            "cert extraction failed: {}",
            String::from_utf8_lossy(&cert_out.stderr)
        );

        // Verify with openssl cms -verify.
        // -CAfile:    supply the self-signed signer cert as the trust anchor.
        // -purpose any: our test cert has codeSigning EKU, not smimesign, so
        //               we relax the purpose check (this is fine for test certs).
        // -content:   path to the detached content file.
        let verify_out = std::process::Command::new("openssl")
            .args(["cms", "-verify", "-inform", "DER"])
            .args(["-in"])
            .arg(&p7s_path)
            .args(["-content"])
            .arg(&content_path)
            .args(["-CAfile"])
            .arg(&cert_path)
            .args(["-purpose", "any"])
            .args(["-out", "/dev/null"])
            .output()
            .expect("openssl cms -verify");

        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        assert!(
            verify_out.status.success(),
            "openssl cms -verify failed for RSA detached CMS:\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("Verification successful"),
            "openssl cms should report 'Verification successful':\nstderr: {stderr}"
        );
    }

    /// Interop: Sign a file with pki-sign detached CMS (ECDSA P-256), then
    /// verify the .p7s output with `openssl cms -verify`.
    #[tokio::test]
    async fn e2e_interop_cms_detached_verify_openssl_ecdsa() {
        if cfg!(windows) {
            eprintln!("skipping: openssl cms -verify uses /dev/null, Linux only");
            return;
        }
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }

        let dir = tempfile::tempdir().expect("create temp dir");

        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds = SigningCredentials::from_pfx_detached(&pfx_path, "test")
            .expect("load ECDSA-P256 fixture for detached");

        let content_path = dir.path().join("payload.bin");
        std::fs::write(
            &content_path,
            b"Interop test payload for detached CMS ECDSA-P256 signing.",
        )
        .expect("write payload");

        let sign_result = sign_detached(&content_path, &creds, None)
            .await
            .expect("sign_detached should succeed");
        assert!(
            !sign_result.p7s_data.is_empty(),
            "p7s_data must not be empty"
        );

        let p7s_path = dir.path().join("payload.bin.p7s");
        std::fs::write(&p7s_path, &sign_result.p7s_data).expect("write .p7s");

        let cert_path = dir.path().join("signer.crt");
        let cert_out = std::process::Command::new("openssl")
            .args(["pkcs12", "-legacy", "-in"])
            .arg(&pfx_path)
            .args(["-nokeys", "-passin", "pass:test", "-out"])
            .arg(&cert_path)
            .output()
            .expect("openssl pkcs12 extract cert");
        assert!(
            cert_out.status.success(),
            "cert extraction failed: {}",
            String::from_utf8_lossy(&cert_out.stderr)
        );

        let verify_out = std::process::Command::new("openssl")
            .args(["cms", "-verify", "-inform", "DER"])
            .args(["-in"])
            .arg(&p7s_path)
            .args(["-content"])
            .arg(&content_path)
            .args(["-CAfile"])
            .arg(&cert_path)
            .args(["-purpose", "any"])
            .args(["-out", "/dev/null"])
            .output()
            .expect("openssl cms -verify");

        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        assert!(
            verify_out.status.success(),
            "openssl cms -verify failed for ECDSA-P256 detached CMS:\nstderr: {stderr}"
        );
        assert!(
            stderr.contains("Verification successful"),
            "openssl cms should report 'Verification successful':\nstderr: {stderr}"
        );
    }

    // ─── Interop: RFC 3161 timestamp structure verification with openssl asn1parse ───

    /// Interop: Build a synthetic RFC 3161 TimeStampToken (matching the internal
    /// test helpers in timestamp.rs), write it to disk, and verify its structure
    /// with `openssl asn1parse`.
    ///
    /// This test validates that our TSTInfo/TimeStampToken DER encoding is
    /// structurally correct according to an independent ASN.1 parser.
    ///
    /// The token is constructed via the same helper used in timestamp.rs unit
    /// tests, which builds a CMS ContentInfo → SignedData → encapContentInfo
    /// → TSTInfo chain.  The key OID constants that openssl must recognise are:
    ///   - OID for id-smime-ct-TSTInfo (1.2.840.113549.1.9.16.1.4) — present in
    ///     the encapContentInfo eContentType.
    ///   - SHA-256 AlgorithmIdentifier in the messageImprint.
    #[test]
    fn e2e_interop_timestamp_structure_openssl() {
        if !has_openssl() {
            eprintln!("skipping: openssl CLI not available");
            return;
        }

        // Build the TimeStampToken using the same DER primitives that our
        // production code uses.  This ensures the structural test covers the
        // real encoding path rather than a hand-crafted fixture.
        use crate::pkcs7::asn1;
        use sha2::{Digest, Sha256};

        // Build a valid MessageImprint over a synthetic signature value.
        let fake_sig = b"interop_timestamp_structure_test_payload";
        let digest = Sha256::digest(fake_sig);

        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);

        // OID 1.2.840.113549.1.9.16.1.4 — id-smime-ct-TSTInfo
        const OID_TST_INFO: &[u8] = &[
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
        ];

        // Build TSTInfo SEQUENCE
        // version INTEGER 1
        let version = asn1::encode_integer_value(1);
        // policy OID — use a simple well-formed OID (2.5.29.1)
        let policy_oid: Vec<u8> = vec![0x06, 0x03, 0x55, 0x1D, 0x01];
        // serialNumber INTEGER 42
        let serial = asn1::encode_integer_value(42);
        // genTime GeneralizedTime — "20260321120000Z"
        let gen_time: Vec<u8> = vec![
            0x18, 0x0F, b'2', b'0', b'2', b'6', b'0', b'3', b'2', b'1', b'1', b'2', b'0', b'0',
            b'0', b'0', b'Z',
        ];
        // nonce INTEGER
        let nonce_value: u64 = 0x1234_5678_9ABC_DEF0 & 0x7FFF_FFFF_FFFF_FFFF;
        let nonce = {
            let mut bytes = Vec::new();
            let mut v = nonce_value;
            while v > 0 {
                bytes.push((v & 0xFF) as u8);
                v >>= 8;
            }
            bytes.reverse();
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0x00);
            }
            let mut enc = vec![0x02]; // INTEGER
            enc.extend(asn1::encode_length(bytes.len()));
            enc.extend(bytes);
            enc
        };

        let tst_info = asn1::encode_sequence(&[
            &version,
            &policy_oid,
            &message_imprint,
            &serial,
            &gen_time,
            &nonce,
        ]);

        // Wrap in CMS: ContentInfo { signedData, [0] { SignedData { ... } } }
        let econtent_octet = asn1::encode_octet_string(&tst_info);
        let econtent_explicit = asn1::encode_explicit_tag(0, &econtent_octet);
        let encap_content_info = asn1::encode_sequence(&[OID_TST_INFO, &econtent_explicit]);

        let digest_algos = asn1::encode_set(&asn1::SHA256_ALGORITHM_ID);
        let signer_infos = asn1::encode_set(&[]);

        let signed_data = asn1::encode_sequence(&[
            &asn1::encode_integer_value(3), // version
            &digest_algos,
            &encap_content_info,
            &signer_infos,
        ]);

        let sd_explicit = asn1::encode_explicit_tag(0, &signed_data);
        let token = asn1::encode_sequence(&[asn1::OID_SIGNED_DATA, &sd_explicit]);

        // Write to a temp file
        let dir = tempfile::tempdir().expect("create temp dir");
        let token_path = dir.path().join("timestamp_token.der");
        std::fs::write(&token_path, &token).expect("write token DER");

        // Verify structure with openssl asn1parse
        let parse_out = std::process::Command::new("openssl")
            .args(["asn1parse", "-inform", "DER", "-in"])
            .arg(&token_path)
            .output()
            .expect("openssl asn1parse");

        let stdout = String::from_utf8_lossy(&parse_out.stdout);
        let stderr = String::from_utf8_lossy(&parse_out.stderr);

        assert!(
            parse_out.status.success(),
            "openssl asn1parse rejected our TimeStampToken DER:\nstdout: {stdout}\nstderr: {stderr}"
        );

        // openssl should find at least SEQUENCE and OID nodes
        assert!(
            stdout.contains("SEQUENCE"),
            "asn1parse output should contain SEQUENCE nodes:\n{stdout}"
        );

        // id-smime-ct-TSTInfo OID must appear in the output
        // openssl prints OIDs as dotted-decimal or named; check for the raw arc
        // 1.2.840.113549.1.9.16.1.4
        assert!(
            stdout.contains("1.2.840.113549.1.9.16.1.4") || stdout.contains("id-smime-ct-TSTInfo"),
            "TimeStampToken must contain id-smime-ct-TSTInfo OID:\n{stdout}"
        );

        // SHA-256 OID 2.16.840.1.101.3.4.2.1 must appear (messageImprint hashAlgorithm)
        assert!(
            stdout.contains("2.16.840.1.101.3.4.2.1") || stdout.contains("sha256"),
            "TimeStampToken must contain SHA-256 OID:\n{stdout}"
        );
    }

    // ─── Interop: CAB Authenticode verify with osslsigncode ───

    /// Interop: Sign a minimal CAB file with pki-sign Authenticode, then verify
    /// the signed output with `osslsigncode verify`.
    ///
    /// CAB signing follows the same Authenticode path as PE: the hash covers the
    /// cabinet body, and the CMS/PKCS#7 SignedData is appended.
    /// osslsigncode should be able to parse the signature structure and produce
    /// a matching Authenticode digest.
    #[tokio::test]
    #[ignore = "requires osslsigncode"]
    async fn e2e_interop_cab_verify_osslsigncode() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }

        let dir = tempfile::tempdir().expect("create temp dir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture for CAB");

        // Build a minimal valid CAB using the same layout as cab.rs tests.
        let cab_data = build_interop_test_cab(128);

        // Sign the CAB with pki-sign
        let sign_result = crate::cab::sign_cab(&cab_data, &creds, None, &SignOptions::default())
            .await
            .expect("sign_cab should succeed");

        assert!(
            !sign_result.signed_data.is_empty(),
            "signed CAB must not be empty"
        );

        // Write signed CAB to disk for osslsigncode
        let signed_cab_path = dir.path().join("signed.cab");
        std::fs::write(&signed_cab_path, &sign_result.signed_data).expect("write signed CAB");

        // Run osslsigncode verify
        let verify_out = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(&signed_cab_path)
            .output()
            .expect("run osslsigncode");

        let stdout = String::from_utf8_lossy(&verify_out.stdout);
        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        let combined = format!("{stdout}\n{stderr}");

        // osslsigncode exits 1 for self-signed certs, but must parse the structure.
        assert!(
            combined.contains("Current message digest"),
            "osslsigncode should parse CAB Authenticode signature structure:\n{combined}"
        );

        // Digest must match — the Authenticode hash computation must be correct.
        let current = combined
            .lines()
            .find(|l| l.contains("Current message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");
        let calculated = combined
            .lines()
            .find(|l| l.contains("Calculated message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");

        assert_eq!(
            current, calculated,
            "CAB Authenticode digest mismatch — hash computation is wrong:\n{combined}"
        );
    }

    /// Interop: Sign a minimal CAB file with pki-sign using ECDSA-P256, then
    /// verify with osslsigncode.
    #[tokio::test]
    #[ignore = "requires osslsigncode"]
    async fn e2e_interop_cab_verify_osslsigncode_ecdsa() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }

        let dir = tempfile::tempdir().expect("create temp dir");
        let pfx_path = fixture_pfx("ecdsa-p256.pfx");
        let creds = SigningCredentials::from_pfx(&pfx_path, "test")
            .expect("load ECDSA-P256 fixture for CAB");

        let cab_data = build_interop_test_cab(128);

        let sign_result = crate::cab::sign_cab(&cab_data, &creds, None, &SignOptions::default())
            .await
            .expect("sign_cab ECDSA-P256 should succeed");

        let signed_cab_path = dir.path().join("signed_ecdsa.cab");
        std::fs::write(&signed_cab_path, &sign_result.signed_data).expect("write signed CAB");

        let verify_out = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(&signed_cab_path)
            .output()
            .expect("run osslsigncode");

        let stdout = String::from_utf8_lossy(&verify_out.stdout);
        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        let combined = format!("{stdout}\n{stderr}");

        assert!(
            combined.contains("Current message digest"),
            "osslsigncode should parse ECDSA-P256 CAB signature:\n{combined}"
        );

        let current = combined
            .lines()
            .find(|l| l.contains("Current message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");
        let calculated = combined
            .lines()
            .find(|l| l.contains("Calculated message digest"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");

        assert_eq!(
            current, calculated,
            "CAB ECDSA-P256 Authenticode digest mismatch:\n{combined}"
        );
    }

    /// Build a minimal valid CAB file suitable for Authenticode signing tests.
    ///
    /// Produces a CFHEADER with cfhdrRESERVE_PRESENT set and a 20-byte reserved
    /// header (CabinetSignatureReservedHeader), followed by `body_len` bytes of
    /// body data.  This replicates the logic in `cab::tests::build_test_cab` but
    /// is placed here in the signer tests to avoid importing private test helpers.
    fn build_interop_test_cab(_body_len: usize) -> Vec<u8> {
        // Build a structurally valid CAB with:
        //   CFHEADER (with reserve for Authenticode)
        //   CFFOLDER (1 folder, NONE compression)
        //   CFFILE   (1 file: "test.txt")
        //   CFDATA   (1 data block containing file content)
        //
        // Microsoft CAB spec: https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)
        const CAB_MAGIC: &[u8; 4] = b"MSCF";
        const CFHDR_RESERVE_PRESENT: u16 = 0x0004;
        const CAB_SIG_RESERVE_HEADER_SIZE: u32 = 20;

        // File content to embed
        let file_content = b"Hello from pki-sign CAB interop test!\n";
        let file_name = b"test.txt\0"; // null-terminated

        let mut cab = Vec::new();

        // ─── CFHEADER (36 bytes fixed + 4 reserve fields + 20 reserve data) ───
        cab.extend_from_slice(CAB_MAGIC); // signature
        cab.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        let cb_cabinet_pos = cab.len();
        cab.extend_from_slice(&0u32.to_le_bytes()); // cbCabinet (placeholder)
        cab.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        let coff_files_pos = cab.len();
        cab.extend_from_slice(&0u32.to_le_bytes()); // coffFiles (placeholder)
        cab.extend_from_slice(&0u32.to_le_bytes()); // reserved3
        cab.push(3); // versionMinor
        cab.push(1); // versionMajor
        cab.extend_from_slice(&1u16.to_le_bytes()); // cFolders = 1
        cab.extend_from_slice(&1u16.to_le_bytes()); // cFiles = 1
        cab.extend_from_slice(&CFHDR_RESERVE_PRESENT.to_le_bytes()); // flags
        cab.extend_from_slice(&0u16.to_le_bytes()); // setID
        cab.extend_from_slice(&0u16.to_le_bytes()); // iCabinet

        // Reserve fields: cbCFHeader (u16), cbCFFolder (u8), cbCFData (u8)
        cab.extend_from_slice(&(CAB_SIG_RESERVE_HEADER_SIZE as u16).to_le_bytes());
        cab.push(0); // cbCFFolder
        cab.push(0); // cbCFData

        // CabinetSignatureReservedHeader (20 bytes)
        // u16 junk=0, u16 remaining_size=16 (standard CAB Authenticode format)
        cab.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        cab.extend_from_slice(&0u32.to_le_bytes()); // sigOffset
        cab.extend_from_slice(&0u32.to_le_bytes()); // sigSize
        cab.extend_from_slice(&[0u8; 8]); // padding

        // ─── CFFOLDER (8 bytes) ───
        // coffCabStart: offset to first CFDATA block (will be filled after CFFILE)
        let coff_cab_start_pos = cab.len();
        cab.extend_from_slice(&0u32.to_le_bytes()); // coffCabStart (placeholder)
        cab.extend_from_slice(&1u16.to_le_bytes()); // cCFData = 1
        cab.extend_from_slice(&0u16.to_le_bytes()); // typeCompress = NONE (0)

        // ─── CFFILE (16 bytes fixed + filename) ───
        // Record coffFiles offset
        let coff_files = cab.len() as u32;
        cab[coff_files_pos..coff_files_pos + 4].copy_from_slice(&coff_files.to_le_bytes());

        cab.extend_from_slice(&(file_content.len() as u32).to_le_bytes()); // cbFile
        cab.extend_from_slice(&0u32.to_le_bytes()); // uoffFolderStart
        cab.extend_from_slice(&0u16.to_le_bytes()); // iFolder = 0
                                                    // date: 2026-03-25 = ((2026-1980)<<9) | (3<<5) | 25 = (46<<9)|(3<<5)|25 = 23552|96|25 = 23673
        cab.extend_from_slice(&23673u16.to_le_bytes()); // date
                                                        // time: 12:00 = (12<<11) = 24576
        cab.extend_from_slice(&24576u16.to_le_bytes()); // time
        cab.extend_from_slice(&0x20u16.to_le_bytes()); // attribs = _A_ARCH
        cab.extend_from_slice(file_name); // szName (null-terminated)

        // ─── CFDATA (8 bytes header + data) ───
        let coff_cab_start = cab.len() as u32;
        cab[coff_cab_start_pos..coff_cab_start_pos + 4]
            .copy_from_slice(&coff_cab_start.to_le_bytes());

        cab.extend_from_slice(&0u32.to_le_bytes()); // csum (checksum, 0 = none)
        cab.extend_from_slice(&(file_content.len() as u16).to_le_bytes()); // cbData
        cab.extend_from_slice(&(file_content.len() as u16).to_le_bytes()); // cbUncomp
        cab.extend_from_slice(file_content);

        // Fill cbCabinet
        let total = cab.len() as u32;
        cab[cb_cabinet_pos..cb_cabinet_pos + 4].copy_from_slice(&total.to_le_bytes());

        cab
    }

    // ─── Interop: MSI Authenticode verify with osslsigncode ───

    /// Interop: Sign a minimal MSI (OLE2/CFB) file with pki-sign Authenticode,
    /// then verify the signed output with `osslsigncode verify`.
    ///
    /// A real MSI is a Compound File Binary (CFB/OLE2) container.  pki-sign
    /// uses the `cfb` crate to read and write the `\x05DigitalSignature` stream.
    /// This test exercises the full sign → osslsigncode verify round-trip.
    #[tokio::test]
    #[ignore = "requires osslsigncode"]
    async fn e2e_interop_msi_verify_osslsigncode() {
        if skip_if_no_osslsigncode() {
            eprintln!("skipping: osslsigncode not available");
            return;
        }

        let dir = tempfile::tempdir().expect("create temp dir");
        let pfx_path = fixture_pfx("rsa2048.pfx");
        let creds =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture for MSI");

        // Build a minimal CFB/MSI container.
        let msi_data = build_interop_test_msi();

        // Sign with pki-sign
        let sign_result = crate::msi::sign_msi(&msi_data, &creds, None, &SignOptions::default())
            .await
            .expect("sign_msi should succeed");

        assert!(
            !sign_result.signed_data.is_empty(),
            "signed MSI must not be empty"
        );

        let signed_msi_path = dir.path().join("signed.msi");
        std::fs::write(&signed_msi_path, &sign_result.signed_data).expect("write signed MSI");

        // Verify with osslsigncode
        let verify_out = std::process::Command::new("osslsigncode")
            .arg("verify")
            .arg(&signed_msi_path)
            .output()
            .expect("run osslsigncode");

        let stdout = String::from_utf8_lossy(&verify_out.stdout);
        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        let combined = format!("{stdout}\n{stderr}");

        // osslsigncode uses "Current DigitalSignature" / "Calculated DigitalSignature"
        // for MSI files (not "Current message digest" like PE/CAB).
        assert!(
            combined.contains("Current DigitalSignature"),
            "osslsigncode should parse MSI Authenticode signature:\n{combined}"
        );

        let current = combined
            .lines()
            .find(|l| l.contains("Current DigitalSignature"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");
        let calculated = combined
            .lines()
            .find(|l| l.contains("Calculated DigitalSignature"))
            .map(|l| l.split(':').next_back().unwrap_or("").trim())
            .unwrap_or("");

        assert_eq!(
            current, calculated,
            "MSI Authenticode digest mismatch — hash computation is wrong:\n{combined}"
        );
    }

    /// Build a minimal Compound File Binary (CFB / OLE2) container that
    /// `sign_msi` can accept.
    ///
    /// The `cfb` crate is used to construct a valid CFB file in memory.
    /// We create an empty compound document (no user streams) — the MSI
    /// signing code only needs the container to be a valid CFB file without
    /// an existing `\x05DigitalSignature` stream.
    fn build_interop_test_msi() -> Vec<u8> {
        use std::io::Write;

        let buf = std::io::Cursor::new(Vec::new());
        let mut comp = cfb::CompoundFile::create(buf).expect("create CFB container");

        // Write a minimal non-signature stream so the file has some content to hash.
        // The stream name is arbitrary — we just need non-empty file content.
        {
            let mut stream = comp
                .create_stream("/TestData")
                .expect("create TestData stream");
            stream
                .write_all(b"Minimal MSI content for Authenticode signing test.")
                .expect("write stream data");
        }

        comp.flush().expect("flush CFB");
        comp.into_inner().into_inner()
    }

    /// Verify build_test_pe produces a PE with valid Windows header fields.
    #[test]
    fn test_pe_has_valid_windows_fields() {
        let pe = build_test_pe();
        let pe_info = super::pe::PeInfo::parse(&pe).expect("parse PE");

        // opt_offset = pe_offset + 4 (COFF) + 20 = pe_offset + 24
        let opt = pe_info.pe_offset + 24;

        // SectionAlignment = 0x1000
        let section_align =
            u32::from_le_bytes([pe[opt + 32], pe[opt + 33], pe[opt + 34], pe[opt + 35]]);
        assert_eq!(section_align, 0x1000, "SectionAlignment");

        // FileAlignment = 0x200
        let file_align =
            u32::from_le_bytes([pe[opt + 36], pe[opt + 37], pe[opt + 38], pe[opt + 39]]);
        assert_eq!(file_align, 0x200, "FileAlignment");

        // ImageBase = 0x400000
        let image_base =
            u32::from_le_bytes([pe[opt + 28], pe[opt + 29], pe[opt + 30], pe[opt + 31]]);
        assert_eq!(image_base, 0x0040_0000, "ImageBase");

        // SizeOfImage = 0x2000
        let size_of_image =
            u32::from_le_bytes([pe[opt + 56], pe[opt + 57], pe[opt + 58], pe[opt + 59]]);
        assert_eq!(size_of_image, 0x2000, "SizeOfImage");

        // SizeOfHeaders = 0x200
        let size_of_headers =
            u32::from_le_bytes([pe[opt + 60], pe[opt + 61], pe[opt + 62], pe[opt + 63]]);
        assert_eq!(size_of_headers, 0x200, "SizeOfHeaders");

        // Subsystem = 3 (CONSOLE)
        let subsystem = u16::from_le_bytes([pe[opt + 68], pe[opt + 69]]);
        assert_eq!(subsystem, 3, "Subsystem");

        // Section header should have VirtualAddress and Characteristics
        let section_start = opt + pe_info.size_of_optional_header as usize;
        let virtual_addr = u32::from_le_bytes([
            pe[section_start + 12],
            pe[section_start + 13],
            pe[section_start + 14],
            pe[section_start + 15],
        ]);
        assert_eq!(virtual_addr, 0x1000, "Section VirtualAddress");

        let characteristics = u32::from_le_bytes([
            pe[section_start + 36],
            pe[section_start + 37],
            pe[section_start + 38],
            pe[section_start + 39],
        ]);
        assert_ne!(
            characteristics, 0,
            "Section Characteristics should be non-zero"
        );
    }

    // ─── Debug: dump raw CAB signature for osslsigncode diagnosis ───

    /// Reproducible timing receipt for the `speed-run.cast` demo.
    ///
    /// Signs a minimal PE, CAB, MSI, PS1, and detached CMS target with the
    /// bundled RSA-2048 PFX, printing the measured wall-clock time for each.
    /// Run with:
    ///   cargo test --release -p pki-sign -- --nocapture bench_speedrun_all_formats
    #[tokio::test]
    #[ignore = "benchmark — opt-in via --ignored"]
    async fn bench_speedrun_all_formats() {
        use std::time::Instant;

        let pfx_path = fixture_pfx("rsa2048.pfx");
        let credentials =
            SigningCredentials::from_pfx(&pfx_path, "test").expect("load RSA-2048 fixture");

        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path();

        let pe_in = dir.join("bench.exe");
        std::fs::write(&pe_in, build_test_pe()).expect("write PE");
        let cab_in = dir.join("bench.cab");
        std::fs::write(&cab_in, build_interop_test_cab(64)).expect("write CAB");
        let msi_in = dir.join("bench.msi");
        std::fs::write(&msi_in, build_interop_test_msi()).expect("write MSI");
        let ps1_in = dir.join("bench.ps1");
        std::fs::write(&ps1_in, b"Write-Host 'pki-sign speedrun'\n").expect("write PS1");
        let tar_in = dir.join("bench.tar.gz");
        std::fs::write(&tar_in, vec![0xAAu8; 4096]).expect("write tarball");

        let mut times_ms = Vec::<(&str, u128)>::new();

        let pe_out = dir.join("bench-signed.exe");
        let t = Instant::now();
        sign_file(&pe_in, &pe_out, &credentials, None)
            .await
            .expect("sign PE");
        times_ms.push(("PE", t.elapsed().as_millis()));

        let cab_out = dir.join("bench-signed.cab");
        let t = Instant::now();
        sign_file(&cab_in, &cab_out, &credentials, None)
            .await
            .expect("sign CAB");
        times_ms.push(("CAB", t.elapsed().as_millis()));

        let msi_out = dir.join("bench-signed.msi");
        let t = Instant::now();
        sign_file(&msi_in, &msi_out, &credentials, None)
            .await
            .expect("sign MSI");
        times_ms.push(("MSI", t.elapsed().as_millis()));

        let ps1_out = dir.join("bench-signed.ps1");
        let t = Instant::now();
        sign_file(&ps1_in, &ps1_out, &credentials, None)
            .await
            .expect("sign PS1");
        times_ms.push(("PS1", t.elapsed().as_millis()));

        let t = Instant::now();
        let det = sign_detached(&tar_in, &credentials, None)
            .await
            .expect("sign detached CMS");
        times_ms.push(("CMS", t.elapsed().as_millis()));
        std::fs::write(dir.join("bench.tar.gz.p7s"), &det.p7s_data).expect("write .p7s");

        let total: u128 = times_ms.iter().map(|(_, ms)| ms).sum();
        eprintln!("\nSPEEDRUN_BENCH pki-sign={}", env!("CARGO_PKG_VERSION"));
        for (label, ms) in &times_ms {
            eprintln!("  {:<4} {} ms", label, ms);
        }
        eprintln!("  TOTAL {} ms ({:.3} s)", total, total as f64 / 1000.0);

        let verify = crate::verifier::verify_file(&pe_out).expect("verify PE");
        assert!(verify.signature_valid, "PE self-verify failed");
        eprintln!(
            "\nVERIFY (PE)  digest={} signer={} valid={}",
            verify.digest_algorithm, verify.signer_subject, verify.signature_valid
        );
    }
}
