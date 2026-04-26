//! Private key material and signing credentials.
//!
//! Holds the [`PrivateKey`] enum (RSA / ECDSA / Ed25519 / optional ML-DSA) and
//! the [`SigningCredentials`] struct that pairs a key with its certificate chain
//! and exposes signing operations.

use std::path::Path;

use rsa::pkcs1v15::SigningKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::Signer;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
#[cfg(feature = "pq-experimental")]
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use p521::ecdsa::SigningKey as P521SigningKey;

use crate::cert::validate::{
    validate_cert_validity, validate_eku_for_code_signing, validate_key_usage_for_signing,
};
use crate::error::{SignError, SignResult};

use super::pfx::load_pfx;

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
    pub(super) private_key: PrivateKey,
    /// DER-encoded signing certificate.
    pub(super) signer_cert_der: Vec<u8>,
    /// DER-encoded chain certificates.
    pub(super) chain_certs_der: Vec<Vec<u8>>,
}

impl SigningCredentials {
    /// Load signing credentials from a PFX/PKCS#12 file.
    ///
    /// Validates that the certificate has the codeSigning EKU (required for Authenticode)
    /// and that the certificate is currently valid (not expired, not yet valid).
    pub fn from_pfx(pfx_path: &Path, password: &str) -> SignResult<Self> {
        let (private_key, signer_cert_der, chain_certs_der) = load_pfx(pfx_path, password)?;

        validate_key_usage_for_signing(&signer_cert_der)?;
        validate_eku_for_code_signing(&signer_cert_der)?;
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

        validate_key_usage_for_signing(&signer_cert_der)?;
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
