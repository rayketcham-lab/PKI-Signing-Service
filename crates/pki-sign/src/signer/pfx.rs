//! PFX/PKCS#12 loading for signing credentials.

use std::path::Path;

use pkcs8::DecodePrivateKey;
use zeroize::Zeroizing;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
#[cfg(feature = "pq-experimental")]
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey};
use rsa::RsaPrivateKey;

use crate::error::{SignError, SignResult};

use super::keys::PrivateKey;

/// Load PFX and extract key material (shared between from_pfx and from_pfx_detached).
///
/// Tries the legacy `p12` crate first (SHA-1 MAC, RC2/3DES encryption), then
/// falls back to `p12-keystore` for modern PKCS#12 files (PBES2/AES, SHA-256 MAC).
pub(super) fn load_pfx(
    pfx_path: &Path,
    password: &str,
) -> SignResult<(PrivateKey, Vec<u8>, Vec<Vec<u8>>)> {
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
pub(super) fn parse_private_key(key_der: &[u8]) -> SignResult<PrivateKey> {
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
