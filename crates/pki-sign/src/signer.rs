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

/// Loaded signing credentials from a PFX file.
pub struct SigningCredentials {
    /// RSA private key for signing.
    rsa_key: RsaPrivateKey,
    /// DER-encoded signing certificate.
    signer_cert_der: Vec<u8>,
    /// DER-encoded chain certificates.
    chain_certs_der: Vec<Vec<u8>>,
}

impl SigningCredentials {
    /// Load signing credentials from a PFX/PKCS#12 file.
    ///
    /// Validates that the certificate has the codeSigning EKU (required for Authenticode).
    pub fn from_pfx(pfx_path: &Path, password: &str) -> SignResult<Self> {
        let (rsa_key, signer_cert_der, chain_certs_der) = load_pfx(pfx_path, password)?;

        // RFC 5280 §4.2.1.3: Validate the signing certificate's keyUsage extension.
        // If present, it MUST include digitalSignature (bit 0) for code signing.
        validate_key_usage_for_signing(&signer_cert_der)?;

        // RFC 5280 §4.2.1.12: Validate the signing certificate's extendedKeyUsage.
        // If present, it MUST include id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
        validate_eku_for_code_signing(&signer_cert_der)?;

        Ok(SigningCredentials {
            rsa_key,
            signer_cert_der,
            chain_certs_der,
        })
    }

    /// Load signing credentials from a PFX/PKCS#12 file for detached signing.
    ///
    /// Only requires digitalSignature keyUsage — no codeSigning EKU requirement.
    pub fn from_pfx_detached(pfx_path: &Path, password: &str) -> SignResult<Self> {
        let (rsa_key, signer_cert_der, chain_certs_der) = load_pfx(pfx_path, password)?;

        // For detached signing, only digitalSignature keyUsage is required
        validate_key_usage_for_signing(&signer_cert_der)?;

        Ok(SigningCredentials {
            rsa_key,
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

    /// Sign data using RSASSA-PKCS1-v1_5 with SHA-256.
    ///
    /// The input should be the DER-encoded signed attributes (as a SET).
    /// The `Signer::sign` method internally computes SHA-256(data), builds
    /// DigestInfo, applies PKCS#1 v1.5 padding, and performs RSA.
    pub fn sign_data(&self, data: &[u8]) -> SignResult<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.rsa_key.clone());
        let signature = signing_key.sign(data);
        // Convert Signature → Box<[u8]> → Vec<u8>
        let sig_bytes: Box<[u8]> = signature.into();
        Ok(sig_bytes.into_vec())
    }
}

/// Load PFX and extract key material (shared between from_pfx and from_pfx_detached).
fn load_pfx(pfx_path: &Path, password: &str) -> SignResult<(RsaPrivateKey, Vec<u8>, Vec<Vec<u8>>)> {
    let pfx_data = std::fs::read(pfx_path).map_err(|e| {
        SignError::Certificate(format!(
            "Failed to read PFX file {}: {}",
            pfx_path.display(),
            e
        ))
    })?;

    let pfx = p12::PFX::parse(&pfx_data)
        .map_err(|e| SignError::Certificate(format!("Failed to parse PFX: {e}")))?;

    // Verify the MAC to ensure correct password
    if !pfx.verify_mac(password) {
        return Err(SignError::Certificate(
            "PFX password incorrect (MAC verification failed)".into(),
        ));
    }

    // Extract private key(s) — PKCS#8 DER format
    let key_bags = pfx
        .key_bags(password)
        .map_err(|e| SignError::Certificate(format!("Failed to extract private key: {e}")))?;

    if key_bags.is_empty() {
        return Err(SignError::Certificate(
            "PFX contains no private keys".into(),
        ));
    }

    // Wrap key material in Zeroizing for secure cleanup
    let key_der = Zeroizing::new(key_bags[0].clone());

    // Parse as RSA private key from PKCS#8 DER
    let rsa_key = RsaPrivateKey::from_pkcs8_der(&key_der)
        .map_err(|e| SignError::Certificate(format!("Failed to parse RSA private key: {e}")))?;

    // Extract certificates
    let cert_bags = pfx
        .cert_x509_bags(password)
        .map_err(|e| SignError::Certificate(format!("Failed to extract certificates: {e}")))?;

    if cert_bags.is_empty() {
        return Err(SignError::Certificate(
            "PFX contains no certificates".into(),
        ));
    }

    // First certificate is the signing cert, rest are chain certs
    let signer_cert_der = cert_bags[0].clone();
    let chain_certs_der = cert_bags[1..].to_vec();

    Ok((rsa_key, signer_cert_der, chain_certs_der))
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

/// Sign a file using Authenticode.
///
/// This is the main entry point for signing operations.
pub async fn sign_file(
    input_path: &Path,
    output_path: &Path,
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
) -> SignResult<SigningResult> {
    let file_type = FileType::from_extension(input_path)?;

    let data = std::fs::read(input_path)?;
    let original_hash = hex::encode(Sha256::digest(&data));

    match file_type {
        FileType::Pe => {
            let result = sign_pe(&data, credentials, tsa_config).await?;
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
            crate::powershell::sign_ps1(&data, output_path, credentials, tsa_config).await
        }
        FileType::Msi | FileType::Cab => Err(SignError::UnsupportedFileType(
            "MSI/CAB signing not yet implemented".into(),
        )),
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
    let file_hash = hex::encode(Sha256::digest(&data));

    // Compute SHA-256 of the entire file content
    let digest = Sha256::digest(&data);

    // Build detached CMS/PKCS#7 SignedData using OID_DATA content type
    let mut builder =
        Pkcs7Builder::new_detached(credentials.signer_cert_der.clone(), digest.to_vec());

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

    // Parse keyUsage extension
    let ku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
    if let Some(ku_pos) = cert_der.windows(ku_oid.len()).position(|w| w == ku_oid) {
        let after = &cert_der[ku_pos + ku_oid.len()..];
        for i in 0..after.len().min(20) {
            if after[i] == 0x03 && i + 3 < after.len() {
                if let Ok((_, bit_content)) = asn1::parse_tlv(&after[i..]) {
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
                        break;
                    }
                }
            }
        }
    }

    // Parse EKU extension
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];
    if let Some(eku_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) {
        let search = &cert_der[eku_pos..cert_der.len().min(eku_pos + 200)];
        let code_signing: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
        let server_auth: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let email_prot: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
        let ts: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

        if search
            .windows(code_signing.len())
            .any(|w| w == code_signing)
        {
            extended_key_usage.push("codeSigning".into());
        }
        if search.windows(server_auth.len()).any(|w| w == server_auth) {
            extended_key_usage.push("serverAuth".into());
        }
        if search.windows(email_prot.len()).any(|w| w == email_prot) {
            extended_key_usage.push("emailProtection".into());
        }
        if search.windows(ts.len()).any(|w| w == ts) {
            extended_key_usage.push("timeStamping".into());
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
) -> SignResult<PeSignResult> {
    // Parse PE headers
    let pe_info = pe::PeInfo::parse(data)?;

    // Reject already-signed files
    if pe_info.is_signed() {
        return Err(SignError::AlreadySigned(
            "PE file already contains an Authenticode signature".into(),
        ));
    }

    // Compute Authenticode hash (SHA-256)
    let image_hash = pe::compute_authenticode_hash(data, &pe_info)?;

    // Build CMS/PKCS#7 SignedData
    let mut builder = Pkcs7Builder::new(credentials.signer_cert_der.clone(), image_hash);

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

    // Embed the signature in the PE file
    let signed_pe = pe::embed_signature(data, &pe_info, &pkcs7_der)?;

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
        return Err(SignError::AlreadySigned(
            "PE file already contains an Authenticode signature".into(),
        ));
    }

    let image_hash = pe::compute_authenticode_hash(data, &pe_info)?;

    let mut builder = Pkcs7Builder::new(credentials.signer_cert_der.clone(), image_hash);

    for chain_cert in &credentials.chain_certs_der {
        builder.add_chain_cert(chain_cert.clone());
    }

    let pkcs7_der = builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;

    pe::embed_signature(data, &pe_info, &pkcs7_der)
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
        let eku_seq = asn1::encode_sequence(
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
        // SizeOfHeaders at opt+60 = 0x98+60 = 0xD4
        pe[0xD4] = 0x00;
        pe[0xD5] = 0x02; // 0x200

        // NumberOfRvaAndSizes at opt+92 = 0x98+92 = 0xF4
        pe[0xF4] = 16; // 16 data directories

        // Certificate table is data directory index 4 at opt+96+4*8 = 0x98+96+32 = 0x118
        // Leave zeroed (unsigned)

        // Section header at opt + SizeOfOptionalHeader = 0x98 + 0xE0 = 0x178
        // Name: ".text\0\0\0"
        pe[0x178] = b'.';
        pe[0x179] = b't';
        pe[0x17A] = b'e';
        pe[0x17B] = b'x';
        pe[0x17C] = b't';
        // SizeOfRawData at section+16 = 0x178+16 = 0x188
        pe[0x188] = 0x00;
        pe[0x189] = 0x02; // 0x200 = 512 bytes
                          // PointerToRawData at section+20 = 0x178+20 = 0x18C
        pe[0x18C] = 0x00;
        pe[0x18D] = 0x02; // starts at 0x200

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
}
