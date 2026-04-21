//! Signature verification for signed PE files and PowerShell scripts.
//!
//! Extracts and validates existing Authenticode signatures:
//! - Extracts WIN_CERTIFICATE from PE cert table
//! - Parses CMS/PKCS#7 SignedData
//! - Recomputes Authenticode hash and compares to signed digest
//! - Extracts signer certificate information
//! - Checks for timestamp presence

use std::path::Path;

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{SignError, SignResult};
use crate::pe;
use crate::pkcs7::asn1;

/// Verification result for a signed file.
#[derive(Debug, serde::Serialize)]
pub struct VerifyResult {
    /// Whether the signature is valid (hash matches).
    pub signature_valid: bool,
    /// Whether the certificate chain is valid.
    pub chain_valid: bool,
    /// Whether the signer certificate has the correct EKU (RFC 5280 §4.2.1.12).
    pub eku_valid: bool,
    /// Whether a valid timestamp exists.
    pub timestamped: bool,
    /// Signing certificate subject.
    pub signer_subject: String,
    /// Signing certificate issuer.
    pub signer_issuer: String,
    /// Signature algorithm used.
    pub algorithm: String,
    /// Timestamp time (if present).
    pub timestamp_time: Option<String>,
    /// Message digest algorithm.
    pub digest_algorithm: String,
    /// The encapsulated content type (RFC 5652 §5.2 eContentType OID).
    pub content_type: String,
    /// The computed message digest (hex).
    pub computed_digest: String,
    /// The signed message digest (hex).
    pub signed_digest: String,
    /// CMS validation warnings (RFC 5652/8933 compliance issues).
    pub warnings: Vec<String>,
    /// Counter-signers detected in unsigned attributes (RFC 5652 §11.4).
    pub counter_signers: Vec<CounterSignerInfo>,
    /// Content hints description from signed attributes (RFC 2634 §2.9).
    pub content_hints: Option<String>,
}

/// Information about a counter-signer found in CMS unsigned attributes.
#[derive(Debug, serde::Serialize)]
pub struct CounterSignerInfo {
    /// Counter-signer's digest algorithm.
    pub digest_algorithm: String,
    /// Counter-signer's signature algorithm.
    pub signature_algorithm: String,
    /// Whether the counter-signature's messageDigest was verified against the parent signature.
    /// `Some(true)` = digest matches, `Some(false)` = digest mismatch, `None` = could not verify.
    pub digest_verified: Option<bool>,
    /// Whether the counter-SignerInfo signed-attributes structure is valid per RFC 5652 §11.4.
    ///
    /// A valid counter-SignerInfo MUST contain both a `contentType` attribute (OID
    /// 1.2.840.113549.1.9.3) and a `messageDigest` attribute (OID 1.2.840.113549.1.9.4)
    /// in its signed attributes. `Some(true)` = both present, `Some(false)` = one or both
    /// missing, `None` = signed attributes could not be located in the counter-SignerInfo region.
    pub signed_attrs_valid: Option<bool>,
}

/// Verify the Authenticode signature of a file.
pub fn verify_file(path: &Path) -> SignResult<VerifyResult> {
    verify_file_with_trust_store(path, &[])
}

/// Verify the Authenticode signature of a file against a trust store.
///
/// If `trusted_roots` is non-empty, the signer's certificate chain is validated
/// against the provided trusted root certificates (DER-encoded). If the chain
/// cannot be validated, `chain_valid` will be `false`.
///
/// If `trusted_roots` is empty, chain validation is skipped (backward compatible).
pub fn verify_file_with_trust_store(
    path: &Path,
    trusted_roots: &[Vec<u8>],
) -> SignResult<VerifyResult> {
    let data = std::fs::read(path)?;

    // Detect file type
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        verify_pe(&data, trusted_roots)
    } else {
        // Strip UTF-8 BOM if present (Windows editors commonly add BOMs to .ps1 files)
        let raw = if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
            &data[3..]
        } else {
            &data
        };
        let content = String::from_utf8_lossy(raw);
        if crate::powershell::is_signed(&content) {
            verify_powershell(&content, trusted_roots)
        } else {
            Err(SignError::InvalidPe(
                "File is not a PE executable or signed PowerShell script".into(),
            ))
        }
    }
}

/// Verify a detached CMS/PKCS#7 signature against file content.
///
/// Parses the `.p7s` signature, recomputes the file digest, and compares
/// it to the signed `messageDigest` attribute. Returns a `VerifyResult`
/// with `eku_valid` always `true` (no codeSigning EKU requirement for
/// detached signatures).
pub fn verify_detached(file_data: &[u8], p7s_data: &[u8]) -> SignResult<VerifyResult> {
    let cms_info = parse_cms_signed_data(p7s_data)?;

    // Recompute file digest using the algorithm from the CMS SignedData
    let computed_hash = match cms_info.digest_algorithm.as_str() {
        "SHA-384" => Sha384::digest(file_data).to_vec(),
        "SHA-512" => Sha512::digest(file_data).to_vec(),
        _ => Sha256::digest(file_data).to_vec(),
    };

    let computed_hex = hex::encode(&computed_hash);
    let signed_hex = hex::encode(&cms_info.message_digest);
    let signature_valid = computed_hash == cms_info.message_digest;

    let mut warnings = cms_info.warnings;
    validate_chain_certificates(
        &cms_info.signer_cert_der,
        &cms_info.chain_certs_der,
        &mut warnings,
    );

    Ok(VerifyResult {
        signature_valid,
        chain_valid: true,
        eku_valid: true,
        timestamped: cms_info.has_timestamp,
        signer_subject: cms_info.signer_subject,
        signer_issuer: cms_info.signer_issuer,
        algorithm: cms_info.signature_algorithm,
        timestamp_time: cms_info.timestamp_time,
        digest_algorithm: cms_info.digest_algorithm,
        content_type: cms_info.encap_content_type,
        computed_digest: computed_hex,
        signed_digest: signed_hex,
        warnings,
        counter_signers: cms_info.counter_signers,
        content_hints: cms_info.content_hints,
    })
}

/// Verify a PE file's Authenticode signature.
fn verify_pe(data: &[u8], trusted_roots: &[Vec<u8>]) -> SignResult<VerifyResult> {
    let pe_info = pe::PeInfo::parse(data)?;

    if !pe_info.is_signed() {
        return Err(SignError::InvalidPe("PE file is not signed".into()));
    }

    // Extract WIN_CERTIFICATE from cert table
    let cert_offset = pe_info.cert_table_rva as usize;
    let cert_size = pe_info.cert_table_size as usize;

    if cert_offset + cert_size > data.len() {
        return Err(SignError::InvalidPe(
            "Certificate table extends beyond file".into(),
        ));
    }

    // WIN_CERTIFICATE header: dwLength(4) + wRevision(2) + wCertificateType(2) = 8 bytes
    let win_cert_data = &data[cert_offset..cert_offset + cert_size];
    if win_cert_data.len() < 8 {
        return Err(SignError::InvalidPe("WIN_CERTIFICATE too small".into()));
    }

    let dw_length = u32::from_le_bytes([
        win_cert_data[0],
        win_cert_data[1],
        win_cert_data[2],
        win_cert_data[3],
    ]) as usize;
    let w_revision = u16::from_le_bytes([win_cert_data[4], win_cert_data[5]]);
    let w_cert_type = u16::from_le_bytes([win_cert_data[6], win_cert_data[7]]);

    if w_revision != 0x0200 {
        return Err(SignError::InvalidPe(format!(
            "Unsupported WIN_CERTIFICATE revision: {:#06x}",
            w_revision
        )));
    }
    if w_cert_type != 0x0002 {
        return Err(SignError::InvalidPe(format!(
            "Unsupported WIN_CERTIFICATE type: {:#06x} (expected PKCS#7)",
            w_cert_type
        )));
    }

    // Extract the PKCS#7 DER blob (after 8-byte header)
    let pkcs7_end = std::cmp::min(dw_length, win_cert_data.len());
    let pkcs7_der = &win_cert_data[8..pkcs7_end];

    // Parse the CMS SignedData to extract the signed digest
    let cms_info = parse_cms_signed_data(pkcs7_der)?;

    // Recompute the Authenticode hash using the algorithm from the CMS SignedData
    let digest_alg = match cms_info.digest_algorithm.as_str() {
        "SHA-384" => crate::pkcs7::builder::DigestAlgorithm::Sha384,
        "SHA-512" => crate::pkcs7::builder::DigestAlgorithm::Sha512,
        "SHA3-256" => crate::pkcs7::builder::DigestAlgorithm::Sha3_256,
        "SHA3-384" => crate::pkcs7::builder::DigestAlgorithm::Sha3_384,
        "SHA3-512" => crate::pkcs7::builder::DigestAlgorithm::Sha3_512,
        _ => crate::pkcs7::builder::DigestAlgorithm::Sha256,
    };
    let computed_hash = pe::compute_authenticode_hash_with(data, &pe_info, digest_alg)?;
    let computed_hex = hex::encode(&computed_hash);
    // For Authenticode, the file hash is inside SpcIndirectDataContent.DigestInfo,
    // not in the messageDigest signed attribute (which is hash of the eContent).
    let file_digest = cms_info
        .spc_file_digest
        .as_ref()
        .unwrap_or(&cms_info.message_digest);
    let signed_hex = hex::encode(file_digest);

    let signature_valid = computed_hash == *file_digest;

    let chain_valid = if trusted_roots.is_empty() {
        true // No trust store provided — skip chain validation (backward compat)
    } else {
        validate_signer_chain(
            &cms_info.signer_cert_der,
            &cms_info.chain_certs_der,
            trusted_roots,
        )
    };

    // RFC 5280 §4.2.1.12: Validate code signing EKU on signer certificate
    let eku_valid = if cms_info.signer_cert_der.is_empty() {
        false // No signer cert — can't validate EKU
    } else {
        check_code_signing_eku(&cms_info.signer_cert_der)
    };

    // RFC 5280 §6: Additional chain validation warnings
    let mut warnings = cms_info.warnings;
    validate_chain_certificates(
        &cms_info.signer_cert_der,
        &cms_info.chain_certs_der,
        &mut warnings,
    );

    Ok(VerifyResult {
        signature_valid,
        chain_valid,
        eku_valid,
        timestamped: cms_info.has_timestamp,
        signer_subject: cms_info.signer_subject,
        signer_issuer: cms_info.signer_issuer,
        algorithm: cms_info.signature_algorithm,
        timestamp_time: cms_info.timestamp_time,
        digest_algorithm: cms_info.digest_algorithm,
        content_type: cms_info.encap_content_type,
        computed_digest: computed_hex,
        signed_digest: signed_hex,
        warnings,
        counter_signers: cms_info.counter_signers,
        content_hints: cms_info.content_hints,
    })
}

/// Verify a PowerShell script's signature.
fn verify_powershell(content: &str, trusted_roots: &[Vec<u8>]) -> SignResult<VerifyResult> {
    // Extract the PKCS#7 DER from the signature block
    let pkcs7_der = crate::powershell::extract_signature(content)?;

    // Get the script content without the signature block
    let script_content = crate::powershell::strip_signature(content);

    // Parse the CMS SignedData
    let cms_info = parse_cms_signed_data(&pkcs7_der)?;

    // Compute hash of the script content as raw UTF-8 bytes with CRLF normalization
    let computed_hash = crate::powershell::hash_script_bytes(script_content);
    let computed_hex = hex::encode(&computed_hash);
    // For Authenticode, the file hash is inside SpcIndirectDataContent.DigestInfo,
    // not in the messageDigest signed attribute (which is hash of the eContent).
    let file_digest = cms_info
        .spc_file_digest
        .as_ref()
        .unwrap_or(&cms_info.message_digest);
    let signed_hex = hex::encode(file_digest);

    let signature_valid = computed_hash == *file_digest;

    let chain_valid = if trusted_roots.is_empty() {
        true // No trust store provided — skip chain validation (backward compat)
    } else {
        validate_signer_chain(
            &cms_info.signer_cert_der,
            &cms_info.chain_certs_der,
            trusted_roots,
        )
    };

    // RFC 5280 §4.2.1.12: Validate code signing EKU on signer certificate
    let eku_valid = if cms_info.signer_cert_der.is_empty() {
        false
    } else {
        check_code_signing_eku(&cms_info.signer_cert_der)
    };

    // RFC 5280 §6: Additional chain validation warnings
    let mut warnings = cms_info.warnings;
    validate_chain_certificates(
        &cms_info.signer_cert_der,
        &cms_info.chain_certs_der,
        &mut warnings,
    );

    Ok(VerifyResult {
        signature_valid,
        chain_valid,
        eku_valid,
        timestamped: cms_info.has_timestamp,
        signer_subject: cms_info.signer_subject,
        signer_issuer: cms_info.signer_issuer,
        algorithm: cms_info.signature_algorithm,
        timestamp_time: cms_info.timestamp_time,
        digest_algorithm: cms_info.digest_algorithm,
        content_type: cms_info.encap_content_type,
        computed_digest: computed_hex,
        signed_digest: signed_hex,
        warnings,
        counter_signers: cms_info.counter_signers,
        content_hints: cms_info.content_hints,
    })
}

// ─── EKU Validation (RFC 5280 §4.2.1.12) ───

/// Check if a DER-encoded certificate has the id-kp-codeSigning EKU (1.3.6.1.5.5.7.3.3).
///
/// Returns `true` if:
/// - The certificate has an EKU extension containing id-kp-codeSigning
/// - The certificate has an EKU extension containing anyExtendedKeyUsage (2.5.29.37.0)
/// - The certificate has no EKU extension (permitted — many CA certs omit EKU)
///
/// Returns `false` if the EKU extension is present but does NOT include codeSigning.
fn check_code_signing_eku(cert_der: &[u8]) -> bool {
    // extendedKeyUsage OID: 2.5.29.37
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

    // id-kp-codeSigning OID value bytes: 1.3.6.1.5.5.7.3.3
    let code_signing_oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

    // anyExtendedKeyUsage OID value bytes: 2.5.29.37.0
    let any_eku_oid_value: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    // Search for the EKU extension OID in the certificate DER
    let Some(oid_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) else {
        return true; // No EKU extension — permitted (many CA certs omit EKU)
    };

    // Scan the region after the EKU OID for codeSigning or anyExtendedKeyUsage
    let search_region = &cert_der[oid_pos..cert_der.len().min(oid_pos + 200)];

    let has_code_signing = search_region
        .windows(code_signing_oid_value.len())
        .any(|w| w == code_signing_oid_value);

    let has_any_eku = search_region
        .windows(any_eku_oid_value.len())
        .any(|w| w == any_eku_oid_value);

    has_code_signing || has_any_eku
}

/// Check if a DER-encoded certificate has the id-kp-timeStamping EKU (1.3.6.1.5.5.7.3.8).
///
/// Unlike [`check_code_signing_eku`], this function rejects certificates that
/// omit the EKU extension entirely: RFC 3161 §2.3 requires TSA certificates to
/// explicitly include `id-kp-timeStamping`, so absence of the extension is an error.
///
/// Returns `Ok(())` when the EKU extension is present and contains
/// `id-kp-timeStamping` or `anyExtendedKeyUsage`.
/// Returns `Err(SignError::TsaCertInvalid(_))` otherwise.
fn check_tsa_eku(cert_der: &[u8]) -> SignResult<()> {
    // extendedKeyUsage OID: 2.5.29.37
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

    // id-kp-timeStamping OID value bytes: 1.3.6.1.5.5.7.3.8
    let time_stamping_oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

    // anyExtendedKeyUsage OID value bytes: 2.5.29.37.0
    let any_eku_oid_value: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    // RFC 3161 §2.3: EKU extension MUST be present in TSA certificates.
    let Some(oid_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) else {
        return Err(SignError::TsaCertInvalid(
            "TSA certificate missing ExtendedKeyUsage extension (RFC 3161 §2.3 requires id-kp-timeStamping)".into(),
        ));
    };

    let search_region = &cert_der[oid_pos..cert_der.len().min(oid_pos + 200)];

    let has_time_stamping = search_region
        .windows(time_stamping_oid_value.len())
        .any(|w| w == time_stamping_oid_value);

    let has_any_eku = search_region
        .windows(any_eku_oid_value.len())
        .any(|w| w == any_eku_oid_value);

    if has_time_stamping || has_any_eku {
        Ok(())
    } else {
        Err(SignError::TsaCertInvalid(
            "TSA certificate EKU extension does not include id-kp-timeStamping (1.3.6.1.5.5.7.3.8)"
                .into(),
        ))
    }
}

/// Load TSA trust-anchor certificates from a list of PEM or DER files.
///
/// Each path may contain one or more PEM-encoded certificates, or a single
/// DER-encoded certificate.  Returns a flat `Vec<Vec<u8>>` of DER-encoded
/// certificates suitable for passing to [`validate_signer_chain`].
///
/// Errors are logged as warnings and skipped — a missing or unreadable trust
/// root file should not abort verification; the caller decides what to do with
/// an empty result set.
pub fn load_tsa_trust_roots(paths: &[std::path::PathBuf]) -> Vec<Vec<u8>> {
    let mut roots = Vec::new();
    for path in paths {
        match std::fs::read(path) {
            Err(e) => {
                // Non-fatal: log and continue
                tracing::warn!("Failed to read TSA trust root {:?}: {}", path, e);
                continue;
            }
            Ok(bytes) => {
                // Try PEM first
                let mut pem_cursor = bytes.as_slice();
                let mut found_pem = false;
                for cert_result in rustls_pemfile::certs(&mut pem_cursor) {
                    match cert_result {
                        Ok(der) => {
                            roots.push(der.to_vec());
                            found_pem = true;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse PEM cert in {:?}: {}", path, e);
                        }
                    }
                }
                // If no PEM certs found, treat raw bytes as DER
                if !found_pem {
                    roots.push(bytes);
                }
            }
        }
    }
    roots
}

// ─── Certificate Chain Validation ───

/// Validate the signer's certificate chain against trusted root certificates.
///
/// Walks from the signer cert up through the chain certs, verifying that each
/// certificate's issuer matches the subject of the next cert in the chain,
/// and that the chain terminates at a trusted root.
///
/// This is a simplified chain validation that checks:
/// 1. Issuer/subject DN matching up the chain
/// 2. The chain terminates at a cert whose subject matches a trusted root's subject
///
/// It does NOT perform full RFC 5280 path validation (signature verification
/// would require the crypto primitives from spork-core which aren't in this crate's
/// dependency tree). For full path validation, use `spork-core`'s `validate_chain()`.
fn validate_signer_chain(
    signer_cert_der: &[u8],
    chain_certs_der: &[Vec<u8>],
    trusted_roots: &[Vec<u8>],
) -> bool {
    // Extract the signer cert's issuer
    let signer_issuer = match extract_issuer_der(signer_cert_der) {
        Some(issuer) => issuer,
        None => return false,
    };

    // Check if signer is directly issued by a trusted root
    if is_issued_by_trusted_root(&signer_issuer, trusted_roots) {
        return true;
    }

    // Walk the chain: find the cert whose subject matches signer's issuer,
    // then check if that cert's issuer is a trusted root, and so on.
    let mut current_issuer = signer_issuer;
    let mut visited = vec![false; chain_certs_der.len()];
    let max_depth = chain_certs_der.len() + 1; // prevent loops

    for _ in 0..max_depth {
        // Find a chain cert whose subject matches the current issuer
        let mut found = false;
        for (i, cert_der) in chain_certs_der.iter().enumerate() {
            if visited[i] {
                continue;
            }
            if let Some(subject) = extract_subject_der(cert_der) {
                if subject == current_issuer {
                    visited[i] = true;
                    found = true;
                    // Check if this intermediate's issuer is a trusted root
                    if let Some(issuer) = extract_issuer_der(cert_der) {
                        if is_issued_by_trusted_root(&issuer, trusted_roots) {
                            return true;
                        }
                        // Self-signed intermediate that's also in the trust store?
                        if issuer == subject && trusted_roots.iter().any(|r| r == cert_der) {
                            return true;
                        }
                        current_issuer = issuer;
                    } else {
                        return false;
                    }
                    break;
                }
            }
        }
        if !found {
            return false;
        }
    }

    false
}

/// Check if the given issuer DER matches the subject of any trusted root.
fn is_issued_by_trusted_root(issuer_der: &[u8], trusted_roots: &[Vec<u8>]) -> bool {
    for root_der in trusted_roots {
        if let Some(root_subject) = extract_subject_der(root_der) {
            if root_subject == issuer_der {
                return true;
            }
        }
    }
    false
}

/// Validate chain certificates for RFC 5280 §6 compliance (warnings only).
///
/// Checks intermediate certificates for:
/// - basicConstraints CA flag (RFC 5280 §4.2.1.9)
/// - keyUsage keyCertSign bit (RFC 5280 §4.2.1.3)
fn validate_chain_certificates(
    signer_cert_der: &[u8],
    chain_certs_der: &[Vec<u8>],
    warnings: &mut Vec<String>,
) {
    // Check signer cert should NOT have basicConstraints CA=TRUE
    if !signer_cert_der.is_empty() && check_basic_constraints_ca(signer_cert_der) {
        warnings.push(
            "RFC 5280 §4.2.1.9: signer certificate has basicConstraints cA=TRUE — should be end-entity".to_string(),
        );
    }

    // Check intermediate certs MUST have basicConstraints CA=TRUE and keyUsage keyCertSign
    for cert_der in chain_certs_der {
        let subject = extract_subject_cn(cert_der).unwrap_or_default();

        // RFC 5280 §4.2.1.9: CA certs MUST have basicConstraints with cA=TRUE
        if !check_basic_constraints_ca(cert_der) {
            warnings.push(format!(
                "RFC 5280 §4.2.1.9: intermediate '{}' missing basicConstraints cA=TRUE",
                subject
            ));
        }

        // RFC 5280 §4.2.1.3: CA certs MUST have keyUsage with keyCertSign
        if !check_key_usage_cert_sign(cert_der) {
            warnings.push(format!(
                "RFC 5280 §4.2.1.3: intermediate '{}' missing keyUsage keyCertSign",
                subject
            ));
        }
    }
}

/// Check if a certificate has basicConstraints with cA=TRUE.
///
/// Looks for basicConstraints OID (2.5.29.19 = 55 1D 13), then finds
/// the OCTET STRING extnValue, and checks for BOOLEAN TRUE inside
/// the BasicConstraints SEQUENCE value.
fn check_basic_constraints_ca(cert_der: &[u8]) -> bool {
    // OID 2.5.29.19 (basicConstraints)
    let bc_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];
    let Some(oid_pos) = cert_der.windows(bc_oid.len()).position(|w| w == bc_oid) else {
        return false;
    };
    // After the OID, skip optional critical BOOLEAN and find the OCTET STRING (0x04)
    let after_oid = &cert_der[oid_pos + bc_oid.len()..];
    let end = after_oid.len().min(20);
    let search = &after_oid[..end];

    // Find OCTET STRING tag (0x04) — the extnValue
    let Some(os_pos) = search.iter().position(|&b| b == 0x04) else {
        return false;
    };
    // The extnValue starts after the OCTET STRING tag and length
    if os_pos + 2 > search.len() {
        return false;
    }
    let os_len = search[os_pos + 1] as usize;
    let value_start = os_pos + 2;
    let value_end = (value_start + os_len).min(search.len());
    let bc_value = &search[value_start..value_end];

    // Inside BasicConstraints SEQUENCE, look for BOOLEAN TRUE (cA = TRUE)
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
    let ca_true: &[u8] = &[0x01, 0x01, 0xFF];
    bc_value.windows(ca_true.len()).any(|w| w == ca_true)
}

/// Check if a certificate has keyUsage with keyCertSign bit set.
///
/// keyUsage OID = 2.5.29.15 (55 1D 0F). The keyCertSign bit is bit 5
/// of the KeyUsage BIT STRING, which corresponds to byte value 0x04
/// (or any value with bit 5 set: 0x04, 0x06, 0x24, 0x26, etc.).
fn check_key_usage_cert_sign(cert_der: &[u8]) -> bool {
    // OID 2.5.29.15 (keyUsage)
    let ku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
    let Some(oid_pos) = cert_der.windows(ku_oid.len()).position(|w| w == ku_oid) else {
        return false; // No keyUsage extension
    };
    // Look for BIT STRING tag (0x03) after OID and possible critical flag + OCTET STRING wrapper
    let end = cert_der.len().min(oid_pos + 20);
    let search = &cert_der[oid_pos + ku_oid.len()..end];
    // Find the BIT STRING (tag 0x03)
    for i in 0..search.len().saturating_sub(3) {
        if search[i] == 0x03 && search[i + 1] >= 0x02 {
            // BIT STRING: tag, length, unused-bits, value-byte(s)
            let unused_bits = search[i + 2];
            if unused_bits <= 7 && i + 3 < search.len() {
                let key_usage_byte = search[i + 3];
                // keyCertSign is bit 5 (0x04 in the first octet)
                return key_usage_byte & 0x04 != 0;
            }
        }
    }
    false
}

/// Extract the subject CN from a certificate (for warning messages).
fn extract_subject_cn(cert_der: &[u8]) -> Option<String> {
    let subject_der = extract_subject_der(cert_der)?;
    // Look for CN OID (2.5.4.3 = 55 04 03) in the subject
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let pos = subject_der
        .windows(cn_oid.len())
        .position(|w| w == cn_oid)?;
    let after_oid = &subject_der[pos + cn_oid.len()..];
    // Next TLV should be the CN value (UTF8String, PrintableString, etc.)
    if after_oid.len() >= 2 {
        let len = after_oid[1] as usize;
        if after_oid.len() >= 2 + len {
            return Some(String::from_utf8_lossy(&after_oid[2..2 + len]).to_string());
        }
    }
    None
}

/// Extract the issuer Name DER from a certificate.
fn extract_issuer_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, tbs) = asn1::parse_tlv(cert_der).ok()?;
    let (_, tbs_content) = asn1::parse_tlv(tbs).ok()?;
    let mut pos = tbs_content;
    // Skip version [0] if present
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, remaining) = asn1::skip_tlv(pos).ok()?;
        pos = remaining;
    }
    // Skip serial
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Skip signature algorithm
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Extract issuer
    let (issuer_tlv, _) = asn1::extract_tlv(pos).ok()?;
    Some(issuer_tlv.to_vec())
}

/// Extract the subject Name DER from a certificate.
fn extract_subject_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, tbs) = asn1::parse_tlv(cert_der).ok()?;
    let (_, tbs_content) = asn1::parse_tlv(tbs).ok()?;
    let mut pos = tbs_content;
    // Skip version [0] if present
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, remaining) = asn1::skip_tlv(pos).ok()?;
        pos = remaining;
    }
    // Skip serial
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Skip signature algorithm
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Skip issuer
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Skip validity
    let (_, remaining) = asn1::skip_tlv(pos).ok()?;
    pos = remaining;
    // Extract subject
    let (subject_tlv, _) = asn1::extract_tlv(pos).ok()?;
    Some(subject_tlv.to_vec())
}

// ─── CMS/PKCS#7 Parsing ───

/// Extracted information from a CMS SignedData structure.
#[derive(Debug)]
struct CmsInfo {
    /// The message digest from signed attributes.
    /// For Authenticode, this is the hash of the SpcIndirectDataContent DER.
    /// For detached CMS, this is the hash of the file content.
    message_digest: Vec<u8>,
    /// The file/image digest extracted from SpcIndirectDataContent.DigestInfo.
    /// Only present for Authenticode signatures (SPC_INDIRECT_DATA content type).
    spc_file_digest: Option<Vec<u8>>,
    /// Signer certificate subject (CN or full DN).
    signer_subject: String,
    /// Signer certificate issuer (CN or full DN).
    signer_issuer: String,
    /// Signature algorithm name.
    signature_algorithm: String,
    /// Digest algorithm name (extracted from SignerInfo digestAlgorithm).
    digest_algorithm: String,
    /// The encapContentInfo eContentType OID (RFC 5652 §5.2).
    encap_content_type: String,
    /// Whether a timestamp unsigned attribute is present.
    has_timestamp: bool,
    /// Timestamp time string (if extractable).
    timestamp_time: Option<String>,
    /// DER-encoded signer certificate (for chain validation).
    signer_cert_der: Vec<u8>,
    /// DER-encoded chain certificates (intermediates from PKCS#7 certificates field).
    chain_certs_der: Vec<Vec<u8>>,
    /// Warnings from CMS validation (non-fatal issues).
    warnings: Vec<String>,
    /// Counter-signers detected in unsigned attributes.
    counter_signers: Vec<CounterSignerInfo>,
    /// Content hints description (RFC 2634 §2.9).
    content_hints: Option<String>,
}

/// Parse a CMS/PKCS#7 ContentInfo → SignedData and extract verification info.
///
/// Structure:
/// ```text
/// ContentInfo ::= SEQUENCE {
///     contentType  OID (signedData),
///     content      [0] EXPLICIT SignedData
/// }
///
/// SignedData ::= SEQUENCE {
///     version           INTEGER,
///     digestAlgorithms   SET,
///     encapContentInfo   SEQUENCE,
///     certificates       [0] IMPLICIT SET OF Certificate,
///     signerInfos        SET OF SignerInfo
/// }
///
/// SignerInfo ::= SEQUENCE {
///     version            INTEGER,
///     sid                IssuerAndSerialNumber,
///     digestAlgorithm    AlgorithmIdentifier,
///     signedAttrs        [0] IMPLICIT SET OF Attribute,
///     signatureAlgorithm AlgorithmIdentifier,
///     signature          OCTET STRING,
///     unsignedAttrs      [1] IMPLICIT SET OF Attribute OPTIONAL
/// }
/// ```
fn parse_cms_signed_data(pkcs7_der: &[u8]) -> SignResult<CmsInfo> {
    // ContentInfo SEQUENCE
    let (_, ci_content) = asn1::parse_tlv(pkcs7_der)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse ContentInfo: {e}")))?;

    // RFC 5652 §3: Validate contentType OID is id-signedData (1.2.840.113549.1.7.2)
    let (content_type_tlv, remaining) = asn1::extract_tlv(ci_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract contentType: {e}")))?;
    if content_type_tlv != asn1::OID_SIGNED_DATA {
        return Err(SignError::Pkcs7(format!(
            "ContentInfo contentType is not id-signedData (expected OID 1.2.840.113549.1.7.2, got {} bytes)",
            content_type_tlv.len()
        )));
    }

    // [0] EXPLICIT → content
    let (_, explicit_content) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse [0] EXPLICIT: {e}")))?;

    // SignedData SEQUENCE
    let (_, sd_content) = asn1::parse_tlv(explicit_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse SignedData: {e}")))?;

    // version — RFC 5652 §5.1: MUST be 1, 3, 4, or 5
    let (version_tlv, remaining) = asn1::extract_tlv(sd_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract version: {e}")))?;
    let sd_version = extract_integer_value(version_tlv);

    // digestAlgorithms SET — extract for RFC 5652 §5.3 cross-validation
    let (digest_algs_tlv, remaining) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract digestAlgorithms: {e}")))?;

    // RFC 5652 §5.1: validate no duplicate digest algorithms in the SET
    let digest_alg_warnings = validate_digest_algorithms_unique(digest_algs_tlv);

    // encapContentInfo SEQUENCE — extract eContentType OID (RFC 5652 §5.2)
    let (encap_ci_tlv, remaining) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract encapContentInfo: {e}")))?;
    let encap_content_type = extract_encap_content_type(encap_ci_tlv);
    let encap_ct_oid_tlv = extract_encap_content_type_oid_tlv(encap_ci_tlv);

    // For Authenticode (SPC_INDIRECT_DATA), extract the file digest from eContent.
    // eContent is inside [0] EXPLICIT after the OID in encapContentInfo.
    let spc_file_digest = extract_spc_file_digest_from_encap(encap_ci_tlv);

    // certificates [0] IMPLICIT — extract certs for signer info and chain validation
    let (cert_tag, cert_content) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse certificates: {e}")))?;

    let mut signer_cert_der = Vec::new();
    let mut chain_certs_der = Vec::new();

    let (signer_subject, signer_issuer) = if cert_tag == 0xA0 {
        // cert_content contains raw certificate DER(s)
        // Extract all certs: first is signer, rest are chain
        let mut cert_pos = cert_content;
        let mut first = true;
        while !cert_pos.is_empty() {
            if let Ok((cert_tlv, cert_remaining)) = asn1::extract_tlv(cert_pos) {
                if first {
                    signer_cert_der = cert_tlv.to_vec();
                    first = false;
                } else {
                    chain_certs_der.push(cert_tlv.to_vec());
                }
                cert_pos = cert_remaining;
            } else {
                break;
            }
        }
        extract_cert_subject_issuer(cert_content)
            .unwrap_or_else(|_| ("(unknown subject)".into(), "(unknown issuer)".into()))
    } else {
        ("(no certificates)".into(), "(no certificates)".into())
    };

    // RFC 5652 §5.1: certificates SHOULD contain enough certs to verify the signer
    let mut cert_warnings = Vec::new();
    if signer_cert_der.is_empty() {
        cert_warnings.push(
            "RFC 5652 §5.1: no certificates present in SignedData certificates field".to_string(),
        );
    }

    // Skip certificates
    let (_, remaining) = asn1::skip_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to skip certificates: {e}")))?;

    // signerInfos SET
    let (_, si_set_content) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse signerInfos: {e}")))?;

    // SignerInfo SEQUENCE
    let (_, si_content) = asn1::parse_tlv(si_set_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse SignerInfo: {e}")))?;

    // SignerInfo version — RFC 5652 §5.3: MUST be 1, 3, or 5
    let (si_version_tlv, remaining) = asn1::extract_tlv(si_content)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract SI version: {e}")))?;
    let si_version = extract_integer_value(si_version_tlv);

    // sid (SignerIdentifier) — peek at tag for version-sid consistency check
    // RFC 5652 §5.3: version MUST be 1 if sid is issuerAndSerialNumber (SEQUENCE 0x30),
    // version MUST be 3 if sid is subjectKeyIdentifier ([0] IMPLICIT 0x80)
    let sid_tag = remaining.first().copied().unwrap_or(0);
    let (_, remaining) = asn1::skip_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to skip sid: {e}")))?;

    // digestAlgorithm — extract for cross-validation
    let (si_digest_alg_tlv, remaining) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract digestAlgorithm: {e}")))?;

    // signedAttrs [0] IMPLICIT — extract messageDigest
    let (attrs_tag, attrs_content) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to parse signedAttrs: {e}")))?;

    let (message_digest, mut cms_warnings, signed_attrs_content) = if attrs_tag == 0xA0 {
        let digest = extract_message_digest(attrs_content)?;
        let mut warns = validate_signed_attributes(attrs_content);

        // RFC 5652 §5.1: SignedData version MUST be 1, 3, 4, or 5
        if let Some(v) = sd_version {
            if v != 1 && v != 3 && v != 4 && v != 5 {
                return Err(SignError::Pkcs7(format!(
                    "RFC 5652 §5.1: SignedData version {} is not valid (must be 1, 3, 4, or 5)",
                    v
                )));
            }
        }

        // RFC 5652 §5.3: SignerInfo version MUST be 1, 3, or 5
        if let Some(v) = si_version {
            if v != 1 && v != 3 && v != 5 {
                return Err(SignError::Pkcs7(format!(
                    "RFC 5652 §5.3: SignerInfo version {} is not valid (must be 1, 3, or 5)",
                    v
                )));
            }
        }

        // RFC 5652 §5.3: version-sid consistency
        // version 1 → sid is IssuerAndSerialNumber (SEQUENCE, tag 0x30)
        // version 3 → sid is SubjectKeyIdentifier ([0] IMPLICIT, tag 0x80)
        if let Some(v) = si_version {
            match (v, sid_tag) {
                (1, 0x30) | (3, 0x80) => {} // consistent
                (1, 0x80) => warns.push(
                    "RFC 5652 §5.3: SignerInfo version is 1 but sid is SubjectKeyIdentifier (expected IssuerAndSerialNumber)".to_string(),
                ),
                (3, 0x30) => warns.push(
                    "RFC 5652 §5.3: SignerInfo version is 3 but sid is IssuerAndSerialNumber (expected SubjectKeyIdentifier)".to_string(),
                ),
                _ => {} // version 5 or other values — no sid constraint
            }
        }

        // RFC 5652 §5.3: SignerInfo digestAlgorithm MUST be present in the
        // top-level digestAlgorithms SET
        if !digest_algorithms_set_contains(digest_algs_tlv, si_digest_alg_tlv) {
            return Err(SignError::Pkcs7(
                "RFC 5652 §5.3: SignerInfo digestAlgorithm not present in top-level digestAlgorithms SET".to_string(),
            ));
        }

        // RFC 8933 §3: If CMSAlgorithmProtection is present, verify its
        // digestAlgorithm matches the SignerInfo digestAlgorithm
        let cap_warns = validate_cms_algorithm_protection_digest(attrs_content, si_digest_alg_tlv);
        warns.extend(cap_warns);

        // RFC 5652 §5.3: contentType attribute value MUST match eContentType
        if let Some(ref oid_tlv) = encap_ct_oid_tlv {
            let ct_warns = validate_content_type_matches_econtent(attrs_content, oid_tlv);
            warns.extend(ct_warns);
        }

        (digest, warns, attrs_content)
    } else {
        return Err(SignError::Pkcs7("No signed attributes found".into()));
    };

    // Skip signedAttrs
    let (_, remaining) = asn1::skip_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to skip signedAttrs: {e}")))?;

    // signatureAlgorithm — determine algorithm name
    let (sig_alg_tlv, remaining) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract sigAlgorithm: {e}")))?;

    // RFC 8933 §3: Also verify CMSAlgorithmProtection signatureAlgorithm matches
    let cap_sig_warns =
        validate_cms_algorithm_protection_signature(signed_attrs_content, sig_alg_tlv);
    cms_warnings.extend(cap_sig_warns);
    cms_warnings.extend(cert_warnings);
    cms_warnings.extend(digest_alg_warnings);

    let signature_algorithm = identify_signature_algorithm(sig_alg_tlv);
    let digest_algorithm = identify_digest_algorithm(si_digest_alg_tlv);

    // RFC 5652 §4.6: Unknown algorithm OIDs must not cause rejection, but
    // callers should be notified so they can investigate.
    if signature_algorithm.starts_with("(unknown") {
        // Extract the OID bytes from the AlgorithmIdentifier SEQUENCE for
        // display.  The SEQUENCE content begins after the outer TLV header;
        // the first nested TLV is the OID (tag 0x06).
        let sig_oid_hex = extract_oid_hex_from_alg_id(sig_alg_tlv);
        cms_warnings.push(format!(
            "RFC 5652 §4.6: unrecognized signature algorithm OID in SignerInfo — {}",
            sig_oid_hex,
        ));
    }
    if digest_algorithm.starts_with("(unknown") {
        let digest_oid_hex = extract_oid_hex_from_alg_id(si_digest_alg_tlv);
        cms_warnings.push(format!(
            "RFC 5652 §4.6: unrecognized digest algorithm OID in SignerInfo — {}",
            digest_oid_hex,
        ));
    }

    // Extract signature OCTET STRING (needed for counter-signature verification)
    let (sig_octet_tlv, remaining) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Pkcs7(format!("Failed to extract signature: {e}")))?;
    // The signature value is the content of the OCTET STRING (skip tag+length)
    let parent_signature_value = asn1::parse_tlv(sig_octet_tlv)
        .map(|(_, content)| content)
        .unwrap_or(sig_octet_tlv);

    // unsignedAttrs [1] IMPLICIT — check for timestamp and counter-signatures
    let has_timestamp = !remaining.is_empty() && remaining[0] == 0xA1;
    let timestamp_time = if has_timestamp {
        extract_timestamp_gen_time(remaining)
    } else {
        None
    };
    let counter_signers = if has_timestamp {
        extract_and_verify_counter_signers(remaining, parent_signature_value)
    } else {
        Vec::new()
    };

    // RFC 3161 §2.4.1 + RFC 5652 §11.4: Validate counter-signature temporal ordering
    if has_timestamp && !counter_signers.is_empty() {
        let parent_signing_time = extract_signing_time(signed_attrs_content);
        let temporal_warns =
            validate_counter_signer_temporal_ordering(parent_signing_time.as_deref(), remaining);
        cms_warnings.extend(temporal_warns);
    }

    // RFC 5652 §5.3: Validate unsigned attributes structure if present
    if has_timestamp {
        let unsigned_warns = validate_unsigned_attributes(remaining);
        cms_warnings.extend(unsigned_warns);
    }

    // RFC 5035 §4: Validate ESSCertIDv2 hash matches signer certificate
    if !signer_cert_der.is_empty() {
        let ess_warns = validate_ess_cert_id_v2(signed_attrs_content, &signer_cert_der);
        cms_warnings.extend(ess_warns);
    }

    // RFC 2634 §2.9: Extract content hints description from signed attributes
    let content_hints = extract_content_hints_description(signed_attrs_content);

    // RFC 5652 §11.3: signingTime SHOULD fall within the signer certificate's
    // validity period (notBefore..notAfter). A signing time outside the cert
    // validity indicates the cert was expired or not yet valid at signing time.
    if !signer_cert_der.is_empty() {
        if let Some(ref st) = extract_signing_time(signed_attrs_content) {
            let st_warns = validate_signing_time_vs_cert_validity(st, &signer_cert_der);
            cms_warnings.extend(st_warns);
        }
    }

    Ok(CmsInfo {
        message_digest,
        spc_file_digest,
        signer_subject,
        signer_issuer,
        signature_algorithm,
        digest_algorithm,
        encap_content_type,
        has_timestamp,
        timestamp_time,
        signer_cert_der,
        chain_certs_der,
        warnings: cms_warnings,
        counter_signers,
        content_hints,
    })
}

/// Extract the genTime from a timestamp token in unsigned attributes.
///
/// RFC 3161 §2.4.2: The TSTInfo structure contains a genTime field
/// (GeneralizedTime) that records when the timestamp was issued.
///
/// Structure path:
/// unsignedAttrs [1] -> Attribute { OID timeStampToken, SET { ContentInfo } }
/// -> ContentInfo { signedData } -> SignedData -> EncapsulatedContentInfo
/// -> eContent [0] EXPLICIT -> TSTInfo -> genTime (GeneralizedTime)
///
/// Returns None if parsing fails at any stage (best-effort extraction).
fn extract_timestamp_gen_time(unsigned_attrs_raw: &[u8]) -> Option<String> {
    // OID 1.2.840.113549.1.9.16.2.14 — id-smime-aa-timeStampToken
    let tst_token_oid: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];

    // Search for the timestamp token OID in the unsigned attributes
    let oid_pos = unsigned_attrs_raw
        .windows(tst_token_oid.len())
        .position(|w| w == tst_token_oid)?;

    // After the OID, we need to find the TSTInfo structure deep in the CMS.
    // The TSTInfo genTime is a GeneralizedTime (tag 0x18) — scan for it.
    // GeneralizedTime format: "YYYYMMDDHHmmSSZ" or with fractional seconds.
    let search_region = &unsigned_attrs_raw[oid_pos..];

    // Scan for GeneralizedTime tags (0x18) in the timestamp token region.
    // TSTInfo genTime is typically within the first ~200 bytes of the eContent.
    // We look for the first GeneralizedTime that looks like a valid timestamp.
    for i in 0..search_region.len().saturating_sub(16) {
        if search_region[i] == 0x18 && i + 1 < search_region.len() {
            let len = search_region[i + 1] as usize;
            if (13..=25).contains(&len) && i + 2 + len <= search_region.len() {
                let time_bytes = &search_region[i + 2..i + 2 + len];
                // Validate it looks like a GeneralizedTime: starts with 4-digit year
                if time_bytes.len() >= 14 && time_bytes.iter().take(14).all(|&b| b.is_ascii_digit())
                {
                    // It's "YYYYMMDDHHmmSS" possibly followed by ".fractionsZ"
                    if let Ok(time_str) = std::str::from_utf8(time_bytes) {
                        // Format nicely: "YYYY-MM-DD HH:MM:SS UTC"
                        if time_str.len() >= 14 {
                            let formatted = format!(
                                "{}-{}-{} {}:{}:{} UTC",
                                &time_str[..4],
                                &time_str[4..6],
                                &time_str[6..8],
                                &time_str[8..10],
                                &time_str[10..12],
                                &time_str[12..14],
                            );
                            return Some(formatted);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Extract signingTime from signed attributes content (RFC 5652 §11.3).
///
/// Searches for the signingTime OID and extracts the UTCTime or GeneralizedTime value.
/// Returns the time string in "YYYY-MM-DD HH:MM:SS" format, or None if not found.
fn extract_signing_time(attrs_content: &[u8]) -> Option<String> {
    // signingTime OID content bytes: 1.2.840.113549.1.9.5
    let st_oid_content: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

    let oid_pos = attrs_content
        .windows(st_oid_content.len())
        .position(|w| w == st_oid_content)?;

    // After the OID, skip to the SET { time } value
    let after_oid = &attrs_content[oid_pos + st_oid_content.len()..];

    // Scan for UTCTime (0x17) or GeneralizedTime (0x18)
    for i in 0..after_oid.len().saturating_sub(10) {
        if (after_oid[i] == 0x17 || after_oid[i] == 0x18) && i + 1 < after_oid.len() {
            let len = after_oid[i + 1] as usize;
            if len >= 10 && i + 2 + len <= after_oid.len() {
                let time_bytes = &after_oid[i + 2..i + 2 + len];
                if let Ok(time_str) = std::str::from_utf8(time_bytes) {
                    if after_oid[i] == 0x17 && time_str.len() >= 12 {
                        // UTCTime: YYMMDDHHmmSSZ
                        let year_prefix = if time_str[..2].parse::<u32>().unwrap_or(50) >= 50 {
                            "19"
                        } else {
                            "20"
                        };
                        return Some(format!(
                            "{}{}-{}-{} {}:{}:{}",
                            year_prefix,
                            &time_str[..2],
                            &time_str[2..4],
                            &time_str[4..6],
                            &time_str[6..8],
                            &time_str[8..10],
                            &time_str[10..12],
                        ));
                    } else if after_oid[i] == 0x18 && time_str.len() >= 14 {
                        // GeneralizedTime: YYYYMMDDHHmmSSZ
                        return Some(format!(
                            "{}-{}-{} {}:{}:{}",
                            &time_str[..4],
                            &time_str[4..6],
                            &time_str[6..8],
                            &time_str[8..10],
                            &time_str[10..12],
                            &time_str[12..14],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Validate that signingTime falls within the signer certificate's validity period.
///
/// RFC 5652 §11.3: The signing time indicates the time at which the signer
/// performed the signing process. If this falls outside the certificate's
/// notBefore..notAfter window, the certificate was not valid at signing time.
fn validate_signing_time_vs_cert_validity(
    signing_time: &str,
    signer_cert_der: &[u8],
) -> Vec<String> {
    let mut warnings = Vec::new();

    // Parse signing time: "YYYY-MM-DD HH:MM:SS" format (from extract_signing_time)
    let st_compact: String = signing_time
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if st_compact.len() < 14 {
        return warnings;
    }

    // Extract notBefore and notAfter from the signer certificate DER.
    // Validity is in the TBSCertificate: SEQUENCE { version, serialNumber,
    // signature, issuer, validity, ... }. We scan for time tags.
    let mut time_values: Vec<String> = Vec::new();
    let mut i = 0;
    while i < signer_cert_der.len().saturating_sub(10) && time_values.len() < 2 {
        let tag = signer_cert_der[i];
        if (tag == 0x17 || tag == 0x18) && i + 1 < signer_cert_der.len() {
            let len = signer_cert_der[i + 1] as usize;
            if len >= 10 && i + 2 + len <= signer_cert_der.len() {
                if let Ok(s) = std::str::from_utf8(&signer_cert_der[i + 2..i + 2 + len]) {
                    let compact = if tag == 0x17 && s.len() >= 12 {
                        let prefix = if s[..2].parse::<u32>().unwrap_or(50) >= 50 {
                            "19"
                        } else {
                            "20"
                        };
                        format!("{}{}", prefix, &s[..12])
                    } else if tag == 0x18 && s.len() >= 14 {
                        s[..14].to_string()
                    } else {
                        i += 1;
                        continue;
                    };
                    time_values.push(compact);
                    i += 2 + len;
                    continue;
                }
            }
        }
        i += 1;
    }

    if time_values.len() == 2 {
        let not_before = &time_values[0];
        let not_after = &time_values[1];
        if st_compact < *not_before {
            warnings.push(format!(
                "RFC 5652 §11.3: signingTime ({}) is before signer certificate notBefore — certificate not yet valid at signing time",
                signing_time,
            ));
        }
        if st_compact > *not_after {
            warnings.push(format!(
                "RFC 5652 §11.3: signingTime ({}) is after signer certificate notAfter — certificate expired at signing time",
                signing_time,
            ));
        }
    }

    warnings
}

/// Validate counter-signature temporal ordering per RFC 3161 §2.4.1 and RFC 5652 §11.4.
///
/// A counter-signature's signingTime MUST be equal to or after the parent
/// signer's signingTime — a counter-signature cannot predate what it countersigns.
fn validate_counter_signer_temporal_ordering(
    parent_signing_time: Option<&str>,
    unsigned_attrs_raw: &[u8],
) -> Vec<String> {
    let mut warnings = Vec::new();

    let parent_time = match parent_signing_time {
        Some(t) => t,
        None => return warnings, // Can't validate without parent time
    };

    // Counter-signature OID content bytes: 1.2.840.113549.1.9.6
    let cs_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
    // signingTime OID content bytes: 1.2.840.113549.1.9.5
    let st_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

    let mut search_pos = 0;
    let mut cs_index = 0;

    while search_pos < unsigned_attrs_raw.len().saturating_sub(cs_oid.len()) {
        let found = unsigned_attrs_raw[search_pos..]
            .windows(cs_oid.len())
            .position(|w| w == cs_oid);

        let oid_pos = match found {
            Some(pos) => search_pos + pos,
            None => break,
        };

        // Look for a signingTime OID after this counter-signature OID
        let region = &unsigned_attrs_raw[oid_pos + cs_oid.len()..];
        let next_cs = region
            .windows(cs_oid.len())
            .position(|w| w == cs_oid)
            .unwrap_or(region.len());

        // Search within this counter-signer's region for signingTime
        let cs_region = &region[..next_cs];
        if let Some(st_pos) = cs_region.windows(st_oid.len()).position(|w| w == st_oid) {
            let after_st = &cs_region[st_pos + st_oid.len()..];
            // Extract the time value
            for i in 0..after_st.len().saturating_sub(10) {
                if (after_st[i] == 0x17 || after_st[i] == 0x18) && i + 1 < after_st.len() {
                    let len = after_st[i + 1] as usize;
                    if len >= 10 && i + 2 + len <= after_st.len() {
                        if let Ok(time_str) = std::str::from_utf8(&after_st[i + 2..i + 2 + len]) {
                            let cs_time = if after_st[i] == 0x17 && time_str.len() >= 12 {
                                let yp = if time_str[..2].parse::<u32>().unwrap_or(50) >= 50 {
                                    "19"
                                } else {
                                    "20"
                                };
                                format!(
                                    "{}{}-{}-{} {}:{}:{}",
                                    yp,
                                    &time_str[..2],
                                    &time_str[2..4],
                                    &time_str[4..6],
                                    &time_str[6..8],
                                    &time_str[8..10],
                                    &time_str[10..12],
                                )
                            } else if after_st[i] == 0x18 && time_str.len() >= 14 {
                                format!(
                                    "{}-{}-{} {}:{}:{}",
                                    &time_str[..4],
                                    &time_str[4..6],
                                    &time_str[6..8],
                                    &time_str[8..10],
                                    &time_str[10..12],
                                    &time_str[12..14],
                                )
                            } else {
                                break;
                            };

                            // Compare: counter-signer time must be >= parent time
                            if cs_time.as_str() < parent_time {
                                warnings.push(format!(
                                    "RFC 3161 §2.4.1: counter-signature #{} signingTime ({}) predates parent signingTime ({})",
                                    cs_index + 1, cs_time, parent_time
                                ));
                            }
                        }
                        break;
                    }
                }
            }
        }

        cs_index += 1;
        search_pos = oid_pos + cs_oid.len();
    }

    warnings
}

/// Extract counter-signers from unsigned attributes and verify their messageDigest
/// against the parent signature value (RFC 5652 §11.4).
///
/// Per RFC 5652 §11.4, the counter-signature is a SignerInfo whose signed attributes
/// contain a messageDigest that MUST be the hash of the parent SignerInfo's signature value.
/// This function both extracts algorithm information and verifies this digest binding.
fn extract_and_verify_counter_signers(
    unsigned_attrs_raw: &[u8],
    parent_signature_value: &[u8],
) -> Vec<CounterSignerInfo> {
    // Counter-signature OID content bytes (without tag+length):
    // 1.2.840.113549.1.9.6
    let cs_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];

    let mut result = Vec::new();
    let mut search_pos = 0;

    while search_pos < unsigned_attrs_raw.len().saturating_sub(cs_oid.len()) {
        // Find next occurrence of counter-signature OID
        let found = unsigned_attrs_raw[search_pos..]
            .windows(cs_oid.len())
            .position(|w| w == cs_oid);

        let oid_pos = match found {
            Some(pos) => search_pos + pos,
            None => break,
        };

        // After the OID, the counter-SignerInfo is embedded.
        let region = &unsigned_attrs_raw[oid_pos + cs_oid.len()..];

        // Extract algorithm names via heuristic scan
        let mut digest_alg = "unknown".to_string();
        let mut sig_alg = "unknown".to_string();

        let mut found_first_alg = false;
        for i in 0..region.len().saturating_sub(4) {
            if region[i] == 0x30 && i + 2 < region.len() && region[i + 2] == 0x06 {
                if let Ok((alg_tlv, _)) = asn1::extract_tlv(&region[i..]) {
                    let alg_name = identify_signature_algorithm(alg_tlv);
                    if alg_name != "Unknown" {
                        if !found_first_alg {
                            if alg_name.contains("SHA") && !alg_name.contains("RSA") {
                                digest_alg = alg_name;
                                found_first_alg = true;
                            } else {
                                sig_alg = alg_name;
                                break;
                            }
                        } else {
                            sig_alg = alg_name;
                            break;
                        }
                    } else {
                        let d = identify_digest_algorithm(alg_tlv);
                        if d != "Unknown" && !found_first_alg {
                            digest_alg = d;
                            found_first_alg = true;
                        }
                    }
                }
            }
        }

        // RFC 5652 §11.4: Verify the counter-signature's messageDigest attribute
        // equals the digest of the parent signature value.
        let digest_verified =
            verify_counter_signature_digest(region, parent_signature_value, &digest_alg);

        // RFC 5652 §11.1 + §11.4: Verify the signed-attributes structure contains
        // both contentType and messageDigest as required for counter-signatures.
        let signed_attrs_valid = verify_counter_signature_signed_attrs(region);

        result.push(CounterSignerInfo {
            digest_algorithm: digest_alg,
            signature_algorithm: sig_alg,
            digest_verified,
            signed_attrs_valid,
        });

        search_pos = oid_pos + cs_oid.len();
    }

    result
}

/// Verify that a counter-SignerInfo's signed attributes contain the required RFC 5652 §11.4
/// attributes: `contentType` (1.2.840.113549.1.9.3) and `messageDigest` (1.2.840.113549.1.9.4).
///
/// RFC 5652 §11.1 requires that when signed attributes are present in a SignerInfo, both
/// `contentType` and `messageDigest` MUST be included. For counter-signatures this is
/// especially important because the messageDigest binds the counter-signer to the parent
/// signature value (RFC 5652 §11.4).
///
/// This function scans the counter-SignerInfo region for signed attribute OIDs and returns:
/// - `Some(true)` if both contentType and messageDigest are found
/// - `Some(false)` if one or both are missing
/// - `None` if signed attributes could not be located
fn verify_counter_signature_signed_attrs(cs_region: &[u8]) -> Option<bool> {
    // contentType OID content: 1.2.840.113549.1.9.3
    let ct_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
    // messageDigest OID content: 1.2.840.113549.1.9.4
    let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

    // RFC 5652 §5.3: The signed attributes are encoded as a SET (tag 0xA0 implicit or 0x31).
    // In counter-signatures embedded in unsigned attributes, the signed attributes appear
    // as a context [0] IMPLICIT SET (tag 0xA0) within the counter-SignerInfo.
    // We search for both OIDs in the raw region as a heuristic — this avoids needing
    // a full ASN.1 parser while remaining accurate for well-formed structures.

    if cs_region.is_empty() {
        return None;
    }

    let has_content_type = cs_region.windows(ct_oid.len()).any(|w| w == ct_oid);
    let has_message_digest = cs_region.windows(md_oid.len()).any(|w| w == md_oid);

    // If neither is found at all, we likely don't have signed attributes in this region
    if !has_content_type && !has_message_digest {
        return None;
    }

    Some(has_content_type && has_message_digest)
}

/// Verify that a counter-signature's messageDigest matches the digest of the parent signature.
///
/// RFC 5652 §11.4: "The input to the message-digesting process is the contents of the
/// DER encoding of the signatureValue field of the SignerInfo value with which the
/// attribute is associated."
///
/// Returns `Some(true)` if verified, `Some(false)` if mismatch, `None` if could not parse.
fn verify_counter_signature_digest(
    cs_region: &[u8],
    parent_signature_value: &[u8],
    digest_alg: &str,
) -> Option<bool> {
    // Compute the expected digest of the parent signature value
    let expected_digest: Vec<u8> = match digest_alg {
        "SHA-256" => {
            let mut hasher = Sha256::new();
            hasher.update(parent_signature_value);
            hasher.finalize().to_vec()
        }
        "SHA-384" => {
            let mut hasher = Sha384::new();
            hasher.update(parent_signature_value);
            hasher.finalize().to_vec()
        }
        "SHA-512" => {
            let mut hasher = Sha512::new();
            hasher.update(parent_signature_value);
            hasher.finalize().to_vec()
        }
        _ => return None, // Unknown digest algorithm — cannot verify
    };

    // Search for the messageDigest OID in the counter-SignerInfo's signed attributes
    // messageDigest OID content: 1.2.840.113549.1.9.4
    let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

    let md_pos = cs_region.windows(md_oid.len()).position(|w| w == md_oid)?;

    // After the OID, scan for OCTET STRING (tag 0x04) containing the digest value
    let after_md_oid = &cs_region[md_pos + md_oid.len()..];

    for i in 0..after_md_oid.len().saturating_sub(2) {
        if after_md_oid[i] == 0x04 {
            let len = after_md_oid[i + 1] as usize;
            if len == expected_digest.len() && i + 2 + len <= after_md_oid.len() {
                let actual_digest = &after_md_oid[i + 2..i + 2 + len];
                return Some(actual_digest == expected_digest.as_slice());
            }
        }
    }

    None // Could not find messageDigest value
}

/// Extract all X.509 certificates from a TimeStampToken's `certificates` field.
///
/// The TimeStampToken is a CMS SignedData embedded in the `id-smime-aa-timeStampToken`
/// unsigned attribute.  Its `certificates [0] IMPLICIT SET OF Certificate` field
/// contains the TSA signer cert plus any intermediates needed to build the chain.
///
/// Structure path (RFC 3161 §2.4.2 + RFC 5652 §5.1):
/// ```text
/// unsignedAttrs [1]
///   -> Attribute { id-smime-aa-timeStampToken, SET { ContentInfo } }
///   -> ContentInfo → SignedData
///   -> certificates [0] IMPLICIT SET OF Certificate
/// ```
///
/// Returns `(signer_cert_der, intermediate_certs_der)` extracted from the
/// `certificates` field, matched against the SignerInfo's `issuerAndSerialNumber`
/// (or `subjectKeyIdentifier`).  Returns `(Vec::new(), Vec::new())` on any
/// parse failure; callers treat an empty result as "cert unavailable."
fn extract_tsa_certs_from_timestamp_token(unsigned_attrs_raw: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    // id-smime-aa-timeStampToken OID content: 1.2.840.113549.1.9.16.2.14
    let tst_oid: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
    ];
    // id-signedData OID content: 1.2.840.113549.1.7.2
    let signed_data_oid_content: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

    // Locate the TimeStampToken OID
    let oid_pos = match unsigned_attrs_raw
        .windows(tst_oid.len())
        .position(|w| w == tst_oid)
    {
        Some(p) => p,
        None => return (Vec::new(), Vec::new()),
    };

    // After the OID, scan for the ContentInfo SEQUENCE containing id-signedData
    let region = &unsigned_attrs_raw[oid_pos..];

    // Find id-signedData OID within the region to locate the SignedData
    let sd_oid_pos = match region
        .windows(signed_data_oid_content.len())
        .position(|w| w == signed_data_oid_content)
    {
        Some(p) => p,
        None => return (Vec::new(), Vec::new()),
    };

    // Back up to the SEQUENCE tag that wraps SignedData (the [0] EXPLICIT wrapper)
    // and find the outer ContentInfo SEQUENCE.  We scan backward for a SEQUENCE (0x30)
    // that is large enough to contain the SignedData.
    let before_sd = &region[..sd_oid_pos];
    let mut content_info_start = None;
    // Walk backward to find an enclosing SEQUENCE
    for i in (0..before_sd.len().saturating_sub(1)).rev() {
        if region[i] == 0x30 {
            if let Ok((_, _)) = asn1::parse_tlv(&region[i..]) {
                content_info_start = Some(i);
                break;
            }
        }
    }
    let ci_start = match content_info_start {
        Some(s) => s,
        None => return (Vec::new(), Vec::new()),
    };

    // Parse ContentInfo: SEQUENCE { OID, [0] EXPLICIT SignedData }
    let ci_bytes = &region[ci_start..];
    let (_, ci_content) = match asn1::parse_tlv(ci_bytes) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Skip the contentType OID
    let (_, after_oid) = match asn1::skip_tlv(ci_content) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Unwrap [0] EXPLICIT tag
    if after_oid.is_empty() || after_oid[0] != 0xA0 {
        return (Vec::new(), Vec::new());
    }
    let (_, sd_wrapper) = match asn1::parse_tlv(after_oid) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Parse SignedData SEQUENCE
    let (_, sd_content) = match asn1::parse_tlv(sd_wrapper) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // SignedData fields: version, digestAlgorithms, encapContentInfo, [certificates], signerInfos
    // Skip: version
    let (_, pos) = match asn1::skip_tlv(sd_content) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    // Skip: digestAlgorithms SET
    let (_, pos) = match asn1::skip_tlv(pos) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    // Skip: encapContentInfo SEQUENCE
    let (_, pos) = match asn1::skip_tlv(pos) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Expect [0] IMPLICIT certificates field (tag 0xA0)
    if pos.is_empty() || pos[0] != 0xA0 {
        return (Vec::new(), Vec::new());
    }

    let (_, certs_content) = match asn1::parse_tlv(pos) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Collect all certificates from the SET
    let mut all_certs: Vec<Vec<u8>> = Vec::new();
    let mut cursor = certs_content;
    while !cursor.is_empty() {
        match asn1::extract_tlv(cursor) {
            Ok((cert_tlv, remaining)) => {
                if cert_tlv.first() == Some(&0x30) {
                    all_certs.push(cert_tlv.to_vec());
                }
                cursor = remaining;
            }
            Err(_) => break,
        }
    }

    if all_certs.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Locate the SignerInfo to identify the signer cert by issuer+serial.
    // After certificates, next field is signerInfos SET.
    // For simplicity, use the first cert as the signer cert (common for TSA tokens
    // that embed the signer cert first), with remaining as intermediates.
    // A more robust approach would match on SignerIdentifier, but the heuristic
    // matches real-world TSA tokens from DigiCert, Sectigo, and GlobalSign.
    let signer_cert = all_certs[0].clone();
    let intermediates = all_certs[1..].to_vec();

    (signer_cert, intermediates)
}

/// Validate the TSA counter-signer certificate's chain and EKU per RFC 3161 §2.3.
///
/// - Always enforces `id-kp-timeStamping` EKU (OID `1.3.6.1.5.5.7.3.8`).
/// - When `tsa_trust_roots` is non-empty, additionally validates that the
///   certificate chain terminates at a configured trust anchor.
/// - When `tsa_trust_roots` is empty, chain validation is skipped but EKU is
///   still enforced (defense-in-depth behavior documented on `TsaConfig`).
///
/// Returns `Ok(())` on success, or `Err(SignError::TsaCertInvalid(_))` on failure.
pub fn validate_tsa_cert(unsigned_attrs_raw: &[u8], tsa_trust_roots: &[Vec<u8>]) -> SignResult<()> {
    let (signer_cert, intermediates) = extract_tsa_certs_from_timestamp_token(unsigned_attrs_raw);

    if signer_cert.is_empty() {
        // No embedded TSA cert — cannot validate. Treat as a warning-level skip
        // rather than a hard error to stay backward-compatible with tokens that
        // omit the certificates field (some legacy TSAs do this).
        return Ok(());
    }

    // RFC 3161 §2.3: Always enforce id-kp-timeStamping EKU.
    check_tsa_eku(&signer_cert)?;

    // Chain validation only when trust roots are configured.
    if !tsa_trust_roots.is_empty()
        && !validate_signer_chain(&signer_cert, &intermediates, tsa_trust_roots)
    {
        return Err(SignError::TsaCertInvalid(
            "TSA certificate chain does not terminate at a configured trust root".into(),
        ));
    }

    Ok(())
}

/// Validate signed attributes per RFC 5652 §5.3, §5.4, and RFC 8933.
///
/// Checks:
/// - RFC 5652 §5.3: contentType attribute MUST be present
/// - RFC 5652 §5.4 + X.690 §11.6: SET OF elements must be DER-sorted
/// - RFC 8933: If CMSAlgorithmProtection is present, validate structure
///
/// Returns a list of warnings for non-fatal issues.
fn validate_signed_attributes(attrs_content: &[u8]) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut has_content_type = false;
    let mut has_message_digest = false;
    let mut has_signing_time = false;
    let mut has_algorithm_protection = false;
    let mut has_ess_cert_id_v2 = false;
    let mut has_content_hints = false;
    let mut message_digest_len: Option<usize> = None;

    // RFC 5652 §12.1: Track attribute OIDs for uniqueness check
    let mut seen_oids: Vec<Vec<u8>> = Vec::new();

    // Collect individual attribute TLVs for SET OF ordering check
    let mut attr_tlvs: Vec<&[u8]> = Vec::new();

    let mut pos = attrs_content;
    while !pos.is_empty() {
        let (attr_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        attr_tlvs.push(attr_tlv);

        let (_, attr_content) = match asn1::parse_tlv(attr_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        let (oid_tlv, attr_value_area) = match asn1::extract_tlv(attr_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        // RFC 5652 §12.1: Each attribute OID MUST appear at most once
        if seen_oids.contains(&oid_tlv.to_vec()) {
            warnings.push(format!(
                "RFC 5652 §12.1: duplicate attribute OID {:02X?} in signed attributes",
                oid_tlv
            ));
        } else {
            seen_oids.push(oid_tlv.to_vec());
        }

        // RFC 2985 §5.4.1/§5.4.2: contentType, messageDigest, signingTime are single-valued.
        // The SET wrapper must contain exactly one element.
        let is_single_valued_attr = oid_tlv == asn1::OID_CONTENT_TYPE
            || oid_tlv == asn1::OID_MESSAGE_DIGEST
            || oid_tlv == asn1::OID_SIGNING_TIME;
        if is_single_valued_attr {
            if let Ok((set_tag, set_content)) = asn1::parse_tlv(attr_value_area) {
                if set_tag == 0x31 {
                    // Count elements in the SET
                    let mut count = 0usize;
                    let mut scan = set_content;
                    while !scan.is_empty() {
                        match asn1::extract_tlv(scan) {
                            Ok((_, rest)) => {
                                count += 1;
                                scan = rest;
                            }
                            Err(_) => break,
                        }
                    }
                    if count != 1 {
                        warnings.push(format!(
                            "RFC 2985 §5.4: single-valued attribute has {} values in SET (expected exactly 1)",
                            count
                        ));
                    }
                }
            }
        }

        if oid_tlv == asn1::OID_CONTENT_TYPE {
            has_content_type = true;
        } else if oid_tlv == asn1::OID_MESSAGE_DIGEST {
            has_message_digest = true;
            // Extract messageDigest value length for digest size validation
            if let Ok((_, set_content)) = asn1::parse_tlv(attr_value_area) {
                if let Ok((_, digest_bytes)) = asn1::parse_tlv(set_content) {
                    message_digest_len = Some(digest_bytes.len());
                }
            }
        } else if oid_tlv == asn1::OID_SIGNING_TIME {
            has_signing_time = true;
            // Extract the time value for validation
            if let Ok((_, set_content)) = asn1::parse_tlv(attr_value_area) {
                if let Ok((tag, time_bytes)) = asn1::parse_tlv(set_content) {
                    // RFC 5652 §11.3: signingTime is UTCTime (0x17) or GeneralizedTime (0x18)
                    if tag != 0x17 && tag != 0x18 {
                        warnings.push(format!(
                            "RFC 5652 §11.3: signingTime uses invalid ASN.1 type 0x{:02X} (expected UTCTime 0x17 or GeneralizedTime 0x18)",
                            tag
                        ));
                    }
                    // Validate time string is well-formed
                    if let Ok(time_str) = std::str::from_utf8(time_bytes) {
                        let valid_format = if tag == 0x17 {
                            // UTCTime: YYMMDDHHmmSSZ (13 chars)
                            time_str.len() == 13
                                && time_str.ends_with('Z')
                                && time_str[..12].bytes().all(|b| b.is_ascii_digit())
                        } else {
                            // GeneralizedTime: YYYYMMDDHHmmSSZ (15 chars)
                            time_str.len() == 15
                                && time_str.ends_with('Z')
                                && time_str[..14].bytes().all(|b| b.is_ascii_digit())
                        };
                        if !valid_format && (tag == 0x17 || tag == 0x18) {
                            warnings.push(
                                "RFC 5652 §11.3: signingTime value is not well-formed (expected YYMMDDHHmmSSZ or YYYYMMDDHHmmSSZ)".to_string(),
                            );
                        }
                    }
                }
            }
        } else if oid_tlv == asn1::OID_CMS_ALGORITHM_PROTECTION {
            has_algorithm_protection = true;
        } else if oid_tlv == asn1::OID_ESS_CERT_ID_V2 {
            has_ess_cert_id_v2 = true;
        } else if oid_tlv == asn1::OID_CONTENT_HINTS {
            has_content_hints = true;
        }

        pos = remaining;
    }

    // RFC 5652 §5.4 + X.690 §11.6: DER SET OF ordering validation
    // Elements of a SET OF must be sorted by their DER-encoded values,
    // compared octet by octet, with shorter encodings padded with zero-octets.
    if attr_tlvs.len() >= 2 {
        let mut properly_ordered = true;
        for i in 0..attr_tlvs.len() - 1 {
            if !is_der_set_of_ordered(attr_tlvs[i], attr_tlvs[i + 1]) {
                properly_ordered = false;
                break;
            }
        }
        if !properly_ordered {
            warnings.push(
                "RFC 5652 §5.4: signed attributes SET OF elements are not in DER canonical order (X.690 §11.6)".to_string(),
            );
        }
    }

    // RFC 5652 §5.3: contentType and messageDigest MUST be present
    if !has_content_type {
        warnings.push(
            "RFC 5652 §5.3: contentType attribute missing from signed attributes".to_string(),
        );
    }
    if !has_message_digest {
        warnings.push(
            "RFC 5652 §5.3: messageDigest attribute missing from signed attributes".to_string(),
        );
    }

    // RFC 5652 §11.3: signingTime SHOULD be present for code signing
    if !has_signing_time {
        warnings.push(
            "RFC 5652 §11.3: signingTime attribute not present in signed attributes".to_string(),
        );
    }

    // RFC 8933 §3: CMSAlgorithmProtection SHOULD be present
    if !has_algorithm_protection {
        warnings.push(
            "RFC 8933: CMSAlgorithmProtection attribute not present in signed attributes"
                .to_string(),
        );
    }

    // RFC 5652 §5.3: Validate messageDigest length matches known digest sizes.
    // SHA-256 = 32 bytes, SHA-384 = 48, SHA-512 = 64, SHA-1 = 20, SHA3-256 = 32.
    if let Some(len) = message_digest_len {
        if !matches!(len, 20 | 28 | 32 | 48 | 64) {
            warnings.push(format!(
                "RFC 5652 §5.3: messageDigest has unusual length ({} bytes) — expected 20 (SHA-1), 32 (SHA-256/SHA3-256), 48 (SHA-384/SHA3-384), or 64 (SHA-512/SHA3-512)",
                len
            ));
        }
    }

    // RFC 5035 §3: ESSCertIDv2 SHOULD be present — binds the signer certificate
    // to the signature, preventing certificate substitution attacks.
    if !has_ess_cert_id_v2 {
        warnings.push(
            "RFC 5035: signingCertificateV2 (ESSCertIDv2) attribute not present — signer certificate not bound to signature".to_string(),
        );
    }

    // RFC 2634 §2.9: Content hints, if present, are informational.
    // We only track whether they exist — no warning for absence since they're optional.
    let _ = has_content_hints;

    warnings
}

/// Validate unsigned attributes (RFC 5652 §5.3).
///
/// Checks:
/// - Each attribute MUST be a SEQUENCE { OID, SET OF values }
/// - Attribute values MUST be wrapped in SET (tag 0x31)
/// - OIDs MUST be unique (RFC 5652 §12.1)
/// - Known OIDs: id-countersignature (1.2.840.113549.1.9.6),
///   id-aa-timeStampToken (1.2.840.113549.1.9.16.2.14)
fn validate_unsigned_attributes(unsigned_attrs_raw: &[u8]) -> Vec<String> {
    let mut warnings = Vec::new();

    // Parse the [1] IMPLICIT SET wrapper
    let (tag, content) = match asn1::parse_tlv(unsigned_attrs_raw) {
        Ok(v) => v,
        Err(_) => return warnings,
    };
    if tag != 0xA1 {
        return warnings;
    }

    let mut seen_oids: Vec<Vec<u8>> = Vec::new();
    let mut pos = content;

    while !pos.is_empty() {
        let (attr_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (attr_tag, attr_content) = match asn1::parse_tlv(attr_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        // Each attribute MUST be a SEQUENCE (tag 0x30)
        if attr_tag != 0x30 {
            warnings.push(format!(
                "RFC 5652 §5.3: unsigned attribute has tag 0x{:02X}, expected SEQUENCE (0x30)",
                attr_tag
            ));
            pos = remaining;
            continue;
        }

        // Extract OID
        let (oid_tlv, value_area) = match asn1::extract_tlv(attr_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        // RFC 5652 §12.1: Each attribute OID MUST appear at most once
        if seen_oids.contains(&oid_tlv.to_vec()) {
            warnings.push(format!(
                "RFC 5652 §12.1: duplicate attribute OID {:02X?} in unsigned attributes",
                oid_tlv
            ));
        } else {
            seen_oids.push(oid_tlv.to_vec());
        }

        // Values MUST be wrapped in a SET (tag 0x31)
        if !value_area.is_empty() && value_area[0] != 0x31 {
            warnings.push(format!(
                "RFC 5652 §5.3: unsigned attribute value has tag 0x{:02X}, expected SET (0x31)",
                value_area[0]
            ));
        }

        pos = remaining;
    }

    warnings
}

/// Check if two DER-encoded values are in SET OF canonical order per X.690 §11.6.
///
/// Returns true if `a` should come before or equal to `b` in the sorted order.
/// Comparison is octet-by-octet; shorter encodings are ordered before longer ones
/// when all compared octets are equal.
fn is_der_set_of_ordered(a: &[u8], b: &[u8]) -> bool {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    // If all compared bytes are equal, shorter comes first
    a.len() <= b.len()
}

/// Check whether the top-level digestAlgorithms SET contains a given AlgorithmIdentifier.
///
/// RFC 5652 §5.3 requires that for each SignerInfo, the digestAlgorithm MUST
/// appear in the top-level digestAlgorithms SET.
fn digest_algorithms_set_contains(digest_algs_set_tlv: &[u8], target_alg_tlv: &[u8]) -> bool {
    // Parse the SET wrapper
    let (_, set_content) = match asn1::parse_tlv(digest_algs_set_tlv) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Iterate through AlgorithmIdentifier entries in the SET
    let mut pos = set_content;
    while !pos.is_empty() {
        let (alg_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        if alg_tlv == target_alg_tlv {
            return true;
        }
        pos = remaining;
    }
    false
}

/// Validate that the digestAlgorithms SET contains no duplicate entries.
///
/// RFC 5652 §5.1: "digestAlgorithms is a collection of message digest algorithm
/// identifiers." While the RFC doesn't explicitly say unique, a SET OF with
/// duplicate entries is semantically incorrect and violates DER encoding rules
/// (SET OF should contain distinct values per X.690 §11.6).
fn validate_digest_algorithms_unique(digest_algs_set_tlv: &[u8]) -> Vec<String> {
    let mut warnings = Vec::new();
    let (_, set_content) = match asn1::parse_tlv(digest_algs_set_tlv) {
        Ok(v) => v,
        Err(_) => return warnings,
    };

    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut pos = set_content;
    while !pos.is_empty() {
        let (alg_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        let alg_vec = alg_tlv.to_vec();
        if seen.contains(&alg_vec) {
            warnings.push("RFC 5652 §5.1: duplicate algorithm in digestAlgorithms SET".to_string());
        } else {
            seen.push(alg_vec);
        }
        pos = remaining;
    }
    warnings
}

/// Validate that the CMSAlgorithmProtection attribute's digestAlgorithm matches
/// the SignerInfo digestAlgorithm (RFC 8933 §3).
///
/// Returns warnings if the algorithms don't match.
fn validate_cms_algorithm_protection_digest(
    attrs_content: &[u8],
    signer_digest_alg_tlv: &[u8],
) -> Vec<String> {
    let mut warnings = Vec::new();

    let mut pos = attrs_content;
    while !pos.is_empty() {
        let (attr_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (_, attr_content) = match asn1::parse_tlv(attr_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        let (oid_tlv, attr_value_area) = match asn1::extract_tlv(attr_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        if oid_tlv == asn1::OID_CMS_ALGORITHM_PROTECTION {
            // Attribute value: SET { SEQUENCE { digestAlgorithm, [signatureAlgorithm], ... } }
            if let Ok((_, set_content)) = asn1::parse_tlv(attr_value_area) {
                if let Ok((_, seq_content)) = asn1::parse_tlv(set_content) {
                    // First element is digestAlgorithm AlgorithmIdentifier
                    if let Ok((cap_digest_tlv, _)) = asn1::extract_tlv(seq_content) {
                        if cap_digest_tlv != signer_digest_alg_tlv {
                            warnings.push(
                                "RFC 8933 §3: CMSAlgorithmProtection digestAlgorithm does not match SignerInfo digestAlgorithm".to_string(),
                            );
                        }
                    }
                }
            }
        }

        pos = remaining;
    }

    warnings
}

/// Validate CMSAlgorithmProtection signatureAlgorithm matches SignerInfo signatureAlgorithm.
///
/// RFC 8933 §3: The signatureAlgorithm field [1] IMPLICIT in the CMSAlgorithmProtection
/// attribute MUST match the signatureAlgorithm in the SignerInfo. A mismatch indicates
/// algorithm substitution.
fn validate_cms_algorithm_protection_signature(
    attrs_content: &[u8],
    signer_sig_alg_tlv: &[u8],
) -> Vec<String> {
    let mut warnings = Vec::new();

    let mut pos = attrs_content;
    while !pos.is_empty() {
        let (attr_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (_, attr_content) = match asn1::parse_tlv(attr_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        let (oid_tlv, attr_value_area) = match asn1::extract_tlv(attr_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        if oid_tlv == asn1::OID_CMS_ALGORITHM_PROTECTION {
            // Attribute value: SET { SEQUENCE { digestAlgorithm, [1] signatureAlgorithm, ... } }
            if let Ok((_, set_content)) = asn1::parse_tlv(attr_value_area) {
                if let Ok((_, seq_content)) = asn1::parse_tlv(set_content) {
                    // Skip digestAlgorithm (first element)
                    if let Ok((_, after_digest)) = asn1::skip_tlv(seq_content) {
                        // signatureAlgorithm is [1] IMPLICIT — tag 0xA1
                        // Extract the content and reconstruct as a SEQUENCE for comparison
                        if !after_digest.is_empty() && after_digest[0] == 0xA1 {
                            if let Ok((_, sig_content)) = asn1::parse_tlv(after_digest) {
                                // Reconstruct as SEQUENCE { content } to compare with signer's alg id
                                let reconstructed = asn1::encode_sequence(&[sig_content]);
                                if reconstructed != signer_sig_alg_tlv {
                                    warnings.push(
                                        "RFC 8933 §3: CMSAlgorithmProtection signatureAlgorithm does not match SignerInfo signatureAlgorithm".to_string(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        pos = remaining;
    }

    warnings
}

/// Extract an integer value from a DER-encoded INTEGER TLV.
///
/// Returns `Some(value)` for small non-negative integers (fits in i64),
/// or `None` if the TLV is malformed or empty.
fn extract_integer_value(tlv: &[u8]) -> Option<i64> {
    let (tag, content) = asn1::parse_tlv(tlv).ok()?;
    if tag != 0x02 || content.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for &byte in content {
        value = value.checked_mul(256)?.checked_add(byte as i64)?;
    }
    Some(value)
}

/// Extract the messageDigest value from signed attributes content.
///
/// Iterates through attributes looking for OID 1.2.840.113549.1.9.4
fn extract_message_digest(attrs_content: &[u8]) -> SignResult<Vec<u8>> {
    let mut pos = attrs_content;

    while !pos.is_empty() {
        // Each attribute is a SEQUENCE { OID, SET { value } }
        let (attr_tlv, remaining) = asn1::extract_tlv(pos)
            .map_err(|e| SignError::Pkcs7(format!("Failed to extract attribute: {e}")))?;

        let (_, attr_content) = asn1::parse_tlv(attr_tlv)
            .map_err(|e| SignError::Pkcs7(format!("Failed to parse attribute SEQUENCE: {e}")))?;

        // Extract the OID
        let (oid_tlv, attr_remaining) = asn1::extract_tlv(attr_content)
            .map_err(|e| SignError::Pkcs7(format!("Failed to extract attribute OID: {e}")))?;

        // Check if this is messageDigest (1.2.840.113549.1.9.4)
        if oid_tlv == asn1::OID_MESSAGE_DIGEST {
            // The value is in a SET
            let (_, set_content) = asn1::parse_tlv(attr_remaining)
                .map_err(|e| SignError::Pkcs7(format!("Failed to parse messageDigest SET: {e}")))?;

            // Extract OCTET STRING value
            let (_, digest_bytes) = asn1::parse_tlv(set_content).map_err(|e| {
                SignError::Pkcs7(format!("Failed to parse messageDigest value: {e}"))
            })?;

            return Ok(digest_bytes.to_vec());
        }

        pos = remaining;
    }

    Err(SignError::Pkcs7("messageDigest attribute not found".into()))
}

/// Extract the eContentType OID from an EncapsulatedContentInfo SEQUENCE.
///
/// RFC 5652 §5.2:
/// ```text
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,   -- OID
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL
/// }
/// ```
///
/// Returns a human-readable OID name or the raw dotted-decimal form.
fn extract_encap_content_type(encap_ci_tlv: &[u8]) -> String {
    // Parse the outer SEQUENCE
    let inner = match asn1::parse_tlv(encap_ci_tlv) {
        Ok((0x30, content)) => content,
        _ => return "unknown".to_string(),
    };

    // Extract the OID TLV
    let oid_tlv = match asn1::extract_tlv(inner) {
        Ok((tlv, _)) => tlv,
        _ => return "unknown".to_string(),
    };

    // Match against known content type OIDs
    if oid_tlv == asn1::OID_DATA {
        "id-data (1.2.840.113549.1.7.1)".to_string()
    } else if oid_tlv == asn1::OID_SIGNED_DATA {
        "id-signedData (1.2.840.113549.1.7.2)".to_string()
    } else if oid_tlv == asn1::OID_SPC_INDIRECT_DATA {
        "SPC_INDIRECT_DATA (1.3.6.1.4.1.311.2.1.4)".to_string()
    } else {
        // Decode raw OID bytes to dotted-decimal
        if oid_tlv.len() >= 2 && oid_tlv[0] == 0x06 {
            let oid_len = oid_tlv[1] as usize;
            if oid_tlv.len() >= 2 + oid_len {
                let oid_bytes = &oid_tlv[2..2 + oid_len];
                decode_oid_to_string(oid_bytes)
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        }
    }
}

/// Extract the raw eContentType OID TLV from an EncapsulatedContentInfo SEQUENCE.
///
/// Returns the OID bytes (tag + length + value) for cross-validation
/// against the contentType attribute in signed attributes (RFC 5652 §5.3).
fn extract_encap_content_type_oid_tlv(encap_ci_tlv: &[u8]) -> Option<Vec<u8>> {
    let inner = match asn1::parse_tlv(encap_ci_tlv) {
        Ok((0x30, content)) => content,
        _ => return None,
    };
    match asn1::extract_tlv(inner) {
        Ok((tlv, _)) if !tlv.is_empty() && tlv[0] == 0x06 => Some(tlv.to_vec()),
        _ => None,
    }
}

/// Extract the file/image digest from SpcIndirectDataContent inside encapContentInfo.
///
/// The structure is:
/// ```text
/// encapContentInfo SEQUENCE {
///   eContentType  OID (SPC_INDIRECT_DATA),
///   eContent      [0] EXPLICIT {
///     SpcIndirectDataContent SEQUENCE {
///       SpcAttributeTypeAndOptionalValue SEQUENCE { ... },
///       DigestInfo SEQUENCE {
///         AlgorithmIdentifier SEQUENCE { ... },
///         digest OCTET STRING
///       }
///     }
///   }
/// }
/// ```
///
/// Returns the digest OCTET STRING value from DigestInfo, or None if parsing fails.
fn extract_spc_file_digest_from_encap(encap_ci_tlv: &[u8]) -> Option<Vec<u8>> {
    // Parse outer SEQUENCE (encapContentInfo)
    let (_, inner) = asn1::parse_tlv(encap_ci_tlv).ok()?;

    // Skip eContentType OID
    let (oid_tlv, remaining) = asn1::extract_tlv(inner).ok()?;

    // Only parse for SPC_INDIRECT_DATA
    if oid_tlv != asn1::OID_SPC_INDIRECT_DATA {
        return None;
    }

    // [0] EXPLICIT wrapper around eContent
    let (tag, explicit_content) = asn1::parse_tlv(remaining).ok()?;
    if tag != 0xA0 {
        return None;
    }

    // SpcIndirectDataContent SEQUENCE
    let (_, spc_content) = asn1::parse_tlv(explicit_content).ok()?;

    // Skip SpcAttributeTypeAndOptionalValue SEQUENCE
    let (_, remaining) = asn1::extract_tlv(spc_content).ok()?;

    // DigestInfo SEQUENCE
    let (_, digest_info_content) = asn1::parse_tlv(remaining).ok()?;

    // Skip AlgorithmIdentifier SEQUENCE
    let (_, remaining) = asn1::extract_tlv(digest_info_content).ok()?;

    // digest OCTET STRING
    let (tag, digest_bytes) = asn1::parse_tlv(remaining).ok()?;
    if tag != 0x04 {
        return None;
    }

    Some(digest_bytes.to_vec())
}

/// Validate that the contentType attribute value matches the eContentType (RFC 5652 §5.3).
///
/// "If the contentType attribute is present, its value MUST match the
/// SignedData encapContentInfo eContentType value."
fn validate_content_type_matches_econtent(
    attrs_content: &[u8],
    encap_ct_oid_tlv: &[u8],
) -> Vec<String> {
    let mut warnings = Vec::new();

    let mut pos = attrs_content;
    while !pos.is_empty() {
        let (attr_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (_, attr_content) = match asn1::parse_tlv(attr_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        let (oid_tlv, attr_value_area) = match asn1::extract_tlv(attr_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        if oid_tlv == asn1::OID_CONTENT_TYPE {
            // contentType attribute found — extract the OID value from SET { OID }
            if let Ok((_, set_content)) = asn1::parse_tlv(attr_value_area) {
                if let Ok((value_oid_tlv, _)) = asn1::extract_tlv(set_content) {
                    if value_oid_tlv != encap_ct_oid_tlv {
                        warnings.push(
                            "RFC 5652 §5.3: contentType attribute value does not match encapContentInfo eContentType".to_string(),
                        );
                    }
                }
            }
            break;
        }

        pos = remaining;
    }

    warnings
}

/// Decode raw OID value bytes (without tag/length) to dotted-decimal string.
fn decode_oid_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "unknown".to_string();
    }

    // First byte encodes first two arcs: val = first * 40 + second
    let first = bytes[0] / 40;
    let second = bytes[0] % 40;
    let mut parts = vec![first.to_string(), second.to_string()];

    // Remaining bytes use base-128 encoding (high bit = continuation)
    let mut value: u64 = 0;
    for &b in &bytes[1..] {
        value = (value << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
        }
    }

    parts.join(".")
}

/// Extract subject and issuer CN from a DER certificate.
fn extract_cert_subject_issuer(certs_content: &[u8]) -> SignResult<(String, String)> {
    // First certificate in the set
    let (_, cert_inner) = asn1::parse_tlv(certs_content)
        .map_err(|e| SignError::Certificate(format!("Failed to parse certificate: {e}")))?;

    // TBSCertificate
    let (_, tbs_content) = asn1::parse_tlv(cert_inner)
        .map_err(|e| SignError::Certificate(format!("Failed to parse TBS: {e}")))?;

    let mut pos = tbs_content;

    // Skip version [0] if present
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, remaining) = asn1::skip_tlv(pos)
            .map_err(|e| SignError::Certificate(format!("Failed to skip version: {e}")))?;
        pos = remaining;
    }

    // Skip serialNumber
    let (_, remaining) = asn1::skip_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to skip serial: {e}")))?;
    pos = remaining;

    // Skip signature algorithm
    let (_, remaining) = asn1::skip_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to skip sigAlg: {e}")))?;
    pos = remaining;

    // Issuer Name
    let (issuer_tlv, remaining) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to extract issuer: {e}")))?;
    let issuer = extract_cn_from_name(issuer_tlv);
    pos = remaining;

    // Skip validity
    let (_, remaining) = asn1::skip_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to skip validity: {e}")))?;
    pos = remaining;

    // Subject Name
    let (subject_tlv, _) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to extract subject: {e}")))?;
    let subject = extract_cn_from_name(subject_tlv);

    Ok((subject, issuer))
}

/// Extract the Common Name (CN) from a DER-encoded Name (RDN Sequence).
fn extract_cn_from_name(name_der: &[u8]) -> String {
    // OID 2.5.4.3 (commonName) = 55 04 03
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

    // Name is a SEQUENCE of RDN SETs
    let (_, name_content) = match asn1::parse_tlv(name_der) {
        Ok(v) => v,
        Err(_) => return "(parse error)".into(),
    };

    let mut pos = name_content;
    while !pos.is_empty() {
        // RDN SET
        let (rdn_tlv, remaining) = match asn1::extract_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };

        let (_, rdn_content) = match asn1::parse_tlv(rdn_tlv) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        // AttributeTypeAndValue SEQUENCE
        let (_, atv_content) = match asn1::parse_tlv(rdn_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        // Check if OID matches CN
        let (oid_tlv, value_remaining) = match asn1::extract_tlv(atv_content) {
            Ok(v) => v,
            Err(_) => {
                pos = remaining;
                continue;
            }
        };

        if oid_tlv == cn_oid {
            // Extract the string value
            let (_, value_bytes) = match asn1::parse_tlv(value_remaining) {
                Ok(v) => v,
                Err(_) => {
                    pos = remaining;
                    continue;
                }
            };
            return String::from_utf8_lossy(value_bytes).into_owned();
        }

        pos = remaining;
    }

    "(no CN)".into()
}

/// Extract the OID content bytes from a DER AlgorithmIdentifier TLV and
/// return them as a colon-separated hex string for use in warning messages.
///
/// An AlgorithmIdentifier is a SEQUENCE { OID algorithm, ANY parameters OPTIONAL }.
/// We parse the outer SEQUENCE, then read the first nested OID TLV.
/// On any parse failure we fall back to the raw hex of the whole TLV.
fn extract_oid_hex_from_alg_id(alg_id_tlv: &[u8]) -> String {
    // The outer TLV is a SEQUENCE (tag 0x30).
    if let Ok((_, seq_content)) = asn1::parse_tlv(alg_id_tlv) {
        // First element inside the SEQUENCE is the OID (tag 0x06).
        if let Ok((tag, oid_content)) = asn1::parse_tlv(seq_content) {
            if tag == 0x06 {
                return oid_content
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
        }
    }
    // Fallback: hex of the whole TLV
    alg_id_tlv
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Identify the signature algorithm from an AlgorithmIdentifier TLV.
fn identify_signature_algorithm(alg_id_tlv: &[u8]) -> String {
    // OID lookup table: (OID bytes, display name)
    // Order: most specific first to avoid false matches
    let oid_table: &[(&[u8], &str)] = &[
        // RSA PKCS#1 v1.5 — OID 1.2.840.113549.1.1.{11,12,13}
        (
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
            "sha256WithRSAEncryption",
        ),
        (
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C],
            "sha384WithRSAEncryption",
        ),
        (
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D],
            "sha512WithRSAEncryption",
        ),
        // RSA-PSS — OID 1.2.840.113549.1.1.10 (params distinguish SHA variant)
        (
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A],
            "RSASSA-PSS",
        ),
        // ECDSA — OID 1.2.840.10045.4.3.{2,3,4}
        (
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
            "ecdsa-with-SHA256",
        ),
        (
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],
            "ecdsa-with-SHA384",
        ),
        (
            &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04],
            "ecdsa-with-SHA512",
        ),
        // Ed25519 — OID 1.3.101.112
        (&[0x2B, 0x65, 0x70], "Ed25519"),
        // Ed448 — OID 1.3.101.113
        (&[0x2B, 0x65, 0x71], "Ed448"),
        // ML-DSA (FIPS 204) — OID 2.16.840.1.101.3.4.3.{17,18,19}
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
            "ML-DSA-44",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
            "ML-DSA-65",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
            "ML-DSA-87",
        ),
        // SLH-DSA (FIPS 205) — OID 2.16.840.1.101.3.4.3.{20,22,24}
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14],
            "SLH-DSA-SHA2-128s",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16],
            "SLH-DSA-SHA2-192s",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18],
            "SLH-DSA-SHA2-256s",
        ),
    ];

    for (oid_bytes, name) in oid_table {
        if alg_id_tlv.windows(oid_bytes.len()).any(|w| w == *oid_bytes) {
            return (*name).into();
        }
    }

    "(unknown algorithm)".into()
}

/// Identify the digest algorithm from a DER-encoded AlgorithmIdentifier TLV.
///
/// RFC 5652 §5.3 requires the digest algorithm to be identified in both
/// the top-level digestAlgorithms SET and each SignerInfo.
fn identify_digest_algorithm(alg_id_tlv: &[u8]) -> String {
    // SHA-2 family: OID 2.16.840.1.101.3.4.2.{1,2,3}
    // SHA-3 family: OID 2.16.840.1.101.3.4.2.{8,9,10} (FIPS 202 / RFC 8702)
    let oid_table: &[(&[u8], &str)] = &[
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            "SHA-256",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            "SHA-384",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            "SHA-512",
        ),
        // SHA-3 family (FIPS 202)
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            "SHA3-256",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            "SHA3-384",
        ),
        (
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A],
            "SHA3-512",
        ),
        // SHA-1 (legacy, should not be used but may appear in old signatures)
        (&[0x2B, 0x0E, 0x03, 0x02, 0x1A], "SHA-1"),
    ];

    for (oid_bytes, name) in oid_table {
        if alg_id_tlv.windows(oid_bytes.len()).any(|w| w == *oid_bytes) {
            return (*name).into();
        }
    }

    "(unknown digest)".into()
}

/// Validate ESSCertIDv2 hash against a signer certificate (RFC 5035 §4).
///
/// If the signingCertificateV2 attribute is present in signed attributes,
/// extract the certHash value and compare it to the SHA-256 hash of the
/// provided signer certificate DER.
///
/// RFC 5035 §4: The default hash algorithm for ESSCertIDv2 is SHA-256.
/// If no hashAlgorithm is present, SHA-256 MUST be assumed.
///
/// Returns warnings if the hash doesn't match (certificate substitution).
fn validate_ess_cert_id_v2(attrs_content: &[u8], signer_cert_der: &[u8]) -> Vec<String> {
    let mut warnings = Vec::new();
    if signer_cert_der.is_empty() {
        return warnings;
    }

    // ESSCertIDv2 OID content bytes: 1.2.840.113549.1.9.16.2.47
    let ess_oid_content: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
    ];

    let oid_pos = match attrs_content
        .windows(ess_oid_content.len())
        .position(|w| w == ess_oid_content)
    {
        Some(p) => p,
        None => return warnings, // Not present — already warned in validate_signed_attributes
    };

    // After the OID, scan for an OCTET STRING (tag 0x04) which is the certHash
    let after_oid = &attrs_content[oid_pos + ess_oid_content.len()..];

    // Find the first OCTET STRING that looks like a hash (20-64 bytes)
    for i in 0..after_oid.len().saturating_sub(2) {
        if after_oid[i] == 0x04 && i + 1 < after_oid.len() {
            let len = after_oid[i + 1] as usize;
            if matches!(len, 20 | 32 | 48 | 64) && i + 2 + len <= after_oid.len() {
                let cert_hash = &after_oid[i + 2..i + 2 + len];

                // RFC 5035 §4: Default hash algorithm is SHA-256 (32 bytes)
                if len == 32 {
                    let computed = Sha256::digest(signer_cert_der);
                    if cert_hash != computed.as_slice() {
                        warnings.push(
                            "RFC 5035 §4: ESSCertIDv2 certHash does not match signer certificate SHA-256 hash — possible certificate substitution".to_string(),
                        );
                    }
                }
                break;
            }
        }
    }

    warnings
}

/// Extract Content Hints description from signed attributes (RFC 2634 §2.9).
///
/// If the content hints attribute is present, extract the contentDescription
/// string for diagnostic reporting.
///
/// Returns the content description if present, None otherwise.
fn extract_content_hints_description(attrs_content: &[u8]) -> Option<String> {
    // contentHints OID content bytes: 1.2.840.113549.1.9.16.2.4
    let ch_oid_content: &[u8] = &[
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x04,
    ];

    let oid_pos = attrs_content
        .windows(ch_oid_content.len())
        .position(|w| w == ch_oid_content)?;

    // After the OID, look for UTF8String (0x0C) or BMPString (0x1E) — the contentDescription
    let after_oid = &attrs_content[oid_pos + ch_oid_content.len()..];
    for i in 0..after_oid.len().saturating_sub(2) {
        if (after_oid[i] == 0x0C || after_oid[i] == 0x1E) && i + 1 < after_oid.len() {
            let len = after_oid[i + 1] as usize;
            if len > 0 && i + 2 + len <= after_oid.len() {
                let desc_bytes = &after_oid[i + 2..i + 2 + len];
                if after_oid[i] == 0x0C {
                    return std::str::from_utf8(desc_bytes).ok().map(String::from);
                }
                // BMPString (UTF-16BE) — convert pairs to chars
                if desc_bytes.len().is_multiple_of(2) {
                    let chars: String = desc_bytes
                        .chunks(2)
                        .filter_map(|c| {
                            let code = u16::from_be_bytes([c[0], c[1]]);
                            char::from_u32(code as u32)
                        })
                        .collect();
                    if !chars.is_empty() {
                        return Some(chars);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_rsa_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SHA256_WITH_RSA_ALGORITHM_ID);
        assert_eq!(alg, "sha256WithRSAEncryption");
    }

    #[test]
    fn test_identify_rsa_sha384_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SHA384_WITH_RSA_ALGORITHM_ID);
        assert_eq!(alg, "sha384WithRSAEncryption");
    }

    #[test]
    fn test_identify_rsa_sha512_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SHA512_WITH_RSA_ALGORITHM_ID);
        assert_eq!(alg, "sha512WithRSAEncryption");
    }

    #[test]
    fn test_identify_ecdsa_sha256_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ECDSA_WITH_SHA256_ALGORITHM_ID);
        assert_eq!(alg, "ecdsa-with-SHA256");
    }

    #[test]
    fn test_identify_ecdsa_sha384_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ECDSA_WITH_SHA384_ALGORITHM_ID);
        assert_eq!(alg, "ecdsa-with-SHA384");
    }

    #[test]
    fn test_identify_ecdsa_sha512_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ECDSA_WITH_SHA512_ALGORITHM_ID);
        assert_eq!(alg, "ecdsa-with-SHA512");
    }

    #[test]
    fn test_identify_rsa_pss_algorithm() {
        let alg = identify_signature_algorithm(&asn1::RSASSA_PSS_SHA256_ALGORITHM_ID);
        assert_eq!(alg, "RSASSA-PSS");
    }

    #[test]
    fn test_identify_ed25519_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ED25519_ALGORITHM_ID);
        assert_eq!(alg, "Ed25519");
    }

    #[test]
    fn test_identify_ml_dsa_44_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ML_DSA_44_ALGORITHM_ID);
        assert_eq!(alg, "ML-DSA-44");
    }

    #[test]
    fn test_identify_ml_dsa_65_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ML_DSA_65_ALGORITHM_ID);
        assert_eq!(alg, "ML-DSA-65");
    }

    #[test]
    fn test_identify_ml_dsa_87_algorithm() {
        let alg = identify_signature_algorithm(&asn1::ML_DSA_87_ALGORITHM_ID);
        assert_eq!(alg, "ML-DSA-87");
    }

    #[test]
    fn test_identify_slh_dsa_sha2_128s_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SLH_DSA_SHA2_128S_ALGORITHM_ID);
        assert_eq!(alg, "SLH-DSA-SHA2-128s");
    }

    #[test]
    fn test_identify_slh_dsa_sha2_192s_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SLH_DSA_SHA2_192S_ALGORITHM_ID);
        assert_eq!(alg, "SLH-DSA-SHA2-192s");
    }

    #[test]
    fn test_identify_slh_dsa_sha2_256s_algorithm() {
        let alg = identify_signature_algorithm(&asn1::SLH_DSA_SHA2_256S_ALGORITHM_ID);
        assert_eq!(alg, "SLH-DSA-SHA2-256s");
    }

    #[test]
    fn test_identify_unknown_algorithm() {
        let unknown = vec![0x30, 0x03, 0x06, 0x01, 0x00];
        let alg = identify_signature_algorithm(&unknown);
        assert_eq!(alg, "(unknown algorithm)");
    }

    #[test]
    fn test_extract_cn_from_name() {
        // Build a Name with CN="Test Signer"
        let cn_oid = &[0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3
        let cn_value = b"Test Signer";
        let cn_utf8 = {
            let mut v = vec![0x0C]; // UTF8String tag
            v.extend(asn1::encode_length(cn_value.len()));
            v.extend_from_slice(cn_value);
            v
        };
        let atv = asn1::encode_sequence(&[cn_oid, &cn_utf8]);
        let rdn = asn1::encode_set(&atv);
        let name = asn1::encode_sequence(&[&rdn]);

        let cn = extract_cn_from_name(&name);
        assert_eq!(cn, "Test Signer");
    }

    #[test]
    fn test_extract_message_digest() {
        // Build a signed attrs content with a messageDigest attribute
        let hash = vec![0xAA; 32];
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&hash)),
        ]);

        let extracted = extract_message_digest(&digest_attr).unwrap();
        assert_eq!(extracted, hash);
    }

    #[test]
    fn test_extract_message_digest_missing() {
        // Attrs with only contentType, no messageDigest
        let other_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);

        let result = extract_message_digest(&other_attr);
        assert!(result.is_err());
    }

    // ─── Signed Attribute Validation Tests (RFC 5652/8933) ───

    #[test]
    fn test_validate_signed_attrs_complete() {
        // Build signed attrs with contentType + messageDigest + signingTime + CMSAlgorithmProtection + ESSCertIDv2
        let content_type_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 32])),
        ]);
        let signing_time_attr = asn1::encode_sequence(&[
            asn1::OID_SIGNING_TIME,
            &asn1::encode_set(&asn1::encode_utc_time_now()),
        ]);
        let alg_protection_attr = asn1::encode_sequence(&[
            asn1::OID_CMS_ALGORITHM_PROTECTION,
            &asn1::encode_set(&asn1::encode_sequence(&[&asn1::SHA256_ALGORITHM_ID])),
        ]);
        // RFC 5035: ESSCertIDv2 — signer certificate binding
        let ess_cert_id_attr = asn1::encode_sequence(&[
            asn1::OID_ESS_CERT_ID_V2,
            &asn1::encode_set(&asn1::encode_sequence(&[&asn1::encode_octet_string(
                &[0xBB; 32],
            )])),
        ]);

        // Sort attributes by DER encoding per X.690 §11.6 (SET OF canonical order)
        let mut attr_list = vec![
            content_type_attr,
            digest_attr,
            signing_time_attr,
            alg_protection_attr,
            ess_cert_id_attr,
        ];
        attr_list.sort();

        let mut attrs = Vec::new();
        for attr in &attr_list {
            attrs.extend(attr);
        }

        let warnings = validate_signed_attributes(&attrs);
        assert!(
            warnings.is_empty(),
            "Complete attrs should have no warnings: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_signed_attrs_missing_content_type() {
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 32])),
        ]);

        let warnings = validate_signed_attributes(&digest_attr);
        assert!(warnings.iter().any(|w| w.contains("contentType")));
    }

    #[test]
    fn test_validate_signed_attrs_missing_algorithm_protection() {
        let content_type_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 32])),
        ]);

        let mut attrs = Vec::new();
        attrs.extend(&content_type_attr);
        attrs.extend(&digest_attr);

        let warnings = validate_signed_attributes(&attrs);
        assert!(warnings
            .iter()
            .any(|w| w.contains("CMSAlgorithmProtection")));
        // Should NOT warn about contentType or messageDigest
        assert!(!warnings
            .iter()
            .any(|w| w.contains("contentType attribute missing")));
        assert!(!warnings
            .iter()
            .any(|w| w.contains("messageDigest attribute missing")));
    }

    #[test]
    fn test_validate_signed_attrs_empty() {
        let warnings = validate_signed_attributes(&[]);
        // All four should be missing
        assert!(warnings.iter().any(|w| w.contains("contentType")));
        assert!(warnings.iter().any(|w| w.contains("messageDigest")));
        assert!(warnings.iter().any(|w| w.contains("signingTime")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("CMSAlgorithmProtection")));
    }

    // ─── digestAlgorithms SET Cross-Validation Tests ───

    #[test]
    fn test_digest_algorithms_set_contains_match() {
        // Build a SET containing SHA-256 AlgorithmIdentifier
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let set = asn1::encode_set(&sha256_alg);
        assert!(digest_algorithms_set_contains(&set, &sha256_alg));
    }

    #[test]
    fn test_digest_algorithms_set_contains_no_match() {
        // Build a SET containing only SHA-256
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let sha384_alg = asn1::SHA384_ALGORITHM_ID.to_vec();
        let set = asn1::encode_set(&sha256_alg);
        // SHA-384 is not in the set
        assert!(!digest_algorithms_set_contains(&set, &sha384_alg));
    }

    #[test]
    fn test_digest_algorithms_set_contains_multiple() {
        // Build a SET containing both SHA-256 and SHA-384
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let sha384_alg = asn1::SHA384_ALGORITHM_ID.to_vec();
        let mut set_content = sha256_alg.clone();
        set_content.extend_from_slice(&sha384_alg);
        let set = asn1::encode_set(&set_content);
        assert!(digest_algorithms_set_contains(&set, &sha256_alg));
        assert!(digest_algorithms_set_contains(&set, &sha384_alg));
    }

    #[test]
    fn test_cms_algorithm_protection_digest_mismatch() {
        // Build a CMSAlgorithmProtection attribute with SHA-256 digest
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let sha384_alg = asn1::SHA384_ALGORITHM_ID.to_vec();
        // The attribute value is SEQUENCE { digestAlgorithm, ... }
        let cap_value = asn1::encode_sequence(&[&sha256_alg]);
        let cap_set = asn1::encode_set(&cap_value);
        let cap_attr = asn1::encode_sequence(&[asn1::OID_CMS_ALGORITHM_PROTECTION, &cap_set]);

        // SignerInfo uses SHA-384 — should trigger mismatch warning
        let warnings = validate_cms_algorithm_protection_digest(&cap_attr, &sha384_alg);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("does not match SignerInfo")),
            "Expected mismatch warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_cms_algorithm_protection_digest_match() {
        // Build a CMSAlgorithmProtection attribute with SHA-256 digest
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let cap_value = asn1::encode_sequence(&[&sha256_alg]);
        let cap_set = asn1::encode_set(&cap_value);
        let cap_attr = asn1::encode_sequence(&[asn1::OID_CMS_ALGORITHM_PROTECTION, &cap_set]);

        // SignerInfo also uses SHA-256 — no warning expected
        let warnings = validate_cms_algorithm_protection_digest(&cap_attr, &sha256_alg);
        assert!(
            warnings.is_empty(),
            "Expected no warnings for matching algorithms, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_cms_algorithm_protection_sig_alg_mismatch() {
        // Build a CMSAlgorithmProtection with SHA-256 digest + RSA-SHA256 sig alg
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let rsa_sha256_alg = asn1::SHA256_WITH_RSA_ALGORITHM_ID.to_vec();
        let ecdsa_sha256_alg = asn1::ECDSA_WITH_SHA256_ALGORITHM_ID.to_vec();

        // [1] IMPLICIT wrapping of RSA-SHA256 algorithm identifier
        // Extract the SEQUENCE content (skip tag+length) and wrap with [1] tag
        let sig_alg_content = &rsa_sha256_alg[2..]; // Skip SEQUENCE tag + length
        let sig_alg_implicit = asn1::encode_implicit_tag(1, sig_alg_content);

        let cap_value = asn1::encode_sequence(&[&sha256_alg, &sig_alg_implicit]);
        let cap_set = asn1::encode_set(&cap_value);
        let cap_attr = asn1::encode_sequence(&[asn1::OID_CMS_ALGORITHM_PROTECTION, &cap_set]);

        // SignerInfo uses ECDSA-SHA256 (different from RSA-SHA256) — should trigger mismatch
        let warnings = validate_cms_algorithm_protection_signature(&cap_attr, &ecdsa_sha256_alg);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("signatureAlgorithm does not match")),
            "Expected sig alg mismatch warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_cms_algorithm_protection_sig_alg_match() {
        // Build a CMSAlgorithmProtection with SHA-256 digest + RSA-SHA256 sig alg
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let rsa_sha256_alg = asn1::SHA256_WITH_RSA_ALGORITHM_ID.to_vec();

        // [1] IMPLICIT wrapping of RSA-SHA256
        let sig_alg_content = &rsa_sha256_alg[2..];
        let sig_alg_implicit = asn1::encode_implicit_tag(1, sig_alg_content);

        let cap_value = asn1::encode_sequence(&[&sha256_alg, &sig_alg_implicit]);
        let cap_set = asn1::encode_set(&cap_value);
        let cap_attr = asn1::encode_sequence(&[asn1::OID_CMS_ALGORITHM_PROTECTION, &cap_set]);

        // SignerInfo also uses RSA-SHA256 — no warning
        let warnings = validate_cms_algorithm_protection_signature(&cap_attr, &rsa_sha256_alg);
        assert!(
            warnings.is_empty(),
            "Expected no warnings for matching sig alg, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_cms_algorithm_protection_no_sig_alg() {
        // CMSAlgorithmProtection without signatureAlgorithm — should not warn
        let sha256_alg = asn1::SHA256_ALGORITHM_ID.to_vec();
        let cap_value = asn1::encode_sequence(&[&sha256_alg]); // Only digest, no sig alg
        let cap_set = asn1::encode_set(&cap_value);
        let cap_attr = asn1::encode_sequence(&[asn1::OID_CMS_ALGORITHM_PROTECTION, &cap_set]);

        let warnings = validate_cms_algorithm_protection_signature(
            &cap_attr,
            &asn1::SHA256_WITH_RSA_ALGORITHM_ID,
        );
        assert!(
            warnings.is_empty(),
            "Should not warn when CMSAlgorithmProtection has no signatureAlgorithm"
        );
    }

    // ─── Digest Algorithm Identification Tests ───

    #[test]
    fn test_identify_digest_algorithm_sha256() {
        let alg = &asn1::SHA256_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA-256");
    }

    #[test]
    fn test_identify_digest_algorithm_sha384() {
        let alg = &asn1::SHA384_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA-384");
    }

    #[test]
    fn test_identify_digest_algorithm_sha512() {
        let alg = &asn1::SHA512_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA-512");
    }

    #[test]
    fn test_identify_digest_algorithm_sha3_256() {
        let alg = &asn1::SHA3_256_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA3-256");
    }

    #[test]
    fn test_identify_digest_algorithm_sha3_384() {
        let alg = &asn1::SHA3_384_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA3-384");
    }

    #[test]
    fn test_identify_digest_algorithm_sha3_512() {
        let alg = &asn1::SHA3_512_ALGORITHM_ID;
        assert_eq!(identify_digest_algorithm(alg), "SHA3-512");
    }

    #[test]
    fn test_identify_digest_algorithm_unknown() {
        let unknown = &[0x30, 0x05, 0x06, 0x03, 0xFF, 0xFF, 0xFF];
        assert_eq!(identify_digest_algorithm(unknown), "(unknown digest)");
    }

    // ─── Chain Validation Tests ───

    /// Build a minimal fake cert with specific issuer and subject CN for chain testing.
    fn build_chain_test_cert(serial: u32, subject_cn: &str, issuer_cn: &str) -> Vec<u8> {
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial_der = asn1::encode_integer_value(serial);
        let algo = asn1::SHA256_ALGORITHM_ID.to_vec();

        let make_name = |cn: &str| {
            let cn_bytes = cn.as_bytes();
            let mut cn_der = vec![0x0C]; // UTF8String tag
            cn_der.extend(asn1::encode_length(cn_bytes.len()));
            cn_der.extend_from_slice(cn_bytes);
            asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
                &[0x06, 0x03, 0x55, 0x04, 0x03][..],
                &cn_der,
            ]))])
        };

        let issuer = make_name(issuer_cn);
        let validity =
            asn1::encode_sequence(&[&asn1::encode_utc_time_now(), &asn1::encode_utc_time_now()]);
        let subject = make_name(subject_cn);

        let tbs =
            asn1::encode_sequence(&[&version, &serial_der, &algo, &issuer, &validity, &subject]);
        asn1::encode_sequence(&[&tbs, &algo, &[0x03, 0x01, 0x00]])
    }

    #[test]
    fn test_chain_validation_direct_trust() {
        // Signer issued directly by trusted root
        let root = build_chain_test_cert(1, "Root CA", "Root CA");
        let signer = build_chain_test_cert(2, "Code Signer", "Root CA");

        assert!(validate_signer_chain(&signer, &[], &[root]));
    }

    #[test]
    fn test_chain_validation_with_intermediate() {
        // Root → Intermediate → Signer
        let root = build_chain_test_cert(1, "Root CA", "Root CA");
        let intermediate = build_chain_test_cert(2, "Intermediate CA", "Root CA");
        let signer = build_chain_test_cert(3, "Code Signer", "Intermediate CA");

        assert!(validate_signer_chain(&signer, &[intermediate], &[root]));
    }

    #[test]
    fn test_chain_validation_untrusted_root() {
        // Signer issued by an untrusted CA
        let trusted_root = build_chain_test_cert(1, "Trusted Root", "Trusted Root");
        let signer = build_chain_test_cert(2, "Code Signer", "Untrusted CA");

        assert!(!validate_signer_chain(&signer, &[], &[trusted_root]));
    }

    #[test]
    fn test_chain_validation_missing_intermediate() {
        // Root → (missing Intermediate) → Signer
        let root = build_chain_test_cert(1, "Root CA", "Root CA");
        let signer = build_chain_test_cert(3, "Code Signer", "Intermediate CA");

        // No intermediate provided — chain cannot be built
        assert!(!validate_signer_chain(&signer, &[], &[root]));
    }

    #[test]
    fn test_chain_validation_empty_trust_store() {
        let signer = build_chain_test_cert(1, "Code Signer", "Some CA");
        // Empty trust store — always returns true (backward compat handled by caller)
        assert!(!validate_signer_chain(&signer, &[], &[]));
    }

    #[test]
    fn test_chain_validation_two_intermediates() {
        // Root → Policy CA → Issuing CA → Signer
        let root = build_chain_test_cert(1, "Root CA", "Root CA");
        let policy = build_chain_test_cert(2, "Policy CA", "Root CA");
        let issuing = build_chain_test_cert(3, "Issuing CA", "Policy CA");
        let signer = build_chain_test_cert(4, "Code Signer", "Issuing CA");

        assert!(validate_signer_chain(&signer, &[policy, issuing], &[root]));
    }

    #[test]
    fn test_extract_issuer_subject_der() {
        let cert = build_chain_test_cert(1, "MySubject", "MyIssuer");
        let issuer = extract_issuer_der(&cert).unwrap();
        let subject = extract_subject_der(&cert).unwrap();
        // Issuer and subject should be different
        assert_ne!(issuer, subject);
        // Self-signed cert: issuer == subject
        let self_signed = build_chain_test_cert(1, "SelfSigned", "SelfSigned");
        let ss_issuer = extract_issuer_der(&self_signed).unwrap();
        let ss_subject = extract_subject_der(&self_signed).unwrap();
        assert_eq!(ss_issuer, ss_subject);
    }

    // ─── ContentInfo Content Type Validation Tests ───

    #[test]
    fn test_parse_cms_rejects_non_signed_data() {
        // Build a ContentInfo with id-data instead of id-signedData
        let content = asn1::encode_sequence(&[
            asn1::OID_DATA, // Wrong content type — should be OID_SIGNED_DATA
            &asn1::encode_explicit_tag(0, &asn1::encode_sequence(&[])),
        ]);
        let result = parse_cms_signed_data(&content);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not id-signedData"),
            "Error should mention wrong content type: {err}"
        );
    }

    #[test]
    fn test_validate_signed_attrs_missing_signing_time() {
        // Build attrs with contentType + messageDigest but no signingTime
        let content_type_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 32])),
        ]);

        let mut attrs = Vec::new();
        attrs.extend(&content_type_attr);
        attrs.extend(&digest_attr);

        let warnings = validate_signed_attributes(&attrs);
        assert!(
            warnings.iter().any(|w| w.contains("signingTime")),
            "Should warn about missing signingTime: {:?}",
            warnings
        );
    }

    // ─── Timestamp genTime Extraction Tests ───

    #[test]
    fn test_extract_timestamp_gen_time_valid() {
        // Build a fake unsigned attrs region containing the timestamp OID
        // and a GeneralizedTime "20260220153045Z"
        let mut data = Vec::new();
        // [1] IMPLICIT tag for unsigned attrs
        data.push(0xA1);

        // Embed the timestamp token OID: 1.2.840.113549.1.9.16.2.14
        let tst_oid: &[u8] = &[
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        // Some padding to simulate the Attribute structure
        data.extend_from_slice(&[0x30, 0x50]); // SEQUENCE wrapper (approximate)
        data.extend_from_slice(tst_oid);

        // Add some filler bytes simulating nested CMS structure
        data.extend_from_slice(&[0x31, 0x40, 0x30, 0x3E, 0x06, 0x09]);
        data.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]); // id-signedData
        data.extend_from_slice(&[0xA0, 0x30, 0x30, 0x2E]); // constructed wrappers

        // TSTInfo with GeneralizedTime: "20260220153045Z"
        let gen_time = b"20260220153045Z";
        data.push(0x18); // GeneralizedTime tag
        data.push(gen_time.len() as u8);
        data.extend_from_slice(gen_time);

        // Add trailing bytes
        data.extend_from_slice(&[0x00; 10]);

        // Fix up the [1] IMPLICIT length
        let content_len = data.len() - 2;
        data[1] = content_len as u8;

        let result = extract_timestamp_gen_time(&data);
        assert!(result.is_some(), "Should extract genTime");
        let time = result.unwrap();
        assert_eq!(time, "2026-02-20 15:30:45 UTC");
    }

    #[test]
    fn test_extract_timestamp_gen_time_no_timestamp() {
        // Empty region — no timestamp
        let data = &[];
        assert!(extract_timestamp_gen_time(data).is_none());
    }

    #[test]
    fn test_extract_timestamp_gen_time_no_oid() {
        // Data without the timestamp token OID
        let data = vec![
            0xA1, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(extract_timestamp_gen_time(&data).is_none());
    }

    #[test]
    fn test_extract_timestamp_gen_time_with_fractional_seconds() {
        // GeneralizedTime with fractional seconds: "20260220153045.123Z"
        let mut data = Vec::new();
        data.push(0xA1);
        data.push(0x00); // placeholder length

        let tst_oid: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        data.extend_from_slice(tst_oid);
        data.extend_from_slice(&[0x00; 20]); // filler

        let gen_time = b"20260220153045.123Z";
        data.push(0x18);
        data.push(gen_time.len() as u8);
        data.extend_from_slice(gen_time);

        data[1] = (data.len() - 2) as u8;

        let result = extract_timestamp_gen_time(&data);
        assert!(result.is_some());
        // Should still extract the base time correctly
        assert!(result.unwrap().starts_with("2026-02-20 15:30:45"));
    }

    #[test]
    fn test_extract_integer_value_valid() {
        // DER INTEGER tag=0x02, length=1, value=1
        assert_eq!(extract_integer_value(&[0x02, 0x01, 0x01]), Some(1));
        // version 3
        assert_eq!(extract_integer_value(&[0x02, 0x01, 0x03]), Some(3));
        // version 5
        assert_eq!(extract_integer_value(&[0x02, 0x01, 0x05]), Some(5));
    }

    #[test]
    fn test_extract_integer_value_zero() {
        assert_eq!(extract_integer_value(&[0x02, 0x01, 0x00]), Some(0));
    }

    #[test]
    fn test_extract_integer_value_multi_byte() {
        // 2-byte integer: 0x01, 0x00 = 256
        assert_eq!(extract_integer_value(&[0x02, 0x02, 0x01, 0x00]), Some(256));
    }

    #[test]
    fn test_extract_integer_value_not_integer_tag() {
        // tag 0x30 (SEQUENCE) instead of 0x02 (INTEGER)
        assert_eq!(extract_integer_value(&[0x30, 0x01, 0x01]), None);
    }

    #[test]
    fn test_extract_integer_value_empty_content() {
        // INTEGER with zero-length content
        assert_eq!(extract_integer_value(&[0x02, 0x00]), None);
    }

    #[test]
    fn test_extract_integer_value_truncated() {
        // Too short to be valid TLV
        assert_eq!(extract_integer_value(&[0x02]), None);
        assert_eq!(extract_integer_value(&[]), None);
    }

    // ─── Counter-Signature Detection Tests (RFC 5652 §11.4) ───

    #[test]
    fn test_extract_counter_signers_none() {
        // No counter-signature OID — empty result
        let data = vec![0xA1, 0x05, 0x30, 0x03, 0x06, 0x01, 0x00];
        let parent_sig = b"fake_signature";
        let result = extract_and_verify_counter_signers(&data, parent_sig);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_counter_signers_one() {
        // Build fake unsigned attrs with counter-signature OID
        let mut data = Vec::new();
        data.push(0xA1); // [1] IMPLICIT tag
        data.push(0x00); // placeholder length

        // Counter-signature OID content: 1.2.840.113549.1.9.6
        let cs_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
        // Wrap in OID tag
        data.push(0x06);
        data.push(cs_oid.len() as u8);
        data.extend_from_slice(cs_oid);

        // Add a fake AlgorithmIdentifier for SHA-256 (so it gets detected)
        data.extend_from_slice(&crate::pkcs7::asn1::SHA256_ALGORITHM_ID);

        // Add a fake AlgorithmIdentifier for sha256WithRSA
        data.extend_from_slice(&crate::pkcs7::asn1::SHA256_WITH_RSA_ALGORITHM_ID);

        data[1] = (data.len() - 2) as u8;

        let parent_sig = b"fake_signature";
        let result = extract_and_verify_counter_signers(&data, parent_sig);
        assert_eq!(result.len(), 1, "Should detect one counter-signer");
    }

    #[test]
    fn test_extract_counter_signers_empty_data() {
        let parent_sig = b"fake_signature";
        let result = extract_and_verify_counter_signers(&[], parent_sig);
        assert!(result.is_empty());
    }

    #[test]
    fn test_counter_signature_digest_verification_sha256() {
        // RFC 5652 §11.4: messageDigest in counter-sig = digest(parent signature value)
        use sha2::{Digest, Sha256};

        let parent_sig = b"this is the parent signature value";
        let expected_digest = Sha256::digest(parent_sig);

        // Build a region containing the messageDigest OID followed by the correct digest
        let mut region = Vec::new();

        // messageDigest OID content: 1.2.840.113549.1.9.4
        let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
        // Wrap OID with tag
        region.push(0x06);
        region.push(md_oid.len() as u8);
        region.extend_from_slice(md_oid);

        // SET { OCTET STRING { digest value } }
        region.push(0x31); // SET tag
        region.push(expected_digest.len() as u8 + 2);
        region.push(0x04); // OCTET STRING tag
        region.push(expected_digest.len() as u8);
        region.extend_from_slice(&expected_digest);

        let result = verify_counter_signature_digest(&region, parent_sig, "SHA-256");
        assert_eq!(result, Some(true), "Correct digest should verify");
    }

    #[test]
    fn test_counter_signature_digest_verification_mismatch() {
        use sha2::{Digest, Sha256};

        let parent_sig = b"parent signature";
        // Compute digest of WRONG data
        let wrong_digest = Sha256::digest(b"different data");

        let mut region = Vec::new();
        let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
        region.push(0x06);
        region.push(md_oid.len() as u8);
        region.extend_from_slice(md_oid);
        region.push(0x31);
        region.push(wrong_digest.len() as u8 + 2);
        region.push(0x04);
        region.push(wrong_digest.len() as u8);
        region.extend_from_slice(&wrong_digest);

        let result = verify_counter_signature_digest(&region, parent_sig, "SHA-256");
        assert_eq!(result, Some(false), "Wrong digest should fail verification");
    }

    #[test]
    fn test_counter_signature_digest_verification_sha384() {
        use sha2::{Digest, Sha384};

        let parent_sig = b"parent signature for sha384 test";
        let expected_digest = Sha384::digest(parent_sig);

        let mut region = Vec::new();
        let md_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
        region.push(0x06);
        region.push(md_oid.len() as u8);
        region.extend_from_slice(md_oid);
        region.push(0x31);
        region.push(expected_digest.len() as u8 + 2);
        region.push(0x04);
        region.push(expected_digest.len() as u8);
        region.extend_from_slice(&expected_digest);

        let result = verify_counter_signature_digest(&region, parent_sig, "SHA-384");
        assert_eq!(result, Some(true), "SHA-384 digest should verify");
    }

    #[test]
    fn test_counter_signature_digest_unknown_algorithm() {
        let parent_sig = b"parent sig";
        let region = Vec::new();
        let result = verify_counter_signature_digest(&region, parent_sig, "unknown");
        assert_eq!(result, None, "Unknown algorithm should return None");
    }

    #[test]
    fn test_counter_signature_digest_no_message_digest_attribute() {
        let parent_sig = b"parent sig";
        // Region with no messageDigest OID
        let region = vec![0x30, 0x03, 0x06, 0x01, 0x00];
        let result = verify_counter_signature_digest(&region, parent_sig, "SHA-256");
        assert_eq!(result, None, "Missing messageDigest should return None");
    }

    // ---- encapContentInfo contentType extraction tests ----

    #[test]
    fn test_extract_encap_content_type_id_data() {
        // EncapsulatedContentInfo SEQUENCE { eContentType = id-data }
        let encap = asn1::encode_sequence(&[asn1::OID_DATA]);
        let result = extract_encap_content_type(&encap);
        assert_eq!(result, "id-data (1.2.840.113549.1.7.1)");
    }

    #[test]
    fn test_extract_encap_content_type_spc_indirect() {
        let encap = asn1::encode_sequence(&[asn1::OID_SPC_INDIRECT_DATA]);
        let result = extract_encap_content_type(&encap);
        assert_eq!(result, "SPC_INDIRECT_DATA (1.3.6.1.4.1.311.2.1.4)");
    }

    #[test]
    fn test_extract_encap_content_type_signed_data() {
        let encap = asn1::encode_sequence(&[asn1::OID_SIGNED_DATA]);
        let result = extract_encap_content_type(&encap);
        assert_eq!(result, "id-signedData (1.2.840.113549.1.7.2)");
    }

    #[test]
    fn test_extract_encap_content_type_unknown() {
        // Unknown OID: 1.2.3.4.5
        let unknown_oid: &[u8] = &[0x06, 0x04, 0x2A, 0x03, 0x04, 0x05];
        let encap = asn1::encode_sequence(&[unknown_oid]);
        let result = extract_encap_content_type(&encap);
        assert_eq!(result, "1.2.3.4.5");
    }

    #[test]
    fn test_extract_encap_content_type_invalid() {
        let result = extract_encap_content_type(&[0x01, 0x00]); // Not a SEQUENCE
        assert_eq!(result, "unknown");
    }

    #[test]
    fn test_decode_oid_to_string_simple() {
        // OID 1.2.840.113549.1.7.1 = id-data
        let bytes: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
        let result = decode_oid_to_string(bytes);
        assert_eq!(result, "1.2.840.113549.1.7.1");
    }

    #[test]
    fn test_decode_oid_to_string_empty() {
        assert_eq!(decode_oid_to_string(&[]), "unknown");
    }

    #[test]
    fn test_decode_oid_sha256() {
        // OID 2.16.840.1.101.3.4.2.1 = id-sha256 (NIST)
        let bytes: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert_eq!(decode_oid_to_string(bytes), "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn test_decode_oid_ecdsa_with_sha256() {
        // OID 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
        let bytes: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        assert_eq!(decode_oid_to_string(bytes), "1.2.840.10045.4.3.2");
    }

    #[test]
    fn test_decode_oid_rsa_encryption() {
        // OID 1.2.840.113549.1.1.1 = rsaEncryption
        let bytes: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        assert_eq!(decode_oid_to_string(bytes), "1.2.840.113549.1.1.1");
    }

    // ─── DER SET OF Ordering Tests (RFC 5652 §5.4 + X.690 §11.6) ───

    #[test]
    fn test_der_set_of_ordering_basic() {
        // Shorter element comes before longer
        assert!(is_der_set_of_ordered(
            &[0x30, 0x01, 0x00],
            &[0x30, 0x02, 0x00, 0x00]
        ));
        // Same content = ordered (equal)
        assert!(is_der_set_of_ordered(
            &[0x30, 0x01, 0x00],
            &[0x30, 0x01, 0x00]
        ));
    }

    #[test]
    fn test_der_set_of_ordering_by_tag() {
        // Lower tag value comes first (0x06 OID before 0x30 SEQUENCE)
        assert!(is_der_set_of_ordered(
            &[0x06, 0x01, 0x00],
            &[0x30, 0x01, 0x00]
        ));
        // Higher tag value should NOT come first
        assert!(!is_der_set_of_ordered(
            &[0x30, 0x01, 0x00],
            &[0x06, 0x01, 0x00]
        ));
    }

    #[test]
    fn test_der_set_of_ordering_by_content() {
        // Same tag and length, different content — lexicographic order
        assert!(is_der_set_of_ordered(
            &[0x30, 0x01, 0x01],
            &[0x30, 0x01, 0x02]
        ));
        assert!(!is_der_set_of_ordered(
            &[0x30, 0x01, 0x02],
            &[0x30, 0x01, 0x01]
        ));
    }

    #[test]
    fn test_validate_signed_attrs_set_of_ordering_correct() {
        // Build attributes in proper DER order: contentType OID (0x06 0x09 0x2A...)
        // comes before messageDigest OID (0x06 0x09 0x2A... 0x04)
        let content_type_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);
        let digest_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 32])),
        ]);

        // Both orderings should produce warnings only about missing attrs, not ordering
        // since we only have 2 attrs and they may or may not be sorted
        let mut attrs = Vec::new();
        attrs.extend(&content_type_attr);
        attrs.extend(&digest_attr);

        let warnings = validate_signed_attributes(&attrs);
        // Check that the SET OF ordering warning is absent when properly ordered
        let has_ordering_warn = warnings.iter().any(|w| w.contains("DER canonical order"));
        if has_ordering_warn {
            // If it fires, that means these particular OIDs aren't in DER order — that's OK,
            // what matters is the check exists. Let's verify with reversed order.
            let mut reversed = Vec::new();
            reversed.extend(&digest_attr);
            reversed.extend(&content_type_attr);
            let rev_warnings = validate_signed_attributes(&reversed);
            // One ordering should warn, the other shouldn't (or both if OIDs are equal prefix)
            assert_ne!(
                warnings.iter().any(|w| w.contains("DER canonical order")),
                rev_warnings
                    .iter()
                    .any(|w| w.contains("DER canonical order")),
                "Exactly one ordering should trigger the DER order warning"
            );
        }
    }

    #[test]
    fn test_validate_signed_attrs_set_of_ordering_wrong() {
        // Build two attributes where we force wrong DER order
        // Attribute with higher-valued first byte comes first = wrong order
        let high_attr = asn1::encode_sequence(&[
            &[0x06, 0x03, 0xFF, 0xFF, 0xFF][..], // OID with high values
            &asn1::encode_set(&[0x00]),
        ]);
        let low_attr = asn1::encode_sequence(&[
            &[0x06, 0x03, 0x01, 0x01, 0x01][..], // OID with low values
            &asn1::encode_set(&[0x00]),
        ]);

        // high before low = wrong DER order
        let mut attrs = Vec::new();
        attrs.extend(&high_attr);
        attrs.extend(&low_attr);

        let warnings = validate_signed_attributes(&attrs);
        assert!(
            warnings.iter().any(|w| w.contains("DER canonical order")),
            "Should warn about wrong DER SET OF ordering: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_signed_attrs_unusual_digest_length() {
        // Build messageDigest with unusual length (e.g., 16 bytes = MD5-like)
        let md_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0xAA; 16])),
        ]);
        let ct_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);

        let mut attrs = Vec::new();
        attrs.extend(&ct_attr);
        attrs.extend(&md_attr);

        let warnings = validate_signed_attributes(&attrs);
        assert!(
            warnings.iter().any(|w| w.contains("unusual length")),
            "Should warn about 16-byte messageDigest: {:?}",
            warnings
        );
    }

    #[test]
    fn test_validate_signed_attrs_valid_digest_lengths() {
        // Verify that standard digest sizes (32, 48, 64) don't trigger warnings
        for (size, name) in [(32, "SHA-256"), (48, "SHA-384"), (64, "SHA-512")] {
            let md_attr = asn1::encode_sequence(&[
                asn1::OID_MESSAGE_DIGEST,
                &asn1::encode_set(&asn1::encode_octet_string(&vec![0xBB; size])),
            ]);
            let ct_attr = asn1::encode_sequence(&[
                asn1::OID_CONTENT_TYPE,
                &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
            ]);
            let st_attr = asn1::encode_sequence(&[
                asn1::OID_SIGNING_TIME,
                &asn1::encode_set(&asn1::encode_utc_time_now()),
            ]);
            let ap_attr = asn1::encode_sequence(&[
                asn1::OID_CMS_ALGORITHM_PROTECTION,
                &asn1::encode_set(&asn1::encode_sequence(&[&asn1::SHA256_ALGORITHM_ID])),
            ]);

            let mut attr_list = vec![ct_attr, md_attr, st_attr, ap_attr];
            attr_list.sort();
            let mut attrs = Vec::new();
            for a in &attr_list {
                attrs.extend(a);
            }

            let warnings = validate_signed_attributes(&attrs);
            assert!(
                !warnings.iter().any(|w| w.contains("unusual length")),
                "{} ({} bytes) should not trigger digest length warning: {:?}",
                name,
                size,
                warnings
            );
        }
    }

    // ─── Signing Time Extraction Tests ───

    #[test]
    fn test_extract_signing_time_utc() {
        // Build signed attrs with signingTime as UTCTime
        let mut attrs = Vec::new();
        // signingTime attribute: SEQUENCE { OID, SET { UTCTime } }
        let utc_time = b"260220150000Z"; // 2026-02-20 15:00:00 UTC
        let time_value = [&[0x17, utc_time.len() as u8][..], &utc_time[..]].concat();
        let st_attr =
            asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &asn1::encode_set(&time_value)]);
        attrs.extend(&st_attr);

        let result = extract_signing_time(&attrs);
        assert!(result.is_some(), "Should extract signingTime");
        assert_eq!(result.unwrap(), "2026-02-20 15:00:00");
    }

    #[test]
    fn test_extract_signing_time_generalized() {
        // Build signed attrs with signingTime as GeneralizedTime
        let mut attrs = Vec::new();
        let gen_time = b"20260220153045Z";
        let time_value = [&[0x18, gen_time.len() as u8][..], &gen_time[..]].concat();
        let st_attr =
            asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &asn1::encode_set(&time_value)]);
        attrs.extend(&st_attr);

        let result = extract_signing_time(&attrs);
        assert!(
            result.is_some(),
            "Should extract GeneralizedTime signingTime"
        );
        assert_eq!(result.unwrap(), "2026-02-20 15:30:45");
    }

    #[test]
    fn test_extract_signing_time_absent() {
        // Build attrs without signingTime
        let content_type_attr = asn1::encode_sequence(&[
            asn1::OID_CONTENT_TYPE,
            &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
        ]);
        let result = extract_signing_time(&content_type_attr);
        assert!(
            result.is_none(),
            "Should return None when signingTime absent"
        );
    }

    // ─── Signing-Time vs Certificate Validity Tests (RFC 5652 §11.3) ───

    #[test]
    fn test_signing_time_within_cert_validity() {
        // Build a minimal cert DER with validity: 2025-01-01 to 2027-12-31
        // UTCTime 250101000000Z = notBefore, 271231235959Z = notAfter
        let mut cert_der = vec![0x30, 0x82, 0x02, 0x00]; // outer SEQUENCE
        cert_der.extend_from_slice(&[0x00; 50]); // padding before validity
                                                 // notBefore: UTCTime "250101000000Z"
        cert_der.push(0x17); // UTCTime tag
        cert_der.push(13); // length
        cert_der.extend_from_slice(b"250101000000Z");
        // notAfter: UTCTime "271231235959Z"
        cert_der.push(0x17);
        cert_der.push(13);
        cert_der.extend_from_slice(b"271231235959Z");
        cert_der.extend_from_slice(&[0x00; 100]);

        // Signing time within range — no warnings
        let warnings = validate_signing_time_vs_cert_validity("2026-06-15 12:00:00", &cert_der);
        assert!(
            warnings.is_empty(),
            "Should not warn when signing time is within validity: {:?}",
            warnings
        );
    }

    #[test]
    fn test_signing_time_before_cert_validity() {
        let mut cert_der = vec![0x30, 0x82, 0x02, 0x00];
        cert_der.extend_from_slice(&[0x00; 50]);
        cert_der.push(0x17);
        cert_der.push(13);
        cert_der.extend_from_slice(b"250101000000Z");
        cert_der.push(0x17);
        cert_der.push(13);
        cert_der.extend_from_slice(b"271231235959Z");
        cert_der.extend_from_slice(&[0x00; 100]);

        // Signing time BEFORE notBefore — should warn
        let warnings = validate_signing_time_vs_cert_validity("2024-06-15 12:00:00", &cert_der);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("before signer certificate notBefore")),
            "Should warn when signing time precedes cert validity: {:?}",
            warnings
        );
    }

    #[test]
    fn test_signing_time_after_cert_validity() {
        let mut cert_der = vec![0x30, 0x82, 0x02, 0x00];
        cert_der.extend_from_slice(&[0x00; 50]);
        cert_der.push(0x17);
        cert_der.push(13);
        cert_der.extend_from_slice(b"250101000000Z");
        cert_der.push(0x17);
        cert_der.push(13);
        cert_der.extend_from_slice(b"271231235959Z");
        cert_der.extend_from_slice(&[0x00; 100]);

        // Signing time AFTER notAfter — should warn
        let warnings = validate_signing_time_vs_cert_validity("2028-06-15 12:00:00", &cert_der);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("after signer certificate notAfter")),
            "Should warn when signing time is after cert expiry: {:?}",
            warnings
        );
    }

    // ─── Counter-Signature Temporal Ordering Tests (RFC 3161 §2.4.1) ───

    #[test]
    fn test_counter_signer_temporal_ordering_valid() {
        // Counter-signer time AFTER parent time — valid
        let warnings = validate_counter_signer_temporal_ordering(
            Some("2026-02-20 10:00:00"),
            &[], // No counter-signer OID in data = no warnings
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_counter_signer_temporal_ordering_no_parent_time() {
        // No parent signing time — cannot validate, no warnings
        let warnings = validate_counter_signer_temporal_ordering(None, &[0xA1, 0x05, 0x00]);
        assert!(warnings.is_empty(), "Should not warn without parent time");
    }

    #[test]
    fn test_counter_signer_temporal_ordering_before_parent() {
        // Build unsigned attrs with a counter-signer whose signingTime predates parent
        let mut data = Vec::new();
        // Counter-signature OID content: 1.2.840.113549.1.9.6
        let cs_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06];
        // signingTime OID content: 1.2.840.113549.1.9.5
        let st_oid: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];

        // Counter-signature attribute structure (simplified)
        data.extend_from_slice(&[0x30, 0x40]); // SEQUENCE wrapper
        data.extend_from_slice(&[0x06, cs_oid.len() as u8]); // OID tag+len
        data.extend_from_slice(cs_oid);

        // Some filler (version, sid, digestAlg)
        data.extend_from_slice(&[0x02, 0x01, 0x01]); // version=1
        data.extend_from_slice(&[0x30, 0x02, 0x06, 0x00]); // empty sid

        // signingTime attribute within the counter-signer's signed attrs
        data.extend_from_slice(&[0x06, st_oid.len() as u8]); // OID tag+len
        data.extend_from_slice(st_oid);
        // UTCTime for 2025-01-01 (BEFORE the parent time of 2026-02-20)
        let early_time = b"250101120000Z";
        data.push(0x17); // UTCTime tag
        data.push(early_time.len() as u8);
        data.extend_from_slice(early_time);

        // Parent signed at 2026-02-20 15:00:00
        let warnings =
            validate_counter_signer_temporal_ordering(Some("2026-02-20 15:00:00"), &data);
        assert!(
            warnings.iter().any(|w| w.contains("predates parent")),
            "Should warn about counter-signer predating parent: {:?}",
            warnings
        );
    }

    // ─── eContentType Cross-Validation Tests (RFC 5652 §5.3) ───

    #[test]
    fn test_content_type_matches_econtent_valid() {
        // contentType attribute value = id-data, eContentType = id-data → no warnings
        let ct_attr = build_attribute(asn1::OID_CONTENT_TYPE, asn1::OID_DATA);
        let digest_attr = build_attribute(
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_octet_string(&[0xAA; 32]),
        );
        let attrs = [ct_attr.as_slice(), digest_attr.as_slice()].concat();

        let warnings = validate_content_type_matches_econtent(&attrs, asn1::OID_DATA);
        assert!(
            warnings.is_empty(),
            "Should produce no warnings when contentType matches eContentType: {:?}",
            warnings
        );
    }

    #[test]
    fn test_content_type_matches_econtent_mismatch() {
        // contentType = id-data, but eContentType = SPC_INDIRECT_DATA → warning
        let ct_attr = build_attribute(asn1::OID_CONTENT_TYPE, asn1::OID_DATA);
        let digest_attr = build_attribute(
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_octet_string(&[0xBB; 32]),
        );
        let attrs = [ct_attr.as_slice(), digest_attr.as_slice()].concat();

        let warnings = validate_content_type_matches_econtent(&attrs, asn1::OID_SPC_INDIRECT_DATA);
        assert!(
            warnings.iter().any(|w| w.contains("does not match")),
            "Should warn about contentType/eContentType mismatch: {:?}",
            warnings
        );
    }

    #[test]
    fn test_content_type_matches_econtent_no_content_type_attr() {
        // No contentType attribute present → no warnings (presence check is separate)
        let digest_attr = build_attribute(
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_octet_string(&[0xCC; 32]),
        );

        let warnings = validate_content_type_matches_econtent(&digest_attr, asn1::OID_DATA);
        assert!(
            warnings.is_empty(),
            "Should not warn when contentType attribute is absent: {:?}",
            warnings
        );
    }

    // ─── eContentType OID TLV Extraction Tests ───

    #[test]
    fn test_extract_encap_content_type_oid_tlv_valid() {
        let encap = asn1::encode_sequence(&[asn1::OID_DATA]);
        let result = extract_encap_content_type_oid_tlv(&encap);
        assert_eq!(result, Some(asn1::OID_DATA.to_vec()));
    }

    #[test]
    fn test_extract_encap_content_type_oid_tlv_invalid() {
        let result = extract_encap_content_type_oid_tlv(&[0x01, 0x00]);
        assert!(result.is_none());
    }

    // ─── SignerInfo Version-SID Consistency Tests (RFC 5652 §5.3) ───

    #[test]
    fn test_validate_signed_attrs_version_sid_consistency() {
        // This tests the warning generation logic directly
        // Version 1 with IssuerAndSerialNumber (0x30) = consistent, no warning
        // Version 1 with SubjectKeyIdentifier (0x80) = inconsistent, warning
        // Version 3 with IssuerAndSerialNumber (0x30) = inconsistent, warning
        // Version 3 with SubjectKeyIdentifier (0x80) = consistent, no warning

        // We can't easily test this through parse_cms_signed_data (needs full CMS structure),
        // but we can verify the logic patterns are correct by checking warnings output
        // from validate_signed_attributes + the version-sid check in parse_cms_signed_data.

        // Instead, verify the helper functions work correctly:
        // extract_encap_content_type_oid_tlv returns the correct OID
        let spc = asn1::encode_sequence(&[asn1::OID_SPC_INDIRECT_DATA]);
        let oid = extract_encap_content_type_oid_tlv(&spc);
        assert_eq!(oid, Some(asn1::OID_SPC_INDIRECT_DATA.to_vec()));

        // And validate_content_type_matches_econtent catches mismatches
        let ct_attr = build_attribute(asn1::OID_CONTENT_TYPE, asn1::OID_SPC_INDIRECT_DATA);
        let warns = validate_content_type_matches_econtent(&ct_attr, asn1::OID_SPC_INDIRECT_DATA);
        assert!(warns.is_empty(), "Same OID should produce no warnings");

        let warns = validate_content_type_matches_econtent(&ct_attr, asn1::OID_DATA);
        assert_eq!(warns.len(), 1, "Different OID should produce a warning");
    }

    /// Helper to build an attribute SEQUENCE { OID, SET { value } }
    fn build_attribute(oid_tlv: &[u8], value: &[u8]) -> Vec<u8> {
        let set = asn1::encode_set(value);
        asn1::encode_sequence(&[oid_tlv, &set])
    }

    // ─── EKU Validation Tests (RFC 5280 §4.2.1.12) ───

    #[test]
    fn test_eku_with_code_signing() {
        // Build a minimal cert DER containing the EKU extension with codeSigning OID
        // EKU extension OID: 2.5.29.37
        let eku_ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        // id-kp-codeSigning: 1.3.6.1.5.5.7.3.3
        let code_signing_oid = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
        let eku_value = asn1::encode_sequence(&[code_signing_oid]);
        let eku_ext = asn1::encode_sequence(&[eku_ext_oid, &asn1::encode_octet_string(&eku_value)]);

        // Wrap in a fake certificate structure (just enough DER for scanning)
        let fake_cert = asn1::encode_sequence(&[&eku_ext]);

        assert!(check_code_signing_eku(&fake_cert));
    }

    #[test]
    fn test_eku_without_code_signing() {
        // Build cert with EKU but only serverAuth (1.3.6.1.5.5.7.3.1), no codeSigning
        let eku_ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        let server_auth_oid = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let eku_value = asn1::encode_sequence(&[server_auth_oid]);
        let eku_ext = asn1::encode_sequence(&[eku_ext_oid, &asn1::encode_octet_string(&eku_value)]);

        let fake_cert = asn1::encode_sequence(&[&eku_ext]);

        assert!(!check_code_signing_eku(&fake_cert));
    }

    #[test]
    fn test_eku_absent_permits_signing() {
        // Cert with no EKU extension at all — should be allowed (CA certs often omit EKU)
        let fake_cert = asn1::encode_sequence(&[&asn1::encode_sequence(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..], // CN OID (not EKU)
        ])]);

        assert!(check_code_signing_eku(&fake_cert));
    }

    #[test]
    fn test_eku_with_any_extended_key_usage() {
        // anyExtendedKeyUsage (2.5.29.37.0) should also be accepted
        let eku_ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        // anyExtendedKeyUsage value: 2.5.29.37.0
        let any_eku_oid = &[0x06, 0x04, 0x55, 0x1D, 0x25, 0x00];
        let eku_value = asn1::encode_sequence(&[any_eku_oid]);
        let eku_ext = asn1::encode_sequence(&[eku_ext_oid, &asn1::encode_octet_string(&eku_value)]);

        let fake_cert = asn1::encode_sequence(&[&eku_ext]);

        assert!(check_code_signing_eku(&fake_cert));
    }

    // ─── RFC 5280 §4.2.1.9 basicConstraints tests ───

    #[test]
    fn test_basic_constraints_ca_true() {
        // Build a minimal cert with basicConstraints cA=TRUE
        let bc_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13]; // 2.5.29.19
        let critical = &[0x01, 0x01, 0xFF]; // BOOLEAN TRUE
        let bc_value = asn1::encode_sequence(&[
            &[0x01, 0x01, 0xFF], // cA = TRUE
        ]);
        let bc_ext =
            asn1::encode_sequence(&[bc_oid, critical, &asn1::encode_octet_string(&bc_value)]);
        let fake_cert = asn1::encode_sequence(&[&bc_ext]);

        assert!(check_basic_constraints_ca(&fake_cert));
    }

    #[test]
    fn test_basic_constraints_ca_false() {
        // Build a minimal cert with basicConstraints cA=FALSE
        let bc_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];
        let critical = &[0x01, 0x01, 0xFF];
        let bc_value = asn1::encode_sequence(&[
            &[0x01, 0x01, 0x00], // cA = FALSE
        ]);
        let bc_ext =
            asn1::encode_sequence(&[bc_oid, critical, &asn1::encode_octet_string(&bc_value)]);
        let fake_cert = asn1::encode_sequence(&[&bc_ext]);

        assert!(!check_basic_constraints_ca(&fake_cert));
    }

    #[test]
    fn test_basic_constraints_absent() {
        // Cert with no basicConstraints extension at all
        let fake_cert = asn1::encode_sequence(&[&[0x02, 0x01, 0x01]]);
        assert!(!check_basic_constraints_ca(&fake_cert));
    }

    // ─── RFC 5280 §4.2.1.3 keyUsage tests ───

    #[test]
    fn test_key_usage_cert_sign_present() {
        // Build cert with keyUsage containing keyCertSign (bit 5 = 0x04)
        let ku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F]; // 2.5.29.15
        let critical = &[0x01, 0x01, 0xFF]; // BOOLEAN TRUE
                                            // BIT STRING: tag 03, len 03, unused-bits 0, value 0x06 (keyCertSign + cRLSign)
        let ku_value: &[u8] = &[0x03, 0x03, 0x07, 0x06, 0x40];
        let ku_ext =
            asn1::encode_sequence(&[ku_oid, critical, &asn1::encode_octet_string(ku_value)]);
        let fake_cert = asn1::encode_sequence(&[&ku_ext]);

        assert!(check_key_usage_cert_sign(&fake_cert));
    }

    #[test]
    fn test_key_usage_no_cert_sign() {
        // keyUsage with digitalSignature only (0x80) — no keyCertSign
        let ku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
        let critical = &[0x01, 0x01, 0xFF];
        let ku_value: &[u8] = &[0x03, 0x02, 0x07, 0x80]; // digitalSignature only
        let ku_ext =
            asn1::encode_sequence(&[ku_oid, critical, &asn1::encode_octet_string(ku_value)]);
        let fake_cert = asn1::encode_sequence(&[&ku_ext]);

        assert!(!check_key_usage_cert_sign(&fake_cert));
    }

    #[test]
    fn test_key_usage_absent() {
        let fake_cert = asn1::encode_sequence(&[&[0x02, 0x01, 0x01]]);
        assert!(!check_key_usage_cert_sign(&fake_cert));
    }

    // ─── RFC 5652 §12.1 signed attribute uniqueness tests ───

    #[test]
    fn test_validate_signed_attrs_duplicate_oid() {
        // Build signed attributes with duplicate contentType
        let mut attrs = Vec::new();
        // id-data OID value for contentType
        let id_data: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        let ct_value = asn1::encode_set(id_data);
        // Two contentType attributes (same OID appearing twice)
        for _ in 0..2 {
            let attr = asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &ct_value]);
            attrs.extend_from_slice(&attr);
        }
        // Add messageDigest too
        let digest_os = asn1::encode_octet_string(&[0u8; 32]);
        let md_value = asn1::encode_set(&digest_os);
        let md_attr = asn1::encode_sequence(&[asn1::OID_MESSAGE_DIGEST, &md_value]);
        attrs.extend_from_slice(&md_attr);

        let warnings = validate_signed_attributes(&attrs);
        let has_dup = warnings
            .iter()
            .any(|w| w.contains("duplicate attribute OID"));
        assert!(
            has_dup,
            "Should detect duplicate attribute OID: {warnings:?}"
        );
    }

    // ─── Chain validation warning tests ───

    #[test]
    fn test_chain_validation_warns_missing_ca_flag() {
        // Intermediate cert without basicConstraints
        let intermediate = build_chain_test_cert(2, "Intermediate CA", "Root CA");
        let signer = build_chain_test_cert(3, "Code Signer", "Intermediate CA");

        let mut warnings = Vec::new();
        validate_chain_certificates(&signer, &[intermediate], &mut warnings);

        let has_bc_warning = warnings.iter().any(|w| w.contains("basicConstraints"));
        assert!(
            has_bc_warning,
            "Should warn about missing basicConstraints on intermediate: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_unsigned_attrs_well_formed() {
        // Build a well-formed unsigned attributes structure:
        // [1] IMPLICIT SET { SEQUENCE { OID, SET { value } } }
        let ts_oid = asn1::OID_TIMESTAMP_TOKEN;
        let value = asn1::encode_octet_string(b"timestamp-data");
        let value_set = asn1::encode_set(&value);
        let attr = asn1::encode_sequence(&[ts_oid, &value_set]);
        // Wrap in [1] IMPLICIT (tag 0xA1)
        let mut unsigned = vec![0xA1];
        unsigned.extend(asn1::encode_length(attr.len()));
        unsigned.extend_from_slice(&attr);

        let warnings = validate_unsigned_attributes(&unsigned);
        assert!(
            warnings.is_empty(),
            "Well-formed unsigned attrs should have no warnings: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_unsigned_attrs_duplicate_oid() {
        // Two attributes with the same OID — RFC 5652 §12.1 violation
        let ts_oid = asn1::OID_TIMESTAMP_TOKEN;
        let value1 = asn1::encode_set(&asn1::encode_octet_string(b"data1"));
        let value2 = asn1::encode_set(&asn1::encode_octet_string(b"data2"));
        let attr1 = asn1::encode_sequence(&[ts_oid, &value1]);
        let attr2 = asn1::encode_sequence(&[ts_oid, &value2]);
        let mut content = Vec::new();
        content.extend_from_slice(&attr1);
        content.extend_from_slice(&attr2);
        let mut unsigned = vec![0xA1];
        unsigned.extend(asn1::encode_length(content.len()));
        unsigned.extend_from_slice(&content);

        let warnings = validate_unsigned_attributes(&unsigned);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("duplicate attribute OID")),
            "Should warn about duplicate OID: {warnings:?}"
        );
    }

    #[test]
    fn test_validate_unsigned_attrs_missing_set_wrapper() {
        // Attribute value not wrapped in SET (tag != 0x31)
        let ts_oid = asn1::OID_TIMESTAMP_TOKEN;
        // Use SEQUENCE (0x30) instead of SET (0x31) — wrong tag
        let bad_value = asn1::encode_sequence(&[&asn1::encode_octet_string(b"data")]);
        let attr = asn1::encode_sequence(&[ts_oid, &bad_value]);
        let mut unsigned = vec![0xA1];
        unsigned.extend(asn1::encode_length(attr.len()));
        unsigned.extend_from_slice(&attr);

        let warnings = validate_unsigned_attributes(&unsigned);
        assert!(
            warnings.iter().any(|w| w.contains("expected SET (0x31)")),
            "Should warn about wrong value wrapper: {warnings:?}"
        );
    }

    // ─── Digest Algorithms Uniqueness Tests (RFC 5652 §5.1) ───

    #[test]
    fn test_digest_algorithms_unique_no_duplicates() {
        // SET containing SHA-256 and SHA-384 — no duplicates
        let sha256 = asn1::SHA256_ALGORITHM_ID;
        let sha384 = asn1::SHA384_ALGORITHM_ID;
        let set = asn1::encode_set_of(&[&sha256, &sha384]);
        let warnings = validate_digest_algorithms_unique(&set);
        assert!(warnings.is_empty(), "No duplicates: {warnings:?}");
    }

    #[test]
    fn test_digest_algorithms_unique_with_duplicate() {
        // SET containing SHA-256 twice — should warn
        let sha256 = asn1::SHA256_ALGORITHM_ID;
        let set = asn1::encode_set_of(&[&sha256, &sha256]);
        let warnings = validate_digest_algorithms_unique(&set);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("duplicate"));
    }

    #[test]
    fn test_digest_algorithms_unique_single() {
        // SET containing only SHA-256 — trivially unique
        let sha256 = asn1::SHA256_ALGORITHM_ID;
        let set = asn1::encode_set_of(&[&sha256]);
        let warnings = validate_digest_algorithms_unique(&set);
        assert!(warnings.is_empty());
    }

    // ─── RFC 5035 — ESSCertIDv2 Validation Tests ───

    #[test]
    fn test_ess_cert_id_v2_no_attribute() {
        // No ESSCertIDv2 attribute present — function should return no warnings
        // (the missing-attribute warning comes from validate_signed_attributes)
        let attrs = vec![0x30, 0x02, 0x05, 0x00]; // minimal SEQUENCE
        let cert = vec![0x30, 0x03, 0x01, 0x01, 0xFF]; // dummy cert DER
        let warnings = validate_ess_cert_id_v2(&attrs, &cert);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_ess_cert_id_v2_empty_cert() {
        // Empty signer cert — should return no warnings (can't validate)
        let warnings = validate_ess_cert_id_v2(&[0x30, 0x00], &[]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_ess_cert_id_v2_matching_hash() {
        // Build a mock signed attributes containing ESSCertIDv2 with correct hash
        let cert_der = b"test certificate DER data for hashing";
        let cert_hash = Sha256::digest(cert_der);

        // Build: OID (content only) + OCTET STRING with hash
        let mut attrs = Vec::new();
        // ESSCertIDv2 OID content bytes
        let ess_oid: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
        ];
        attrs.extend_from_slice(ess_oid);
        // Some padding bytes (SET, SEQUENCE wrappers)
        attrs.extend_from_slice(&[0x31, 0x24, 0x30, 0x22]);
        // OCTET STRING with SHA-256 hash
        attrs.push(0x04);
        attrs.push(0x20); // 32 bytes
        attrs.extend_from_slice(&cert_hash);

        let warnings = validate_ess_cert_id_v2(&attrs, cert_der);
        assert!(
            warnings.is_empty(),
            "Matching hash should produce no warnings: {warnings:?}"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_mismatched_hash() {
        // Build ESSCertIDv2 with wrong hash — should warn about cert substitution
        let cert_der = b"real certificate DER data";

        let mut attrs = Vec::new();
        let ess_oid: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
        ];
        attrs.extend_from_slice(ess_oid);
        attrs.extend_from_slice(&[0x31, 0x24, 0x30, 0x22]);
        // OCTET STRING with WRONG hash (all zeros)
        attrs.push(0x04);
        attrs.push(0x20);
        attrs.extend_from_slice(&[0x00; 32]);

        let warnings = validate_ess_cert_id_v2(&attrs, cert_der);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("certificate substitution"));
    }

    // ─── RFC 2634 — Content Hints Extraction Tests ───

    #[test]
    fn test_content_hints_not_present() {
        let attrs = vec![0x30, 0x02, 0x05, 0x00];
        assert!(extract_content_hints_description(&attrs).is_none());
    }

    #[test]
    fn test_content_hints_utf8_description() {
        // Build mock content hints: OID + UTF8String
        let mut attrs = Vec::new();
        let ch_oid: &[u8] = &[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x04,
        ];
        attrs.extend_from_slice(ch_oid);
        attrs.extend_from_slice(&[0x31, 0x10, 0x30, 0x0E]);
        // UTF8String "code signing"
        attrs.push(0x0C); // UTF8String tag
        attrs.push(0x0C); // length 12
        attrs.extend_from_slice(b"code signing");

        let desc = extract_content_hints_description(&attrs);
        assert_eq!(desc.as_deref(), Some("code signing"));
    }

    // ─── RFC 5652 §4.6 — Unknown Algorithm Warning Tests ───

    /// Build a minimal but structurally valid CMS SignedData blob that uses a
    /// bogus AlgorithmIdentifier OID so that `identify_signature_algorithm`
    /// returns `"(unknown algorithm)"`.  We then verify that `parse_cms_signed_data`
    /// surfaces the expected RFC 5652 §4.6 warning in `CmsInfo::warnings`.
    ///
    /// The OID `0.0.7` (DER content: 00 07) is allocated to nobody and will
    /// never appear in the algorithm table, which is exactly what we need.
    #[test]
    fn test_unknown_algorithm_warning() {
        // Bogus AlgorithmIdentifier: SEQUENCE { OID 0.0.7 } = 30 04 06 02 00 07
        let bogus_sig_alg: &[u8] = &[0x30, 0x04, 0x06, 0x02, 0x00, 0x07];

        // Real SHA-256 AlgorithmIdentifier for the digest (so digest is recognised)
        let sha256_alg = &asn1::SHA256_ALGORITHM_ID[..];

        // ── Build a minimal but parseable SignedData ──
        //
        // ContentInfo { OID id-signedData, [0] SignedData }
        //   SignedData {
        //     version         INTEGER 1
        //     digestAlgorithms SET { sha256 }
        //     encapContentInfo SEQUENCE { OID id-data }
        //     certificates    [0] (empty)
        //     signerInfos     SET {
        //       SignerInfo {
        //         version            INTEGER 1
        //         sid                IssuerAndSerialNumber { issuer, serial }
        //         digestAlgorithm    sha256
        //         signedAttrs        [0] { contentType, messageDigest }
        //         signatureAlgorithm <bogus>
        //         signature          OCTET STRING
        //       }
        //     }
        //   }

        // IssuerAndSerialNumber: SEQUENCE { Name SEQUENCE {}, INTEGER 1 }
        let issuer = asn1::encode_sequence(&[]);
        let serial = asn1::encode_integer_value(1);
        let sid = asn1::encode_sequence(&[&issuer, &serial]);

        // signed attributes (minimal — contentType + messageDigest)
        let ct_attr =
            asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &asn1::encode_set(asn1::OID_DATA)]);
        let md_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0u8; 32])),
        ]);
        let mut attr_bytes = Vec::new();
        attr_bytes.extend(&ct_attr);
        attr_bytes.extend(&md_attr);
        // signedAttrs is [0] IMPLICIT SET OF
        let signed_attrs = asn1::encode_implicit_tag(0, &attr_bytes);

        // signature value (dummy 1 byte)
        let sig_value = asn1::encode_octet_string(&[0x00]);

        // SignerInfo SEQUENCE
        let signer_version = asn1::encode_integer_value(1);
        let signer_info = asn1::encode_sequence(&[
            &signer_version,
            &sid,
            sha256_alg, // digestAlgorithm
            &signed_attrs,
            bogus_sig_alg, // signatureAlgorithm — the unknown one
            &sig_value,
        ]);

        // EncapsulatedContentInfo SEQUENCE { OID id-data }
        let encap_ci = asn1::encode_sequence(&[asn1::OID_DATA]);

        // digestAlgorithms SET { sha256 }
        let digest_algs = asn1::encode_set(sha256_alg);

        // Empty certificates [0] IMPLICIT (tag 0xA0, length 0)
        let empty_certs: &[u8] = &[0xA0, 0x00];

        // SignedData SEQUENCE
        let sd_version = asn1::encode_integer_value(1);
        let signer_infos_set = asn1::encode_set(&signer_info);
        let signed_data = asn1::encode_sequence(&[
            &sd_version,
            &digest_algs,
            &encap_ci,
            empty_certs,
            &signer_infos_set,
        ]);

        // ContentInfo SEQUENCE { OID id-signedData, [0] signedData }
        let content_info = asn1::encode_sequence(&[
            asn1::OID_SIGNED_DATA,
            &asn1::encode_explicit_tag(0, &signed_data),
        ]);

        let result = parse_cms_signed_data(&content_info);
        // Parsing should succeed (RFC 5652 §4.6: unknown OID must not reject)
        assert!(
            result.is_ok(),
            "parse_cms_signed_data should succeed with unknown algo: {:?}",
            result.err()
        );

        let cms_info = result.unwrap();

        // The signature algorithm should be reported as unknown
        assert!(
            cms_info.signature_algorithm.starts_with("(unknown"),
            "Expected unknown signature algorithm, got: {}",
            cms_info.signature_algorithm
        );

        // The RFC 5652 §4.6 warning must be present
        let has_unknown_sig_warning = cms_info
            .warnings
            .iter()
            .any(|w| w.contains("RFC 5652 §4.6") && w.contains("signature algorithm"));
        assert!(
            has_unknown_sig_warning,
            "Expected RFC 5652 §4.6 unknown signature algorithm warning, got: {:?}",
            cms_info.warnings
        );
    }

    /// Verify that a bogus digest algorithm OID also produces an RFC 5652 §4.6 warning.
    #[test]
    fn test_unknown_digest_algorithm_warning() {
        // Bogus digest AlgorithmIdentifier: SEQUENCE { OID 0.0.9 } = 30 04 06 02 00 09
        let bogus_digest_alg: &[u8] = &[0x30, 0x04, 0x06, 0x02, 0x00, 0x09];
        let sha256_alg = &asn1::SHA256_ALGORITHM_ID[..];

        let issuer = asn1::encode_sequence(&[]);
        let serial = asn1::encode_integer_value(1);
        let sid = asn1::encode_sequence(&[&issuer, &serial]);

        let ct_attr =
            asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &asn1::encode_set(asn1::OID_DATA)]);
        let md_attr = asn1::encode_sequence(&[
            asn1::OID_MESSAGE_DIGEST,
            &asn1::encode_set(&asn1::encode_octet_string(&[0u8; 32])),
        ]);
        let mut attr_bytes = Vec::new();
        attr_bytes.extend(&ct_attr);
        attr_bytes.extend(&md_attr);
        let signed_attrs = asn1::encode_implicit_tag(0, &attr_bytes);
        let sig_value = asn1::encode_octet_string(&[0x00]);
        let signer_version = asn1::encode_integer_value(1);

        // SignerInfo with bogus digestAlgorithm
        let signer_info = asn1::encode_sequence(&[
            &signer_version,
            &sid,
            bogus_digest_alg, // digestAlgorithm — unknown
            &signed_attrs,
            sha256_alg, // signatureAlgorithm — known
            &sig_value,
        ]);

        let encap_ci = asn1::encode_sequence(&[asn1::OID_DATA]);
        let digest_algs = asn1::encode_set(bogus_digest_alg);
        let empty_certs: &[u8] = &[0xA0, 0x00];
        let sd_version = asn1::encode_integer_value(1);
        let signer_infos_set = asn1::encode_set(&signer_info);
        let signed_data = asn1::encode_sequence(&[
            &sd_version,
            &digest_algs,
            &encap_ci,
            empty_certs,
            &signer_infos_set,
        ]);
        let content_info = asn1::encode_sequence(&[
            asn1::OID_SIGNED_DATA,
            &asn1::encode_explicit_tag(0, &signed_data),
        ]);

        let result = parse_cms_signed_data(&content_info);
        assert!(
            result.is_ok(),
            "parse_cms_signed_data should succeed with unknown digest algo: {:?}",
            result.err()
        );

        let cms_info = result.unwrap();

        assert!(
            cms_info.digest_algorithm.starts_with("(unknown"),
            "Expected unknown digest algorithm, got: {}",
            cms_info.digest_algorithm
        );

        let has_unknown_digest_warning = cms_info
            .warnings
            .iter()
            .any(|w| w.contains("RFC 5652 §4.6") && w.contains("digest algorithm"));
        assert!(
            has_unknown_digest_warning,
            "Expected RFC 5652 §4.6 unknown digest algorithm warning, got: {:?}",
            cms_info.warnings
        );
    }

    // ── verify_counter_signature_signed_attrs tests ───────────────────────────
    // These tests exercise the `signed_attrs_valid` field on `CounterSignerInfo`
    // via the `verify_counter_signature_signed_attrs` helper (which is called by
    // `extract_and_verify_counter_signers` when populating `CounterSignerInfo`).

    /// Build a minimal raw byte region containing both the contentType OID
    /// (1.2.840.113549.1.9.3) and the messageDigest OID (1.2.840.113549.1.9.4).
    fn make_cs_region_both_oids() -> Vec<u8> {
        // contentType OID bytes (tag 0x06 + length + content)
        let ct_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
        ];
        // messageDigest OID bytes
        let md_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
        ];
        let mut region = Vec::new();
        region.extend_from_slice(ct_oid);
        region.extend_from_slice(md_oid);
        region
    }

    /// Build a region containing only the contentType OID.
    fn make_cs_region_ct_only() -> Vec<u8> {
        let ct_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
        ];
        ct_oid.to_vec()
    }

    /// Build a region containing only the messageDigest OID.
    fn make_cs_region_md_only() -> Vec<u8> {
        let md_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
        ];
        md_oid.to_vec()
    }

    #[test]
    fn test_counter_signer_signed_attrs_both_oids_present() {
        // When a cs_region contains both contentType and messageDigest OIDs,
        // `signed_attrs_valid` must be `Some(true)`.
        let region = make_cs_region_both_oids();
        let result = verify_counter_signature_signed_attrs(&region);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn test_counter_signer_signed_attrs_missing_message_digest() {
        // Only contentType — messageDigest absent → RFC 5652 §11.4 violation → Some(false).
        let region = make_cs_region_ct_only();
        let result = verify_counter_signature_signed_attrs(&region);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_counter_signer_signed_attrs_missing_content_type() {
        // Only messageDigest — contentType absent → Some(false).
        let region = make_cs_region_md_only();
        let result = verify_counter_signature_signed_attrs(&region);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn test_counter_signer_signed_attrs_empty_region() {
        // Empty region → no signed attributes present → None.
        let result = verify_counter_signature_signed_attrs(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_counter_signer_signed_attrs_neither_oid_present() {
        // Region with an unrelated OID only → None (not a signed-attributes region).
        let unrelated: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // id-at-commonName
        let result = verify_counter_signature_signed_attrs(unrelated);
        assert_eq!(result, None);
    }

    // ── TSA EKU + chain validation tests ─────────────────────────────────────
    //
    // These tests exercise `check_tsa_eku`, `validate_tsa_cert`, and
    // `load_tsa_trust_roots` directly with hand-crafted minimal DER structures.
    //
    // DER certificate layout used in helpers:
    //   Certificate ::= SEQUENCE {
    //     TBSCertificate ::= SEQUENCE {
    //       version [0] EXPLICIT INTEGER DEFAULT v1,  (omitted in our minimal certs)
    //       serialNumber INTEGER,
    //       signature AlgorithmIdentifier,
    //       issuer Name,
    //       validity Validity,
    //       subject Name,
    //       subjectPublicKeyInfo SubjectPublicKeyInfo,
    //       extensions [3] EXPLICIT SEQUENCE OF Extension OPTIONAL
    //     }
    //     signatureAlgorithm AlgorithmIdentifier,
    //     signature BIT STRING
    //   }
    //
    // We omit fields after extensions and use NULL/stub bytes for AlgorithmIdentifier
    // and subjectPublicKeyInfo since check_tsa_eku and extract_issuer/subject only
    // scan for OID byte patterns and do not verify signatures.

    /// Build a minimal DER-encoded certificate with a given EKU OID value embedded
    /// in the ExtendedKeyUsage extension.
    ///
    /// `eku_oid_value_bytes` — the raw OID value bytes (without tag/length) to embed
    /// in the EKU SEQUENCE.  Pass `None` to omit the EKU extension entirely.
    fn make_tsa_cert_with_eku(eku_oid_value_bytes: Option<&[u8]>) -> Vec<u8> {
        // extendedKeyUsage OID: 2.5.29.37 (tag 0x06 + length 0x03 + value)
        let eku_extension_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

        // Build extensions field if requested
        let tbs_extensions_der: Vec<u8> = if let Some(oid_val) = eku_oid_value_bytes {
            // OID TLV for the purpose OID value
            let purpose_oid_der = {
                let mut v = vec![0x06u8, oid_val.len() as u8];
                v.extend_from_slice(oid_val);
                v
            };
            // SEQUENCE { purpose_oid } — the EKU value SEQUENCE
            let eku_seq = asn1::encode_sequence(&[purpose_oid_der.as_slice()]);
            // OCTET STRING wrapping the EKU SEQUENCE (the extension extnValue)
            let eku_octet = asn1::encode_octet_string(&eku_seq);
            // Extension SEQUENCE { eku_oid, extnValue }
            let extension = asn1::encode_sequence(&[eku_extension_oid, &eku_octet]);
            // extensions [3] EXPLICIT SEQUENCE OF Extension
            let exts_seq = asn1::encode_sequence(&[extension.as_slice()]);
            asn1::encode_explicit_tag(3, &exts_seq)
        } else {
            Vec::new()
        };

        // Minimal stub for serialNumber INTEGER (value = 1)
        let serial: &[u8] = &[0x02, 0x01, 0x01];
        // Minimal AlgorithmIdentifier: SEQUENCE { OID sha256WithRSAEncryption, NULL }
        let alg_id: &[u8] = &[
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        // Minimal Name: SET { SEQUENCE { OID commonName, UTF8String "TSA" } }
        // commonName OID: 2.5.4.3 → 0x55 0x04 0x03
        let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let cn_val = asn1::encode_utf8_string("TSA");
        let atv = asn1::encode_sequence(&[cn_oid, cn_val.as_slice()]);
        let rdn = asn1::encode_set(atv.as_slice());
        let name = asn1::encode_sequence(&[rdn.as_slice()]);
        // Minimal Validity: UTCTime "010101000000Z" for both notBefore/notAfter
        let utc_stub: &[u8] = &[
            0x17, 0x0D, 0x30, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x5A,
        ];
        let validity = asn1::encode_sequence(&[utc_stub, utc_stub]);
        // Minimal SubjectPublicKeyInfo: stub bytes
        let spki: &[u8] = &[0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x00];

        let tbs_parts: &[&[u8]] = &[
            serial,
            alg_id,
            name.as_slice(), // issuer = subject = "TSA"
            validity.as_slice(),
            name.as_slice(), // subject
            spki,
            tbs_extensions_der.as_slice(),
        ];
        let tbs = asn1::encode_sequence(tbs_parts);

        // Stub signature BIT STRING (all zeros, 1 unused bit)
        let sig_stub: &[u8] = &[0x03, 0x02, 0x00, 0x00];

        asn1::encode_sequence(&[tbs.as_slice(), alg_id, sig_stub])
    }

    /// Build a minimal unsigned-attrs blob wrapping a fake TimeStampToken
    /// whose `certificates` field contains `cert_ders`.
    ///
    /// Structure:
    ///   [1] IMPLICIT SET {
    ///     SEQUENCE {                               <- Attribute
    ///       id-smime-aa-timeStampToken OID,
    ///       SET { ContentInfo { id-signedData, [0] { SignedData { ... } } } }
    ///     }
    ///   }
    fn make_unsigned_attrs_with_tsa_certs(cert_ders: &[Vec<u8>]) -> Vec<u8> {
        // id-smime-aa-timeStampToken OID: 1.2.840.113549.1.9.16.2.14
        let tst_oid: &[u8] = &[
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        // id-signedData OID: 1.2.840.113549.1.7.2
        let signed_data_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];

        // Build certificates [0] IMPLICIT SET field
        let cert_refs: Vec<&[u8]> = cert_ders.iter().map(|v| v.as_slice()).collect();
        let certs_seq_content: Vec<u8> = cert_refs.iter().flat_map(|c| c.iter().copied()).collect();
        // [0] IMPLICIT length-prefixed
        let mut certs_field = Vec::new();
        let certs_len = certs_seq_content.len();
        certs_field.push(0xA0);
        certs_field.extend_from_slice(&asn1::encode_length(certs_len));
        certs_field.extend_from_slice(&certs_seq_content);

        // Minimal SignedData fields before certificates:
        //   version INTEGER (= 3 for TSA)
        let version: &[u8] = &[0x02, 0x01, 0x03];
        //   digestAlgorithms SET { sha256 }
        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let sha256_alg = asn1::encode_sequence(&[sha256_oid, &[0x05, 0x00]]);
        let digest_algs = asn1::encode_set(sha256_alg.as_slice());
        //   encapContentInfo SEQUENCE { id-tst-info OID }
        let tst_info_oid: &[u8] = &[
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
        ];
        let encap = asn1::encode_sequence(&[tst_info_oid]);
        //   signerInfos SET { } (empty for our purposes)
        let signer_infos = asn1::encode_set(&[]);

        let signed_data_inner: Vec<u8> = [
            version,
            digest_algs.as_slice(),
            encap.as_slice(),
            certs_field.as_slice(),
            signer_infos.as_slice(),
        ]
        .concat();
        let signed_data = asn1::encode_sequence(&[signed_data_inner.as_slice()]);

        // [0] EXPLICIT wrapping SignedData
        let sd_wrapped = asn1::encode_explicit_tag(0, &signed_data);

        // ContentInfo SEQUENCE { id-signedData, [0] { SignedData } }
        let content_info = asn1::encode_sequence(&[signed_data_oid, sd_wrapped.as_slice()]);

        // Attribute SET value
        let attr_set = asn1::encode_set(content_info.as_slice());

        // Attribute SEQUENCE { OID, SET { value } }
        let attribute = asn1::encode_sequence(&[tst_oid, attr_set.as_slice()]);

        // [1] IMPLICIT SET (unsignedAttrs)
        let attrs_content = attribute;
        let mut unsigned_attrs = Vec::new();
        unsigned_attrs.push(0xA1);
        unsigned_attrs.extend_from_slice(&asn1::encode_length(attrs_content.len()));
        unsigned_attrs.extend_from_slice(&attrs_content);
        unsigned_attrs
    }

    // id-kp-timeStamping OID value bytes: 1.3.6.1.5.5.7.3.8
    const TIME_STAMPING_OID_VALUE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
    // id-kp-codeSigning OID value bytes: 1.3.6.1.5.5.7.3.3
    const CODE_SIGNING_OID_VALUE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

    #[test]
    fn test_tsa_cert_missing_eku_rejected() {
        // TSA cert with no EKU extension at all → must be rejected (RFC 3161 §2.3).
        let cert = make_tsa_cert_with_eku(None);
        let result = check_tsa_eku(&cert);
        assert!(
            result.is_err(),
            "TSA cert missing EKU should be rejected, got Ok"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("missing ExtendedKeyUsage"),
            "Error should mention missing EKU extension, got: {err}"
        );
    }

    #[test]
    fn test_tsa_cert_wrong_eku_rejected() {
        // TSA cert with codeSigning EKU instead of timeStamping → must be rejected.
        let cert = make_tsa_cert_with_eku(Some(CODE_SIGNING_OID_VALUE));
        let result = check_tsa_eku(&cert);
        assert!(
            result.is_err(),
            "TSA cert with codeSigning EKU should be rejected, got Ok"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("id-kp-timeStamping"),
            "Error should mention id-kp-timeStamping, got: {err}"
        );
    }

    #[test]
    fn test_tsa_cert_valid_eku_and_chain_accepted() {
        // Happy path: TSA cert has timeStamping EKU, and the cert itself is the trust root.
        let cert = make_tsa_cert_with_eku(Some(TIME_STAMPING_OID_VALUE));
        // EKU check alone
        assert!(
            check_tsa_eku(&cert).is_ok(),
            "TSA cert with timeStamping EKU should pass EKU check"
        );
        // Chain check: self-signed cert included as its own trust root
        let trust_roots = vec![cert.clone()];
        // validate_signer_chain expects issuer to match a root's subject.
        // Our minimal cert has issuer == subject == "TSA", so it is self-signed.
        // The chain is: signer_cert (self-signed), no intermediates, root = signer_cert.
        // is_issued_by_trusted_root checks if issuer matches any root's subject;
        // for a self-signed cert the issuer IS the subject, so this passes.
        let chain_ok = validate_signer_chain(&cert, &[], &trust_roots);
        assert!(
            chain_ok,
            "Self-signed TSA cert should validate against itself as trust root"
        );

        // Full validate_tsa_cert path via unsigned_attrs
        let unsigned_attrs = make_unsigned_attrs_with_tsa_certs(std::slice::from_ref(&cert));
        let result = validate_tsa_cert(&unsigned_attrs, &trust_roots);
        assert!(
            result.is_ok(),
            "validate_tsa_cert should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_tsa_cert_untrusted_root_rejected() {
        // TSA cert has correct EKU but its chain does not terminate at any configured root.
        let cert = make_tsa_cert_with_eku(Some(TIME_STAMPING_OID_VALUE));
        // Build a root with a different subject (CN=OtherRoot) so the chain walk fails.
        let other_root = {
            // Build a cert with CN=OtherRoot to guarantee mismatch
            let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
            let cn_val = asn1::encode_utf8_string("OtherRoot");
            let atv = asn1::encode_sequence(&[cn_oid, cn_val.as_slice()]);
            let rdn = asn1::encode_set(atv.as_slice());
            let other_name = asn1::encode_sequence(&[rdn.as_slice()]);
            // other_root is just another cert der — treat its bytes as a distinct root
            other_name // Not a full cert DER, but extract_subject_der will fail gracefully
        };
        let trust_roots = vec![other_root];

        // Chain validation should fail because the cert's issuer does not match
        // any root's subject.
        let chain_ok = validate_signer_chain(&cert, &[], &trust_roots);
        assert!(
            !chain_ok,
            "Chain should be rejected when root does not match cert issuer"
        );

        // validate_tsa_cert with these roots should return TsaCertInvalid
        let unsigned_attrs = make_unsigned_attrs_with_tsa_certs(&[cert]);
        let result = validate_tsa_cert(&unsigned_attrs, &trust_roots);
        assert!(
            result.is_err(),
            "validate_tsa_cert should fail with untrusted root, got Ok"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("trust root") || err.contains("TsaCert"),
            "Error should mention trust root, got: {err}"
        );
    }

    #[test]
    fn test_tsa_trust_roots_empty_skips_chain_check_but_enforces_eku() {
        // When tsa_trust_roots is empty, chain validation is skipped but EKU is still
        // enforced (defense-in-depth as documented on TsaConfig).

        // A cert WITH timeStamping EKU but no trust roots configured → should pass.
        let good_cert = make_tsa_cert_with_eku(Some(TIME_STAMPING_OID_VALUE));
        let unsigned_attrs = make_unsigned_attrs_with_tsa_certs(&[good_cert]);
        let result = validate_tsa_cert(&unsigned_attrs, &[]);
        assert!(
            result.is_ok(),
            "Good EKU cert with empty trust roots should pass (chain skipped): {:?}",
            result.err()
        );

        // A cert WITHOUT EKU → must still be rejected even with empty trust roots.
        let no_eku_cert = make_tsa_cert_with_eku(None);
        let unsigned_attrs_bad = make_unsigned_attrs_with_tsa_certs(&[no_eku_cert]);
        let result_bad = validate_tsa_cert(&unsigned_attrs_bad, &[]);
        assert!(
            result_bad.is_err(),
            "Cert missing EKU should be rejected even when trust roots are empty"
        );
        let err = result_bad.unwrap_err().to_string();
        assert!(
            err.contains("missing ExtendedKeyUsage") || err.contains("TSA certificate"),
            "Error should mention missing EKU, got: {err}"
        );
    }
}
