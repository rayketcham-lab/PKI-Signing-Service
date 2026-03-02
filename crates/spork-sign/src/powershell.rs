//! PowerShell script signing (.ps1).
//!
//! PowerShell scripts are signed by appending a Base64-encoded PKCS#7
//! signature block at the end of the file:
//!
//! ```text
//! # SIG # Begin signature block
//! # MIIxxxxx...  (Base64 lines, 64 chars wide)
//! # SIG # End signature block
//! ```
//!
//! The hash covers the script content before the signature block,
//! encoded as UTF-8.

use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;
use crate::pkcs7::Pkcs7Builder;
use crate::signer::{SigningCredentials, SigningResult};
use crate::timestamp::TsaConfig;

/// Marker for the start of a PowerShell signature block.
const SIG_BEGIN: &str = "# SIG # Begin signature block";

/// Marker for the end of a PowerShell signature block.
const SIG_END: &str = "# SIG # End signature block";

/// Check if a PowerShell script already has a signature block.
pub fn is_signed(content: &str) -> bool {
    content.contains(SIG_BEGIN)
}

/// Strip an existing signature block from a PowerShell script.
///
/// Returns the script content before the signature markers.
pub fn strip_signature(content: &str) -> &str {
    if let Some(pos) = content.find(SIG_BEGIN) {
        // Trim trailing whitespace/newlines before the signature block
        content[..pos].trim_end_matches(['\r', '\n'])
    } else {
        content
    }
}

/// Build a CMS/PKCS#7 SignedData for PowerShell script content.
///
/// Unlike PE Authenticode which uses SPC_INDIRECT_DATA, PowerShell signing
/// uses standard CMS SignedData with id-data as the content type.
/// The hash covers the UTF-8 script bytes (everything before the sig block).
fn build_ps1_pkcs7(
    script_hash: &[u8],
    credentials: &SigningCredentials,
    timestamp_token: Option<&[u8]>,
) -> SignResult<Vec<u8>> {
    // For PowerShell, we use the same Pkcs7Builder (it builds Authenticode-style)
    // but the content is the script hash rather than a PE image hash.
    let mut builder =
        Pkcs7Builder::new(credentials.signer_cert_der().to_vec(), script_hash.to_vec());

    for chain_cert in credentials.chain_certs_der() {
        builder.add_chain_cert(chain_cert.clone());
    }

    if let Some(token) = timestamp_token {
        builder.set_timestamp_token(token.to_vec());
    }

    builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))
}

/// Format a DER blob as a PowerShell signature block.
///
/// Base64-encodes the DER, splits into 64-character lines,
/// prefixes each with `# `, and wraps in SIG markers.
fn format_signature_block(pkcs7_der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs7_der);

    let mut block = String::new();
    block.push_str("\r\n");
    block.push_str(SIG_BEGIN);
    block.push_str("\r\n");

    // Split into 64-character lines, prefix with "# "
    for chunk in b64.as_bytes().chunks(64) {
        block.push_str("# ");
        block.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        block.push_str("\r\n");
    }

    block.push_str(SIG_END);
    block.push_str("\r\n");

    block
}

/// Sign a PowerShell script.
///
/// Computes SHA-256 of the script content, builds a CMS SignedData,
/// optionally timestamps it, then appends the signature block.
pub async fn sign_ps1(
    data: &[u8],
    output_path: &Path,
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
) -> SignResult<SigningResult> {
    // Strip UTF-8 BOM (0xEF 0xBB 0xBF) if present — Windows editors commonly
    // add BOMs to .ps1 files, and they must be excluded from the hash computation
    // to ensure cross-platform signing consistency.
    let raw = if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &data[3..]
    } else {
        data
    };
    let content = String::from_utf8_lossy(raw);

    // Strip existing signature if present (for re-signing)
    let script_content = if is_signed(&content) {
        strip_signature(&content).to_string()
    } else {
        content.into_owned()
    };

    // Compute original file hash for reporting
    let original_hash = hex::encode(Sha256::digest(data));

    // Hash the script content (UTF-8 bytes)
    let script_hash = Sha256::digest(script_content.as_bytes()).to_vec();

    // Build the PKCS#7 signature
    let mut timestamp_token: Option<Vec<u8>> = None;
    let mut timestamped = false;

    if let Some(tsa) = tsa_config {
        // Build once to get signature bytes for timestamping
        let temp_pkcs7 = build_ps1_pkcs7(&script_hash, credentials, None)?;

        // Extract signature bytes from the PKCS#7 for timestamping
        match crate::signer::extract_signature_from_pkcs7(&temp_pkcs7) {
            Ok(sig_bytes) => match crate::timestamp::request_timestamp(&sig_bytes, tsa).await {
                Ok(token) => {
                    timestamp_token = Some(token);
                    timestamped = true;
                }
                Err(e) => {
                    eprintln!("Warning: timestamping failed: {e}");
                }
            },
            Err(e) => {
                eprintln!("Warning: could not extract signature for timestamping: {e}");
            }
        }
    }

    // Build final PKCS#7 with optional timestamp
    let pkcs7_der = build_ps1_pkcs7(&script_hash, credentials, timestamp_token.as_deref())?;

    // Format the signature block
    let sig_block = format_signature_block(&pkcs7_der);

    // Compose final output: script content + signature block
    let mut signed_content = script_content;
    signed_content.push_str(&sig_block);

    let signed_bytes = signed_content.into_bytes();
    let signed_hash = hex::encode(Sha256::digest(&signed_bytes));

    // Write to output file
    std::fs::write(output_path, &signed_bytes)?;

    Ok(SigningResult {
        signed_data: signed_bytes,
        timestamped,
        original_hash,
        signed_hash,
    })
}

/// Extract the Base64-encoded signature from a signed PowerShell script.
///
/// Returns the decoded DER bytes of the PKCS#7 signature.
pub fn extract_signature(content: &str) -> SignResult<Vec<u8>> {
    let begin_pos = content
        .find(SIG_BEGIN)
        .ok_or_else(|| SignError::PowerShell("No signature block found".into()))?;
    let end_pos = content
        .find(SIG_END)
        .ok_or_else(|| SignError::PowerShell("Incomplete signature block".into()))?;

    let block = &content[begin_pos + SIG_BEGIN.len()..end_pos];

    // Strip "# " prefix from each line and concatenate Base64
    let mut b64 = String::new();
    for line in block.lines() {
        let stripped = line.trim();
        if let Some(data) = stripped.strip_prefix("# ") {
            b64.push_str(data);
        } else if !stripped.is_empty() {
            b64.push_str(stripped);
        }
    }

    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| SignError::PowerShell(format!("Invalid Base64 in signature block: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_signed_detects_block() {
        let signed =
            "Write-Host 'Hello'\n# SIG # Begin signature block\n# abc\n# SIG # End signature block";
        assert!(is_signed(signed));
    }

    #[test]
    fn test_is_signed_unsigned() {
        let unsigned = "Write-Host 'Hello'\n# Just a comment\n";
        assert!(!is_signed(unsigned));
    }

    #[test]
    fn test_strip_signature() {
        let content = "Write-Host 'Hello'\r\n# SIG # Begin signature block\r\n# data\r\n# SIG # End signature block\r\n";
        let stripped = strip_signature(content);
        assert_eq!(stripped, "Write-Host 'Hello'");
    }

    #[test]
    fn test_strip_signature_no_sig() {
        let content = "Write-Host 'Hello'\n";
        assert_eq!(strip_signature(content), content);
    }

    #[test]
    fn test_format_signature_block() {
        // 100 bytes of fake DER data
        let fake_der = vec![0x30; 100];
        let block = format_signature_block(&fake_der);

        assert!(block.contains(SIG_BEGIN));
        assert!(block.contains(SIG_END));

        // Each data line should start with "# "
        for line in block.lines() {
            if line != SIG_BEGIN && line != SIG_END && !line.is_empty() {
                assert!(
                    line.starts_with("# "),
                    "Line doesn't start with '# ': {line}"
                );
            }
        }
    }

    #[test]
    fn test_extract_signature_roundtrip() {
        let original_der = vec![0x30, 0x82, 0x01, 0x00]; // fake DER
                                                         // Pad to make it a reasonable size
        let mut der = original_der.clone();
        der.extend(vec![0xAA; 252]); // total 256 bytes

        let block = format_signature_block(&der);
        let script = format!("Write-Host 'test'\r\n{block}");

        let extracted = extract_signature(&script).unwrap();
        assert_eq!(extracted, der);
    }

    #[test]
    fn test_extract_signature_no_block() {
        let script = "Write-Host 'test'";
        assert!(extract_signature(script).is_err());
    }

    #[test]
    fn test_utf8_bom_stripped_from_signing_input() {
        // Verify that UTF-8 BOM bytes are correctly detected
        let with_bom = b"\xEF\xBB\xBFWrite-Host 'Hello'";
        let without_bom = b"Write-Host 'Hello'";

        assert!(with_bom.starts_with(&[0xEF, 0xBB, 0xBF]));

        // After BOM stripping, content should match
        let stripped = if with_bom.starts_with(&[0xEF, 0xBB, 0xBF]) {
            &with_bom[3..]
        } else {
            &with_bom[..]
        };
        assert_eq!(stripped, without_bom);
    }

    #[test]
    fn test_no_bom_data_unchanged() {
        let data = b"Write-Host 'Hello'";
        let stripped = if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
            &data[3..]
        } else {
            &data[..]
        };
        assert_eq!(stripped, data);
    }
}
