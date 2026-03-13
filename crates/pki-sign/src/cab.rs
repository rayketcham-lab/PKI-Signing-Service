//! CAB (Cabinet) file signing via Authenticode.
//!
//! Cabinet files embed Authenticode signatures in a reserved area within the
//! CFHEADER structure. The CFHEADER has reserved bytes that are used to store
//! the signature.
//!
//! ## CAB Header Structure
//!
//! ```text
//! CFHEADER {
//!     u8[4]  signature       "MSCF" (0x4D, 0x53, 0x43, 0x46)
//!     u32    reserved1       (must be 0)
//!     u32    cbCabinet       total cabinet file size
//!     u32    reserved2       (must be 0)
//!     u32    coffFiles       offset of first CFFILE entry
//!     u32    reserved3       (must be 0)
//!     u8     versionMinor
//!     u8     versionMajor
//!     u16    cFolders
//!     u16    cFiles
//!     u16    flags           bit 2 (0x0004) = cfhdrRESERVE_PRESENT
//!     u16    setID
//!     u16    iCabinet
//!     // if cfhdrRESERVE_PRESENT:
//!     u16    cbCFHeader      per-header reserved bytes
//!     u8     cbCFFolder      per-folder reserved bytes
//!     u8     cbCFData        per-data-block reserved bytes
//!     u8[cbCFHeader] abReserve  per-header reserved data
//! }
//! ```
//!
//! For Authenticode signing, the reserved area uses a specific header:
//! ```text
//! CabinetSignatureReservedHeader {
//!     u32    headerSize      size of this header (must be 20)
//!     u32    sigOffset       offset from start of cabinet to the signature
//!     u32    sigSize         size of the signature
//!     u8[8]  padding         (zeroes)
//! }
//! ```
//!
//! The signature data itself is appended after the cabinet data.
//!
//! ## Authenticode Hash
//!
//! The hash covers the entire cabinet file EXCEPT:
//! - The sigOffset and sigSize fields in the reserved header
//! - The appended signature data

use sha2::{Digest, Sha256};

use crate::error::{SignError, SignResult};
use crate::pkcs7::Pkcs7Builder;
use crate::signer::{SignOptions, SigningCredentials};
use crate::timestamp::TsaConfig;

/// Magic bytes for a cabinet file: "MSCF"
const CAB_MAGIC: &[u8; 4] = b"MSCF";

/// Flag indicating reserved fields are present in the cabinet header.
const CFHDR_RESERVE_PRESENT: u16 = 0x0004;

/// Size of the Authenticode reserved header in the CFHEADER.
const CAB_SIG_RESERVE_HEADER_SIZE: u32 = 20;

/// Size of the fixed CFHEADER fields (before optional reserved area).
const CFHEADER_FIXED_SIZE: usize = 36;

/// Offset of the flags field within CFHEADER.
const FLAGS_OFFSET: usize = 30;

/// Parsed CAB header information needed for signing.
#[derive(Debug)]
struct CabInfo {
    /// Total cabinet file size from header.
    cb_cabinet: u32,
    /// Offset within the reserved header where sigOffset lives.
    sig_offset_pos: usize,
    /// Offset within the reserved header where sigSize lives.
    sig_size_pos: usize,
    /// Size of the per-header reserved area (cbCFHeader).
    cb_cf_header: u16,
    /// End of the cabinet data (before any appended signature).
    end_of_cab: usize,
}

/// Parse a CAB file header and extract signing-relevant information.
fn parse_cab_header(data: &[u8]) -> SignResult<CabInfo> {
    if data.len() < CFHEADER_FIXED_SIZE {
        return Err(SignError::Hash("CAB file too small for header".into()));
    }

    // Verify magic bytes
    if &data[0..4] != CAB_MAGIC {
        return Err(SignError::Hash("Not a valid CAB file (bad magic)".into()));
    }

    let cb_cabinet = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let flags = u16::from_le_bytes([data[FLAGS_OFFSET], data[FLAGS_OFFSET + 1]]);

    if flags & CFHDR_RESERVE_PRESENT != 0 {
        // Reserved area is present — parse cbCFHeader, cbCFFolder, cbCFData
        if data.len() < CFHEADER_FIXED_SIZE + 4 {
            return Err(SignError::Hash(
                "CAB file too small for reserved header fields".into(),
            ));
        }

        let cb_cf_header =
            u16::from_le_bytes([data[CFHEADER_FIXED_SIZE], data[CFHEADER_FIXED_SIZE + 1]]);

        // The reserved header data starts at CFHEADER_FIXED_SIZE + 4
        // (after cbCFHeader u16, cbCFFolder u8, cbCFData u8)
        let reserve_start = CFHEADER_FIXED_SIZE + 4;

        if (cb_cf_header as u32) < CAB_SIG_RESERVE_HEADER_SIZE {
            return Err(SignError::Hash(
                "CAB reserved header too small for Authenticode signature".into(),
            ));
        }

        if data.len() < reserve_start + cb_cf_header as usize {
            return Err(SignError::Hash(
                "CAB file too small for reserved data".into(),
            ));
        }

        // Parse the signature reserve header
        let header_size = u32::from_le_bytes([
            data[reserve_start],
            data[reserve_start + 1],
            data[reserve_start + 2],
            data[reserve_start + 3],
        ]);

        if header_size != CAB_SIG_RESERVE_HEADER_SIZE {
            return Err(SignError::Hash(format!(
                "CAB signature reserved header size mismatch: expected {CAB_SIG_RESERVE_HEADER_SIZE}, got {header_size}"
            )));
        }

        let sig_offset_pos = reserve_start + 4;
        let sig_size_pos = reserve_start + 8;

        // Read existing signature offset/size to determine end of cab
        let existing_sig_offset = u32::from_le_bytes([
            data[sig_offset_pos],
            data[sig_offset_pos + 1],
            data[sig_offset_pos + 2],
            data[sig_offset_pos + 3],
        ]);
        let existing_sig_size = u32::from_le_bytes([
            data[sig_size_pos],
            data[sig_size_pos + 1],
            data[sig_size_pos + 2],
            data[sig_size_pos + 3],
        ]);

        let end_of_cab = if existing_sig_offset > 0 && existing_sig_size > 0 {
            // Signature already exists — strip it, use original cab size
            existing_sig_offset as usize
        } else {
            cb_cabinet as usize
        };

        Ok(CabInfo {
            cb_cabinet,
            sig_offset_pos,
            sig_size_pos,
            cb_cf_header,
            end_of_cab,
        })
    } else {
        // No reserved area — we need to add one
        Err(SignError::Hash(
            "CAB file has no reserved area for Authenticode signature. \
             The file must be created with reserved space for signing."
                .into(),
        ))
    }
}

/// Compute the Authenticode hash for a CAB file.
///
/// The hash covers the entire cabinet EXCEPT:
/// - The sigOffset field (4 bytes at `cab_info.sig_offset_pos`)
/// - The sigSize field (4 bytes at `cab_info.sig_size_pos`)
/// - Any appended signature data beyond `cab_info.end_of_cab`
fn compute_cab_hash(data: &[u8], cab_info: &CabInfo) -> SignResult<Vec<u8>> {
    let end = cab_info.end_of_cab.min(data.len());
    let mut hasher = Sha256::new();

    // Build exclusion ranges (must be sorted by offset)
    let exclusions = [
        (cab_info.sig_offset_pos, 4usize),
        (cab_info.sig_size_pos, 4usize),
    ];

    let mut pos = 0;
    for &(exc_start, exc_len) in &exclusions {
        if exc_start >= end {
            break;
        }
        if pos < exc_start {
            hasher.update(&data[pos..exc_start]);
        }
        pos = exc_start + exc_len;
    }

    if pos < end {
        hasher.update(&data[pos..end]);
    }

    Ok(hasher.finalize().to_vec())
}

/// Embed an Authenticode signature into a CAB file.
///
/// The signature is appended after the cabinet data, and the reserved
/// header fields are updated to point to it.
fn embed_cab_signature(data: &[u8], cab_info: &CabInfo, pkcs7_der: &[u8]) -> SignResult<Vec<u8>> {
    let end_of_cab = cab_info.end_of_cab;

    // Start with the cabinet data (without any existing signature)
    let mut output = data[..end_of_cab].to_vec();

    // Update cbCabinet in the header to reflect new total size
    let new_total_size = (end_of_cab + pkcs7_der.len()) as u32;
    output[8..12].copy_from_slice(&new_total_size.to_le_bytes());

    // Update sigOffset to point to end of cab data
    let sig_offset = end_of_cab as u32;
    output[cab_info.sig_offset_pos..cab_info.sig_offset_pos + 4]
        .copy_from_slice(&sig_offset.to_le_bytes());

    // Update sigSize
    let sig_size = pkcs7_der.len() as u32;
    output[cab_info.sig_size_pos..cab_info.sig_size_pos + 4]
        .copy_from_slice(&sig_size.to_le_bytes());

    // Append the signature
    output.extend_from_slice(pkcs7_der);

    Ok(output)
}

/// Result of a CAB signing operation.
pub struct CabSignResult {
    /// The signed CAB file data.
    pub signed_data: Vec<u8>,
    /// Whether a timestamp was applied.
    pub timestamped: bool,
}

/// Sign a CAB file with Authenticode.
///
/// Computes the Authenticode hash over the cabinet data (excluding signature
/// areas), builds a CMS/PKCS#7 SignedData envelope, optionally timestamps it,
/// and appends the signature to the cabinet file.
pub async fn sign_cab(
    data: &[u8],
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
    options: &SignOptions,
) -> SignResult<CabSignResult> {
    let cab_info = parse_cab_header(data)?;

    // Reject already-signed CAB files unless allow_resign is set
    if cab_info.end_of_cab < cab_info.cb_cabinet as usize {
        if !options.allow_resign {
            return Err(SignError::AlreadySigned(
                "CAB file already contains an Authenticode signature".into(),
            ));
        }
        tracing::info!("Re-signing already-signed CAB file (allow_resign=true)");
        // For CAB re-signing, the hash computation excludes the signature area,
        // so the new signature will correctly replace the old one.
    }

    // Compute Authenticode hash
    let image_hash = compute_cab_hash(data, &cab_info)?;

    // Build CMS/PKCS#7 SignedData
    let mut builder = Pkcs7Builder::new(credentials.signer_cert_der().to_vec(), image_hash);
    builder.with_algorithm(credentials.signing_algorithm());

    for chain_cert in credentials.chain_certs_der() {
        builder.add_chain_cert(chain_cert.clone());
    }

    let mut timestamped = false;

    if let Some(tsa) = tsa_config {
        let sig_bytes = {
            let temp_pkcs7 =
                builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;
            crate::signer::extract_signature_from_pkcs7(&temp_pkcs7)?
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

    let pkcs7_der = builder.build(|signed_attrs_der| credentials.sign_data(signed_attrs_der))?;

    let signed_data = embed_cab_signature(data, &cab_info, &pkcs7_der)?;

    Ok(CabSignResult {
        signed_data,
        timestamped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal CAB file with the CFHDR_RESERVE_PRESENT flag and
    /// an Authenticode signature reserved header.
    fn build_test_cab(body_len: usize) -> Vec<u8> {
        // CFHEADER fixed fields (36 bytes)
        let mut cab = Vec::new();

        // signature: "MSCF"
        cab.extend_from_slice(CAB_MAGIC);
        // reserved1: u32 = 0
        cab.extend_from_slice(&0u32.to_le_bytes());
        // cbCabinet: will be filled after we know the total size
        let cb_cabinet_pos = cab.len();
        cab.extend_from_slice(&0u32.to_le_bytes()); // placeholder
                                                    // reserved2: u32 = 0
        cab.extend_from_slice(&0u32.to_le_bytes());
        // coffFiles: u32 (offset of first CFFILE entry, doesn't matter for test)
        cab.extend_from_slice(&0u32.to_le_bytes());
        // reserved3: u32 = 0
        cab.extend_from_slice(&0u32.to_le_bytes());
        // versionMinor: u8 = 3, versionMajor: u8 = 1
        cab.push(3);
        cab.push(1);
        // cFolders: u16 = 0
        cab.extend_from_slice(&0u16.to_le_bytes());
        // cFiles: u16 = 0
        cab.extend_from_slice(&0u16.to_le_bytes());
        // flags: u16 — set cfhdrRESERVE_PRESENT
        cab.extend_from_slice(&CFHDR_RESERVE_PRESENT.to_le_bytes());
        // setID: u16 = 0
        cab.extend_from_slice(&0u16.to_le_bytes());
        // iCabinet: u16 = 0
        cab.extend_from_slice(&0u16.to_le_bytes());

        assert_eq!(cab.len(), CFHEADER_FIXED_SIZE);

        // Reserved fields: cbCFHeader (u16), cbCFFolder (u8), cbCFData (u8)
        let cb_cf_header: u16 = CAB_SIG_RESERVE_HEADER_SIZE as u16;
        cab.extend_from_slice(&cb_cf_header.to_le_bytes());
        cab.push(0); // cbCFFolder
        cab.push(0); // cbCFData

        // Reserved header data (20 bytes):
        // headerSize: u32 = 20
        cab.extend_from_slice(&CAB_SIG_RESERVE_HEADER_SIZE.to_le_bytes());
        // sigOffset: u32 = 0 (no signature yet)
        cab.extend_from_slice(&0u32.to_le_bytes());
        // sigSize: u32 = 0 (no signature yet)
        cab.extend_from_slice(&0u32.to_le_bytes());
        // padding: 8 bytes of zeros
        cab.extend_from_slice(&[0u8; 8]);

        // Add body data
        cab.extend(std::iter::repeat_n(0xAAu8, body_len));

        // Fill in cbCabinet
        let total = cab.len() as u32;
        cab[cb_cabinet_pos..cb_cabinet_pos + 4].copy_from_slice(&total.to_le_bytes());

        cab
    }

    #[test]
    fn test_parse_valid_cab() {
        let cab = build_test_cab(64);
        let info = parse_cab_header(&cab).unwrap();
        assert_eq!(info.cb_cf_header, CAB_SIG_RESERVE_HEADER_SIZE as u16);
        assert_eq!(info.end_of_cab, cab.len());
    }

    #[test]
    fn test_parse_rejects_bad_magic() {
        let mut cab = build_test_cab(64);
        cab[0] = 0x00; // corrupt magic
        assert!(parse_cab_header(&cab).is_err());
    }

    #[test]
    fn test_parse_rejects_no_reserve() {
        let mut cab = build_test_cab(64);
        // Clear the CFHDR_RESERVE_PRESENT flag
        cab[FLAGS_OFFSET] = 0;
        cab[FLAGS_OFFSET + 1] = 0;
        let err = parse_cab_header(&cab).unwrap_err();
        assert!(err.to_string().contains("no reserved area"));
    }

    #[test]
    fn test_parse_rejects_too_small() {
        let data = vec![0u8; 10];
        assert!(parse_cab_header(&data).is_err());
    }

    #[test]
    fn test_cab_hash_deterministic() {
        let cab = build_test_cab(64);
        let info = parse_cab_header(&cab).unwrap();
        let hash1 = compute_cab_hash(&cab, &info).unwrap();
        let hash2 = compute_cab_hash(&cab, &info).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256
    }

    #[test]
    fn test_cab_hash_excludes_sig_fields() {
        let cab = build_test_cab(64);
        let info = parse_cab_header(&cab).unwrap();

        let hash1 = compute_cab_hash(&cab, &info).unwrap();

        // Modify sigOffset and sigSize fields — hash should not change
        let mut cab2 = cab.clone();
        cab2[info.sig_offset_pos] = 0xFF;
        cab2[info.sig_offset_pos + 1] = 0xFF;
        cab2[info.sig_size_pos] = 0xFF;
        cab2[info.sig_size_pos + 1] = 0xFF;

        let hash2 = compute_cab_hash(&cab2, &info).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_cab_hash_changes_with_content() {
        let cab_a = build_test_cab(64);
        let info_a = parse_cab_header(&cab_a).unwrap();
        let hash_a = compute_cab_hash(&cab_a, &info_a).unwrap();

        let mut cab_b = cab_a.clone();
        // Modify body data
        let body_start = CFHEADER_FIXED_SIZE + 4 + CAB_SIG_RESERVE_HEADER_SIZE as usize;
        cab_b[body_start] = 0xBB;
        let hash_b = compute_cab_hash(&cab_b, &info_a).unwrap();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_embed_cab_signature() {
        let cab = build_test_cab(64);
        let info = parse_cab_header(&cab).unwrap();
        let fake_sig = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let signed = embed_cab_signature(&cab, &info, &fake_sig).unwrap();

        // Total size should be original cab + signature
        assert_eq!(signed.len(), info.end_of_cab + fake_sig.len());

        // cbCabinet should be updated
        let new_cb = u32::from_le_bytes([signed[8], signed[9], signed[10], signed[11]]);
        assert_eq!(new_cb as usize, signed.len());

        // sigOffset should point to end of original cab
        let sig_off = u32::from_le_bytes([
            signed[info.sig_offset_pos],
            signed[info.sig_offset_pos + 1],
            signed[info.sig_offset_pos + 2],
            signed[info.sig_offset_pos + 3],
        ]);
        assert_eq!(sig_off as usize, info.end_of_cab);

        // sigSize should match signature length
        let sig_sz = u32::from_le_bytes([
            signed[info.sig_size_pos],
            signed[info.sig_size_pos + 1],
            signed[info.sig_size_pos + 2],
            signed[info.sig_size_pos + 3],
        ]);
        assert_eq!(sig_sz as usize, fake_sig.len());

        // Signature data should be at the end
        assert_eq!(&signed[info.end_of_cab..], &fake_sig);
    }

    #[test]
    fn test_embed_preserves_cab_body() {
        let cab = build_test_cab(64);
        let info = parse_cab_header(&cab).unwrap();
        let body_start = CFHEADER_FIXED_SIZE + 4 + CAB_SIG_RESERVE_HEADER_SIZE as usize;

        let fake_sig = vec![0x01; 16];
        let signed = embed_cab_signature(&cab, &info, &fake_sig).unwrap();

        // Body data should be preserved
        assert_eq!(
            &signed[body_start..body_start + 64],
            &cab[body_start..body_start + 64]
        );
    }
}
