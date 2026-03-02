//! Signature embedding into PE files.
//!
//! After the CMS/PKCS#7 signature is built, it must be embedded into
//! the PE file as a WIN_CERTIFICATE structure in the certificate table.
//!
//! The WIN_CERTIFICATE structure:
//! ```text
//! struct WIN_CERTIFICATE {
//!     dwLength: u32,        // Total length including header + padding
//!     wRevision: u16,       // 0x0200 for PKCS#7
//!     wCertificateType: u16, // 0x0002 for PKCS#7 signed data
//!     bCertificate: [u8],   // The PKCS#7 SignedData DER blob
//! }
//! ```
//!
//! After embedding:
//! - PE CheckSum field must be recalculated
//! - Certificate Table directory entry (RVA + size) must be updated

use super::parser::PeInfo;
use crate::error::{SignError, SignResult};

/// WIN_CERTIFICATE revision for PKCS#7.
const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// WIN_CERTIFICATE type for PKCS#7 signed data.
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// Embed an Authenticode signature into a PE file.
///
/// Takes the original PE data and the DER-encoded CMS/PKCS#7 SignedData,
/// and returns a new Vec<u8> with the signature embedded.
///
/// The PE file is truncated at `end_of_image` (removing any existing
/// signature), then the new WIN_CERTIFICATE structure is appended.
pub fn embed_signature(data: &[u8], pe_info: &PeInfo, pkcs7_der: &[u8]) -> SignResult<Vec<u8>> {
    // WIN_CERTIFICATE header is 8 bytes (dwLength + wRevision + wCertificateType)
    let win_cert_header_size = 8;
    let cert_data_len = win_cert_header_size + pkcs7_der.len();

    // Align to 8-byte boundary (Authenticode requirement)
    let aligned_len = (cert_data_len + 7) & !7;
    let padding = aligned_len - cert_data_len;

    // Start with original PE data up to end of image (strip existing sigs)
    let mut output = data[..pe_info.end_of_image].to_vec();

    // Build WIN_CERTIFICATE structure
    let dw_length = aligned_len as u32;
    output.extend_from_slice(&dw_length.to_le_bytes());
    output.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    output.extend_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    output.extend_from_slice(pkcs7_der);

    // Add padding bytes
    output.extend(std::iter::repeat_n(0u8, padding));

    // Update Certificate Table directory entry
    // RVA = file offset of the WIN_CERTIFICATE (= end_of_image)
    let cert_rva = pe_info.end_of_image as u32;
    let cert_size = aligned_len as u32;

    // Write certificate table RVA
    output[pe_info.cert_table_offset..pe_info.cert_table_offset + 4]
        .copy_from_slice(&cert_rva.to_le_bytes());
    // Write certificate table size
    output[pe_info.cert_table_offset + 4..pe_info.cert_table_offset + 8]
        .copy_from_slice(&cert_size.to_le_bytes());

    // Recalculate PE checksum
    let checksum = compute_pe_checksum(&output, pe_info.checksum_offset);
    output[pe_info.checksum_offset..pe_info.checksum_offset + 4]
        .copy_from_slice(&checksum.to_le_bytes());

    Ok(output)
}

/// Compute the PE file checksum.
///
/// This is the standard PE checksum algorithm: sum all 16-bit words
/// (excluding the checksum field itself), fold carry bits, then add
/// the file length.
fn compute_pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;

    // Process as 16-bit little-endian words
    let mut i = 0;
    while i + 1 < data.len() {
        // Skip the checksum field (4 bytes = 2 words)
        if i == checksum_offset || i == checksum_offset + 2 {
            i += 2;
            continue;
        }
        let word = u16::from_le_bytes([data[i], data[i + 1]]) as u64;
        sum += word;
        i += 2;
    }

    // Handle odd trailing byte
    if i < data.len() {
        sum += data[i] as u64;
    }

    // Fold 32-bit carries
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Add file length
    sum as u32 + data.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_checksum_deterministic() {
        let data = vec![0x55u8; 100];
        let cs1 = compute_pe_checksum(&data, 64);
        let cs2 = compute_pe_checksum(&data, 64);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn test_win_cert_alignment() {
        // WIN_CERTIFICATE must be 8-byte aligned
        let pkcs7_len = 13; // odd size
        let header = 8;
        let total = header + pkcs7_len;
        let aligned = (total + 7) & !7;
        assert_eq!(aligned % 8, 0);
    }

    #[test]
    fn test_checksum_skips_checksum_field() {
        let data1 = vec![0x55u8; 100];
        let mut data2 = data1.clone();
        // Modify checksum field (bytes 64-67)
        data2[64] = 0xFF;
        data2[65] = 0xFF;
        data2[66] = 0xFF;
        data2[67] = 0xFF;
        let cs1 = compute_pe_checksum(&data1, 64);
        let cs2 = compute_pe_checksum(&data2, 64);
        assert_eq!(cs1, cs2);
    }

    #[test]
    fn test_checksum_includes_file_length() {
        let data = vec![0u8; 100];
        let cs = compute_pe_checksum(&data, 64);
        // With all zeros, the word sum is 0, so checksum = 0 + file_length = 100
        assert_eq!(cs, 100);
    }

    #[test]
    fn test_checksum_handles_odd_length() {
        // Odd-length data should still produce a valid checksum
        let data = vec![0x01u8; 101];
        let cs = compute_pe_checksum(&data, 64);
        assert!(cs > 0);
    }

    #[test]
    fn test_checksum_changes_with_content() {
        let data1 = vec![0x00u8; 100];
        let mut data2 = vec![0x00u8; 100];
        data2[0] = 0xFF;
        data2[1] = 0xFF;
        let cs1 = compute_pe_checksum(&data1, 64);
        let cs2 = compute_pe_checksum(&data2, 64);
        assert_ne!(cs1, cs2);
    }

    fn make_test_pe_info() -> PeInfo {
        PeInfo {
            pe_offset: 0,
            is_pe32_plus: false,
            checksum_offset: 10,
            cert_table_offset: 20,
            cert_table_rva: 0,
            cert_table_size: 0,
            end_of_image: 100,
            file_size: 100,
            sections: vec![],
            size_of_optional_header: 0,
            number_of_rva_and_sizes: 16,
        }
    }

    #[test]
    fn test_embed_signature_updates_cert_table() {
        let pe_info = make_test_pe_info();
        let data = vec![0u8; 100];
        let pkcs7 = vec![0xAA; 32];

        let output = embed_signature(&data, &pe_info, &pkcs7).unwrap();

        // Cert table RVA should point to end_of_image (100)
        let rva = u32::from_le_bytes([output[20], output[21], output[22], output[23]]);
        assert_eq!(rva, 100);

        // Cert table size should be aligned to 8 bytes
        let size = u32::from_le_bytes([output[24], output[25], output[26], output[27]]);
        assert_eq!(size % 8, 0);
    }

    #[test]
    fn test_embed_signature_win_cert_header() {
        let pe_info = make_test_pe_info();
        let data = vec![0u8; 100];
        let pkcs7 = vec![0xBB; 16];

        let output = embed_signature(&data, &pe_info, &pkcs7).unwrap();

        // WIN_CERTIFICATE starts at end_of_image (100)
        // wRevision at offset 104 (100+4)
        let revision = u16::from_le_bytes([output[104], output[105]]);
        assert_eq!(revision, WIN_CERT_REVISION_2_0);

        // wCertificateType at offset 106 (100+6)
        let cert_type = u16::from_le_bytes([output[106], output[107]]);
        assert_eq!(cert_type, WIN_CERT_TYPE_PKCS_SIGNED_DATA);
    }

    #[test]
    fn test_embed_signature_preserves_original_data() {
        let pe_info = make_test_pe_info();
        let mut data = vec![0x55u8; 100];
        // Put some marker bytes in a region that shouldn't change
        data[30] = 0xDE;
        data[31] = 0xAD;
        let pkcs7 = vec![0xBB; 8];

        let output = embed_signature(&data, &pe_info, &pkcs7).unwrap();

        // Marker bytes preserved (outside checksum and cert_table regions)
        assert_eq!(output[30], 0xDE);
        assert_eq!(output[31], 0xAD);
    }

    #[test]
    fn test_embed_signature_output_aligned() {
        let pe_info = make_test_pe_info();
        let data = vec![0u8; 100];
        // Use an odd-sized PKCS7 blob
        let pkcs7 = vec![0xCC; 13];

        let output = embed_signature(&data, &pe_info, &pkcs7).unwrap();

        // Output should be end_of_image + aligned WIN_CERTIFICATE
        assert_eq!(output.len() % 8, 100 % 8); // only the win_cert part is aligned
        let cert_size = u32::from_le_bytes([output[24], output[25], output[26], output[27]]);
        assert_eq!(cert_size % 8, 0);
    }
}
