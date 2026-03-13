//! PE file header parsing.
//!
//! Extracts the information needed for Authenticode signing:
//! - PE signature offset and optional header location
//! - Checksum field offset
//! - Certificate table directory entry (RVA + size)
//! - Section table for hash range computation
//! - Whether the file is PE32 or PE32+ (64-bit)

use crate::error::{SignError, SignResult};

/// Parsed PE file information needed for Authenticode operations.
#[derive(Debug)]
pub struct PeInfo {
    /// Offset of the PE signature ("PE\0\0") from file start.
    pub pe_offset: usize,
    /// Whether this is PE32+ (64-bit) vs PE32 (32-bit).
    pub is_pe32_plus: bool,
    /// Offset of the CheckSum field within the file.
    pub checksum_offset: usize,
    /// Offset of the Certificate Table directory entry (RVA field).
    pub cert_table_offset: usize,
    /// Current certificate table RVA (0 if unsigned).
    pub cert_table_rva: u32,
    /// Current certificate table size (0 if unsigned).
    pub cert_table_size: u32,
    /// End of the last section's raw data (where signature data begins).
    pub end_of_image: usize,
    /// Total file size.
    pub file_size: usize,
    /// Section info for hash computation: (pointer_to_raw_data, size_of_raw_data).
    pub sections: Vec<(u32, u32)>,
    /// Size of optional header (used for offset calculations).
    pub size_of_optional_header: u16,
    /// Number of data directory entries.
    pub number_of_rva_and_sizes: u32,
}

impl PeInfo {
    /// Parse PE headers from file data.
    ///
    /// Validates that the file is a valid PE and extracts all offsets
    /// needed for Authenticode hash computation and signature embedding.
    pub fn parse(data: &[u8]) -> SignResult<Self> {
        // Minimum PE file size check
        if data.len() < 64 {
            return Err(SignError::InvalidPe("File too small to be a PE".into()));
        }

        // Check MZ magic
        if data[0] != b'M' || data[1] != b'Z' {
            return Err(SignError::InvalidPe("Missing MZ signature".into()));
        }

        // Get PE header offset from e_lfanew (offset 0x3C, 4 bytes LE)
        let pe_offset =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        if pe_offset + 4 > data.len() {
            return Err(SignError::InvalidPe("PE offset beyond file".into()));
        }

        // Check PE signature "PE\0\0"
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(SignError::InvalidPe("Missing PE signature".into()));
        }

        // COFF header starts at pe_offset + 4
        let coff_offset = pe_offset + 4;

        // Number of sections (offset 2 in COFF header)
        let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
        let size_of_optional_header =
            u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]);

        // Optional header starts at coff_offset + 20
        let opt_offset = coff_offset + 20;

        if opt_offset + 2 > data.len() {
            return Err(SignError::InvalidPe("Optional header truncated".into()));
        }

        // Determine PE32 vs PE32+
        let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        let is_pe32_plus = match magic {
            0x10B => false, // PE32
            0x20B => true,  // PE32+
            _ => {
                return Err(SignError::InvalidPe(format!(
                    "Unknown optional header magic: {:#06x}",
                    magic
                )))
            }
        };

        // Checksum is at optional header + 64
        let checksum_offset = opt_offset + 64;

        // Certificate table directory entry location depends on PE32 vs PE32+
        // It's data directory index 4 (SECURITY), each entry is 8 bytes (RVA + size)
        // Data directories start after the fixed optional header fields
        let data_dir_offset = if is_pe32_plus {
            opt_offset + 112 // PE32+: 112 bytes of fixed fields
        } else {
            opt_offset + 96 // PE32: 96 bytes of fixed fields
        };

        // Number of RVA and sizes
        let num_rva_offset = if is_pe32_plus {
            opt_offset + 108
        } else {
            opt_offset + 92
        };
        let number_of_rva_and_sizes = u32::from_le_bytes([
            data[num_rva_offset],
            data[num_rva_offset + 1],
            data[num_rva_offset + 2],
            data[num_rva_offset + 3],
        ]);

        if number_of_rva_and_sizes < 5 {
            return Err(SignError::InvalidPe(
                "PE has fewer than 5 data directories (no security entry)".into(),
            ));
        }

        // Certificate table is data directory entry 4 (0-indexed)
        let cert_table_offset = data_dir_offset + 4 * 8; // index 4 * 8 bytes per entry

        if cert_table_offset + 8 > data.len() {
            return Err(SignError::InvalidPe(
                "Certificate table offset beyond file".into(),
            ));
        }

        let cert_table_rva = u32::from_le_bytes([
            data[cert_table_offset],
            data[cert_table_offset + 1],
            data[cert_table_offset + 2],
            data[cert_table_offset + 3],
        ]);
        let cert_table_size = u32::from_le_bytes([
            data[cert_table_offset + 4],
            data[cert_table_offset + 5],
            data[cert_table_offset + 6],
            data[cert_table_offset + 7],
        ]);

        // Parse section headers
        let section_table_offset = opt_offset + size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(num_sections as usize);

        for i in 0..num_sections as usize {
            let sec_offset = section_table_offset + i * 40;
            if sec_offset + 40 > data.len() {
                return Err(SignError::InvalidPe("Section header truncated".into()));
            }
            let ptr_raw = u32::from_le_bytes([
                data[sec_offset + 20],
                data[sec_offset + 21],
                data[sec_offset + 22],
                data[sec_offset + 23],
            ]);
            let size_raw = u32::from_le_bytes([
                data[sec_offset + 16],
                data[sec_offset + 17],
                data[sec_offset + 18],
                data[sec_offset + 19],
            ]);
            sections.push((ptr_raw, size_raw));
        }

        // Per Authenticode spec: hash covers FILE_SIZE minus certificate table.
        // This correctly includes overlay data (debug info, resources, etc.)
        // that exists beyond the last PE section.
        let end_of_image = data.len() - cert_table_size as usize;

        Ok(PeInfo {
            pe_offset,
            is_pe32_plus,
            checksum_offset,
            cert_table_offset,
            cert_table_rva,
            cert_table_size,
            end_of_image,
            file_size: data.len(),
            sections,
            size_of_optional_header,
            number_of_rva_and_sizes,
        })
    }

    /// Returns true if the PE file already contains an Authenticode signature.
    pub fn is_signed(&self) -> bool {
        self.cert_table_rva != 0 && self.cert_table_size != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_empty_file() {
        let data = vec![0u8; 32];
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_rejects_non_pe() {
        let data = b"This is not a PE file at all, just some random text data here.....";
        assert!(PeInfo::parse(data).is_err());
    }

    #[test]
    fn test_rejects_elf() {
        let mut data = vec![0u8; 256];
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        assert!(PeInfo::parse(&data).is_err());
    }

    /// Build a minimal valid PE32 file structure for testing.
    fn make_minimal_pe32() -> Vec<u8> {
        let mut data = vec![0u8; 512];
        // MZ magic
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x80 (PE header offset)
        data[0x3C] = 0x80;
        // PE signature at 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        // COFF header at 0x84
        // NumberOfSections = 1
        data[0x86] = 1;
        data[0x87] = 0;
        // SizeOfOptionalHeader = 224 (0xE0) — standard PE32
        data[0x94] = 0xE0;
        data[0x95] = 0x00;
        // Optional header at 0x98
        // Magic = 0x10B (PE32)
        data[0x98] = 0x0B;
        data[0x99] = 0x01;
        // NumberOfRvaAndSizes at opt+92 = 0x98+92 = 0xF4
        data[0xF4] = 16; // 16 data directories
                         // Section header at opt + SizeOfOptionalHeader = 0x98 + 0xE0 = 0x178
                         // SizeOfRawData at section+16 = 0x178+16 = 0x188
        data[0x188] = 0x00;
        data[0x189] = 0x02; // 0x200 = 512 bytes
                            // PointerToRawData at section+20 = 0x178+20 = 0x18C
        data[0x18C] = 0x00;
        data[0x18D] = 0x02; // 0x200
        data
    }

    #[test]
    fn test_parse_minimal_pe32() {
        let data = make_minimal_pe32();
        let info = PeInfo::parse(&data).unwrap();
        assert!(!info.is_pe32_plus);
        assert_eq!(info.pe_offset, 0x80);
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.number_of_rva_and_sizes, 16);
        assert!(!info.is_signed());
    }

    #[test]
    fn test_pe32_plus_magic() {
        let mut data = make_minimal_pe32();
        // Change magic to PE32+ (0x20B)
        data[0x98] = 0x0B;
        data[0x99] = 0x02;
        // NumberOfRvaAndSizes for PE32+ is at opt+108 = 0x98+108 = 0x104
        data[0x104] = 16;
        // Need to extend data for the larger PE32+ optional header
        data.resize(1024, 0);
        let info = PeInfo::parse(&data).unwrap();
        assert!(info.is_pe32_plus);
    }

    #[test]
    fn test_is_signed_detection() {
        let info = PeInfo {
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
        };
        assert!(!info.is_signed());

        let signed_info = PeInfo {
            cert_table_rva: 0x1000,
            cert_table_size: 0x200,
            ..info
        };
        assert!(signed_info.is_signed());
    }

    #[test]
    fn test_rejects_truncated_mz() {
        // MZ header but file too small for PE offset
        let data = vec![b'M', b'Z'];
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_rejects_bad_pe_offset() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        // Point e_lfanew beyond file
        data[0x3C] = 0xFF;
        data[0x3D] = 0xFF;
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_rejects_missing_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80;
        // Don't write PE\0\0 at 0x80
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_rejects_unknown_magic() {
        let mut data = make_minimal_pe32();
        // Set unknown optional header magic
        data[0x98] = 0xFF;
        data[0x99] = 0xFF;
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_rejects_too_few_data_directories() {
        let mut data = make_minimal_pe32();
        // Set NumberOfRvaAndSizes to 3 (need at least 5 for cert table)
        data[0xF4] = 3;
        assert!(PeInfo::parse(&data).is_err());
    }

    #[test]
    fn test_pe_info_debug() {
        let info = PeInfo {
            pe_offset: 0x80,
            is_pe32_plus: true,
            checksum_offset: 0xD8,
            cert_table_offset: 0x130,
            cert_table_rva: 0,
            cert_table_size: 0,
            end_of_image: 0x400,
            file_size: 0x400,
            sections: vec![(0x200, 0x200)],
            size_of_optional_header: 0xF0,
            number_of_rva_and_sizes: 16,
        };
        let dbg = format!("{:?}", info);
        assert!(dbg.contains("PeInfo"));
        assert!(dbg.contains("pe_offset: 128"));
    }
}
