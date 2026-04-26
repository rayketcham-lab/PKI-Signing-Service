//! File type detection for code signing dispatch.

use std::path::Path;

use crate::error::{SignError, SignResult};

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
}
