//! MSI (Windows Installer) file signing via Authenticode.
//!
//! MSI files use the OLE Compound Document Format (CFBF / structured storage).
//! Authenticode signatures are stored in a dedicated stream named
//! `"\x05DigitalSignature"` within the compound document.
//!
//! ## Signing Process
//!
//! 1. Open the MSI as a compound document (CFB)
//! 2. Compute the Authenticode hash over all streams EXCEPT the
//!    `\x05DigitalSignature` and `\x05MsiDigitalSignatureEx` streams
//! 3. Build a CMS/PKCS#7 SignedData envelope containing the hash
//! 4. Write the signature into the `\x05DigitalSignature` stream
//!
//! ## Hash Computation
//!
//! The Authenticode hash for MSI files covers:
//! - All stream data in the compound document, sorted by stream name
//! - The `\x05DigitalSignature` and `\x05MsiDigitalSignatureEx` streams
//!   are excluded from hashing
//!
//! The content type OID used is `SPC_PE_IMAGE_DATAOBJ` (1.3.6.1.4.1.311.2.1.15),
//! which is shared between PE and MSI Authenticode signatures.

use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek, Write};

use crate::error::{SignError, SignResult};
use crate::pkcs7::Pkcs7Builder;
use crate::signer::{SignOptions, SigningCredentials};
use crate::timestamp::TsaConfig;

/// Stream name for the Authenticode digital signature.
const DIGITAL_SIGNATURE_STREAM: &str = "\x05DigitalSignature";

/// Stream name for the extended MSI digital signature (excluded from hash).
const DIGITAL_SIGNATURE_EX_STREAM: &str = "\x05MsiDigitalSignatureEx";

/// Compute the Authenticode hash for an MSI file.
///
/// Opens the MSI as a CFB compound document and hashes all stream data
/// except the signature streams. Streams are processed in sorted order
/// by name to ensure deterministic hashing.
fn compute_msi_hash(data: &[u8]) -> SignResult<Vec<u8>> {
    let cursor = Cursor::new(data);
    let comp = cfb::CompoundFile::open(cursor)
        .map_err(|e| SignError::Hash(format!("Failed to open MSI as compound document: {e}")))?;

    // Collect all stream entries and their paths, excluding signature streams
    let mut stream_entries: Vec<String> = Vec::new();
    collect_stream_paths(&comp, "/", &mut stream_entries)?;

    // Sort by name for deterministic hashing
    stream_entries.sort();

    // Re-open to read streams (need mutable borrow)
    let cursor = Cursor::new(data);
    let mut comp = cfb::CompoundFile::open(cursor)
        .map_err(|e| SignError::Hash(format!("Failed to reopen MSI: {e}")))?;

    let mut hasher = Sha256::new();

    for path in &stream_entries {
        let mut stream = comp
            .open_stream(path)
            .map_err(|e| SignError::Hash(format!("Failed to open stream '{path}': {e}")))?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|e| SignError::Hash(format!("Failed to read stream '{path}': {e}")))?;
        hasher.update(&buf);
    }

    Ok(hasher.finalize().to_vec())
}

/// Recursively collect stream paths from a compound document, excluding
/// signature streams.
fn collect_stream_paths<F: Read + Seek>(
    comp: &cfb::CompoundFile<F>,
    dir: &str,
    out: &mut Vec<String>,
) -> SignResult<()> {
    let entries: Vec<cfb::Entry> = comp
        .read_storage(dir)
        .map_err(|e| SignError::Hash(format!("Failed to read storage '{dir}': {e}")))?
        .collect();

    for entry in entries {
        let name = entry.name().to_string();
        let full_path = if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        };

        if entry.is_stream() {
            // Skip signature streams
            if name == DIGITAL_SIGNATURE_STREAM || name == DIGITAL_SIGNATURE_EX_STREAM {
                continue;
            }
            out.push(full_path);
        } else if entry.is_storage() {
            collect_stream_paths(comp, &full_path, out)?;
        }
    }

    Ok(())
}

/// Embed an Authenticode signature into an MSI file.
///
/// Writes the PKCS#7 DER data into the `\x05DigitalSignature` stream
/// within the compound document.
fn embed_msi_signature(data: &[u8], pkcs7_der: &[u8]) -> SignResult<Vec<u8>> {
    let cursor = Cursor::new(data.to_vec());
    let mut comp = cfb::CompoundFile::open(cursor)
        .map_err(|e| SignError::Embed(format!("Failed to open MSI for writing: {e}")))?;

    // Create or overwrite the DigitalSignature stream
    let sig_path = format!("/{DIGITAL_SIGNATURE_STREAM}");
    let mut stream = comp
        .create_stream(&sig_path)
        .map_err(|e| SignError::Embed(format!("Failed to create signature stream: {e}")))?;
    stream
        .write_all(pkcs7_der)
        .map_err(|e| SignError::Embed(format!("Failed to write signature data: {e}")))?;
    // Explicitly drop the stream borrow before flushing
    drop(stream);

    comp.flush()
        .map_err(|e| SignError::Embed(format!("Failed to flush MSI: {e}")))?;

    // Extract the modified data
    let inner = comp.into_inner();
    Ok(inner.into_inner())
}

/// Result of an MSI signing operation.
pub struct MsiSignResult {
    /// The signed MSI file data.
    pub signed_data: Vec<u8>,
    /// Whether a timestamp was applied.
    pub timestamped: bool,
}

/// Sign an MSI file with Authenticode.
///
/// Computes the Authenticode hash over the MSI content (excluding signature
/// streams), builds a CMS/PKCS#7 SignedData envelope, optionally timestamps
/// it, and embeds the signature in the `\x05DigitalSignature` stream.
pub async fn sign_msi(
    data: &[u8],
    credentials: &SigningCredentials,
    tsa_config: Option<&TsaConfig>,
    options: &SignOptions,
) -> SignResult<MsiSignResult> {
    // Check if already signed
    {
        let cursor = Cursor::new(data);
        let comp = cfb::CompoundFile::open(cursor)
            .map_err(|e| SignError::Hash(format!("Failed to open MSI: {e}")))?;

        let sig_path = format!("/{DIGITAL_SIGNATURE_STREAM}");
        if comp.is_stream(&sig_path) {
            if !options.allow_resign {
                return Err(SignError::AlreadySigned(
                    "MSI file already contains an Authenticode signature".into(),
                ));
            }
            tracing::info!("Re-signing already-signed MSI file (allow_resign=true)");
            // For MSI re-signing, the existing DigitalSignature stream will be
            // overwritten with the new signature.
        }
    }

    // Compute Authenticode hash
    let image_hash = compute_msi_hash(data)?;

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

    let signed_data = embed_msi_signature(data, &pkcs7_der)?;

    Ok(MsiSignResult {
        signed_data,
        timestamped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid CFB compound document with a test stream.
    fn build_test_msi() -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut comp = cfb::CompoundFile::create(cursor).unwrap();

        // Add a test stream with some content
        let mut stream = comp.create_stream("/TestStream").unwrap();
        stream.write_all(b"Hello, MSI!").unwrap();
        drop(stream);

        // Add another stream
        let mut stream2 = comp.create_stream("/AnotherStream").unwrap();
        stream2.write_all(b"More data here").unwrap();
        drop(stream2);

        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    #[test]
    fn test_compute_msi_hash_deterministic() {
        let msi = build_test_msi();
        let hash1 = compute_msi_hash(&msi).unwrap();
        let hash2 = compute_msi_hash(&msi).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256
    }

    #[test]
    fn test_compute_msi_hash_excludes_signature_stream() {
        let msi_unsigned = build_test_msi();
        let hash_unsigned = compute_msi_hash(&msi_unsigned).unwrap();

        // Embed a fake signature into the same file — the hash should
        // remain identical because the signature stream is excluded.
        let msi_signed = embed_msi_signature(&msi_unsigned, b"fake sig data").unwrap();
        let hash_signed = compute_msi_hash(&msi_signed).unwrap();

        assert_eq!(hash_unsigned, hash_signed);
    }

    #[test]
    fn test_compute_msi_hash_changes_with_content() {
        let msi_a = build_test_msi();

        // Build a different MSI
        let cursor = Cursor::new(Vec::new());
        let mut comp = cfb::CompoundFile::create(cursor).unwrap();
        let mut stream = comp.create_stream("/TestStream").unwrap();
        stream.write_all(b"Different content!").unwrap();
        drop(stream);
        comp.flush().unwrap();
        let msi_b = comp.into_inner().into_inner();

        let hash_a = compute_msi_hash(&msi_a).unwrap();
        let hash_b = compute_msi_hash(&msi_b).unwrap();
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_embed_msi_signature() {
        let msi = build_test_msi();
        let fake_sig = b"fake PKCS#7 signature data";

        let signed = embed_msi_signature(&msi, fake_sig).unwrap();

        // Verify the signature stream exists and contains our data
        let cursor = Cursor::new(&signed);
        let mut comp = cfb::CompoundFile::open(cursor).unwrap();
        let sig_path = format!("/{DIGITAL_SIGNATURE_STREAM}");
        assert!(comp.is_stream(&sig_path));

        let mut stream = comp.open_stream(&sig_path).unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, fake_sig);
    }

    #[test]
    fn test_embed_preserves_existing_streams() {
        let msi = build_test_msi();
        let fake_sig = b"fake sig";

        let signed = embed_msi_signature(&msi, fake_sig).unwrap();

        // Verify original streams are preserved
        let cursor = Cursor::new(&signed);
        let mut comp = cfb::CompoundFile::open(cursor).unwrap();

        let mut stream = comp.open_stream("/TestStream").unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, b"Hello, MSI!");
    }

    #[test]
    fn test_rejects_invalid_data() {
        let bad_data = vec![0xFF; 100];
        assert!(compute_msi_hash(&bad_data).is_err());
    }

    #[test]
    fn test_rejects_empty_data() {
        let empty = Vec::new();
        assert!(compute_msi_hash(&empty).is_err());
    }
}
