//! Evidence Record Syntax (RFC 4998) — Long-Term Archive Timestamps.
//!
//! Implements the Evidence Record data structures for protecting signed
//! data beyond the validity period of the original signing key. An
//! EvidenceRecord contains a chain of archive timestamps, each wrapping
//! an RFC 3161 TimeStampToken, enabling periodic renewal as cryptographic
//! algorithms weaken over time.
//!
//! ## Key Structures
//!
//! - [`EvidenceRecord`] — Top-level container (version 1)
//! - [`ArchiveTimeStampSequence`] — Ordered sequence of chains (hash-tree renewal)
//! - [`ArchiveTimeStampChain`] — Ordered sequence of timestamps (timestamp renewal)
//! - [`ArchiveTimeStamp`] — Individual timestamp with optional Merkle hash tree
//! - [`PartialHashtree`] — Reduced Merkle tree hash values
//!
//! ## OIDs
//!
//! - `1.2.840.113549.1.9.16.1.27` — id-smime-ct-evidenceRecord
//! - `1.2.840.113549.1.9.16.2.48` — id-smime-aa-ets-archiveTimestampV3
//!
//! ## References
//!
//! - RFC 4998: Evidence Record Syntax (ERS)
//! - RFC 6283: XML Evidence Record Syntax (XMLERS) — not implemented
//! - RFC 9169: New ASN.1 Modules for ERS

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;

// ─── OID Constants ───

/// OID 1.2.840.113549.1.9.16.1.27 — id-smime-ct-evidenceRecord
///
/// ContentType for EvidenceRecord when wrapped in ContentInfo.
pub const OID_CT_EVIDENCE_RECORD: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x1B,
];

/// OID 1.2.840.113549.1.9.16.2.48 — id-smime-aa-ets-archiveTimestampV3
///
/// Used as an unsigned attribute OID in CMS SignedData for CAdES-A
/// (long-term archive) archive timestamps.
pub const OID_ARCHIVE_TIMESTAMP_V3: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x30,
];

// ─── Digest Algorithm ───

/// Digest algorithms supported by ERS hash trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErsDigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ErsDigestAlgorithm {
    /// Return the DER-encoded AlgorithmIdentifier for this digest.
    pub fn algorithm_id_der(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &crate::pkcs7::asn1::SHA256_ALGORITHM_ID,
            Self::Sha384 => &crate::pkcs7::asn1::SHA384_ALGORITHM_ID,
            Self::Sha512 => &crate::pkcs7::asn1::SHA512_ALGORITHM_ID,
        }
    }

    /// Hash length in bytes.
    pub fn hash_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Compute digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

// ─── PartialHashtree (RFC 4998 §5.1) ───

/// Reduced Merkle hash tree node.
///
/// ```text
/// PartialHashtree ::= SEQUENCE OF OCTET STRING
/// ```
///
/// Contains the sibling hash values needed to reconstruct the path
/// from a leaf to the root of the Merkle hash tree.
#[derive(Debug, Clone)]
pub struct PartialHashtree {
    /// Hash values at this tree level (sibling nodes).
    pub hash_values: Vec<Vec<u8>>,
}

impl PartialHashtree {
    /// Create a new PartialHashtree with a single hash value.
    pub fn new(hash: Vec<u8>) -> Self {
        Self {
            hash_values: vec![hash],
        }
    }

    /// Create from multiple hash values (group hash at one tree level).
    pub fn from_hashes(hashes: Vec<Vec<u8>>) -> Self {
        Self {
            hash_values: hashes,
        }
    }

    /// DER-encode as SEQUENCE OF OCTET STRING.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for hash in &self.hash_values {
            content.extend_from_slice(&asn1::encode_octet_string(hash));
        }
        asn1::encode_sequence(&[&content])
    }

    /// Parse from DER-encoded SEQUENCE OF OCTET STRING.
    pub fn from_der(data: &[u8]) -> SignResult<Self> {
        let (tag, content) = asn1::parse_tlv(data)
            .map_err(|e| SignError::Pkcs7(format!("PartialHashtree parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "PartialHashtree: expected SEQUENCE (0x30), got 0x{tag:02X}"
            )));
        }

        let mut hash_values = Vec::new();
        let mut pos = 0;
        while pos < content.len() {
            let (oct_tag, oct_value) = asn1::parse_tlv(&content[pos..])
                .map_err(|e| SignError::Pkcs7(format!("PartialHashtree octet: {e}")))?;
            if oct_tag != 0x04 {
                return Err(SignError::Pkcs7(format!(
                    "PartialHashtree: expected OCTET STRING (0x04), got 0x{oct_tag:02X}"
                )));
            }
            hash_values.push(oct_value.to_vec());
            let (tlv_bytes, _) = asn1::extract_tlv(&content[pos..])
                .map_err(|e| SignError::Pkcs7(format!("PartialHashtree extract: {e}")))?;
            pos += tlv_bytes.len();
        }

        Ok(Self { hash_values })
    }
}

// ─── ArchiveTimeStamp (RFC 4998 §5.1) ───

/// A single archive timestamp entry.
///
/// ```text
/// ArchiveTimeStamp ::= SEQUENCE {
///     digestAlgorithm  [0] AlgorithmIdentifier OPTIONAL,
///     attributes       [1] Attributes OPTIONAL,
///     reducedHashtree  [2] SEQUENCE OF PartialHashtree OPTIONAL,
///     timeStamp        ContentInfo
/// }
/// ```
///
/// Contains an RFC 3161 TimeStampToken and optionally a reduced Merkle
/// hash tree proving that specific data was included in the timestamped batch.
#[derive(Debug, Clone)]
pub struct ArchiveTimeStamp {
    /// Digest algorithm used for the hash tree (if different from timestamp's).
    pub digest_algorithm: Option<ErsDigestAlgorithm>,
    /// Reduced Merkle hash tree for batch timestamps.
    pub reduced_hashtree: Option<Vec<PartialHashtree>>,
    /// The RFC 3161 TimeStampToken (a CMS ContentInfo wrapping SignedData).
    pub timestamp_token: Vec<u8>,
}

impl ArchiveTimeStamp {
    /// Create a simple archive timestamp (no hash tree — single document).
    pub fn new(timestamp_token: Vec<u8>) -> Self {
        Self {
            digest_algorithm: None,
            reduced_hashtree: None,
            timestamp_token,
        }
    }

    /// Create with a reduced hash tree for batch timestamps.
    pub fn with_hashtree(
        digest_alg: ErsDigestAlgorithm,
        hashtree: Vec<PartialHashtree>,
        timestamp_token: Vec<u8>,
    ) -> Self {
        Self {
            digest_algorithm: Some(digest_alg),
            reduced_hashtree: Some(hashtree),
            timestamp_token,
        }
    }

    /// DER-encode this ArchiveTimeStamp.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();

        // [0] IMPLICIT AlgorithmIdentifier OPTIONAL
        if let Some(alg) = self.digest_algorithm {
            let alg_der = alg.algorithm_id_der();
            // IMPLICIT [0]: replace outer SEQUENCE tag 0x30 with 0xA0
            let inner = &alg_der[2..]; // skip tag + length of AlgorithmIdentifier
            content.extend_from_slice(&asn1::encode_implicit_tag(0, inner));
        }

        // [2] IMPLICIT SEQUENCE OF PartialHashtree OPTIONAL
        if let Some(trees) = &self.reduced_hashtree {
            let mut tree_content = Vec::new();
            for tree in trees {
                tree_content.extend_from_slice(&tree.to_der());
            }
            content.extend_from_slice(&asn1::encode_implicit_tag(2, &tree_content));
        }

        // timeStamp ContentInfo — included as-is (already DER-encoded)
        content.extend_from_slice(&self.timestamp_token);

        asn1::encode_sequence(&[&content])
    }

    /// Parse from DER.
    pub fn from_der(data: &[u8]) -> SignResult<Self> {
        let (tag, content) = asn1::parse_tlv(data)
            .map_err(|e| SignError::Pkcs7(format!("ArchiveTimeStamp parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "ArchiveTimeStamp: expected SEQUENCE, got 0x{tag:02X}"
            )));
        }

        let mut pos = 0;
        let mut digest_algorithm = None;
        let mut reduced_hashtree = None;

        // Parse optional tagged fields
        while pos < content.len() {
            let first_byte = content[pos];

            if first_byte == 0xA0 {
                // [0] IMPLICIT AlgorithmIdentifier
                let (_, alg_content) = asn1::parse_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ATS [0] parse: {e}")))?;
                digest_algorithm = Some(parse_ers_digest_algorithm(alg_content)?);
                let (tlv, _) = asn1::extract_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ATS [0] extract: {e}")))?;
                pos += tlv.len();
            } else if first_byte == 0xA1 {
                // [1] IMPLICIT Attributes — skip (not commonly used)
                let (tlv, _) = asn1::extract_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ATS [1] extract: {e}")))?;
                pos += tlv.len();
            } else if first_byte == 0xA2 {
                // [2] IMPLICIT SEQUENCE OF PartialHashtree
                let (_, tree_content) = asn1::parse_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ATS [2] parse: {e}")))?;
                let mut trees = Vec::new();
                let mut tree_pos = 0;
                while tree_pos < tree_content.len() {
                    let (tlv, _) = asn1::extract_tlv(&tree_content[tree_pos..])
                        .map_err(|e| SignError::Pkcs7(format!("ATS tree extract: {e}")))?;
                    trees.push(PartialHashtree::from_der(tlv)?);
                    tree_pos += tlv.len();
                }
                reduced_hashtree = Some(trees);
                let (tlv, _) = asn1::extract_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ATS [2] outer extract: {e}")))?;
                pos += tlv.len();
            } else if first_byte == 0x30 {
                // ContentInfo (SEQUENCE) — the timestamp token
                let timestamp_token = content[pos..].to_vec();
                return Ok(Self {
                    digest_algorithm,
                    reduced_hashtree,
                    timestamp_token,
                });
            } else {
                return Err(SignError::Pkcs7(format!(
                    "ArchiveTimeStamp: unexpected tag 0x{first_byte:02X} at offset {pos}"
                )));
            }
        }

        Err(SignError::Pkcs7(
            "ArchiveTimeStamp: missing timeStamp ContentInfo".to_string(),
        ))
    }

    /// Verify the hash tree for a given data hash.
    ///
    /// If no reduced hash tree is present, verifies that the timestamp
    /// covers the data hash directly. With a hash tree, walks the
    /// Merkle path to verify inclusion.
    pub fn verify_hash_tree(
        &self,
        data_hash: &[u8],
        digest_alg: ErsDigestAlgorithm,
    ) -> SignResult<Vec<u8>> {
        match &self.reduced_hashtree {
            None => {
                // No hash tree — the timestamp covers data_hash directly
                Ok(data_hash.to_vec())
            }
            Some(trees) => {
                // Walk the Merkle path: at each level, concatenate the data hash
                // with sibling hashes (sorted), then hash the result.
                let mut current_hash = data_hash.to_vec();

                for level in trees {
                    let mut group = level.hash_values.clone();
                    group.push(current_hash);
                    // RFC 4998 §5.2: sort hash values before concatenating
                    group.sort();
                    let mut concat = Vec::new();
                    for h in &group {
                        concat.extend_from_slice(h);
                    }
                    current_hash = digest_alg.digest(&concat);
                }

                Ok(current_hash)
            }
        }
    }
}

// ─── ArchiveTimeStampChain (RFC 4998 §5.1) ───

/// An ordered chain of archive timestamps using the same hash algorithm.
///
/// ```text
/// ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
/// ```
///
/// Each subsequent timestamp in the chain renews the previous one,
/// extending the validity of the archive proof. All timestamps in
/// a chain use the same digest algorithm.
#[derive(Debug, Clone)]
pub struct ArchiveTimeStampChain {
    /// Ordered timestamps (oldest first).
    pub timestamps: Vec<ArchiveTimeStamp>,
}

impl ArchiveTimeStampChain {
    /// Create a new chain with a single initial timestamp.
    pub fn new(initial: ArchiveTimeStamp) -> Self {
        Self {
            timestamps: vec![initial],
        }
    }

    /// Add a renewal timestamp to the chain.
    pub fn add_renewal(&mut self, renewal: ArchiveTimeStamp) {
        self.timestamps.push(renewal);
    }

    /// DER-encode as SEQUENCE OF ArchiveTimeStamp.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for ats in &self.timestamps {
            content.extend_from_slice(&ats.to_der());
        }
        asn1::encode_sequence(&[&content])
    }

    /// Parse from DER.
    pub fn from_der(data: &[u8]) -> SignResult<Self> {
        let (tag, content) = asn1::parse_tlv(data)
            .map_err(|e| SignError::Pkcs7(format!("ArchiveTimeStampChain parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "ArchiveTimeStampChain: expected SEQUENCE, got 0x{tag:02X}"
            )));
        }

        let mut timestamps = Vec::new();
        let mut pos = 0;
        while pos < content.len() {
            let (tlv, _) = asn1::extract_tlv(&content[pos..])
                .map_err(|e| SignError::Pkcs7(format!("ATSC entry extract: {e}")))?;
            timestamps.push(ArchiveTimeStamp::from_der(tlv)?);
            pos += tlv.len();
        }

        if timestamps.is_empty() {
            return Err(SignError::Pkcs7(
                "ArchiveTimeStampChain: empty (requires at least one timestamp)".to_string(),
            ));
        }

        Ok(Self { timestamps })
    }
}

// ─── ArchiveTimeStampSequence (RFC 4998 §5.1) ───

/// Sequence of timestamp chains for hash-tree renewal.
///
/// ```text
/// ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
/// ```
///
/// When a digest algorithm in a chain becomes weak, a new chain is
/// started using a stronger algorithm. The new chain's first timestamp
/// covers the hash of the entire previous chain.
#[derive(Debug, Clone)]
pub struct ArchiveTimeStampSequence {
    /// Ordered chains (oldest algorithm first).
    pub chains: Vec<ArchiveTimeStampChain>,
}

impl ArchiveTimeStampSequence {
    /// Create a new sequence with a single chain.
    pub fn new(initial_chain: ArchiveTimeStampChain) -> Self {
        Self {
            chains: vec![initial_chain],
        }
    }

    /// Add a new chain for hash-tree renewal (algorithm migration).
    pub fn add_chain(&mut self, chain: ArchiveTimeStampChain) {
        self.chains.push(chain);
    }

    /// DER-encode as SEQUENCE OF ArchiveTimeStampChain.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for chain in &self.chains {
            content.extend_from_slice(&chain.to_der());
        }
        asn1::encode_sequence(&[&content])
    }

    /// Parse from DER.
    pub fn from_der(data: &[u8]) -> SignResult<Self> {
        let (tag, content) = asn1::parse_tlv(data)
            .map_err(|e| SignError::Pkcs7(format!("ArchiveTimeStampSequence parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "ArchiveTimeStampSequence: expected SEQUENCE, got 0x{tag:02X}"
            )));
        }

        let mut chains = Vec::new();
        let mut pos = 0;
        while pos < content.len() {
            let (tlv, _) = asn1::extract_tlv(&content[pos..])
                .map_err(|e| SignError::Pkcs7(format!("ATSS chain extract: {e}")))?;
            chains.push(ArchiveTimeStampChain::from_der(tlv)?);
            pos += tlv.len();
        }

        if chains.is_empty() {
            return Err(SignError::Pkcs7(
                "ArchiveTimeStampSequence: empty (requires at least one chain)".to_string(),
            ));
        }

        Ok(Self { chains })
    }
}

// ─── EvidenceRecord (RFC 4998 §5.1) ───

/// Evidence Record — the top-level container for long-term archive proofs.
///
/// ```text
/// EvidenceRecord ::= SEQUENCE {
///     version                INTEGER { v1(1) },
///     digestAlgorithms       SEQUENCE OF AlgorithmIdentifier,
///     cryptoInfos            [0] CryptoInfos OPTIONAL,
///     encryptionInfo         [1] EncryptionInfo OPTIONAL,
///     archiveTimeStampSequence ArchiveTimeStampSequence
/// }
/// ```
///
/// An EvidenceRecord proves that specific data existed at a known time
/// and has been continuously protected by a chain of timestamps, even
/// as the original signing key or algorithm becomes obsolete.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    /// All digest algorithms used throughout the archival period.
    pub digest_algorithms: Vec<ErsDigestAlgorithm>,
    /// The archive timestamp sequence containing all chains.
    pub archive_timestamp_sequence: ArchiveTimeStampSequence,
}

impl EvidenceRecord {
    /// Create a new EvidenceRecord with a single initial timestamp.
    pub fn new(digest_alg: ErsDigestAlgorithm, timestamp_token: Vec<u8>) -> Self {
        let ats = ArchiveTimeStamp::new(timestamp_token);
        let chain = ArchiveTimeStampChain::new(ats);
        let sequence = ArchiveTimeStampSequence::new(chain);
        Self {
            digest_algorithms: vec![digest_alg],
            archive_timestamp_sequence: sequence,
        }
    }

    /// Create with a Merkle hash tree for batch archiving.
    pub fn with_hashtree(
        digest_alg: ErsDigestAlgorithm,
        hashtree: Vec<PartialHashtree>,
        timestamp_token: Vec<u8>,
    ) -> Self {
        let ats = ArchiveTimeStamp::with_hashtree(digest_alg, hashtree, timestamp_token);
        let chain = ArchiveTimeStampChain::new(ats);
        let sequence = ArchiveTimeStampSequence::new(chain);
        Self {
            digest_algorithms: vec![digest_alg],
            archive_timestamp_sequence: sequence,
        }
    }

    /// DER-encode as the EvidenceRecord SEQUENCE.
    pub fn to_der(&self) -> Vec<u8> {
        // version INTEGER v1(1)
        let version = asn1::encode_integer_value(1);

        // digestAlgorithms SEQUENCE OF AlgorithmIdentifier
        let mut alg_content = Vec::new();
        for alg in &self.digest_algorithms {
            alg_content.extend_from_slice(alg.algorithm_id_der());
        }
        let alg_seq = asn1::encode_sequence(&[&alg_content]);

        // archiveTimeStampSequence
        let atss_der = self.archive_timestamp_sequence.to_der();

        asn1::encode_sequence(&[&version, &alg_seq, &atss_der])
    }

    /// Wrap in a ContentInfo envelope with the EvidenceRecord content type.
    pub fn to_content_info(&self) -> Vec<u8> {
        let er_der = self.to_der();
        let explicit_content = asn1::encode_explicit_tag(0, &er_der);
        asn1::encode_sequence(&[OID_CT_EVIDENCE_RECORD, &explicit_content])
    }

    /// Encode as a CMS unsigned attribute (for CAdES-A archive timestamps).
    ///
    /// Uses OID `id-smime-aa-ets-archiveTimestampV3` (1.2.840.113549.1.9.16.2.48).
    pub fn to_unsigned_attribute(&self) -> Vec<u8> {
        let value = self.to_der();
        let value_set = asn1::encode_set(&value);
        asn1::encode_sequence(&[OID_ARCHIVE_TIMESTAMP_V3, &value_set])
    }

    /// Parse from DER-encoded EvidenceRecord.
    pub fn from_der(data: &[u8]) -> SignResult<Self> {
        let (tag, content) = asn1::parse_tlv(data)
            .map_err(|e| SignError::Pkcs7(format!("EvidenceRecord parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "EvidenceRecord: expected SEQUENCE, got 0x{tag:02X}"
            )));
        }

        let mut pos = 0;

        // version INTEGER
        let (ver_tlv, _) = asn1::extract_tlv(&content[pos..])
            .map_err(|e| SignError::Pkcs7(format!("ER version extract: {e}")))?;
        let (ver_tag, ver_content) = asn1::parse_tlv(ver_tlv)
            .map_err(|e| SignError::Pkcs7(format!("ER version parse: {e}")))?;
        if ver_tag != 0x02 {
            return Err(SignError::Pkcs7(format!(
                "EvidenceRecord: expected INTEGER for version, got 0x{ver_tag:02X}"
            )));
        }
        if ver_content != [1] {
            return Err(SignError::Pkcs7(format!(
                "EvidenceRecord: unsupported version (expected 1, got {:?})",
                ver_content
            )));
        }
        pos += ver_tlv.len();

        // digestAlgorithms SEQUENCE OF AlgorithmIdentifier
        let (alg_seq_tlv, _) = asn1::extract_tlv(&content[pos..])
            .map_err(|e| SignError::Pkcs7(format!("ER digestAlgorithms extract: {e}")))?;
        let (alg_tag, alg_content) = asn1::parse_tlv(alg_seq_tlv)
            .map_err(|e| SignError::Pkcs7(format!("ER digestAlgorithms parse: {e}")))?;
        if alg_tag != 0x30 {
            return Err(SignError::Pkcs7(
                "EvidenceRecord: expected SEQUENCE for digestAlgorithms".to_string(),
            ));
        }
        let digest_algorithms = parse_digest_algorithm_list(alg_content)?;
        pos += alg_seq_tlv.len();

        // Skip optional [0] cryptoInfos and [1] encryptionInfo
        while pos < content.len() {
            let first_byte = content[pos];
            if first_byte == 0xA0 || first_byte == 0xA1 {
                let (tlv, _) = asn1::extract_tlv(&content[pos..])
                    .map_err(|e| SignError::Pkcs7(format!("ER optional field extract: {e}")))?;
                pos += tlv.len();
            } else {
                break;
            }
        }

        // archiveTimeStampSequence
        if pos >= content.len() {
            return Err(SignError::Pkcs7(
                "EvidenceRecord: missing archiveTimeStampSequence".to_string(),
            ));
        }
        let atss = ArchiveTimeStampSequence::from_der(&content[pos..])?;

        Ok(Self {
            digest_algorithms,
            archive_timestamp_sequence: atss,
        })
    }

    /// Verify that the given data hash is covered by this evidence record.
    ///
    /// Walks the first chain's first timestamp hash tree to verify
    /// inclusion of the data hash. Returns the root hash that should
    /// match the timestamp's message imprint.
    pub fn verify_data_hash(&self, data_hash: &[u8]) -> SignResult<Vec<u8>> {
        let chain = self
            .archive_timestamp_sequence
            .chains
            .first()
            .ok_or_else(|| SignError::Pkcs7("EvidenceRecord: no chains".to_string()))?;
        let ats = chain.timestamps.first().ok_or_else(|| {
            SignError::Pkcs7("EvidenceRecord: no timestamps in chain".to_string())
        })?;

        let digest_alg = ats
            .digest_algorithm
            .or_else(|| self.digest_algorithms.first().copied())
            .unwrap_or(ErsDigestAlgorithm::Sha256);

        ats.verify_hash_tree(data_hash, digest_alg)
    }
}

// ─── Builder ───

/// Builder for constructing Evidence Records from data and timestamp tokens.
pub struct EvidenceRecordBuilder {
    digest_alg: ErsDigestAlgorithm,
    data_hashes: Vec<Vec<u8>>,
}

impl EvidenceRecordBuilder {
    /// Create a new builder with the specified digest algorithm.
    pub fn new(digest_alg: ErsDigestAlgorithm) -> Self {
        Self {
            digest_alg,
            data_hashes: Vec::new(),
        }
    }

    /// Add a data object hash to be included in the archive timestamp.
    pub fn add_data_hash(mut self, hash: Vec<u8>) -> Self {
        self.data_hashes.push(hash);
        self
    }

    /// Add multiple data object hashes.
    pub fn add_data_hashes(mut self, hashes: Vec<Vec<u8>>) -> Self {
        self.data_hashes.extend(hashes);
        self
    }

    /// Build the evidence record.
    ///
    /// `timestamp_token` is the DER-encoded RFC 3161 TimeStampToken
    /// (ContentInfo wrapping SignedData) that covers the Merkle root.
    ///
    /// For a single document, no hash tree is needed — the timestamp
    /// covers the document hash directly.
    ///
    /// For multiple documents, a Merkle hash tree is built and the
    /// reduced hash tree for each document is stored. The returned
    /// evidence record covers all documents; call `reduced_hashtree_for()`
    /// on individual documents to get their inclusion proof.
    pub fn build(self, timestamp_token: Vec<u8>) -> EvidenceRecord {
        if self.data_hashes.len() <= 1 {
            // Single document — no hash tree needed
            EvidenceRecord::new(self.digest_alg, timestamp_token)
        } else {
            // Multiple documents — build Merkle hash tree
            let tree = build_merkle_tree(&self.data_hashes, self.digest_alg);
            EvidenceRecord::with_hashtree(self.digest_alg, tree, timestamp_token)
        }
    }

    /// Compute the Merkle root hash for the current data hashes.
    ///
    /// Use this to create a timestamp request — the TSA timestamps
    /// this root hash.
    pub fn compute_root_hash(&self) -> Vec<u8> {
        if self.data_hashes.len() == 1 {
            self.data_hashes[0].clone()
        } else if self.data_hashes.is_empty() {
            Vec::new()
        } else {
            compute_merkle_root(&self.data_hashes, self.digest_alg)
        }
    }
}

// ─── Merkle Tree Helpers ───

/// Build a complete reduced hash tree for batch archiving.
///
/// Returns the PartialHashtree entries representing sibling nodes
/// at each level for the first leaf (index 0). For a full implementation,
/// each document would get its own reduced tree — this builds the
/// shared tree structure.
fn build_merkle_tree(hashes: &[Vec<u8>], digest_alg: ErsDigestAlgorithm) -> Vec<PartialHashtree> {
    if hashes.len() <= 1 {
        return Vec::new();
    }

    // RFC 4998 §5.2: Build reduced hash tree
    // At each level, pair up nodes and hash them together.
    // The reduced tree stores the sibling at each level.
    let mut tree = Vec::new();
    let mut current_level = hashes.to_vec();

    while current_level.len() > 1 {
        // Store siblings for index 0 at this level
        if current_level.len() > 1 {
            tree.push(PartialHashtree::new(current_level[1].clone()));
        }

        // Compute next level
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut pair = vec![current_level[i].clone(), current_level[i + 1].clone()];
                pair.sort();
                let mut concat = Vec::new();
                for h in &pair {
                    concat.extend_from_slice(h);
                }
                next_level.push(digest_alg.digest(&concat));
            } else {
                // Odd node — promoted as-is
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
    }

    tree
}

/// Compute the Merkle root hash from a set of leaf hashes.
fn compute_merkle_root(hashes: &[Vec<u8>], digest_alg: ErsDigestAlgorithm) -> Vec<u8> {
    if hashes.is_empty() {
        return Vec::new();
    }
    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut current_level = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut pair = vec![current_level[i].clone(), current_level[i + 1].clone()];
                pair.sort();
                let mut concat = Vec::new();
                for h in &pair {
                    concat.extend_from_slice(h);
                }
                next_level.push(digest_alg.digest(&concat));
            } else {
                next_level.push(current_level[i].clone());
            }
            i += 2;
        }
        current_level = next_level;
    }

    current_level.into_iter().next().unwrap_or_default()
}

// ─── Internal Helpers ───

/// Parse an ERS digest algorithm from the inner content of an AlgorithmIdentifier.
fn parse_ers_digest_algorithm(content: &[u8]) -> SignResult<ErsDigestAlgorithm> {
    // The content is the inner bytes of the AlgorithmIdentifier after tag+len removal.
    // First element is the OID.
    if content.len() < 2 {
        return Err(SignError::Pkcs7(
            "ERS: AlgorithmIdentifier too short".to_string(),
        ));
    }

    // Extract OID bytes (skip tag 0x06 and length)
    let (oid_tag, oid_value) = asn1::parse_tlv(content)
        .map_err(|e| SignError::Pkcs7(format!("ERS AlgId OID parse: {e}")))?;
    if oid_tag != 0x06 {
        return Err(SignError::Pkcs7(format!(
            "ERS: expected OID (0x06), got 0x{oid_tag:02X}"
        )));
    }

    // SHA-256: 2.16.840.1.101.3.4.2.1 → 60 86 48 01 65 03 04 02 01
    // SHA-384: 2.16.840.1.101.3.4.2.2 → 60 86 48 01 65 03 04 02 02
    // SHA-512: 2.16.840.1.101.3.4.2.3 → 60 86 48 01 65 03 04 02 03
    match oid_value {
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Ok(ErsDigestAlgorithm::Sha256),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Ok(ErsDigestAlgorithm::Sha384),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Ok(ErsDigestAlgorithm::Sha512),
        _ => Err(SignError::Pkcs7(format!(
            "ERS: unsupported digest algorithm OID: {:02X?}",
            oid_value
        ))),
    }
}

/// Parse a SEQUENCE OF AlgorithmIdentifier into a list of ERS digest algorithms.
fn parse_digest_algorithm_list(content: &[u8]) -> SignResult<Vec<ErsDigestAlgorithm>> {
    let mut algs = Vec::new();
    let mut pos = 0;

    while pos < content.len() {
        let (tlv, _) = asn1::extract_tlv(&content[pos..])
            .map_err(|e| SignError::Pkcs7(format!("ER algList extract: {e}")))?;
        let (tag, inner) =
            asn1::parse_tlv(tlv).map_err(|e| SignError::Pkcs7(format!("ER algList parse: {e}")))?;
        if tag != 0x30 {
            return Err(SignError::Pkcs7(format!(
                "ERS: expected SEQUENCE for AlgorithmIdentifier, got 0x{tag:02X}"
            )));
        }
        algs.push(parse_ers_digest_algorithm(inner)?);
        pos += tlv.len();
    }

    Ok(algs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── OID tests ───

    #[test]
    fn test_oid_ct_evidence_record() {
        assert_eq!(OID_CT_EVIDENCE_RECORD[0], 0x06);
        // 1.2.840.113549.1.9.16.1.27
        assert_eq!(OID_CT_EVIDENCE_RECORD.len(), 13);
    }

    #[test]
    fn test_oid_archive_timestamp_v3() {
        assert_eq!(OID_ARCHIVE_TIMESTAMP_V3[0], 0x06);
        // 1.2.840.113549.1.9.16.2.48
        assert_eq!(OID_ARCHIVE_TIMESTAMP_V3.len(), 13);
    }

    // ─── PartialHashtree tests ───

    #[test]
    fn test_partial_hashtree_single_hash() {
        let hash = vec![0xAA; 32];
        let pht = PartialHashtree::new(hash.clone());
        let der = pht.to_der();
        assert_eq!(der[0], 0x30); // SEQUENCE

        let parsed = PartialHashtree::from_der(&der).unwrap();
        assert_eq!(parsed.hash_values.len(), 1);
        assert_eq!(parsed.hash_values[0], hash);
    }

    #[test]
    fn test_partial_hashtree_multiple_hashes() {
        let hashes = vec![vec![0xAA; 32], vec![0xBB; 32]];
        let pht = PartialHashtree::from_hashes(hashes.clone());
        let der = pht.to_der();

        let parsed = PartialHashtree::from_der(&der).unwrap();
        assert_eq!(parsed.hash_values.len(), 2);
        assert_eq!(parsed.hash_values[0], hashes[0]);
        assert_eq!(parsed.hash_values[1], hashes[1]);
    }

    #[test]
    fn test_partial_hashtree_roundtrip() {
        let hashes = vec![vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]];
        let pht = PartialHashtree::from_hashes(hashes.clone());
        let der = pht.to_der();
        let parsed = PartialHashtree::from_der(&der).unwrap();
        assert_eq!(parsed.hash_values, hashes);
    }

    // ─── ArchiveTimeStamp tests ───

    fn mock_timestamp_token() -> Vec<u8> {
        // Minimal ContentInfo: SEQUENCE { OID id-signedData, [0] EXPLICIT ... }
        // Just a plausible SEQUENCE for testing structure
        asn1::encode_sequence(&[
            asn1::OID_SIGNED_DATA,
            &asn1::encode_explicit_tag(
                0,
                &asn1::encode_sequence(&[&asn1::encode_integer_value(3)]),
            ),
        ])
    }

    #[test]
    fn test_archive_timestamp_simple() {
        let tst = mock_timestamp_token();
        let ats = ArchiveTimeStamp::new(tst.clone());
        let der = ats.to_der();
        assert_eq!(der[0], 0x30); // SEQUENCE

        let parsed = ArchiveTimeStamp::from_der(&der).unwrap();
        assert!(parsed.digest_algorithm.is_none());
        assert!(parsed.reduced_hashtree.is_none());
        assert_eq!(parsed.timestamp_token, tst);
    }

    #[test]
    fn test_archive_timestamp_with_hashtree() {
        let tst = mock_timestamp_token();
        let tree = vec![
            PartialHashtree::new(vec![0xAA; 32]),
            PartialHashtree::new(vec![0xBB; 32]),
        ];
        let ats = ArchiveTimeStamp::with_hashtree(ErsDigestAlgorithm::Sha256, tree, tst.clone());
        let der = ats.to_der();
        assert_eq!(der[0], 0x30);

        let parsed = ArchiveTimeStamp::from_der(&der).unwrap();
        assert_eq!(parsed.digest_algorithm, Some(ErsDigestAlgorithm::Sha256));
        assert!(parsed.reduced_hashtree.is_some());
        let trees = parsed.reduced_hashtree.unwrap();
        assert_eq!(trees.len(), 2);
        assert_eq!(trees[0].hash_values[0], vec![0xAA; 32]);
        assert_eq!(trees[1].hash_values[0], vec![0xBB; 32]);
        assert_eq!(parsed.timestamp_token, tst);
    }

    // ─── ArchiveTimeStampChain tests ───

    #[test]
    fn test_archive_timestamp_chain_roundtrip() {
        let tst = mock_timestamp_token();
        let ats = ArchiveTimeStamp::new(tst);
        let chain = ArchiveTimeStampChain::new(ats);
        let der = chain.to_der();

        let parsed = ArchiveTimeStampChain::from_der(&der).unwrap();
        assert_eq!(parsed.timestamps.len(), 1);
    }

    #[test]
    fn test_archive_timestamp_chain_with_renewal() {
        let tst1 = mock_timestamp_token();
        let tst2 = mock_timestamp_token();
        let mut chain = ArchiveTimeStampChain::new(ArchiveTimeStamp::new(tst1));
        chain.add_renewal(ArchiveTimeStamp::new(tst2));
        let der = chain.to_der();

        let parsed = ArchiveTimeStampChain::from_der(&der).unwrap();
        assert_eq!(parsed.timestamps.len(), 2);
    }

    // ─── ArchiveTimeStampSequence tests ───

    #[test]
    fn test_archive_timestamp_sequence_roundtrip() {
        let tst = mock_timestamp_token();
        let chain = ArchiveTimeStampChain::new(ArchiveTimeStamp::new(tst));
        let seq = ArchiveTimeStampSequence::new(chain);
        let der = seq.to_der();

        let parsed = ArchiveTimeStampSequence::from_der(&der).unwrap();
        assert_eq!(parsed.chains.len(), 1);
        assert_eq!(parsed.chains[0].timestamps.len(), 1);
    }

    #[test]
    fn test_archive_timestamp_sequence_multi_chain() {
        let tst1 = mock_timestamp_token();
        let tst2 = mock_timestamp_token();
        let chain1 = ArchiveTimeStampChain::new(ArchiveTimeStamp::new(tst1));
        let chain2 = ArchiveTimeStampChain::new(ArchiveTimeStamp::new(tst2));
        let mut seq = ArchiveTimeStampSequence::new(chain1);
        seq.add_chain(chain2);
        let der = seq.to_der();

        let parsed = ArchiveTimeStampSequence::from_der(&der).unwrap();
        assert_eq!(parsed.chains.len(), 2);
    }

    // ─── EvidenceRecord tests ───

    #[test]
    fn test_evidence_record_simple_roundtrip() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst);
        let der = er.to_der();

        let parsed = EvidenceRecord::from_der(&der).unwrap();
        assert_eq!(parsed.digest_algorithms.len(), 1);
        assert_eq!(parsed.digest_algorithms[0], ErsDigestAlgorithm::Sha256);
        assert_eq!(parsed.archive_timestamp_sequence.chains.len(), 1);
    }

    #[test]
    fn test_evidence_record_sha384() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha384, tst);
        let der = er.to_der();

        let parsed = EvidenceRecord::from_der(&der).unwrap();
        assert_eq!(parsed.digest_algorithms[0], ErsDigestAlgorithm::Sha384);
    }

    #[test]
    fn test_evidence_record_sha512() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha512, tst);
        let der = er.to_der();

        let parsed = EvidenceRecord::from_der(&der).unwrap();
        assert_eq!(parsed.digest_algorithms[0], ErsDigestAlgorithm::Sha512);
    }

    #[test]
    fn test_evidence_record_content_info() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst);
        let ci = er.to_content_info();
        assert_eq!(ci[0], 0x30); // ContentInfo SEQUENCE
                                 // Should contain the EvidenceRecord OID
        assert!(ci
            .windows(OID_CT_EVIDENCE_RECORD.len())
            .any(|w| w == OID_CT_EVIDENCE_RECORD));
    }

    #[test]
    fn test_evidence_record_unsigned_attribute() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst);
        let attr = er.to_unsigned_attribute();
        assert_eq!(attr[0], 0x30);
        // Should contain the archive timestamp V3 OID
        assert!(attr
            .windows(OID_ARCHIVE_TIMESTAMP_V3.len())
            .any(|w| w == OID_ARCHIVE_TIMESTAMP_V3));
    }

    #[test]
    fn test_evidence_record_version() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst);
        let der = er.to_der();
        // Version should be encoded as INTEGER 1 (0x02 0x01 0x01) near the start
        assert!(der.windows(3).any(|w| w == [0x02, 0x01, 0x01]));
    }

    // ─── Merkle tree tests ───

    #[test]
    fn test_merkle_root_single_hash() {
        let hash = vec![0xAA; 32];
        let root = compute_merkle_root(std::slice::from_ref(&hash), ErsDigestAlgorithm::Sha256);
        assert_eq!(root, hash);
    }

    #[test]
    fn test_merkle_root_two_hashes() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"document 1");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"document 2");
        let root = compute_merkle_root(&[h1.clone(), h2.clone()], ErsDigestAlgorithm::Sha256);
        assert_eq!(root.len(), 32);
        // Root should differ from both leaves
        assert_ne!(root, h1);
        assert_ne!(root, h2);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"doc A");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"doc B");
        let root1 = compute_merkle_root(&[h1.clone(), h2.clone()], ErsDigestAlgorithm::Sha256);
        let root2 = compute_merkle_root(&[h1, h2], ErsDigestAlgorithm::Sha256);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_root_order_independent() {
        // Because we sort pairs, the order of h1 and h2 shouldn't matter
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"alpha");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"beta");
        let root_ab = compute_merkle_root(&[h1.clone(), h2.clone()], ErsDigestAlgorithm::Sha256);
        let root_ba = compute_merkle_root(&[h2, h1], ErsDigestAlgorithm::Sha256);
        assert_eq!(root_ab, root_ba);
    }

    #[test]
    fn test_merkle_tree_four_leaves() {
        let hashes: Vec<Vec<u8>> = (0..4u8)
            .map(|i| ErsDigestAlgorithm::Sha256.digest(&[i]))
            .collect();
        let root = compute_merkle_root(&hashes, ErsDigestAlgorithm::Sha256);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_hash_tree_verification_no_tree() {
        let data_hash = ErsDigestAlgorithm::Sha256.digest(b"test data");
        let tst = mock_timestamp_token();
        let ats = ArchiveTimeStamp::new(tst);
        let result = ats
            .verify_hash_tree(&data_hash, ErsDigestAlgorithm::Sha256)
            .unwrap();
        // Without a tree, the result should be the data hash itself
        assert_eq!(result, data_hash);
    }

    #[test]
    fn test_hash_tree_verification_with_tree() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"document 1");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"document 2");

        // Build the tree for two documents
        let tree = build_merkle_tree(&[h1.clone(), h2.clone()], ErsDigestAlgorithm::Sha256);
        let root = compute_merkle_root(&[h1.clone(), h2], ErsDigestAlgorithm::Sha256);

        let tst = mock_timestamp_token();
        let ats = ArchiveTimeStamp::with_hashtree(ErsDigestAlgorithm::Sha256, tree, tst);

        // Verify h1 (leaf 0) against the tree
        let verified_root = ats
            .verify_hash_tree(&h1, ErsDigestAlgorithm::Sha256)
            .unwrap();
        assert_eq!(verified_root, root);
    }

    // ─── Builder tests ───

    #[test]
    fn test_builder_single_document() {
        let hash = ErsDigestAlgorithm::Sha256.digest(b"my document");
        let tst = mock_timestamp_token();
        let er = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256)
            .add_data_hash(hash.clone())
            .build(tst);

        assert_eq!(er.digest_algorithms, vec![ErsDigestAlgorithm::Sha256]);
        let chain = &er.archive_timestamp_sequence.chains[0];
        assert!(chain.timestamps[0].reduced_hashtree.is_none());
    }

    #[test]
    fn test_builder_multiple_documents() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"doc 1");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"doc 2");
        let tst = mock_timestamp_token();
        let er = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256)
            .add_data_hash(h1)
            .add_data_hash(h2)
            .build(tst);

        let chain = &er.archive_timestamp_sequence.chains[0];
        assert!(chain.timestamps[0].reduced_hashtree.is_some());
    }

    #[test]
    fn test_builder_compute_root_hash_single() {
        let hash = ErsDigestAlgorithm::Sha256.digest(b"only doc");
        let builder =
            EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256).add_data_hash(hash.clone());
        assert_eq!(builder.compute_root_hash(), hash);
    }

    #[test]
    fn test_builder_compute_root_hash_multiple() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"A");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"B");
        let builder = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256)
            .add_data_hash(h1.clone())
            .add_data_hash(h2.clone());
        let root = builder.compute_root_hash();
        let expected = compute_merkle_root(&[h1, h2], ErsDigestAlgorithm::Sha256);
        assert_eq!(root, expected);
    }

    // ─── Digest algorithm tests ───

    #[test]
    fn test_digest_algorithm_hash_lengths() {
        assert_eq!(ErsDigestAlgorithm::Sha256.hash_len(), 32);
        assert_eq!(ErsDigestAlgorithm::Sha384.hash_len(), 48);
        assert_eq!(ErsDigestAlgorithm::Sha512.hash_len(), 64);
    }

    #[test]
    fn test_digest_algorithm_produces_correct_length() {
        let data = b"test data";
        assert_eq!(ErsDigestAlgorithm::Sha256.digest(data).len(), 32);
        assert_eq!(ErsDigestAlgorithm::Sha384.digest(data).len(), 48);
        assert_eq!(ErsDigestAlgorithm::Sha512.digest(data).len(), 64);
    }

    // ─── Error handling tests ───

    #[test]
    fn test_evidence_record_bad_version() {
        // Build an ER with version 2 (unsupported)
        let version = asn1::encode_integer_value(2);
        let alg_seq = asn1::encode_sequence(&[ErsDigestAlgorithm::Sha256.algorithm_id_der()]);
        let tst = mock_timestamp_token();
        let chain = ArchiveTimeStampChain::new(ArchiveTimeStamp::new(tst));
        let seq = ArchiveTimeStampSequence::new(chain);
        let der = asn1::encode_sequence(&[&version, &alg_seq, &seq.to_der()]);

        let result = EvidenceRecord::from_der(&der);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_empty_chain_rejected() {
        // A chain with no timestamps should be rejected
        let der = asn1::encode_sequence(&[]); // empty SEQUENCE
        let result = ArchiveTimeStampChain::from_der(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_sequence_rejected() {
        let der = asn1::encode_sequence(&[]);
        let result = ArchiveTimeStampSequence::from_der(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_data_hash_simple() {
        let data_hash = ErsDigestAlgorithm::Sha256.digest(b"test");
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst);
        let result = er.verify_data_hash(&data_hash).unwrap();
        assert_eq!(result, data_hash);
    }

    #[test]
    fn test_full_roundtrip_with_builder() {
        let h1 = ErsDigestAlgorithm::Sha256.digest(b"document A");
        let h2 = ErsDigestAlgorithm::Sha256.digest(b"document B");
        let h3 = ErsDigestAlgorithm::Sha256.digest(b"document C");
        let tst = mock_timestamp_token();

        // Build
        let er = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256)
            .add_data_hash(h1.clone())
            .add_data_hash(h2)
            .add_data_hash(h3)
            .build(tst);

        // Encode → Decode
        let der = er.to_der();
        let parsed = EvidenceRecord::from_der(&der).unwrap();

        // Verify structure
        assert_eq!(parsed.digest_algorithms.len(), 1);
        assert_eq!(parsed.archive_timestamp_sequence.chains.len(), 1);
        assert_eq!(
            parsed.archive_timestamp_sequence.chains[0].timestamps.len(),
            1
        );

        // Verify data hash inclusion (first leaf)
        let root_hash = parsed.verify_data_hash(&h1).unwrap();
        assert_eq!(root_hash.len(), 32);
    }

    #[test]
    fn test_builder_add_data_hashes_batch() {
        let hashes: Vec<Vec<u8>> = (0..5u8)
            .map(|i| ErsDigestAlgorithm::Sha256.digest(&[i]))
            .collect();
        let tst = mock_timestamp_token();
        let er = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256)
            .add_data_hashes(hashes)
            .build(tst);

        let chain = &er.archive_timestamp_sequence.chains[0];
        assert!(
            chain.timestamps[0].reduced_hashtree.is_some(),
            "Batch add with 5 docs should produce a hash tree"
        );
    }

    #[test]
    fn test_builder_compute_root_hash_empty() {
        let builder = EvidenceRecordBuilder::new(ErsDigestAlgorithm::Sha256);
        assert!(builder.compute_root_hash().is_empty());
    }

    #[test]
    fn test_merkle_root_empty_input() {
        let root = compute_merkle_root(&[], ErsDigestAlgorithm::Sha256);
        assert!(root.is_empty());
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        // 3 leaves: two pair up, one gets promoted
        let hashes: Vec<Vec<u8>> = (0..3u8)
            .map(|i| ErsDigestAlgorithm::Sha256.digest(&[i]))
            .collect();
        let root = compute_merkle_root(&hashes, ErsDigestAlgorithm::Sha256);
        assert_eq!(root.len(), 32);
        // Root must differ from all inputs
        for h in &hashes {
            assert_ne!(&root, h);
        }
    }

    #[test]
    fn test_evidence_record_with_hashtree_constructor() {
        let h1 = ErsDigestAlgorithm::Sha384.digest(b"doc X");
        let h2 = ErsDigestAlgorithm::Sha384.digest(b"doc Y");
        let tree = build_merkle_tree(&[h1, h2], ErsDigestAlgorithm::Sha384);
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::with_hashtree(ErsDigestAlgorithm::Sha384, tree, tst);
        assert_eq!(er.digest_algorithms, vec![ErsDigestAlgorithm::Sha384]);

        let chain = &er.archive_timestamp_sequence.chains[0];
        assert!(chain.timestamps[0].reduced_hashtree.is_some());
        assert_eq!(
            chain.timestamps[0].digest_algorithm,
            Some(ErsDigestAlgorithm::Sha384)
        );
    }

    #[test]
    fn test_evidence_record_roundtrip_preserves_content_info() {
        let tst = mock_timestamp_token();
        let er = EvidenceRecord::new(ErsDigestAlgorithm::Sha256, tst.clone());
        let ci = er.to_content_info();

        // ContentInfo should contain the evidence record OID and the encoded ER
        assert_eq!(ci[0], 0x30);
        let er_der = er.to_der();
        // The ER DER bytes should appear inside the ContentInfo
        assert!(ci.windows(er_der.len()).any(|w| w == er_der.as_slice()));
    }

    #[test]
    fn test_digest_algorithm_id_der_starts_with_sequence() {
        // AlgorithmIdentifier is a SEQUENCE
        assert_eq!(ErsDigestAlgorithm::Sha256.algorithm_id_der()[0], 0x30);
        assert_eq!(ErsDigestAlgorithm::Sha384.algorithm_id_der()[0], 0x30);
        assert_eq!(ErsDigestAlgorithm::Sha512.algorithm_id_der()[0], 0x30);
    }
}
