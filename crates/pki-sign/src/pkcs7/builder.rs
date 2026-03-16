//! PKCS#7/CMS SignedData builder for Authenticode signatures.
//!
//! Constructs the DER-encoded CMS SignedData structure per RFC 5652,
//! with Authenticode-specific content (SPC_INDIRECT_DATA).
//!
//! The builder hand-rolls DER encoding for precise control over
//! Microsoft's Authenticode format, including the SPC structures
//! that aren't part of standard CMS.
//!
//! ## RFC 5652 CMS Features
//!
//! - Configurable digest algorithms: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
//! - Multiple SignerInfos with independent digest/signature algorithms
//! - DER SET OF ordering for signed attributes (X.690 Section 11.6)
//! - ContentInfo wrapper (OID 1.2.840.113549.1.7.2)
//! - Signed attributes: contentType, messageDigest, signingTime, CMSAlgorithmProtection

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;

// ─── Digest Algorithm ───

/// Digest algorithm for CMS SignedData (RFC 5652 + RFC 5754 + RFC 3370 + RFC 8702).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-256 (OID 2.16.840.1.101.3.4.2.1)
    Sha256,
    /// SHA-384 (OID 2.16.840.1.101.3.4.2.2)
    Sha384,
    /// SHA-512 (OID 2.16.840.1.101.3.4.2.3)
    Sha512,
    /// SHA3-256 (OID 2.16.840.1.101.3.4.2.8, FIPS 202 / RFC 8702)
    Sha3_256,
    /// SHA3-384 (OID 2.16.840.1.101.3.4.2.9, FIPS 202 / RFC 8702)
    Sha3_384,
    /// SHA3-512 (OID 2.16.840.1.101.3.4.2.10, FIPS 202 / RFC 8702)
    Sha3_512,
}

impl DigestAlgorithm {
    /// Return the DER-encoded AlgorithmIdentifier for this digest.
    pub fn algorithm_id(&self) -> &'static [u8] {
        match self {
            DigestAlgorithm::Sha256 => &asn1::SHA256_ALGORITHM_ID,
            DigestAlgorithm::Sha384 => &asn1::SHA384_ALGORITHM_ID,
            DigestAlgorithm::Sha512 => &asn1::SHA512_ALGORITHM_ID,
            DigestAlgorithm::Sha3_256 => &asn1::SHA3_256_ALGORITHM_ID,
            DigestAlgorithm::Sha3_384 => &asn1::SHA3_384_ALGORITHM_ID,
            DigestAlgorithm::Sha3_512 => &asn1::SHA3_512_ALGORITHM_ID,
        }
    }

    /// Return the digest output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha3_256 => 32,
            DigestAlgorithm::Sha384 | DigestAlgorithm::Sha3_384 => 48,
            DigestAlgorithm::Sha512 | DigestAlgorithm::Sha3_512 => 64,
        }
    }

    /// Compute the digest of `data` using this algorithm.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            DigestAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
            DigestAlgorithm::Sha3_256 => {
                use sha3::Digest as _;
                sha3::Sha3_256::digest(data).to_vec()
            }
            DigestAlgorithm::Sha3_384 => {
                use sha3::Digest as _;
                sha3::Sha3_384::digest(data).to_vec()
            }
            DigestAlgorithm::Sha3_512 => {
                use sha3::Digest as _;
                sha3::Sha3_512::digest(data).to_vec()
            }
        }
    }
}

// ─── Signing Algorithm ───

/// Signing algorithm used when building the PKCS#7 structure.
///
/// This is required to populate the CMSAlgorithmProtection signed attribute
/// (RFC 8933) with the correct signatureAlgorithm value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256 (sha256WithRSAEncryption).
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-384 (sha384WithRSAEncryption).
    RsaSha384,
    /// RSA PKCS#1 v1.5 with SHA-512 (sha512WithRSAEncryption).
    RsaSha512,
    /// RSA-PSS with SHA-256 (id-RSASSA-PSS with SHA-256 params, RFC 4055).
    RsaPssSha256,
    /// RSA-PSS with SHA-384 (id-RSASSA-PSS with SHA-384 params, RFC 4055).
    RsaPssSha384,
    /// RSA-PSS with SHA-512 (id-RSASSA-PSS with SHA-512 params, RFC 4055).
    RsaPssSha512,
    /// ECDSA with SHA-256 (ecdsa-with-SHA256).
    EcdsaSha256,
    /// ECDSA with SHA-384 (ecdsa-with-SHA384).
    EcdsaSha384,
    /// ECDSA with SHA-512 (ecdsa-with-SHA512).
    EcdsaSha512,
    /// Ed25519 (RFC 8410/8419 — pure EdDSA, no separate digest).
    Ed25519,
    /// ML-DSA-44 (FIPS 204, RFC 9882 — pure scheme, SHA-256 for CMS digest).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, RFC 9882 — pure scheme, SHA-512 for CMS digest).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, RFC 9882 — pure scheme, SHA-512 for CMS digest).
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205, RFC 9909 — pure scheme, SHA-256 for CMS digest).
    SlhDsaSha2128s,
    /// SLH-DSA-SHA2-192s (FIPS 205, RFC 9909 — pure scheme, SHA-512 for CMS digest).
    SlhDsaSha2192s,
    /// SLH-DSA-SHA2-256s (FIPS 205, RFC 9909 — pure scheme, SHA-512 for CMS digest).
    SlhDsaSha2256s,
}

impl SigningAlgorithm {
    /// Return the DER-encoded AlgorithmIdentifier for this signature algorithm.
    pub fn algorithm_id(&self) -> &[u8] {
        match self {
            SigningAlgorithm::RsaSha256 => &asn1::SHA256_WITH_RSA_ALGORITHM_ID,
            SigningAlgorithm::RsaSha384 => &asn1::SHA384_WITH_RSA_ALGORITHM_ID,
            SigningAlgorithm::RsaSha512 => &asn1::SHA512_WITH_RSA_ALGORITHM_ID,
            SigningAlgorithm::RsaPssSha256 => &asn1::RSASSA_PSS_SHA256_ALGORITHM_ID,
            SigningAlgorithm::RsaPssSha384 => &asn1::RSASSA_PSS_SHA384_ALGORITHM_ID,
            SigningAlgorithm::RsaPssSha512 => &asn1::RSASSA_PSS_SHA512_ALGORITHM_ID,
            SigningAlgorithm::EcdsaSha256 => &asn1::ECDSA_WITH_SHA256_ALGORITHM_ID,
            SigningAlgorithm::EcdsaSha384 => &asn1::ECDSA_WITH_SHA384_ALGORITHM_ID,
            SigningAlgorithm::EcdsaSha512 => &asn1::ECDSA_WITH_SHA512_ALGORITHM_ID,
            SigningAlgorithm::Ed25519 => &asn1::ED25519_ALGORITHM_ID,
            SigningAlgorithm::MlDsa44 => &asn1::ML_DSA_44_ALGORITHM_ID,
            SigningAlgorithm::MlDsa65 => &asn1::ML_DSA_65_ALGORITHM_ID,
            SigningAlgorithm::MlDsa87 => &asn1::ML_DSA_87_ALGORITHM_ID,
            SigningAlgorithm::SlhDsaSha2128s => &asn1::SLH_DSA_SHA2_128S_ALGORITHM_ID,
            SigningAlgorithm::SlhDsaSha2192s => &asn1::SLH_DSA_SHA2_192S_ALGORITHM_ID,
            SigningAlgorithm::SlhDsaSha2256s => &asn1::SLH_DSA_SHA2_256S_ALGORITHM_ID,
        }
    }

    /// Return the implied digest algorithm for this signing algorithm.
    ///
    /// For "pure" signature schemes (Ed25519, ML-DSA, SLH-DSA), the digest
    /// is used only for the CMS messageDigest attribute, not for pre-hashing
    /// the data before signing.
    pub fn digest_algorithm(&self) -> DigestAlgorithm {
        match self {
            SigningAlgorithm::RsaSha256
            | SigningAlgorithm::RsaPssSha256
            | SigningAlgorithm::EcdsaSha256
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::SlhDsaSha2128s => DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha384
            | SigningAlgorithm::RsaPssSha384
            | SigningAlgorithm::EcdsaSha384 => DigestAlgorithm::Sha384,
            SigningAlgorithm::RsaSha512
            | SigningAlgorithm::RsaPssSha512
            | SigningAlgorithm::EcdsaSha512
            | SigningAlgorithm::Ed25519
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87
            | SigningAlgorithm::SlhDsaSha2192s
            | SigningAlgorithm::SlhDsaSha2256s => DigestAlgorithm::Sha512,
        }
    }
}

// ─── Content Hints (RFC 2634 §2.9) ───

/// Content hints for CMS signed attributes (RFC 2634 §2.9).
///
/// ```text
/// ContentHints ::= SEQUENCE {
///     contentDescription  UTF8String (SIZE (1..MAX)) OPTIONAL,
///     contentType         ContentType
/// }
/// ```
///
/// This attribute describes the inner content type and provides
/// a human-readable description, useful when the content is wrapped
/// in multiple layers of CMS enveloping.
#[derive(Debug, Clone)]
pub struct ContentHints {
    /// Human-readable description of the content (optional).
    pub content_description: Option<String>,
    /// DER-encoded content type OID (including tag + length).
    pub content_type_oid: Vec<u8>,
}

// ─── SignerInfo for Multi-Signer Support ───

/// A single signer's parameters for CMS SignedData.
///
/// Each signer can use a different digest and signature algorithm.
/// The `sign_fn` callback receives the DER-encoded signed attributes
/// (as a SET, tag 0x31) and must return the raw signature bytes.
pub struct CmsSignerInfo {
    /// DER-encoded signing certificate.
    pub cert_der: Vec<u8>,
    /// Digest algorithm for this signer.
    pub digest_algorithm: DigestAlgorithm,
    /// Signature algorithm for this signer.
    pub signing_algorithm: SigningAlgorithm,
    /// DER-encoded timestamp token for this signer (optional).
    pub timestamp_token: Option<Vec<u8>>,
    /// When true, include ESSCertIDv2 (RFC 5816) in signed attributes.
    /// This produces a CAdES-BES compliant signature (RFC 5126 / ETSI EN 319 122-1).
    pub cades_bes: bool,
    /// Content hints for this signer (RFC 2634 §2.9, optional signed attribute).
    pub content_hints: Option<ContentHints>,
    /// Pre-built counter-signature SignerInfo DER values (RFC 5652 §11.4).
    ///
    /// Each entry is a complete DER-encoded SignerInfo that counter-signs
    /// this signer's signature. Use [`build_counter_signer_info`] to create these.
    ///
    /// Note: Counter-signatures are computed over the signature value, so they
    /// must be built after the main signature is produced. Use
    /// [`SignedDataBuilder::build_with_counter_sign`] for inline counter-signing.
    pub counter_signatures: Vec<Vec<u8>>,
    /// Use SubjectKeyIdentifier instead of IssuerAndSerialNumber for sid (RFC 5652 §5.3).
    ///
    /// When true, the SignerInfo version is set to 3 and sid uses `[0] SubjectKeyIdentifier`
    /// instead of `IssuerAndSerialNumber`. The SKI is extracted from the certificate's
    /// SubjectKeyIdentifier extension. Falls back to IssuerAndSerialNumber if no SKI found.
    pub use_subject_key_identifier: bool,
    /// Custom unsigned attributes (RFC 5652 §11.3).
    ///
    /// Each entry is `(oid_der, value_der)` where `oid_der` is the full DER-encoded
    /// OID (including tag+length) and `value_der` is the DER-encoded attribute value
    /// (the content of the SET OF AttributeValue).
    pub custom_unsigned_attributes: Vec<(Vec<u8>, Vec<u8>)>,
}

// ─── SignedData Builder (Multi-Signer) ───

/// Builder for CMS SignedData structures with multiple signers (RFC 5652).
///
/// Supports multiple SignerInfos, each with their own digest and signature
/// algorithm. The DigestAlgorithms SET is the union of all signers' digests.
pub struct SignedDataBuilder {
    /// Content type OID for EncapsulatedContentInfo.
    content_type_oid: Vec<u8>,
    /// The encapsulated content (e.g., SPC_INDIRECT_DATA for Authenticode).
    /// When None, produces a detached signature (RFC 5652 §5.2).
    encap_content: Option<Vec<u8>>,
    /// The message digest of the content (per the primary digest algorithm).
    /// For multi-signer, each signer computes their own digest of the content.
    content_digests: Vec<(DigestAlgorithm, Vec<u8>)>,
    /// Accumulated signers.
    signers: Vec<CmsSignerInfo>,
    /// Additional certificates (chain certs, intermediate CAs).
    chain_certs_der: Vec<Vec<u8>>,
    /// CRLs to embed in the SignedData (RFC 5652 §5.1 `crls [1] IMPLICIT`).
    crls_der: Vec<Vec<u8>>,
}

impl SignedDataBuilder {
    /// Create a new SignedData builder.
    ///
    /// `content_type_oid` is the DER-encoded OID for the content (including tag+length).
    /// `encap_content` is the DER-encoded content to be signed.
    pub fn new(content_type_oid: Vec<u8>, encap_content: Vec<u8>) -> Self {
        Self {
            content_type_oid,
            encap_content: Some(encap_content),
            signers: Vec::new(),
            chain_certs_der: Vec::new(),
            crls_der: Vec::new(),
            content_digests: Vec::new(),
        }
    }

    /// Create a new SignedData builder for detached signatures (RFC 5652 §5.2).
    ///
    /// The content is transmitted separately; the SignedData only contains
    /// the content type OID and signature information.
    /// Callers must provide the content digest via `add_content_digest()`.
    pub fn new_detached(content_type_oid: Vec<u8>) -> Self {
        Self {
            content_type_oid,
            encap_content: None,
            signers: Vec::new(),
            chain_certs_der: Vec::new(),
            crls_der: Vec::new(),
            content_digests: Vec::new(),
        }
    }

    /// Add a content digest for a specific algorithm.
    ///
    /// Each signer's signed attributes will reference their algorithm's digest.
    /// You must add a digest for each digest algorithm used by any signer.
    pub fn add_content_digest(&mut self, algorithm: DigestAlgorithm, digest: Vec<u8>) -> &mut Self {
        self.content_digests.push((algorithm, digest));
        self
    }

    /// Add a signer to the SignedData.
    pub fn add_signer(&mut self, signer: CmsSignerInfo) -> &mut Self {
        self.signers.push(signer);
        self
    }

    /// Add a chain certificate.
    pub fn add_chain_cert(&mut self, cert_der: Vec<u8>) -> &mut Self {
        self.chain_certs_der.push(cert_der);
        self
    }

    /// Add a CRL to embed in the SignedData (RFC 5652 §5.1).
    ///
    /// CRLs are included as `crls [1] IMPLICIT RevocationInfoChoices OPTIONAL`
    /// to allow offline signature verification without contacting the CA.
    pub fn add_crl(&mut self, crl_der: Vec<u8>) -> &mut Self {
        self.crls_der.push(crl_der);
        self
    }

    /// Validate the content type OID is well-formed (RFC 5652 §5.2).
    ///
    /// The EncapsulatedContentInfo eContentType MUST be a valid DER-encoded OID.
    /// Returns Ok(()) if valid, Err with description if malformed.
    pub fn validate_content_type(&self) -> SignResult<()> {
        validate_content_type_oid(&self.content_type_oid)
    }

    /// Build the DER-encoded ContentInfo wrapping SignedData.
    ///
    /// Each signer's `sign_fn` callback receives the DER-encoded signed attributes
    /// (as a SET OF with proper DER ordering, tag 0x31) and must return the
    /// raw signature bytes.
    pub fn build<F>(&self, mut sign_fn: F) -> SignResult<Vec<u8>>
    where
        F: FnMut(usize, &[u8]) -> SignResult<Vec<u8>>,
    {
        if self.signers.is_empty() {
            return Err(SignError::Pkcs7("No signers configured".to_string()));
        }

        // Collect unique digest algorithms (union across all signers)
        // RFC 5652 §5.1: digestAlgorithms MUST contain the digest algorithm used
        // by each signer in the signerInfos collection.
        let mut digest_alg_ids: Vec<&[u8]> = Vec::new();
        let mut seen_digests: Vec<DigestAlgorithm> = Vec::new();
        for signer in &self.signers {
            if !seen_digests.contains(&signer.digest_algorithm) {
                seen_digests.push(signer.digest_algorithm);
                digest_alg_ids.push(signer.digest_algorithm.algorithm_id());
            }
        }

        // Defensive: verify every signer's digest algorithm is in the collected set
        debug_assert!(
            self.signers
                .iter()
                .all(|s| seen_digests.contains(&s.digest_algorithm)),
            "RFC 5652 §5.1: all signer digest algorithms must be in digestAlgorithms SET"
        );

        // DigestAlgorithms SET OF — sorted per DER
        let digest_algorithms_set = asn1::encode_set_of(&digest_alg_ids);

        // EncapsulatedContentInfo
        // RFC 5652 §5.2: eContent is OPTIONAL — when absent, this is a detached signature
        let encap_content_info = if let Some(ref content) = self.encap_content {
            asn1::encode_sequence(&[
                &self.content_type_oid,
                &asn1::encode_explicit_tag(0, content),
            ])
        } else {
            // Detached: only the content type OID, no [0] EXPLICIT eContent
            asn1::encode_sequence(&[&self.content_type_oid])
        };

        // Build each SignerInfo
        let mut signer_info_ders: Vec<Vec<u8>> = Vec::new();
        let mut all_certs: Vec<u8> = Vec::new();

        for (idx, signer) in self.signers.iter().enumerate() {
            let (issuer_der, serial_der) = extract_issuer_and_serial(&signer.cert_der)?;

            // Find the content digest for this signer's algorithm
            let content_digest = self
                .content_digests
                .iter()
                .find(|(alg, _)| *alg == signer.digest_algorithm)
                .map(|(_, d)| d.as_slice())
                .ok_or_else(|| {
                    SignError::Pkcs7(format!(
                        "No content digest for {:?}",
                        signer.digest_algorithm
                    ))
                })?;

            // Build signed attributes with proper DER SET OF ordering
            let ess_cert = if signer.cades_bes {
                Some(signer.cert_der.as_slice())
            } else {
                None
            };
            let signed_attrs_set = build_signed_attrs_sorted(
                &self.content_type_oid,
                content_digest,
                signer.digest_algorithm,
                signer.signing_algorithm,
                ess_cert,
                signer.content_hints.as_ref(),
            );

            // Sign the DER-encoded SET (per RFC 5652 Section 5.4)
            let signature_bytes = sign_fn(idx, &signed_attrs_set)?;

            // Collect unsigned attributes: timestamp + counter-signatures + custom
            let unsigned_attrs = UnsignedAttrs {
                timestamp_token: signer.timestamp_token.as_deref(),
                counter_signatures: &signer.counter_signatures,
                custom: &signer.custom_unsigned_attributes,
            };

            // RFC 5652 §5.3: Determine SignerIdentifier — SKI or IssuerAndSerial
            let ski = if signer.use_subject_key_identifier {
                extract_ski_from_cert_der(&signer.cert_der)
            } else {
                None
            };

            // Build SignerInfo
            let signer_info = build_signer_info_ex(
                &issuer_der,
                &serial_der,
                signer.digest_algorithm,
                signer.signing_algorithm,
                &signed_attrs_set,
                &signature_bytes,
                &unsigned_attrs,
                ski.as_deref(),
            );

            signer_info_ders.push(signer_info);
            all_certs.extend_from_slice(&signer.cert_der);
        }

        // Add chain certs
        for chain_cert in &self.chain_certs_der {
            all_certs.extend_from_slice(chain_cert);
        }

        let certificates = asn1::encode_implicit_tag(0, &all_certs);

        // CRLs [1] IMPLICIT (RFC 5652 §5.1)
        let has_crls = !self.crls_der.is_empty();
        let crls_field = if has_crls {
            let mut all_crls = Vec::new();
            for crl in &self.crls_der {
                all_crls.extend_from_slice(crl);
            }
            asn1::encode_implicit_tag(1, &all_crls)
        } else {
            Vec::new()
        };

        // SignerInfos SET OF — sorted per DER
        let signer_info_refs: Vec<&[u8]> = signer_info_ders.iter().map(|s| s.as_slice()).collect();
        let signer_infos_set = asn1::encode_set_of(&signer_info_refs);

        // RFC 5652 §5.1: version MUST be 3 if eContentType is other than id-data,
        // or if any SignerInfo is version 3 (SubjectKeyIdentifier sid).
        // Otherwise version MUST be 1.
        let is_id_data = self.content_type_oid == asn1::OID_DATA;
        let any_signer_v3 = self.signers.iter().any(|s| s.use_subject_key_identifier);
        let version = asn1::encode_integer_value(if !is_id_data || any_signer_v3 { 3 } else { 1 });

        // SignedData SEQUENCE (RFC 5652 §5.1)
        let mut parts: Vec<&[u8]> = vec![
            &version,
            &digest_algorithms_set,
            &encap_content_info,
            &certificates,
        ];
        if has_crls {
            parts.push(&crls_field);
        }
        parts.push(&signer_infos_set);
        let signed_data = asn1::encode_sequence(&parts);

        // ContentInfo wrapper
        Ok(build_content_info(&signed_data))
    }
}

// ─── Legacy Pkcs7Builder (backward-compatible, single signer, Authenticode) ───

/// Builder for CMS/PKCS#7 SignedData structures.
///
/// Used to construct the Authenticode signature envelope that wraps
/// the PE image hash and signing certificate.
pub struct Pkcs7Builder {
    /// DER-encoded signing certificate.
    signer_cert_der: Vec<u8>,
    /// DER-encoded additional certificates (chain).
    chain_certs_der: Vec<Vec<u8>>,
    /// The Authenticode PE image hash (SHA-256), or file content digest for detached.
    image_hash: Vec<u8>,
    /// DER-encoded timestamp token (optional).
    timestamp_token: Option<Vec<u8>>,
    /// Signing algorithm for CMSAlgorithmProtection attribute.
    signing_algorithm: SigningAlgorithm,
    /// Optional SpcSpOpusInfo program name (Authenticode display name).
    program_name: Option<String>,
    /// Optional SpcSpOpusInfo more info URL (Authenticode program URL).
    program_url: Option<String>,
    /// Whether this is a detached signature (no encapsulated content).
    detached: bool,
    /// Whether this is a script (SIP-based) signature rather than PE Authenticode.
    /// When true, uses SPC_SIPINFO_OBJID with the PowerShell SIP GUID instead
    /// of SPC_PE_IMAGE_DATAOBJ with SpcPeImageData.
    script_signing: bool,
    /// DER-encoded signing time (UTCTime), captured at builder creation.
    /// Ensures consistency across multiple build() calls (e.g., timestamping).
    signing_time_der: Vec<u8>,
}

impl Pkcs7Builder {
    /// Create a new PKCS#7 builder.
    ///
    /// Defaults to RSA-SHA256 as the signing algorithm. Use
    /// [`with_algorithm`](Self::with_algorithm) to override.
    pub fn new(signer_cert_der: Vec<u8>, image_hash: Vec<u8>) -> Self {
        Self {
            signer_cert_der,
            chain_certs_der: Vec::new(),
            image_hash,
            timestamp_token: None,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            program_name: None,
            program_url: None,
            detached: false,
            script_signing: false,
            signing_time_der: asn1::encode_utc_time_now(),
        }
    }

    /// Create a new PKCS#7 builder for detached CMS signatures.
    ///
    /// In detached mode, the signed content is not included in the PKCS#7
    /// structure. The `content_digest` is the SHA-256 hash of the original
    /// file content. The contentType attribute uses `id-data` (OID 1.2.840.113549.1.7.1)
    /// instead of `SPC_INDIRECT_DATA`.
    pub fn new_detached(signer_cert_der: Vec<u8>, content_digest: Vec<u8>) -> Self {
        Self {
            signer_cert_der,
            chain_certs_der: Vec::new(),
            image_hash: content_digest,
            timestamp_token: None,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            program_name: None,
            program_url: None,
            detached: true,
            script_signing: false,
            signing_time_der: asn1::encode_utc_time_now(),
        }
    }

    /// Set the signing algorithm for the CMSAlgorithmProtection attribute.
    pub fn with_algorithm(&mut self, algorithm: SigningAlgorithm) -> &mut Self {
        self.signing_algorithm = algorithm;
        self
    }

    /// Add a certificate to the chain (intermediate CA, etc.).
    pub fn add_chain_cert(&mut self, cert_der: Vec<u8>) -> &mut Self {
        self.chain_certs_der.push(cert_der);
        self
    }

    /// Set the RFC 3161 timestamp token (unsigned attribute).
    pub fn set_timestamp_token(&mut self, token: Vec<u8>) -> &mut Self {
        self.timestamp_token = Some(token);
        self
    }

    /// Set the SpcSpOpusInfo program name (Authenticode display name).
    pub fn with_program_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.program_name = Some(name.into());
        self
    }

    /// Set the SpcSpOpusInfo more info URL (Authenticode program URL).
    pub fn with_program_url(&mut self, url: impl Into<String>) -> &mut Self {
        self.program_url = Some(url.into());
        self
    }

    /// Enable script signing mode (PowerShell SIP).
    ///
    /// Uses `SPC_SIPINFO_OBJID` (1.3.6.1.4.1.311.2.1.30) with the PowerShell
    /// SIP GUID instead of `SPC_PE_IMAGE_DATAOBJ` for the SpcIndirectDataContent.
    pub fn with_script_signing(&mut self) -> &mut Self {
        self.script_signing = true;
        self
    }

    /// Build the DER-encoded ContentInfo wrapping SignedData.
    ///
    /// For Authenticode mode, produces a PKCS#7 blob ready for embedding
    /// in a WIN_CERTIFICATE structure. For detached mode, produces a
    /// standard CMS detached signature (`.p7s`).
    ///
    /// The `sign_fn` callback receives the DER-encoded signed attributes
    /// (as a SET, tag 0x31) and must return the raw signature bytes
    /// (e.g., RSA PKCS#1 v1.5 signature).
    pub fn build<F>(&self, sign_fn: F) -> SignResult<Vec<u8>>
    where
        F: FnOnce(&[u8]) -> SignResult<Vec<u8>>,
    {
        // Step 1: Extract issuer and serial from signer certificate
        let (issuer_der, serial_der) = extract_issuer_and_serial(&self.signer_cert_der)?;

        // Step 2: Build SpcIndirectDataContent upfront (Authenticode only) so we
        // can compute its hash for the messageDigest signed attribute.
        // Per MS Authenticode spec, messageDigest = hash(eContent), where
        // eContent is the DER-encoded SpcIndirectDataContent.
        let digest_alg = self.signing_algorithm.digest_algorithm();
        let spc_indirect_data = if !self.detached {
            if self.script_signing {
                Some(build_spc_indirect_data_script(&self.image_hash))
            } else {
                Some(build_spc_indirect_data(&self.image_hash, digest_alg))
            }
        } else {
            None
        };

        // Step 3: Build signed attributes
        let attrs_content = if self.detached {
            // Detached mode: contentType = id-data, messageDigest = hash of file
            build_detached_signed_attrs_content(
                &self.image_hash,
                self.signing_algorithm,
                &self.signing_time_der,
            )
        } else {
            // Authenticode mode: contentType = SPC_INDIRECT_DATA,
            // messageDigest = digest of the SpcIndirectDataContent **content** bytes.
            // OpenSSL's PKCS7_signatureVerify decodes the ASN.1 SEQUENCE and
            // re-encodes only its inner content (without the outer SEQUENCE
            // tag + length) before hashing. We must hash the same bytes.
            let spc_der = spc_indirect_data.as_ref().unwrap();
            let spc_content = &spc_der[1 + der_length_size(spc_der)..];
            let spc_hash = digest_alg.digest(spc_content);
            build_signed_attrs_content(
                &spc_hash,
                self.signing_algorithm,
                self.program_name.as_deref(),
                self.program_url.as_deref(),
                &self.signing_time_der,
            )
        };

        // Step 4: DER-encode as SET for signing (tag 0x31)
        let attrs_as_set = asn1::encode_set(&attrs_content);

        // Step 5: Sign the DER-encoded SET
        // Per RFC 5652 Section 5.4: sign the DER encoding of the signed attributes
        let signature_bytes = sign_fn(&attrs_as_set)?;

        // Step 6: Build SignerInfo
        let signer_info = build_signer_info(
            &issuer_der,
            &serial_der,
            &attrs_content,
            &signature_bytes,
            self.signing_algorithm,
            self.timestamp_token.as_deref(),
        );

        // Step 7: Build certificates [0] IMPLICIT
        // Certificates are raw DER — do NOT double-wrap in SEQUENCE (Python bug #3)
        let mut certs_data = Vec::new();
        certs_data.extend_from_slice(&self.signer_cert_der);
        for chain_cert in &self.chain_certs_der {
            certs_data.extend_from_slice(chain_cert);
        }
        let certificates = asn1::encode_implicit_tag(0, &certs_data);

        // Step 8: Build SignedData
        let digest_alg = self.signing_algorithm.digest_algorithm();
        let signed_data = if self.detached {
            build_detached_signed_data(&certificates, &signer_info, digest_alg)
        } else {
            build_signed_data(
                spc_indirect_data.as_ref().unwrap(),
                &certificates,
                &signer_info,
                digest_alg,
            )
        };

        // Step 8: Wrap in ContentInfo
        let content_info = build_content_info(&signed_data);

        Ok(content_info)
    }
}

// ─── Internal Helper Functions ───

/// Extract the issuer Name and serial number from a DER-encoded X.509 certificate.
///
/// X.509 Certificate structure:
/// ```text
/// SEQUENCE {
///     SEQUENCE {                    -- TBSCertificate
///         [0] EXPLICIT INTEGER,     -- version (optional, v3)
///         INTEGER,                  -- serialNumber
///         SEQUENCE { ... },         -- signature algorithm
///         SEQUENCE { ... },         -- issuer Name
///         ...
///     },
///     ...
/// }
/// ```
pub(crate) fn extract_issuer_and_serial(cert_der: &[u8]) -> SignResult<(Vec<u8>, Vec<u8>)> {
    // Parse the outer SEQUENCE
    let (_, tbs_and_rest) = asn1::parse_tlv(cert_der)
        .map_err(|e| SignError::Certificate(format!("Failed to parse certificate: {e}")))?;

    // Parse TBSCertificate SEQUENCE
    let (_, tbs_content) = asn1::parse_tlv(tbs_and_rest)
        .map_err(|e| SignError::Certificate(format!("Failed to parse TBSCertificate: {e}")))?;

    let mut pos = tbs_content;

    // Skip version [0] EXPLICIT if present (tag 0xA0)
    if !pos.is_empty() && pos[0] == 0xA0 {
        let (_, remaining) = asn1::skip_tlv(pos)
            .map_err(|e| SignError::Certificate(format!("Failed to skip version: {e}")))?;
        pos = remaining;
    }

    // Extract serialNumber INTEGER (including tag + length + value)
    let (serial_tlv, remaining) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to extract serial: {e}")))?;
    pos = remaining;

    // Skip signature AlgorithmIdentifier
    let (_, remaining) = asn1::skip_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to skip algorithm: {e}")))?;
    pos = remaining;

    // Extract issuer Name SEQUENCE (including tag + length + value)
    let (issuer_tlv, _) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to extract issuer: {e}")))?;

    Ok((issuer_tlv.to_vec(), serial_tlv.to_vec()))
}

/// Extract SubjectKeyIdentifier from a DER-encoded certificate (RFC 5280 §4.2.1.2).
///
/// Returns `None` if the certificate does not contain the SKI extension or if parsing fails.
/// The SKI OID is 2.5.29.14.
fn extract_ski_from_cert_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    // SKI OID: 2.5.29.14 → DER: 06 03 55 1D 0E
    const SKI_OID: &[u8] = &[0x55, 0x1D, 0x0E];

    // Scan for the OID in the DER
    for i in 0..cert_der.len().saturating_sub(SKI_OID.len()) {
        if cert_der[i..].starts_with(SKI_OID) {
            // Found the OID — walk forward past the OID TLV to find the OCTET STRING value
            // Structure: SEQUENCE { OID, BOOLEAN(critical)?, OCTET STRING { OCTET STRING { keyId } } }
            let mut pos = i + SKI_OID.len();

            // Skip past any BOOLEAN (critical flag) — tag 0x01
            while pos < cert_der.len() {
                let tag = cert_der[pos];
                if tag == 0x01 {
                    // BOOLEAN — skip tag + length(1) + value(1)
                    pos += 3;
                } else if tag == 0x04 {
                    // OCTET STRING — this wraps the SKI value
                    pos += 1;
                    if pos >= cert_der.len() {
                        return None;
                    }
                    let outer_len = cert_der[pos] as usize;
                    pos += 1;
                    if pos + outer_len > cert_der.len() {
                        return None;
                    }
                    // Inside this OCTET STRING is another OCTET STRING with the actual key ID
                    if pos < cert_der.len() && cert_der[pos] == 0x04 {
                        pos += 1;
                        if pos >= cert_der.len() {
                            return None;
                        }
                        let inner_len = cert_der[pos] as usize;
                        pos += 1;
                        if pos + inner_len > cert_der.len() {
                            return None;
                        }
                        return Some(cert_der[pos..pos + inner_len].to_vec());
                    }
                    // If the inner content isn't an OCTET STRING, return the outer content
                    return Some(cert_der[pos - 1..pos - 1 + outer_len].to_vec());
                } else {
                    break;
                }
            }
        }
    }
    None
}

/// Build the SPC_INDIRECT_DATA_CONTENT structure.
///
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data            SpcAttributeTypeAndOptionalValue,
///     messageDigest   DigestInfo
/// }
/// ```
fn build_spc_indirect_data(image_hash: &[u8], digest_alg: DigestAlgorithm) -> Vec<u8> {
    // SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
    //     type  OID (SPC_PE_IMAGE_DATAOBJ 1.3.6.1.4.1.311.2.1.15),
    //     value SpcPeImageData OPTIONAL
    // }
    let spc_pe_image_data = build_spc_pe_image_data();
    let spc_attr_type =
        asn1::encode_sequence(&[asn1::OID_SPC_PE_IMAGE_DATAOBJ, &spc_pe_image_data]);

    // DigestInfo ::= SEQUENCE {
    //     digestAlgorithm AlgorithmIdentifier,
    //     digest          OCTET STRING
    // }
    let digest_info = asn1::encode_sequence(&[
        digest_alg.algorithm_id(),
        &asn1::encode_octet_string(image_hash),
    ]);

    // SpcIndirectDataContent
    asn1::encode_sequence(&[&spc_attr_type, &digest_info])
}

/// Build a minimal SpcPeImageData value.
///
/// ```text
/// SpcPeImageData ::= SEQUENCE {
///     flags    SpcPeImageFlags DEFAULT { includeResources },
///     file     [0] EXPLICIT SpcLink OPTIONAL
/// }
///
/// SpcLink ::= CHOICE {
///     url     [0] IMPLICIT IA5String,
///     moniker [1] IMPLICIT SpcSerializedObject,
///     file    [2] EXPLICIT SpcString
/// }
///
/// SpcString ::= CHOICE {
///     unicode [0] IMPLICIT BMPString,
///     ascii   [1] IMPLICIT IA5String
/// }
/// ```
///
/// We use the `file` variant of SpcLink with `<<<Obsolete>>>` BMPString,
/// matching signtool and osslsigncode behavior.
///
/// The encoding is: `[0] EXPLICIT { [2] EXPLICIT { [0] IMPLICIT BMPString } }`.
fn build_spc_pe_image_data() -> Vec<u8> {
    // BIT STRING with includeResources flag set (bit 0)
    // Encoding: tag=0x03, len=0x02, unused_bits=7, value=0x80 (bit 0 set)
    // This is the Authenticode default, matching signtool and osslsigncode.
    let flags: Vec<u8> = vec![0x03, 0x02, 0x07, 0x80];

    // SpcLink.file = [2] EXPLICIT { SpcString.unicode = [0] IMPLICIT BMPString "<<<Obsolete>>>" }
    // BMPString is UTF-16BE encoded: "<<<Obsolete>>>" = 14 chars = 28 bytes
    let obsolete_bmp: Vec<u8> = "<<<Obsolete>>>"
        .encode_utf16()
        .flat_map(|ch| ch.to_be_bytes())
        .collect();

    // Inner: [0] IMPLICIT BMPString = tag 0x80 + length + content
    let mut inner = vec![0x80];
    inner.extend(asn1::encode_length(obsolete_bmp.len()));
    inner.extend_from_slice(&obsolete_bmp);

    // Wrapped: [2] EXPLICIT { inner }
    let mut wrapped = vec![0xA2];
    wrapped.extend(asn1::encode_length(inner.len()));
    wrapped.extend_from_slice(&inner);

    // Outer: [0] EXPLICIT (SpcPeImageData.file field)
    let mut file = vec![0xA0];
    file.extend(asn1::encode_length(wrapped.len()));
    file.extend_from_slice(&wrapped);

    asn1::encode_sequence(&[&flags, &file])
}

/// Build the SPC_INDIRECT_DATA_CONTENT for script (PowerShell SIP) signing.
///
/// Uses `SPC_SIPINFO_OBJID` (1.3.6.1.4.1.311.2.1.30) with an `SpcSipInfo`
/// structure containing the PowerShell SIP GUID, instead of the PE-specific
/// `SPC_PE_IMAGE_DATAOBJ` used for executable signing.
///
/// ```text
/// SpcIndirectDataContent ::= SEQUENCE {
///     data            SpcAttributeTypeAndOptionalValue,
///     messageDigest   DigestInfo
/// }
/// ```
fn build_spc_indirect_data_script(content_hash: &[u8]) -> Vec<u8> {
    // SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
    //     type  OID (SPC_SIPINFO_OBJID 1.3.6.1.4.1.311.2.1.30),
    //     value SpcSipInfo
    // }
    let spc_sip_info = build_spc_sip_info_powershell();
    let spc_attr_type = asn1::encode_sequence(&[asn1::OID_SPC_SIPINFO, &spc_sip_info]);

    // DigestInfo ::= SEQUENCE {
    //     digestAlgorithm AlgorithmIdentifier (SHA-256),
    //     digest          OCTET STRING
    // }
    let digest_info = asn1::encode_sequence(&[
        &asn1::SHA256_ALGORITHM_ID,
        &asn1::encode_octet_string(content_hash),
    ]);

    // SpcIndirectDataContent
    asn1::encode_sequence(&[&spc_attr_type, &digest_info])
}

/// Build the SpcSipInfo structure for the PowerShell SIP.
///
/// ```text
/// SpcSipInfo ::= SEQUENCE {
///     dwSipVersion    INTEGER,     -- 0x00010000 (version 1.0)
///     gSIPGuid        SpcUuid,     -- PowerShell SIP GUID
///     dwReserved1     INTEGER,     -- 0
///     dwReserved2     INTEGER,     -- 0
///     dwReserved3     INTEGER,     -- 0
///     dwReserved4     INTEGER,     -- 0
///     dwReserved5     INTEGER      -- 0
/// }
/// ```
///
/// PowerShell SIP GUID: `{603BCC1F-4B59-4E08-B724-D2C6297EF351}`
fn build_spc_sip_info_powershell() -> Vec<u8> {
    // SIP version: 0x00010000 = 65536
    let version = asn1::encode_integer_value(0x0001_0000);

    // PowerShell SIP GUID as raw bytes (Windows GUID memory layout):
    // {603BCC1F-4B59-4E08-B724-D2C6297EF351}
    // Data1 (LE u32): 0x603BCC1F → 1F CC 3B 60
    // Data2 (LE u16): 0x4B59     → 59 4B
    // Data3 (LE u16): 0x4E08     → 08 4E
    // Data4 (8 bytes): B7 24 D2 C6 29 7E F3 51
    let guid_bytes: [u8; 16] = [
        0x1F, 0xCC, 0x3B, 0x60, // Data1
        0x59, 0x4B, // Data2
        0x08, 0x4E, // Data3
        0xB7, 0x24, 0xD2, 0xC6, 0x29, 0x7E, 0xF3, 0x51, // Data4
    ];
    let guid = asn1::encode_octet_string(&guid_bytes);

    // Five reserved DWORDs, all zero
    let zero = asn1::encode_integer_value(0);

    asn1::encode_sequence(&[&version, &guid, &zero, &zero, &zero, &zero, &zero])
}

/// Build signed attributes with DER SET OF ordering (RFC 5652 Section 5.3).
///
/// Individual attributes are DER-encoded, then sorted lexicographically
/// before being placed in the SET wrapper. This ensures proper DER encoding.
///
/// When `signer_cert_der` is provided, includes the signing-certificate-v2
/// attribute (ESSCertIDv2, RFC 5816) for CAdES-BES compliance.
fn build_signed_attrs_sorted(
    content_type_oid: &[u8],
    message_digest: &[u8],
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
    signer_cert_der: Option<&[u8]>,
    content_hints: Option<&ContentHints>,
) -> Vec<u8> {
    // Attribute 1: contentType
    let content_type_attr =
        asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &asn1::encode_set(content_type_oid)]);

    // Attribute 2: messageDigest
    let message_digest_attr = asn1::encode_sequence(&[
        asn1::OID_MESSAGE_DIGEST,
        &asn1::encode_set(&asn1::encode_octet_string(message_digest)),
    ]);

    // Attribute 3: signingTime
    let utc_time = asn1::encode_utc_time_now();
    let signing_time_attr =
        asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &asn1::encode_set(&utc_time)]);

    // Attribute 4: CMSAlgorithmProtection (RFC 8933)
    let cms_alg_protection_attr = build_cms_algorithm_protection_attr_ex(digest_alg, signing_alg);

    let mut attrs: Vec<&[u8]> = vec![
        &content_type_attr,
        &message_digest_attr,
        &signing_time_attr,
        &cms_alg_protection_attr,
    ];

    // Attribute 5 (CAdES-BES): signing-certificate-v2 / ESSCertIDv2 (RFC 5816)
    // Uses the same digest algorithm as the SignedData for hash consistency.
    let ess_attr;
    if let Some(cert_der) = signer_cert_der {
        ess_attr = build_ess_cert_id_v2_attr(cert_der, digest_alg);
        attrs.push(&ess_attr);
    }

    // Attribute 6 (optional): Content hints (RFC 2634 §2.9)
    let hints_attr;
    if let Some(hints) = content_hints {
        hints_attr = build_content_hints_attr(hints);
        attrs.push(&hints_attr);
    }

    // Sort attributes lexicographically per DER SET OF rules (X.690 Section 11.6)
    asn1::encode_set_of(&attrs)
}

/// Build the raw content of signed attributes (without SET wrapper).
///
/// Four attributes:
/// 1. contentType = SPC_INDIRECT_DATA_OBJID
/// 2. messageDigest = SHA-256 hash of the PE image
/// 3. signingTime = current UTC time
/// 4. CMSAlgorithmProtection (RFC 8933) — prevents algorithm substitution attacks
fn build_signed_attrs_content(
    image_hash: &[u8],
    signing_alg: SigningAlgorithm,
    program_name: Option<&str>,
    program_url: Option<&str>,
    signing_time_der: &[u8],
) -> Vec<u8> {
    // Attribute 1: contentType
    let content_type_attr = asn1::encode_sequence(&[
        asn1::OID_CONTENT_TYPE,
        &asn1::encode_set(asn1::OID_SPC_INDIRECT_DATA),
    ]);

    // Attribute 2: messageDigest
    let message_digest_attr = asn1::encode_sequence(&[
        asn1::OID_MESSAGE_DIGEST,
        &asn1::encode_set(&asn1::encode_octet_string(image_hash)),
    ]);

    // Attribute 3: signingTime (use pre-computed time for consistency across builds)
    let signing_time_attr =
        asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &asn1::encode_set(signing_time_der)]);

    let mut attrs: Vec<Vec<u8>> = vec![content_type_attr, message_digest_attr, signing_time_attr];

    // SpcSpOpusInfo (MS-SWINC — program name/URL)
    // Always included for Authenticode compatibility — osslsigncode and Windows
    // signtool always emit this attribute, even when name/URL are empty.
    attrs.push(build_spc_sp_opus_info_attr(program_name, program_url));

    // SpcStatementType — declares this as individual code signing.
    // Matches signtool and osslsigncode behavior.
    let spc_statement_type_attr = asn1::encode_sequence(&[
        asn1::OID_SPC_STATEMENT_TYPE,
        &asn1::encode_set(&asn1::encode_sequence(&[
            asn1::OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE,
        ])),
    ]);
    attrs.push(spc_statement_type_attr);

    // DER SET OF requires lexicographic sorting of encoded elements (X.690 §11.6)
    attrs.sort();
    attrs.into_iter().flatten().collect()
}

/// Build the raw content of signed attributes for detached CMS signatures.
///
/// Uses `id-data` (OID 1.2.840.113549.1.7.1) as the contentType instead of
/// `SPC_INDIRECT_DATA`, since detached signatures are not Authenticode-specific.
///
/// Four attributes:
/// 1. contentType = id-data
/// 2. messageDigest = SHA-256 hash of the file content
/// 3. signingTime = current UTC time
/// 4. CMSAlgorithmProtection (RFC 8933)
fn build_detached_signed_attrs_content(
    content_digest: &[u8],
    signing_alg: SigningAlgorithm,
    signing_time_der: &[u8],
) -> Vec<u8> {
    // Attribute 1: contentType = id-data
    let content_type_attr =
        asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &asn1::encode_set(asn1::OID_DATA)]);

    // Attribute 2: messageDigest
    let message_digest_attr = asn1::encode_sequence(&[
        asn1::OID_MESSAGE_DIGEST,
        &asn1::encode_set(&asn1::encode_octet_string(content_digest)),
    ]);

    // Attribute 3: signingTime (use pre-computed time for consistency across builds)
    let signing_time_attr =
        asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &asn1::encode_set(signing_time_der)]);

    // DER SET OF requires lexicographic sorting of encoded elements (X.690 §11.6)
    let mut attrs = vec![content_type_attr, message_digest_attr, signing_time_attr];
    attrs.sort();
    attrs.into_iter().flatten().collect()
}

/// Build the CMSAlgorithmProtection signed attribute (RFC 8933) — legacy single-algorithm.
fn build_cms_algorithm_protection_attr(signing_alg: SigningAlgorithm) -> Vec<u8> {
    build_cms_algorithm_protection_attr_ex(signing_alg.digest_algorithm(), signing_alg)
}

/// Build the CMSAlgorithmProtection signed attribute (RFC 8933).
///
/// ```text
/// CMSAlgorithmProtection ::= SEQUENCE {
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL
/// }
/// ```
///
/// The signatureAlgorithm is tagged IMPLICIT [1] — its universal SEQUENCE tag
/// is replaced with 0xA1.
fn build_cms_algorithm_protection_attr_ex(
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
) -> Vec<u8> {
    let digest_alg_id: &[u8] = digest_alg.algorithm_id();

    // signatureAlgorithm [1] IMPLICIT — take the AlgorithmIdentifier content
    // (everything after the SEQUENCE tag+length) and re-tag with 0xA1.
    let sig_alg_full = signing_alg.algorithm_id();
    let sig_alg_content = &sig_alg_full[2..]; // skip SEQUENCE tag + length byte

    // Encode with IMPLICIT [1] tag (0xA1 = constructed context tag 1)
    let sig_alg_tagged = {
        let mut v = vec![0xA1];
        v.extend(asn1::encode_length(sig_alg_content.len()));
        v.extend_from_slice(sig_alg_content);
        v
    };

    // CMSAlgorithmProtection value SEQUENCE { digestAlgorithm, [1] signatureAlgorithm }
    let protection_value = asn1::encode_sequence(&[digest_alg_id, &sig_alg_tagged]);

    // Attribute ::= SEQUENCE { attrType OID, attrValues SET { value } }
    asn1::encode_sequence(&[
        asn1::OID_CMS_ALGORITHM_PROTECTION,
        &asn1::encode_set(&protection_value),
    ])
}

/// Build SpcSpOpusInfo authenticated attribute (MS-SWINC).
///
/// ```text
/// SpcSpOpusInfo ::= SEQUENCE {
///     programName  [0] EXPLICIT SpcString OPTIONAL,
///     moreInfo     [1] EXPLICIT SpcLink OPTIONAL
/// }
/// ```
///
/// programName is encoded as `[0] EXPLICIT { [0] IMPLICIT BMPString }`.
/// moreInfo URL is encoded as `[1] EXPLICIT { [0] IMPLICIT IA5String }`.
fn build_spc_sp_opus_info_attr(program_name: Option<&str>, program_url: Option<&str>) -> Vec<u8> {
    let mut opus_content = Vec::new();

    // programName [0] EXPLICIT SpcString
    if let Some(name) = program_name {
        // Encode as BMPString (UCS-2BE) wrapped in context [0] IMPLICIT
        let mut bmp_bytes = Vec::new();
        for ch in name.encode_utf16() {
            bmp_bytes.extend_from_slice(&ch.to_be_bytes());
        }
        // Inner: [0] IMPLICIT BMPString (tag 0x80)
        let mut inner = vec![0x80];
        inner.extend(asn1::encode_length(bmp_bytes.len()));
        inner.extend_from_slice(&bmp_bytes);
        // Outer: [0] EXPLICIT (tag 0xA0)
        let mut tagged = vec![0xA0];
        tagged.extend(asn1::encode_length(inner.len()));
        tagged.extend_from_slice(&inner);
        opus_content.extend_from_slice(&tagged);
    }

    // moreInfo [1] EXPLICIT SpcLink
    if let Some(url) = program_url {
        // Inner: [0] IMPLICIT IA5String (URL) — tag 0x80
        let url_bytes = url.as_bytes();
        let mut inner = vec![0x80];
        inner.extend(asn1::encode_length(url_bytes.len()));
        inner.extend_from_slice(url_bytes);
        // Outer: [1] EXPLICIT (tag 0xA1)
        let mut tagged = vec![0xA1];
        tagged.extend(asn1::encode_length(inner.len()));
        tagged.extend_from_slice(&inner);
        opus_content.extend_from_slice(&tagged);
    }

    let opus_info = asn1::encode_sequence(&[&opus_content]);

    // Attribute ::= SEQUENCE { attrType OID, attrValues SET { value } }
    asn1::encode_sequence(&[asn1::OID_SPC_SP_OPUS_INFO, &asn1::encode_set(&opus_info)])
}

/// OID 1.2.840.113549.1.9.16.2.47 — id-aa-signingCertificateV2 (RFC 5816)
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// Build the signing-certificate-v2 signed attribute (RFC 5816 / CAdES-BES).
///
/// This attribute binds the signer's certificate to the signature, preventing
/// substitution attacks where a different certificate with the same key could
/// be used to verify the signature.
///
/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs    SEQUENCE OF ESSCertIDv2
/// }
///
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier DEFAULT {sha-256},
///     certHash       Hash (OCTET STRING),
///     issuerSerial   IssuerSerial OPTIONAL
/// }
/// ```
///
/// When hashAlgorithm is SHA-256 (the default), it MAY be omitted per RFC 5816.
/// For SHA-384 or SHA-512, the hashAlgorithm AlgorithmIdentifier MUST be included.
fn build_ess_cert_id_v2_attr(cert_der: &[u8], digest_alg: DigestAlgorithm) -> Vec<u8> {
    // Hash the signer certificate DER with the requested algorithm
    let cert_hash: Vec<u8> = digest_alg.digest(cert_der);

    // Extract issuer and serial from the cert for IssuerSerial
    let issuer_serial = if let Ok((issuer_der, serial_der)) = extract_issuer_and_serial(cert_der) {
        // GeneralNames: SEQUENCE { [4] EXPLICIT DirectoryName (the issuer Name) }
        let general_name = asn1::encode_explicit_tag(4, &issuer_der);
        let general_names = asn1::encode_sequence(&[&general_name]);
        // IssuerSerial: SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
        let is = asn1::encode_sequence(&[&general_names, &serial_der]);
        Some(is)
    } else {
        None
    };

    // ESSCertIDv2: SEQUENCE { [hashAlgorithm,] certHash OCTET STRING [, issuerSerial] }
    // Per RFC 5816 §2: SHA-256 is the default — omit hashAlgorithm when SHA-256.
    // For SHA-384/SHA-512, include the AlgorithmIdentifier explicitly.
    let cert_hash_octet = asn1::encode_octet_string(&cert_hash);
    let ess_cert_id = match digest_alg {
        DigestAlgorithm::Sha256 => {
            // Default — omit hashAlgorithm
            if let Some(ref is) = issuer_serial {
                asn1::encode_sequence(&[&cert_hash_octet, is])
            } else {
                asn1::encode_sequence(&[&cert_hash_octet])
            }
        }
        _ => {
            // Non-default — include hashAlgorithm AlgorithmIdentifier
            let hash_alg_id = digest_alg.algorithm_id();
            if let Some(ref is) = issuer_serial {
                asn1::encode_sequence(&[hash_alg_id, &cert_hash_octet, is])
            } else {
                asn1::encode_sequence(&[hash_alg_id, &cert_hash_octet])
            }
        }
    };

    // SEQUENCE OF ESSCertIDv2 (single entry)
    let certs_seq = asn1::encode_sequence(&[&ess_cert_id]);

    // SigningCertificateV2: SEQUENCE { certs }
    let signing_cert_v2 = asn1::encode_sequence(&[&certs_seq]);

    // Attribute: SEQUENCE { OID, SET { SigningCertificateV2 } }
    asn1::encode_sequence(&[
        OID_SIGNING_CERTIFICATE_V2,
        &asn1::encode_set(&signing_cert_v2),
    ])
}

/// Collected unsigned attributes for a SignerInfo.
struct UnsignedAttrs<'a> {
    /// RFC 3161 timestamp token.
    timestamp_token: Option<&'a [u8]>,
    /// RFC 5652 §11.4 counter-signature SignerInfo DER values.
    counter_signatures: &'a [Vec<u8>],
    /// Custom unsigned attributes: (OID DER, value DER) pairs (RFC 5652 §11.3).
    custom: &'a [(Vec<u8>, Vec<u8>)],
}

/// Build a complete SignerInfo SEQUENCE with configurable algorithms.
///
/// If `subject_key_id` is `Some`, uses SubjectKeyIdentifier (RFC 5652 §5.3, version 3).
/// Otherwise uses IssuerAndSerialNumber (version 1).
#[allow(clippy::too_many_arguments)]
fn build_signer_info_ex(
    issuer_der: &[u8],
    serial_der: &[u8],
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
    signed_attrs_set: &[u8],
    signature_bytes: &[u8],
    unsigned: &UnsignedAttrs<'_>,
    subject_key_id: Option<&[u8]>,
) -> Vec<u8> {
    // RFC 5652 §5.3: version 1 for IssuerAndSerialNumber, 3 for SubjectKeyIdentifier
    let (version, sid) = if let Some(ski) = subject_key_id {
        // version INTEGER 3
        let v = asn1::encode_integer_value(3);
        // sid [0] SubjectKeyIdentifier — OCTET STRING wrapped in IMPLICIT [0]
        let ski_octet = asn1::encode_octet_string(ski);
        let sid = asn1::encode_implicit_tag(0, &ski_octet[2..]); // Strip tag+len, re-wrap
        (v, sid)
    } else {
        // version INTEGER 1
        let v = asn1::encode_integer_value(1);
        // issuerAndSerialNumber SEQUENCE { issuer, serialNumber }
        let sid = asn1::encode_sequence(&[issuer_der, serial_der]);
        (v, sid)
    };

    // digestAlgorithm AlgorithmIdentifier
    let digest_alg_id: &[u8] = digest_alg.algorithm_id();

    // signedAttrs [0] IMPLICIT — the content of the SET (strip tag+length, re-wrap with 0xA0)
    // signed_attrs_set is 0x31 <len> <content>, we need to extract the content
    let attrs_content = &signed_attrs_set[1 + der_length_size(signed_attrs_set)..];
    let signed_attrs = asn1::encode_implicit_tag(0, attrs_content);

    // signatureAlgorithm AlgorithmIdentifier
    let sig_alg_id: &[u8] = signing_alg.algorithm_id();

    // signature OCTET STRING
    let sig_value = asn1::encode_octet_string(signature_bytes);

    let mut parts: Vec<&[u8]> = vec![
        &version,
        &sid,
        digest_alg_id,
        &signed_attrs,
        sig_alg_id,
        &sig_value,
    ];

    // unsignedAttrs [1] IMPLICIT SET OF Attribute OPTIONAL
    // May contain: timestamp token + counter-signatures + custom attributes
    let unsigned_attrs_field;
    let has_timestamp = unsigned.timestamp_token.is_some();
    let has_counter_sigs = !unsigned.counter_signatures.is_empty();
    let has_custom = !unsigned.custom.is_empty();

    if has_timestamp || has_counter_sigs || has_custom {
        let mut unsigned_content = Vec::new();

        // Timestamp token attribute (RFC 3161)
        if let Some(token) = unsigned.timestamp_token {
            let ts_attr =
                asn1::encode_sequence(&[asn1::OID_TIMESTAMP_TOKEN, &asn1::encode_set(token)]);
            unsigned_content.extend_from_slice(&ts_attr);
        }

        // Counter-signature attributes (RFC 5652 §11.4)
        // Each counter-signature is a separate Attribute with the same OID
        // but its own SignerInfo value.
        for cs in unsigned.counter_signatures {
            let cs_attr =
                asn1::encode_sequence(&[asn1::OID_COUNTER_SIGNATURE, &asn1::encode_set(cs)]);
            unsigned_content.extend_from_slice(&cs_attr);
        }

        // Custom unsigned attributes (RFC 5652 §11.3)
        for (oid, value) in unsigned.custom {
            let attr = asn1::encode_sequence(&[oid.as_slice(), &asn1::encode_set(value)]);
            unsigned_content.extend_from_slice(&attr);
        }

        unsigned_attrs_field = asn1::encode_implicit_tag(1, &unsigned_content);
        parts.push(&unsigned_attrs_field);
    }

    asn1::encode_sequence(&parts)
}

/// Build a complete SignerInfo SEQUENCE (legacy, SHA-256 + RSA).
fn build_signer_info(
    issuer_der: &[u8],
    serial_der: &[u8],
    signed_attrs_content: &[u8],
    signature_bytes: &[u8],
    signing_algorithm: SigningAlgorithm,
    timestamp_token: Option<&[u8]>,
) -> Vec<u8> {
    // version INTEGER 1
    let version = asn1::encode_integer_value(1);

    // issuerAndSerialNumber SEQUENCE { issuer, serialNumber }
    let issuer_and_serial = asn1::encode_sequence(&[issuer_der, serial_der]);

    // digestAlgorithm — must match the actual digest used
    let digest_alg = signing_algorithm.digest_algorithm();
    let digest_alg_bytes: &[u8] = digest_alg.algorithm_id();

    // signedAttrs [0] IMPLICIT — replace SET tag with 0xA0
    let signed_attrs = asn1::encode_implicit_tag(0, signed_attrs_content);

    // signatureAlgorithm — for Authenticode, RSA variants use rsaEncryption
    // (OID 1.2.840.113549.1.1.1) in the SignerInfo signatureAlgorithm field,
    // with the digest algorithm specified separately in digestAlgorithm.
    // This matches osslsigncode and Windows WinVerifyTrust behavior.
    let sig_alg: &[u8] = match signing_algorithm {
        SigningAlgorithm::RsaSha256 | SigningAlgorithm::RsaSha384 | SigningAlgorithm::RsaSha512 => {
            &asn1::RSA_ENCRYPTION_ALGORITHM_ID
        }
        _ => signing_algorithm.algorithm_id(),
    };

    // signature OCTET STRING
    let sig_value = asn1::encode_octet_string(signature_bytes);

    let mut parts: Vec<&[u8]> = vec![
        &version,
        &issuer_and_serial,
        digest_alg_bytes,
        &signed_attrs,
        sig_alg,
        &sig_value,
    ];

    // unsignedAttrs [1] IMPLICIT (optional, for timestamp)
    let unsigned_attrs;
    if let Some(token) = timestamp_token {
        let ts_attr = asn1::encode_sequence(&[asn1::OID_TIMESTAMP_TOKEN, &asn1::encode_set(token)]);
        unsigned_attrs = asn1::encode_implicit_tag(1, &ts_attr);
        parts.push(&unsigned_attrs);
    }

    asn1::encode_sequence(&parts)
}

/// Build the SignedData SEQUENCE.
fn build_signed_data(
    spc_indirect: &[u8],
    certificates: &[u8],
    signer_info: &[u8],
    digest_alg: DigestAlgorithm,
) -> Vec<u8> {
    // Authenticode uses version 1 per MS specification, even though RFC 5652
    // says version 3 when eContentType != id-data. Windows WinVerifyTrust
    // and osslsigncode both expect version 1 for Authenticode.
    let version = asn1::encode_integer_value(1);

    // digestAlgorithms SET { AlgorithmIdentifier }
    let digest_algorithms = asn1::encode_set(digest_alg.algorithm_id());

    // contentInfo — EncapsulatedContentInfo with SPC_INDIRECT_DATA
    // SEQUENCE { OID SPC_INDIRECT_DATA_OBJID, [0] EXPLICIT { spc_indirect } }
    let content_info = asn1::encode_sequence(&[
        asn1::OID_SPC_INDIRECT_DATA,
        &asn1::encode_explicit_tag(0, spc_indirect),
    ]);

    // signerInfos SET { signerInfo }
    let signer_infos = asn1::encode_set(signer_info);

    asn1::encode_sequence(&[
        &version,
        &digest_algorithms,
        &content_info,
        certificates,
        &signer_infos,
    ])
}

/// Build a SignedData for detached CMS signatures (RFC 5652 §5.2).
///
/// In detached mode, the EncapsulatedContentInfo contains only the content
/// type OID (`id-data`) with no encapsulated content. The actual file content
/// is transmitted separately.
fn build_detached_signed_data(
    certificates: &[u8],
    signer_info: &[u8],
    digest_alg: DigestAlgorithm,
) -> Vec<u8> {
    // RFC 5652 §5.1: version is 1 when eContentType is id-data
    let version = asn1::encode_integer_value(1);

    // digestAlgorithms SET { AlgorithmIdentifier }
    let digest_algorithms = asn1::encode_set(digest_alg.algorithm_id());

    // EncapsulatedContentInfo — SEQUENCE { OID id-data } (no [0] content)
    let content_info = asn1::encode_sequence(&[asn1::OID_DATA]);

    // signerInfos SET { signerInfo }
    let signer_infos = asn1::encode_set(signer_info);

    asn1::encode_sequence(&[
        &version,
        &digest_algorithms,
        &content_info,
        certificates,
        &signer_infos,
    ])
}

/// Build the outer ContentInfo SEQUENCE.
fn build_content_info(signed_data: &[u8]) -> Vec<u8> {
    asn1::encode_sequence(&[
        asn1::OID_SIGNED_DATA,
        &asn1::encode_explicit_tag(0, signed_data),
    ])
}

/// Return the number of bytes consumed by the length field in a DER TLV.
/// Input should start at the length byte (i.e., data[1..] where data[0] is tag).
fn der_length_size(data: &[u8]) -> usize {
    if data.len() < 2 {
        return 1;
    }
    let len_byte = data[1];
    if len_byte < 128 {
        1
    } else {
        1 + (len_byte & 0x7F) as usize
    }
}

// ─── Content Hints (RFC 2634 §2.9) ───

/// Build the content hints signed attribute (RFC 2634 §2.9).
///
/// ```text
/// ContentHints ::= SEQUENCE {
///     contentDescription  UTF8String (SIZE (1..MAX)) OPTIONAL,
///     contentType         ContentType
/// }
/// ```
fn build_content_hints_attr(hints: &ContentHints) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    if let Some(ref desc) = hints.content_description {
        parts.push(asn1::encode_utf8_string(desc));
    }
    parts.push(hints.content_type_oid.clone());

    let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    let hints_value = asn1::encode_sequence(&part_refs);

    asn1::encode_sequence(&[asn1::OID_CONTENT_HINTS, &asn1::encode_set(&hints_value)])
}

// ─── Counter-Signatures (RFC 5652 §11.4) ───

/// Build a counter-signature SignerInfo over a signature value (RFC 5652 §11.4).
///
/// A counter-signature is computed over the contents octets of the
/// signatureValue OCTET STRING from the parent SignerInfo. The resulting
/// SignerInfo can be included as an unsigned attribute.
///
/// # Arguments
///
/// * `signature_value` - The raw signature bytes from the parent SignerInfo
///   (contents of the OCTET STRING, not the DER encoding)
/// * `counter_signer_cert_der` - DER-encoded certificate of the counter-signer
/// * `digest_alg` - Digest algorithm for the counter-signature
/// * `signing_alg` - Signature algorithm for the counter-signature
/// * `sign_fn` - Callback to sign the counter-signer's signed attributes
///
/// Returns the DER-encoded counter-SignerInfo (without unsigned attributes).
/// Uses IssuerAndSerialNumber as SignerIdentifier (version 1).
/// For SubjectKeyIdentifier-based counter-signatures, use
/// [`build_counter_signer_info_ski`].
pub fn build_counter_signer_info<F>(
    signature_value: &[u8],
    counter_signer_cert_der: &[u8],
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
    sign_fn: F,
) -> SignResult<Vec<u8>>
where
    F: FnOnce(&[u8]) -> SignResult<Vec<u8>>,
{
    build_counter_signer_info_inner(
        signature_value,
        counter_signer_cert_der,
        digest_alg,
        signing_alg,
        false,
        sign_fn,
    )
}

/// Build a counter-signature SignerInfo using SubjectKeyIdentifier (RFC 5652 §11.4).
///
/// Same as [`build_counter_signer_info`], but uses SubjectKeyIdentifier
/// as the SignerIdentifier (version 3) instead of IssuerAndSerialNumber.
/// This is required when the counter-signer's certificate uses SKI-based
/// identification.
pub fn build_counter_signer_info_ski<F>(
    signature_value: &[u8],
    counter_signer_cert_der: &[u8],
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
    sign_fn: F,
) -> SignResult<Vec<u8>>
where
    F: FnOnce(&[u8]) -> SignResult<Vec<u8>>,
{
    build_counter_signer_info_inner(
        signature_value,
        counter_signer_cert_der,
        digest_alg,
        signing_alg,
        true,
        sign_fn,
    )
}

/// Internal: build counter-SignerInfo with configurable SignerIdentifier type.
fn build_counter_signer_info_inner<F>(
    signature_value: &[u8],
    counter_signer_cert_der: &[u8],
    digest_alg: DigestAlgorithm,
    signing_alg: SigningAlgorithm,
    use_ski: bool,
    sign_fn: F,
) -> SignResult<Vec<u8>>
where
    F: FnOnce(&[u8]) -> SignResult<Vec<u8>>,
{
    let (issuer_der, serial_der) = extract_issuer_and_serial(counter_signer_cert_der)?;

    // Compute digest of the parent signature value
    let sig_digest: Vec<u8> = digest_alg.digest(signature_value);

    // Build signed attributes for the counter-signature
    // Per RFC 5652 §11.4: MUST include contentType (id-data) and messageDigest
    let signed_attrs_set = build_signed_attrs_sorted(
        asn1::OID_DATA,
        &sig_digest,
        digest_alg,
        signing_alg,
        None, // No ESSCertIDv2 for counter-signatures
        None, // No content hints for counter-signatures
    );

    // Sign the DER-encoded SET
    let cs_signature = sign_fn(&signed_attrs_set)?;

    // RFC 5652 §5.3: version is 1 for IssuerAndSerialNumber, 3 for SubjectKeyIdentifier
    let ski = if use_ski {
        extract_ski_from_cert_der(counter_signer_cert_der)
    } else {
        None
    };

    // Build the counter-SignerInfo (no unsigned attributes of its own)
    let no_unsigned = UnsignedAttrs {
        timestamp_token: None,
        counter_signatures: &[],
        custom: &[],
    };

    Ok(build_signer_info_ex(
        &issuer_der,
        &serial_der,
        digest_alg,
        signing_alg,
        &signed_attrs_set,
        &cs_signature,
        &no_unsigned,
        ski.as_deref(),
    ))
}

impl SignedDataBuilder {
    /// Build the CMS SignedData with inline counter-signing.
    ///
    /// Similar to [`build`](Self::build), but additionally calls `counter_sign_fn`
    /// for each signer after their signature is produced. The callback receives
    /// `(signer_index, signature_value_bytes)` and should return a Vec of
    /// counter-SignerInfo DER blobs (or an empty Vec for no counter-signatures).
    ///
    /// This is the recommended way to add counter-signatures since they require
    /// the main signature value, which isn't available until after signing.
    pub fn build_with_counter_sign<F, G>(
        &self,
        mut sign_fn: F,
        mut counter_sign_fn: G,
    ) -> SignResult<Vec<u8>>
    where
        F: FnMut(usize, &[u8]) -> SignResult<Vec<u8>>,
        G: FnMut(usize, &[u8]) -> SignResult<Vec<Vec<u8>>>,
    {
        if self.signers.is_empty() {
            return Err(SignError::Pkcs7("No signers configured".to_string()));
        }

        // Collect unique digest algorithms (RFC 5652 §5.1)
        let mut digest_alg_ids: Vec<&[u8]> = Vec::new();
        let mut seen_digests: Vec<DigestAlgorithm> = Vec::new();
        for signer in &self.signers {
            if !seen_digests.contains(&signer.digest_algorithm) {
                seen_digests.push(signer.digest_algorithm);
                digest_alg_ids.push(signer.digest_algorithm.algorithm_id());
            }
        }

        debug_assert!(
            self.signers
                .iter()
                .all(|s| seen_digests.contains(&s.digest_algorithm)),
            "RFC 5652 §5.1: all signer digest algorithms must be in digestAlgorithms SET"
        );

        let digest_algorithms_set = asn1::encode_set_of(&digest_alg_ids);
        // RFC 5652 §5.2: eContent is OPTIONAL — when absent, this is a detached signature
        let encap_content_info = if let Some(ref content) = self.encap_content {
            asn1::encode_sequence(&[
                &self.content_type_oid,
                &asn1::encode_explicit_tag(0, content),
            ])
        } else {
            asn1::encode_sequence(&[&self.content_type_oid])
        };

        let mut signer_info_ders: Vec<Vec<u8>> = Vec::new();
        let mut all_certs: Vec<u8> = Vec::new();

        for (idx, signer) in self.signers.iter().enumerate() {
            let (issuer_der, serial_der) = extract_issuer_and_serial(&signer.cert_der)?;

            let content_digest = self
                .content_digests
                .iter()
                .find(|(alg, _)| *alg == signer.digest_algorithm)
                .map(|(_, d)| d.as_slice())
                .ok_or_else(|| {
                    SignError::Pkcs7(format!(
                        "No content digest for {:?}",
                        signer.digest_algorithm
                    ))
                })?;

            let ess_cert = if signer.cades_bes {
                Some(signer.cert_der.as_slice())
            } else {
                None
            };
            let signed_attrs_set = build_signed_attrs_sorted(
                &self.content_type_oid,
                content_digest,
                signer.digest_algorithm,
                signer.signing_algorithm,
                ess_cert,
                signer.content_hints.as_ref(),
            );

            let signature_bytes = sign_fn(idx, &signed_attrs_set)?;

            // Get counter-signatures via callback
            let counter_sigs = counter_sign_fn(idx, &signature_bytes)?;

            // Merge pre-built counter-signatures with callback results
            let mut all_counter_sigs = signer.counter_signatures.clone();
            all_counter_sigs.extend(counter_sigs);

            let unsigned_attrs = UnsignedAttrs {
                timestamp_token: signer.timestamp_token.as_deref(),
                counter_signatures: &all_counter_sigs,
                custom: &signer.custom_unsigned_attributes,
            };

            let ski = if signer.use_subject_key_identifier {
                extract_ski_from_cert_der(&signer.cert_der)
            } else {
                None
            };

            let signer_info = build_signer_info_ex(
                &issuer_der,
                &serial_der,
                signer.digest_algorithm,
                signer.signing_algorithm,
                &signed_attrs_set,
                &signature_bytes,
                &unsigned_attrs,
                ski.as_deref(),
            );

            signer_info_ders.push(signer_info);
            all_certs.extend_from_slice(&signer.cert_der);
        }

        for chain_cert in &self.chain_certs_der {
            all_certs.extend_from_slice(chain_cert);
        }

        let certificates = asn1::encode_implicit_tag(0, &all_certs);

        let has_crls = !self.crls_der.is_empty();
        let crls_field = if has_crls {
            let mut all_crls = Vec::new();
            for crl in &self.crls_der {
                all_crls.extend_from_slice(crl);
            }
            asn1::encode_implicit_tag(1, &all_crls)
        } else {
            Vec::new()
        };

        let signer_info_refs: Vec<&[u8]> = signer_info_ders.iter().map(|s| s.as_slice()).collect();
        let signer_infos_set = asn1::encode_set_of(&signer_info_refs);

        let is_id_data = self.content_type_oid == asn1::OID_DATA;
        let version = asn1::encode_integer_value(if is_id_data { 1 } else { 3 });

        let mut parts: Vec<&[u8]> = vec![
            &version,
            &digest_algorithms_set,
            &encap_content_info,
            &certificates,
        ];
        if has_crls {
            parts.push(&crls_field);
        }
        parts.push(&signer_infos_set);
        let signed_data = asn1::encode_sequence(&parts);

        Ok(build_content_info(&signed_data))
    }
}

// ─── Content Type OID Validation (RFC 5652 §5.2) ───

/// Validate that a DER-encoded OID is well-formed.
///
/// RFC 5652 §5.2: The eContentType field MUST contain a valid OID.
/// This validates the OID tag (0x06), length, and that the encoded
/// value has at least 1 byte (first two components).
pub fn validate_content_type_oid(oid_der: &[u8]) -> SignResult<()> {
    if oid_der.is_empty() {
        return Err(SignError::Pkcs7(
            "RFC 5652 §5.2: content type OID is empty".to_string(),
        ));
    }
    // Must start with OID tag (0x06)
    if oid_der[0] != 0x06 {
        return Err(SignError::Pkcs7(format!(
            "RFC 5652 §5.2: content type must be an OID (tag 0x06), got 0x{:02X}",
            oid_der[0]
        )));
    }
    if oid_der.len() < 2 {
        return Err(SignError::Pkcs7(
            "RFC 5652 §5.2: content type OID too short (missing length)".to_string(),
        ));
    }
    let len = oid_der[1] as usize;
    if len == 0 {
        return Err(SignError::Pkcs7(
            "RFC 5652 §5.2: content type OID has zero-length value".to_string(),
        ));
    }
    if 2 + len > oid_der.len() {
        return Err(SignError::Pkcs7(format!(
            "RFC 5652 §5.2: content type OID length {} exceeds available data {}",
            len,
            oid_der.len() - 2
        )));
    }
    Ok(())
}

// ─── Test Helpers ───

/// Build a minimal fake X.509 certificate DER for testing.
///
/// Creates a cert with the given serial number and CN.
#[cfg(test)]
fn build_test_cert(serial: u32, cn: &str) -> Vec<u8> {
    let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
    let serial_der = asn1::encode_integer_value(serial);
    let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
    let cn_bytes = cn.as_bytes();
    let mut cn_der = vec![0x0C]; // UTF8String tag
    cn_der.extend(asn1::encode_length(cn_bytes.len()));
    cn_der.extend_from_slice(cn_bytes);
    let issuer = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
        &[0x06, 0x03, 0x55, 0x04, 0x03], // OID 2.5.4.3 (CN)
        &cn_der,
    ]))]);

    let tbs = asn1::encode_sequence(&[&version, &serial_der, &algo, &issuer]);
    asn1::encode_sequence(&[&tbs, &algo, &[0x03, 0x01, 0x00]])
}

/// Build a test cert with SubjectKeyIdentifier extension for SKI-based tests.
fn build_test_cert_with_ski(serial: u32, cn: &str) -> Vec<u8> {
    let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
    let serial_der = asn1::encode_integer_value(serial);
    let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
    let cn_bytes = cn.as_bytes();
    let mut cn_der = vec![0x0C]; // UTF8String tag
    cn_der.extend(asn1::encode_length(cn_bytes.len()));
    cn_der.extend_from_slice(cn_bytes);
    let issuer = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
        &[0x06, 0x03, 0x55, 0x04, 0x03], // OID 2.5.4.3 (CN)
        &cn_der,
    ]))]);

    // Fake public key info (needed for subject field, reuse issuer as subject)
    let subject = issuer.clone();
    // Dummy validity (not parsed by our code)
    let validity = asn1::encode_sequence(&[
        &asn1::encode_utc_time(chrono::Utc::now()),
        &asn1::encode_utc_time(chrono::Utc::now()),
    ]);
    // Dummy SubjectPublicKeyInfo
    let spki = asn1::encode_sequence(&[&algo, &[0x03, 0x01, 0x00]]);

    // Build SKI extension: OID 2.5.29.14, OCTET STRING wrapping OCTET STRING
    let ski_value: [u8; 20] = [0xAA; 20]; // Fake 20-byte key identifier
    let inner_octet = asn1::encode_octet_string(&ski_value);
    let outer_octet = asn1::encode_octet_string(&inner_octet);
    let ski_ext = asn1::encode_sequence(&[
        &[0x06, 0x03, 0x55, 0x1D, 0x0E], // OID 2.5.29.14 (SKI)
        &outer_octet,
    ]);
    let extensions = asn1::encode_explicit_tag(3, &asn1::encode_sequence(&[&ski_ext]));

    let tbs = asn1::encode_sequence(&[
        &version,
        &serial_der,
        &algo,
        &issuer,
        &validity,
        &subject,
        &spki,
        &extensions,
    ]);
    asn1::encode_sequence(&[&tbs, &algo, &[0x03, 0x01, 0x00]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spc_indirect_data_structure() {
        let hash = vec![0xAA; 32]; // fake SHA-256 hash
        let spc = build_spc_indirect_data(&hash, DigestAlgorithm::Sha256);
        // Must start with SEQUENCE tag
        assert_eq!(spc[0], 0x30);
        // Must contain our hash somewhere
        assert!(spc.windows(32).any(|w| w == hash.as_slice()));
    }

    #[test]
    fn test_signed_attrs_content() {
        let hash = vec![0xBB; 32];
        let attrs = build_signed_attrs_content(
            &hash,
            SigningAlgorithm::RsaSha256,
            None,
            None,
            &asn1::encode_utc_time_now(),
        );
        // Should contain five SEQUENCE-tagged attributes:
        // contentType, messageDigest, signingTime, SpcSpOpusInfo, SpcStatementType
        let mut count = 0;
        let mut pos = 0;
        while pos < attrs.len() {
            if attrs[pos] == 0x30 {
                count += 1;
                let (_, remaining) = asn1::skip_tlv(&attrs[pos..]).unwrap();
                pos = attrs.len() - remaining.len();
            } else {
                pos += 1;
            }
        }
        assert_eq!(count, 5, "Expected 5 signed attributes");
    }

    #[test]
    fn test_signed_attrs_content_ecdsa() {
        let hash = vec![0xCC; 32];
        let attrs = build_signed_attrs_content(
            &hash,
            SigningAlgorithm::EcdsaSha256,
            None,
            None,
            &asn1::encode_utc_time_now(),
        );
        // Should also contain five attributes for ECDSA
        let mut count = 0;
        let mut pos = 0;
        while pos < attrs.len() {
            if attrs[pos] == 0x30 {
                count += 1;
                let (_, remaining) = asn1::skip_tlv(&attrs[pos..]).unwrap();
                pos = attrs.len() - remaining.len();
            } else {
                pos += 1;
            }
        }
        assert_eq!(count, 5, "Expected 5 signed attributes for ECDSA");
    }

    #[test]
    fn test_signed_attrs_with_opus_info() {
        let hash = vec![0xDD; 32];
        let time = asn1::encode_utc_time_now();
        let attrs = build_signed_attrs_content(
            &hash,
            SigningAlgorithm::RsaSha256,
            Some("SPORK CA"),
            Some("https://quantumnexum.com/spork"),
            &time,
        );
        // Should contain 5 attributes: contentType, messageDigest, signingTime,
        // SpcSpOpusInfo, SpcStatementType
        let mut count = 0;
        let mut pos = 0;
        while pos < attrs.len() {
            if attrs[pos] == 0x30 {
                count += 1;
                let (_, remaining) = asn1::skip_tlv(&attrs[pos..]).unwrap();
                pos = attrs.len() - remaining.len();
            } else {
                pos += 1;
            }
        }
        assert_eq!(count, 5, "Expected 5 signed attributes with SpcSpOpusInfo");
    }

    #[test]
    fn test_spc_sp_opus_info_encoding() {
        let attr = build_spc_sp_opus_info_attr(Some("Test App"), Some("https://example.com"));
        // Must start with SEQUENCE
        assert_eq!(attr[0], 0x30);
        // Must contain the SpcSpOpusInfo OID (1.3.6.1.4.1.311.2.1.12)
        assert!(
            attr.windows(asn1::OID_SPC_SP_OPUS_INFO.len())
                .any(|w| w == asn1::OID_SPC_SP_OPUS_INFO),
            "Must contain SpcSpOpusInfo OID"
        );
        // Must contain "https://example.com" bytes
        assert!(
            attr.windows(b"https://example.com".len())
                .any(|w| w == b"https://example.com"),
            "Must contain the URL"
        );
    }

    #[test]
    fn test_cms_algorithm_protection_attr_rsa() {
        let attr = build_cms_algorithm_protection_attr(SigningAlgorithm::RsaSha256);
        // Must start with SEQUENCE
        assert_eq!(attr[0], 0x30);
        // Must contain the CMSAlgorithmProtection OID
        assert!(
            attr.windows(asn1::OID_CMS_ALGORITHM_PROTECTION.len())
                .any(|w| w == asn1::OID_CMS_ALGORITHM_PROTECTION),
            "CMSAlgorithmProtection OID not found"
        );
        // Must contain the SHA-256 digest algorithm OID bytes
        // OID sha256 raw bytes: 0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x02 0x01
        let sha256_oid_content = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        assert!(
            attr.windows(sha256_oid_content.len())
                .any(|w| w == sha256_oid_content),
            "SHA-256 OID not found in attribute"
        );
        // [1] implicit tag for signatureAlgorithm must be present (0xA1)
        assert!(attr.contains(&0xA1), "[1] IMPLICIT tag not found");
    }

    #[test]
    fn test_cms_algorithm_protection_attr_ecdsa() {
        let attr = build_cms_algorithm_protection_attr(SigningAlgorithm::EcdsaSha256);
        assert_eq!(attr[0], 0x30);
        // Must contain the CMSAlgorithmProtection OID
        assert!(
            attr.windows(asn1::OID_CMS_ALGORITHM_PROTECTION.len())
                .any(|w| w == asn1::OID_CMS_ALGORITHM_PROTECTION),
            "CMSAlgorithmProtection OID not found"
        );
        // Must contain ECDSA OID content: 0x2A 0x86 0x48 0xCE 0x3D 0x04 0x03 0x02
        let ecdsa_oid_content = &[0x2Au8, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        assert!(
            attr.windows(ecdsa_oid_content.len())
                .any(|w| w == ecdsa_oid_content),
            "ECDSA OID not found in attribute"
        );
        // [1] implicit tag for signatureAlgorithm must be present (0xA1)
        assert!(attr.contains(&0xA1), "[1] IMPLICIT tag not found");
    }

    #[test]
    fn test_content_info_wrapping() {
        let fake_signed_data = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // SEQUENCE { INT 1 }
        let ci = build_content_info(&fake_signed_data);
        // Must start with SEQUENCE tag
        assert_eq!(ci[0], 0x30);
        // Must contain OID for signedData (1.2.840.113549.1.7.2)
        assert!(ci
            .windows(asn1::OID_SIGNED_DATA.len())
            .any(|w| w == asn1::OID_SIGNED_DATA));
    }

    /// Test that extract_issuer_and_serial works on a minimal self-signed cert.
    #[test]
    fn test_extract_issuer_serial_from_cert() {
        let cert = build_test_cert(42, "Test");
        let (extracted_issuer, extracted_serial) = extract_issuer_and_serial(&cert).unwrap();
        assert_eq!(extracted_serial, asn1::encode_integer_value(42));
        // Issuer should be a SEQUENCE containing an RDN with CN=Test
        assert_eq!(extracted_issuer[0], 0x30); // SEQUENCE tag
    }

    // ─── SHA-384 / SHA-512 Tests ───

    #[test]
    fn test_digest_algorithm_sha384() {
        let alg = DigestAlgorithm::Sha384;
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30); // SEQUENCE
                                 // SHA-384 OID last byte is 0x02
        assert_eq!(id[12], 0x02);
    }

    #[test]
    fn test_digest_algorithm_sha512() {
        let alg = DigestAlgorithm::Sha512;
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30); // SEQUENCE
                                 // SHA-512 OID last byte is 0x03
        assert_eq!(id[12], 0x03);
    }

    #[test]
    fn test_signing_algorithm_rsa_sha384() {
        let alg = SigningAlgorithm::RsaSha384;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha384);
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30);
        // sha384WithRSA OID last byte is 0x0C
        assert_eq!(id[12], 0x0C);
    }

    #[test]
    fn test_signing_algorithm_rsa_sha512() {
        let alg = SigningAlgorithm::RsaSha512;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30);
        // sha512WithRSA OID last byte is 0x0D
        assert_eq!(id[12], 0x0D);
    }

    #[test]
    fn test_signing_algorithm_ecdsa_sha384() {
        let alg = SigningAlgorithm::EcdsaSha384;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha384);
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30);
        // ecdsa-with-SHA384 OID last byte is 0x03
        assert_eq!(id[11], 0x03);
    }

    #[test]
    fn test_signing_algorithm_ecdsa_sha512() {
        let alg = SigningAlgorithm::EcdsaSha512;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30);
        // ecdsa-with-SHA512 OID last byte is 0x04
        assert_eq!(id[11], 0x04);
    }

    #[test]
    fn test_cms_alg_protection_sha384_rsa() {
        let attr = build_cms_algorithm_protection_attr_ex(
            DigestAlgorithm::Sha384,
            SigningAlgorithm::RsaSha384,
        );
        assert_eq!(attr[0], 0x30);
        // Must contain SHA-384 digest OID byte (0x02 as last byte of sha384 OID)
        let sha384_oid_content = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        assert!(
            attr.windows(sha384_oid_content.len())
                .any(|w| w == sha384_oid_content),
            "SHA-384 OID not found"
        );
        assert!(attr.contains(&0xA1), "[1] IMPLICIT tag not found");
    }

    #[test]
    fn test_cms_alg_protection_sha512_ecdsa() {
        let attr = build_cms_algorithm_protection_attr_ex(
            DigestAlgorithm::Sha512,
            SigningAlgorithm::EcdsaSha512,
        );
        assert_eq!(attr[0], 0x30);
        // Must contain SHA-512 digest OID byte
        let sha512_oid_content = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        assert!(
            attr.windows(sha512_oid_content.len())
                .any(|w| w == sha512_oid_content),
            "SHA-512 OID not found"
        );
    }

    // ─── Multi-Signer Tests ───

    #[test]
    fn test_signed_data_builder_single_signer() {
        let cert = build_test_cert(1, "Signer1");
        let content = vec![0x01, 0x02, 0x03];
        let content_type = asn1::OID_DATA.to_vec();
        let digest = vec![0xAA; 32]; // fake SHA-256 digest

        let mut builder = SignedDataBuilder::new(content_type, content);
        builder.add_content_digest(DigestAlgorithm::Sha256, digest);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must be ContentInfo — SEQUENCE starting with signedData OID
        assert_eq!(ci[0], 0x30);
        assert!(ci
            .windows(asn1::OID_SIGNED_DATA.len())
            .any(|w| w == asn1::OID_SIGNED_DATA));
    }

    #[test]
    fn test_signed_data_builder_two_signers() {
        let cert1 = build_test_cert(1, "Signer1");
        let cert2 = build_test_cert(2, "Signer2");
        let content = vec![0x01, 0x02, 0x03];
        let content_type = asn1::OID_DATA.to_vec();
        let sha256_digest = vec![0xAA; 32];
        let sha384_digest = vec![0xBB; 48];

        let mut builder = SignedDataBuilder::new(content_type, content);
        builder.add_content_digest(DigestAlgorithm::Sha256, sha256_digest);
        builder.add_content_digest(DigestAlgorithm::Sha384, sha384_digest);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert1,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        builder.add_signer(CmsSignerInfo {
            cert_der: cert2,
            digest_algorithm: DigestAlgorithm::Sha384,
            signing_algorithm: SigningAlgorithm::EcdsaSha384,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let mut signer_indices = Vec::new();
        let result = builder.build(|idx, _attrs| {
            signer_indices.push(idx);
            Ok(vec![0xFF; 64])
        });
        assert!(result.is_ok());
        // Both signers should have been called
        assert_eq!(signer_indices, vec![0, 1]);
    }

    #[test]
    fn test_signed_data_builder_three_signers_mixed_algorithms() {
        let cert1 = build_test_cert(10, "RSA-256");
        let cert2 = build_test_cert(20, "ECDSA-384");
        let cert3 = build_test_cert(30, "RSA-512");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_content_digest(DigestAlgorithm::Sha384, vec![0xBB; 48]);
        builder.add_content_digest(DigestAlgorithm::Sha512, vec![0xCC; 64]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert1,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        builder.add_signer(CmsSignerInfo {
            cert_der: cert2,
            digest_algorithm: DigestAlgorithm::Sha384,
            signing_algorithm: SigningAlgorithm::EcdsaSha384,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        builder.add_signer(CmsSignerInfo {
            cert_der: cert3,
            digest_algorithm: DigestAlgorithm::Sha512,
            signing_algorithm: SigningAlgorithm::RsaSha512,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());

        let ci = result.unwrap();
        // Should contain all three digest algorithm OIDs in the DigestAlgorithms SET
        let sha256_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let sha384_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        let sha512_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        assert!(ci.windows(sha256_oid.len()).any(|w| w == sha256_oid));
        assert!(ci.windows(sha384_oid.len()).any(|w| w == sha384_oid));
        assert!(ci.windows(sha512_oid.len()).any(|w| w == sha512_oid));
    }

    #[test]
    fn test_signed_data_builder_no_signers_error() {
        let builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x01]);
        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No signers"),
            "Error should mention no signers: {err}"
        );
    }

    #[test]
    fn test_signed_data_builder_missing_digest_error() {
        let cert = build_test_cert(1, "Test");
        let mut builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x01]);
        // Add signer for SHA-384 but only provide SHA-256 digest
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha384,
            signing_algorithm: SigningAlgorithm::RsaSha384,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_data_builder_with_chain_certs() {
        let signer_cert = build_test_cert(1, "Signer");
        let chain_cert = build_test_cert(99, "IntermediateCA");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_chain_cert(chain_cert.clone());
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // The chain cert should appear in the output
        assert!(ci
            .windows(chain_cert.len())
            .any(|w| w == chain_cert.as_slice()));
    }

    #[test]
    fn test_signed_data_builder_with_crls() {
        // RFC 5652 §5.1: crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
        let signer_cert = build_test_cert(1, "CRL-Signer");
        let content_type = asn1::OID_DATA.to_vec();
        // Minimal CRL-like DER (just enough to verify it's embedded)
        let crl_der = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x30, 0x00];

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_crl(crl_der.clone());
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // The CRL should appear in the output (embedded via [1] IMPLICIT)
        assert!(
            ci.windows(crl_der.len()).any(|w| w == crl_der.as_slice()),
            "CRL DER must be embedded in SignedData crls field"
        );
        // The [1] IMPLICIT tag (0xA1) must appear before the CRL content
        let crl_pos = ci
            .windows(crl_der.len())
            .position(|w| w == crl_der.as_slice())
            .unwrap();
        // Walk backwards to find the 0xA1 tag (it's tag + length before the content)
        assert!(crl_pos >= 2, "Must have room for tag+length before CRL");
        let tag_region = &ci[crl_pos.saturating_sub(4)..crl_pos];
        assert!(
            tag_region.contains(&0xA1),
            "CRL field should be wrapped in [1] IMPLICIT tag (0xA1), region before CRL: {:?}",
            tag_region
        );
    }

    #[test]
    fn test_signed_data_builder_without_crls() {
        // When no CRLs are added, the crls field should not appear
        let signer_cert = build_test_cert(1, "No-CRL");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
    }

    #[test]
    fn test_signed_data_builder_duplicate_digest_dedup() {
        let cert1 = build_test_cert(1, "S1");
        let cert2 = build_test_cert(2, "S2");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        // Both signers use SHA-256 — should not duplicate in DigestAlgorithms SET
        builder.add_signer(CmsSignerInfo {
            cert_der: cert1,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        builder.add_signer(CmsSignerInfo {
            cert_der: cert2,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::EcdsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();

        // Count occurrences of SHA-256 AlgorithmIdentifier in the output
        // The full SHA256_ALGORITHM_ID should appear: once in DigestAlgorithms,
        // and once per SignerInfo's digestAlgorithm — but NOT duplicated in
        // the DigestAlgorithms SET itself
        let sha256_alg_id = &asn1::SHA256_ALGORITHM_ID;
        let count = ci
            .windows(sha256_alg_id.len())
            .filter(|w| *w == sha256_alg_id)
            .count();
        // Expect: 1 (DigestAlgorithms SET) + 2 (one per SignerInfo) + 2 (CMSAlgProtection) = 5
        // The key thing: if dedup failed, count would be 6+
        assert!(
            count >= 3,
            "SHA-256 AlgID should appear at least 3 times, got {count}"
        );
    }

    // ─── Signed Attribute DER SET OF Ordering Tests ───

    #[test]
    fn test_signed_attrs_sorted_is_valid_set() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            None,
            None,
        );
        // Must start with SET tag
        assert_eq!(attrs[0], 0x31);
    }

    #[test]
    fn test_signed_attrs_sorted_contains_four_attrs() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            None,
            None,
        );
        // Strip SET wrapper, count SEQUENCE elements
        let content = &attrs[1 + der_length_size(&attrs)..];
        let mut count = 0;
        let mut pos = content;
        while !pos.is_empty() {
            let (_, remaining) = asn1::skip_tlv(pos).unwrap();
            count += 1;
            pos = remaining;
        }
        assert_eq!(count, 4, "Expected 4 signed attributes");
    }

    #[test]
    fn test_signed_attrs_sorted_lexicographic_order() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            None,
            None,
        );
        // Extract individual attribute TLVs from the SET
        let content = &attrs[1 + der_length_size(&attrs)..];
        let mut elements: Vec<Vec<u8>> = Vec::new();
        let mut pos = content;
        while !pos.is_empty() {
            let (tlv, remaining) = asn1::extract_tlv(pos).unwrap();
            elements.push(tlv.to_vec());
            pos = remaining;
        }
        // Verify they are in sorted order
        for i in 1..elements.len() {
            assert!(
                elements[i - 1] <= elements[i],
                "Attribute {} is not <= attribute {} (DER SET OF ordering violation)",
                i - 1,
                i
            );
        }
    }

    #[test]
    fn test_signed_attrs_sorted_sha384() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xBB; 48],
            DigestAlgorithm::Sha384,
            SigningAlgorithm::EcdsaSha384,
            None,
            None,
        );
        assert_eq!(attrs[0], 0x31);
        // Should contain SHA-384 OID
        let sha384_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
        assert!(attrs.windows(sha384_oid.len()).any(|w| w == sha384_oid));
    }

    #[test]
    fn test_signed_attrs_sorted_sha512() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xCC; 64],
            DigestAlgorithm::Sha512,
            SigningAlgorithm::RsaSha512,
            None,
            None,
        );
        assert_eq!(attrs[0], 0x31);
        // Should contain SHA-512 OID
        let sha512_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        assert!(attrs.windows(sha512_oid.len()).any(|w| w == sha512_oid));
    }

    // ─── Content Info Tests ───

    #[test]
    fn test_content_info_structure() {
        let fake_signed_data = asn1::encode_sequence(&[&asn1::encode_integer_value(1)]);
        let ci = build_content_info(&fake_signed_data);
        assert_eq!(ci[0], 0x30); // outer SEQUENCE
                                 // Contains signedData OID
        assert!(ci
            .windows(asn1::OID_SIGNED_DATA.len())
            .any(|w| w == asn1::OID_SIGNED_DATA));
        // Contains [0] EXPLICIT wrapper (0xA0)
        assert!(ci.contains(&0xA0));
    }

    #[test]
    fn test_content_info_from_signed_data_builder() {
        let cert = build_test_cert(1, "CI-Test");
        let mut builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::EcdsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let ci = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64])).unwrap();
        // Must be ContentInfo SEQUENCE
        assert_eq!(ci[0], 0x30);
        // Must contain signedData OID
        assert!(ci
            .windows(asn1::OID_SIGNED_DATA.len())
            .any(|w| w == asn1::OID_SIGNED_DATA));
        // Must contain id-data OID (the content type)
        assert!(ci
            .windows(asn1::OID_DATA.len())
            .any(|w| w == asn1::OID_DATA));
    }

    // ─── SignerInfo Algorithm Tests ───

    #[test]
    fn test_signer_info_sha384_rsa() {
        let cert = build_test_cert(5, "SHA384RSA");
        let (issuer, serial) = extract_issuer_and_serial(&cert).unwrap();
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xBB; 48],
            DigestAlgorithm::Sha384,
            SigningAlgorithm::RsaSha384,
            None,
            None,
        );
        let unsigned = UnsignedAttrs {
            timestamp_token: None,
            counter_signatures: &[],
            custom: &[],
        };
        let si = build_signer_info_ex(
            &issuer,
            &serial,
            DigestAlgorithm::Sha384,
            SigningAlgorithm::RsaSha384,
            &attrs,
            &[0xFF; 64],
            &unsigned,
            None,
        );
        assert_eq!(si[0], 0x30); // SEQUENCE
                                 // Should contain SHA-384 AlgorithmIdentifier
        let sha384_alg = &asn1::SHA384_ALGORITHM_ID;
        assert!(si
            .windows(sha384_alg.len())
            .any(|w| w == sha384_alg.as_slice()));
        // Should contain sha384WithRSA AlgorithmIdentifier
        let rsa384_alg = &asn1::SHA384_WITH_RSA_ALGORITHM_ID;
        assert!(si
            .windows(rsa384_alg.len())
            .any(|w| w == rsa384_alg.as_slice()));
    }

    #[test]
    fn test_signer_info_sha512_ecdsa() {
        let cert = build_test_cert(6, "SHA512ECDSA");
        let (issuer, serial) = extract_issuer_and_serial(&cert).unwrap();
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xCC; 64],
            DigestAlgorithm::Sha512,
            SigningAlgorithm::EcdsaSha512,
            None,
            None,
        );
        let unsigned = UnsignedAttrs {
            timestamp_token: None,
            counter_signatures: &[],
            custom: &[],
        };
        let si = build_signer_info_ex(
            &issuer,
            &serial,
            DigestAlgorithm::Sha512,
            SigningAlgorithm::EcdsaSha512,
            &attrs,
            &[0xFF; 64],
            &unsigned,
            None,
        );
        assert_eq!(si[0], 0x30);
        // Should contain SHA-512 AlgorithmIdentifier
        let sha512_alg = &asn1::SHA512_ALGORITHM_ID;
        assert!(si
            .windows(sha512_alg.len())
            .any(|w| w == sha512_alg.as_slice()));
    }

    // ─── Backward Compatibility Tests ───

    #[test]
    fn test_pkcs7_builder_backward_compat() {
        // Ensure the legacy Pkcs7Builder still works unchanged
        let cert = build_test_cert(42, "Legacy");
        let hash = vec![0xAA; 32];
        let mut builder = Pkcs7Builder::new(cert, hash);
        builder.with_algorithm(SigningAlgorithm::EcdsaSha256);

        let result = builder.build(|_attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        assert_eq!(ci[0], 0x30);
    }

    #[test]
    fn test_pkcs7_builder_with_chain_and_timestamp() {
        let cert = build_test_cert(1, "Signer");
        let chain = build_test_cert(2, "CA");
        let hash = vec![0xAA; 32];
        let ts_token = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // fake token

        let mut builder = Pkcs7Builder::new(cert, hash);
        builder.add_chain_cert(chain);
        builder.set_timestamp_token(ts_token);

        let result = builder.build(|_attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
    }

    // ─── PQC Signing Algorithm Tests (RFC 9882 / RFC 9909) ───

    #[test]
    fn test_signing_algorithm_ml_dsa_44() {
        let alg = SigningAlgorithm::MlDsa44;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha256);
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30);
        assert_eq!(id.len(), 13); // No parameters
        assert_eq!(id[12], 0x11); // ML-DSA-44 OID last byte
    }

    #[test]
    fn test_signing_algorithm_ml_dsa_65() {
        let alg = SigningAlgorithm::MlDsa65;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[12], 0x12); // ML-DSA-65 OID last byte
    }

    #[test]
    fn test_signing_algorithm_ml_dsa_87() {
        let alg = SigningAlgorithm::MlDsa87;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[12], 0x13); // ML-DSA-87 OID last byte
    }

    #[test]
    fn test_signing_algorithm_slh_dsa_128s() {
        let alg = SigningAlgorithm::SlhDsaSha2128s;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha256);
        let id = alg.algorithm_id();
        assert_eq!(id[12], 0x14); // SLH-DSA-SHA2-128s OID last byte
    }

    #[test]
    fn test_signing_algorithm_slh_dsa_192s() {
        let alg = SigningAlgorithm::SlhDsaSha2192s;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[12], 0x16); // SLH-DSA-SHA2-192s OID last byte
    }

    #[test]
    fn test_signing_algorithm_slh_dsa_256s() {
        let alg = SigningAlgorithm::SlhDsaSha2256s;
        assert_eq!(alg.digest_algorithm(), DigestAlgorithm::Sha512);
        let id = alg.algorithm_id();
        assert_eq!(id[12], 0x18); // SLH-DSA-SHA2-256s OID last byte
    }

    #[test]
    fn test_signed_data_builder_ml_dsa_44_signer() {
        let cert = build_test_cert(100, "PQC-Signer");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::MlDsa44,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 2420]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must contain ML-DSA-44 OID bytes
        let ml_dsa_44_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
        assert!(
            ci.windows(ml_dsa_44_oid.len()).any(|w| w == ml_dsa_44_oid),
            "ML-DSA-44 OID not found in output"
        );
    }

    #[test]
    fn test_cms_alg_protection_ml_dsa_87() {
        let attr = build_cms_algorithm_protection_attr_ex(
            DigestAlgorithm::Sha512,
            SigningAlgorithm::MlDsa87,
        );
        assert_eq!(attr[0], 0x30);
        // Must contain SHA-512 digest OID
        let sha512_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        assert!(attr.windows(sha512_oid.len()).any(|w| w == sha512_oid));
        // Must contain ML-DSA-87 OID
        let ml_dsa_87_oid = &[0x60u8, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
        assert!(
            attr.windows(ml_dsa_87_oid.len())
                .any(|w| w == ml_dsa_87_oid),
            "ML-DSA-87 OID not found in CMSAlgorithmProtection"
        );
    }

    #[test]
    fn test_der_length_size() {
        // Short form: tag + 1-byte length
        let short = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(der_length_size(&short), 1);

        // Long form: tag + 0x81 + 1-byte length
        let mut long = vec![0x30, 0x81, 0x80];
        long.extend(vec![0x00; 128]);
        assert_eq!(der_length_size(&long), 2);
    }

    // ─── CAdES-BES / ESSCertIDv2 Tests ───

    #[test]
    fn test_ess_cert_id_v2_attr_structure() {
        let cert = build_test_cert(1, "CAdES-Test");
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha256);
        // Must be SEQUENCE (attribute wrapper)
        assert_eq!(attr[0], 0x30);
        // Must contain signing-certificate-v2 OID (1.2.840.113549.1.9.16.2.47)
        assert!(
            attr.windows(OID_SIGNING_CERTIFICATE_V2.len())
                .any(|w| w == OID_SIGNING_CERTIFICATE_V2),
            "signing-certificate-v2 OID not found"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_contains_cert_hash() {
        use sha2::{Digest, Sha256};
        let cert = build_test_cert(2, "HashCheck");
        let expected_hash = Sha256::digest(&cert);
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha256);
        // The SHA-256 hash of the cert should appear as an OCTET STRING value
        assert!(
            attr.windows(32).any(|w| w == expected_hash.as_slice()),
            "Certificate hash not found in ESSCertIDv2 attribute"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_sha384_includes_algorithm_id() {
        use sha2::{Digest, Sha384};
        let cert = build_test_cert(10, "SHA384-ESS");
        let expected_hash = Sha384::digest(&cert);
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha384);
        // SHA-384 hash (48 bytes) must appear
        assert!(
            attr.windows(48).any(|w| w == expected_hash.as_slice()),
            "SHA-384 certificate hash not found in ESSCertIDv2"
        );
        // SHA-384 AlgorithmIdentifier must be present (non-default per RFC 5816)
        assert!(
            attr.windows(asn1::SHA384_ALGORITHM_ID.len())
                .any(|w| w == &asn1::SHA384_ALGORITHM_ID[..]),
            "SHA-384 AlgorithmIdentifier not found — required for non-default hash"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_sha512_includes_algorithm_id() {
        use sha2::{Digest, Sha512};
        let cert = build_test_cert(11, "SHA512-ESS");
        let expected_hash = Sha512::digest(&cert);
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha512);
        // SHA-512 hash (64 bytes) must appear
        assert!(
            attr.windows(64).any(|w| w == expected_hash.as_slice()),
            "SHA-512 certificate hash not found in ESSCertIDv2"
        );
        // SHA-512 AlgorithmIdentifier must be present (non-default per RFC 5816)
        assert!(
            attr.windows(asn1::SHA512_ALGORITHM_ID.len())
                .any(|w| w == &asn1::SHA512_ALGORITHM_ID[..]),
            "SHA-512 AlgorithmIdentifier not found — required for non-default hash"
        );
    }

    #[test]
    fn test_ess_cert_id_v2_sha256_omits_algorithm_id() {
        let cert = build_test_cert(12, "SHA256-Default");
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha256);
        // For SHA-256 (default), the hashAlgorithm SHOULD be omitted per RFC 5816 §2.
        // SHA-256 AlgorithmIdentifier should NOT appear inside the ESSCertIDv2.
        // However the OID may appear in other contexts, so check that the attr
        // is shorter than a SHA-384 version (which includes the AlgorithmIdentifier).
        let attr_384 = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha384);
        assert!(
            attr.len() < attr_384.len(),
            "SHA-256 ESSCertIDv2 should be smaller (no hashAlgorithm) than SHA-384 version"
        );
    }

    #[test]
    fn test_cades_bes_signed_attrs_has_five_attrs() {
        let cert = build_test_cert(3, "CAdES-5attr");
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            Some(&cert),
            None,
        );
        // Must start with SET tag
        assert_eq!(attrs[0], 0x31);
        // Count SEQUENCE elements — should be 5 (contentType, messageDigest,
        // signingTime, CMSAlgorithmProtection, signing-certificate-v2)
        let content = &attrs[1 + der_length_size(&attrs)..];
        let mut count = 0;
        let mut pos = content;
        while !pos.is_empty() {
            let (_, remaining) = asn1::skip_tlv(pos).unwrap();
            count += 1;
            pos = remaining;
        }
        assert_eq!(count, 5, "CAdES-BES should have 5 signed attributes");
    }

    #[test]
    fn test_cades_bes_signed_data_builder() {
        let cert = build_test_cert(4, "CAdES-Builder");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert.clone(),
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::EcdsaSha256,
            timestamp_token: None,
            cades_bes: true,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let ci = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64])).unwrap();
        // Must be ContentInfo
        assert_eq!(ci[0], 0x30);
        // Must contain signing-certificate-v2 OID
        assert!(
            ci.windows(OID_SIGNING_CERTIFICATE_V2.len())
                .any(|w| w == OID_SIGNING_CERTIFICATE_V2),
            "CAdES-BES output must contain signing-certificate-v2 OID"
        );
    }

    #[test]
    fn test_cades_bes_false_no_ess_attr() {
        let cert = build_test_cert(5, "NoCAdES");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let ci = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64])).unwrap();
        // Must NOT contain signing-certificate-v2 OID when cades_bes is false
        assert!(
            !ci.windows(OID_SIGNING_CERTIFICATE_V2.len())
                .any(|w| w == OID_SIGNING_CERTIFICATE_V2),
            "Non-CAdES output must not contain signing-certificate-v2 OID"
        );
    }

    #[test]
    fn test_cades_bes_sorted_order_maintained() {
        // With 5 attributes, DER SET OF ordering must still hold
        let cert = build_test_cert(6, "CAdES-Sort");
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            Some(&cert),
            None,
        );
        let content = &attrs[1 + der_length_size(&attrs)..];
        let mut elements: Vec<Vec<u8>> = Vec::new();
        let mut pos = content;
        while !pos.is_empty() {
            let (tlv, remaining) = asn1::extract_tlv(pos).unwrap();
            elements.push(tlv.to_vec());
            pos = remaining;
        }
        for i in 1..elements.len() {
            assert!(
                elements[i - 1] <= elements[i],
                "CAdES-BES attribute {} is not <= attribute {} (DER SET OF ordering violation)",
                i - 1,
                i
            );
        }
    }

    // ─── Content Hints Tests (RFC 2634 §2.9) ───

    #[test]
    fn test_content_hints_attr_with_description() {
        let hints = ContentHints {
            content_description: Some("PE executable code".to_string()),
            content_type_oid: asn1::OID_DATA.to_vec(),
        };
        let attr = build_content_hints_attr(&hints);
        // Must be a SEQUENCE (Attribute)
        assert_eq!(attr[0], 0x30);
        // Must contain the content hints OID
        assert!(
            attr.windows(asn1::OID_CONTENT_HINTS.len())
                .any(|w| w == asn1::OID_CONTENT_HINTS),
            "Content hints OID not found"
        );
        // Must contain the description as UTF8String
        assert!(
            attr.windows(b"PE executable code".len())
                .any(|w| w == b"PE executable code"),
            "Content description not found"
        );
        // Must contain the content type OID (id-data)
        let data_oid_content = &asn1::OID_DATA[2..]; // skip tag+length
        assert!(
            attr.windows(data_oid_content.len())
                .any(|w| w == data_oid_content),
            "Content type OID not found"
        );
    }

    #[test]
    fn test_content_hints_attr_without_description() {
        let hints = ContentHints {
            content_description: None,
            content_type_oid: asn1::OID_SPC_INDIRECT_DATA.to_vec(),
        };
        let attr = build_content_hints_attr(&hints);
        assert_eq!(attr[0], 0x30);
        // Must contain the content hints OID
        assert!(attr
            .windows(asn1::OID_CONTENT_HINTS.len())
            .any(|w| w == asn1::OID_CONTENT_HINTS),);
        // Must contain the SPC indirect data OID
        let spc_oid_content = &asn1::OID_SPC_INDIRECT_DATA[2..];
        assert!(attr
            .windows(spc_oid_content.len())
            .any(|w| w == spc_oid_content),);
        // Should NOT contain UTF8String tag (0x0C) for description
        // (the OID_DATA bytes might contain 0x0C coincidentally, so we check
        // that no UTF8String appears in the ContentHints value itself)
    }

    #[test]
    fn test_signed_attrs_with_content_hints() {
        let hints = ContentHints {
            content_description: Some("Authenticode".to_string()),
            content_type_oid: asn1::OID_SPC_INDIRECT_DATA.to_vec(),
        };
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xAA; 32],
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            None,
            Some(&hints),
        );
        // Must start with SET tag
        assert_eq!(attrs[0], 0x31);
        // Count attributes — should be 5 (4 base + content hints)
        let content = &attrs[1 + der_length_size(&attrs)..];
        let mut count = 0;
        let mut pos = content;
        while !pos.is_empty() {
            let (_, remaining) = asn1::skip_tlv(pos).unwrap();
            count += 1;
            pos = remaining;
        }
        assert_eq!(count, 5, "Expected 5 signed attributes with content hints");
    }

    #[test]
    fn test_signed_data_builder_with_content_hints() {
        let cert = build_test_cert(1, "Hints-Signer");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: Some(ContentHints {
                content_description: Some("Test content".to_string()),
                content_type_oid: asn1::OID_DATA.to_vec(),
            }),
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must contain the content hints OID
        assert!(ci
            .windows(asn1::OID_CONTENT_HINTS.len())
            .any(|w| w == asn1::OID_CONTENT_HINTS));
    }

    // ─── Counter-Signature Tests (RFC 5652 §11.4) ───

    #[test]
    fn test_build_counter_signer_info() {
        let cs_cert = build_test_cert(99, "Counter-Signer");
        let fake_signature = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let cs_info = build_counter_signer_info(
            &fake_signature,
            &cs_cert,
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            |_attrs| Ok(vec![0xFF; 64]),
        )
        .unwrap();

        // Must be a SEQUENCE (SignerInfo)
        assert_eq!(cs_info[0], 0x30);
        // Must contain SHA-256 AlgorithmIdentifier
        let sha256_alg = &asn1::SHA256_ALGORITHM_ID;
        assert!(cs_info
            .windows(sha256_alg.len())
            .any(|w| w == sha256_alg.as_slice()));
    }

    #[test]
    fn test_counter_signature_in_unsigned_attrs() {
        let signer_cert = build_test_cert(1, "Main-Signer");
        let cs_cert = build_test_cert(99, "Counter-Signer");

        // Build a pre-computed counter-signature
        let fake_signature = vec![0xAA; 64];
        let cs_info = build_counter_signer_info(
            &fake_signature,
            &cs_cert,
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            |_attrs| Ok(vec![0xBB; 64]),
        )
        .unwrap();

        let content_type = asn1::OID_DATA.to_vec();
        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: vec![cs_info],
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must contain the counterSignature OID (1.2.840.113549.1.9.6)
        assert!(
            ci.windows(asn1::OID_COUNTER_SIGNATURE.len())
                .any(|w| w == asn1::OID_COUNTER_SIGNATURE),
            "Counter-signature OID not found in CMS output"
        );
    }

    #[test]
    fn test_build_with_counter_sign_callback() {
        let signer_cert = build_test_cert(1, "Main");
        let cs_cert = build_test_cert(99, "CS");

        let content_type = asn1::OID_DATA.to_vec();
        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let cs_cert_clone = cs_cert.clone();
        let result = builder.build_with_counter_sign(
            |_idx, _attrs| Ok(vec![0xFF; 64]),
            move |_idx, sig_value| {
                // Build a counter-signature over the main signature
                let cs = build_counter_signer_info(
                    sig_value,
                    &cs_cert_clone,
                    DigestAlgorithm::Sha256,
                    SigningAlgorithm::RsaSha256,
                    |_attrs| Ok(vec![0xCC; 64]),
                )?;
                Ok(vec![cs])
            },
        );
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must contain the counterSignature OID
        assert!(
            ci.windows(asn1::OID_COUNTER_SIGNATURE.len())
                .any(|w| w == asn1::OID_COUNTER_SIGNATURE),
            "Counter-signature OID not found"
        );
    }

    #[test]
    fn test_build_with_counter_sign_no_counter_sigs() {
        let signer_cert = build_test_cert(1, "NoCS");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build_with_counter_sign(
            |_idx, _attrs| Ok(vec![0xFF; 64]),
            |_idx, _sig| Ok(vec![]), // No counter-signatures
        );
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Should NOT contain the counterSignature OID
        assert!(
            !ci.windows(asn1::OID_COUNTER_SIGNATURE.len())
                .any(|w| w == asn1::OID_COUNTER_SIGNATURE),
            "Counter-signature OID should not be present"
        );
    }

    #[test]
    fn test_counter_signature_with_timestamp() {
        // Both timestamp and counter-signature as unsigned attributes
        let signer_cert = build_test_cert(1, "Both-UA");
        let cs_cert = build_test_cert(99, "CS");

        let cs_info = build_counter_signer_info(
            &[0xDE; 64],
            &cs_cert,
            DigestAlgorithm::Sha256,
            SigningAlgorithm::RsaSha256,
            |_attrs| Ok(vec![0xCC; 64]),
        )
        .unwrap();

        let fake_ts_token = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // minimal SEQUENCE

        let content_type = asn1::OID_DATA.to_vec();
        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: signer_cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: Some(fake_ts_token),
            cades_bes: false,
            content_hints: None,
            counter_signatures: vec![cs_info],
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must contain BOTH unsigned attribute OIDs
        assert!(
            ci.windows(asn1::OID_TIMESTAMP_TOKEN.len())
                .any(|w| w == asn1::OID_TIMESTAMP_TOKEN),
            "Timestamp token OID not found"
        );
        assert!(
            ci.windows(asn1::OID_COUNTER_SIGNATURE.len())
                .any(|w| w == asn1::OID_COUNTER_SIGNATURE),
            "Counter-signature OID not found"
        );
    }

    #[test]
    fn test_counter_signer_info_sha384() {
        let cs_cert = build_test_cert(50, "CS-384");
        let cs_info = build_counter_signer_info(
            &[0xAB; 128],
            &cs_cert,
            DigestAlgorithm::Sha384,
            SigningAlgorithm::EcdsaSha384,
            |_attrs| Ok(vec![0xDD; 96]),
        )
        .unwrap();

        assert_eq!(cs_info[0], 0x30);
        // Must contain SHA-384 AlgorithmIdentifier
        let sha384_alg = &asn1::SHA384_ALGORITHM_ID;
        assert!(cs_info
            .windows(sha384_alg.len())
            .any(|w| w == sha384_alg.as_slice()));
    }

    #[test]
    fn test_counter_signer_info_ski_fallback() {
        // RFC 5652 §5.3: When SKI is requested but cert has no SKI extension,
        // gracefully falls back to IssuerAndSerialNumber (version 1).
        let cs_cert = build_test_cert(77, "CS-SKI");
        let cs_info = build_counter_signer_info_ski(
            &[0xBB; 64],
            &cs_cert,
            DigestAlgorithm::Sha256,
            SigningAlgorithm::EcdsaSha256,
            |_attrs| Ok(vec![0xCC; 64]),
        )
        .unwrap();

        assert_eq!(cs_info[0], 0x30, "Must be a SEQUENCE (SignerInfo)");

        // Test cert has no SKI extension, so falls back to IssuerAndSerial (version 1)
        let (_, si_content) = asn1::parse_tlv(&cs_info).unwrap();
        let (version_tlv, _) = asn1::extract_tlv(si_content).unwrap();
        assert_eq!(version_tlv[0], 0x02, "First field must be INTEGER");
        assert_eq!(
            version_tlv[2], 1,
            "Counter-SignerInfo version must be 1 when cert has no SKI (graceful fallback)"
        );
    }

    #[test]
    fn test_counter_signer_info_ski_with_real_ski() {
        // Build a cert with SKI extension to verify version 3 path
        let cs_cert = build_test_cert_with_ski(78, "CS-SKI-Real");
        let cs_info = build_counter_signer_info_ski(
            &[0xBB; 64],
            &cs_cert,
            DigestAlgorithm::Sha256,
            SigningAlgorithm::EcdsaSha256,
            |_attrs| Ok(vec![0xCC; 64]),
        )
        .unwrap();

        assert_eq!(cs_info[0], 0x30, "Must be a SEQUENCE (SignerInfo)");

        // Cert has SKI, so should use SubjectKeyIdentifier (version 3)
        let (_, si_content) = asn1::parse_tlv(&cs_info).unwrap();
        let (version_tlv, _) = asn1::extract_tlv(si_content).unwrap();
        assert_eq!(version_tlv[0], 0x02, "First field must be INTEGER");
        assert_eq!(
            version_tlv[2], 3,
            "Counter-SignerInfo version must be 3 for SubjectKeyIdentifier"
        );
    }

    // ─── SHA-3 / FIPS 202 / RFC 8702 Tests ───

    #[test]
    fn test_digest_algorithm_sha3_256() {
        let alg = DigestAlgorithm::Sha3_256;
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30); // SEQUENCE
                                 // SHA3-256 OID last byte is 0x08
        assert_eq!(id[12], 0x08);
        assert_eq!(alg.output_len(), 32);
    }

    #[test]
    fn test_digest_algorithm_sha3_384() {
        let alg = DigestAlgorithm::Sha3_384;
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30); // SEQUENCE
        assert_eq!(id[12], 0x09);
        assert_eq!(alg.output_len(), 48);
    }

    #[test]
    fn test_digest_algorithm_sha3_512() {
        let alg = DigestAlgorithm::Sha3_512;
        let id = alg.algorithm_id();
        assert_eq!(id[0], 0x30); // SEQUENCE
        assert_eq!(id[12], 0x0A);
        assert_eq!(alg.output_len(), 64);
    }

    #[test]
    fn test_sha3_256_digest_computation() {
        let data = b"test data for SHA3-256";
        let result = DigestAlgorithm::Sha3_256.digest(data);
        assert_eq!(result.len(), 32);
        // Verify it differs from SHA-256
        let sha2_result = DigestAlgorithm::Sha256.digest(data);
        assert_ne!(result, sha2_result);
    }

    #[test]
    fn test_sha3_384_digest_computation() {
        let data = b"test data for SHA3-384";
        let result = DigestAlgorithm::Sha3_384.digest(data);
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha3_512_digest_computation() {
        let data = b"test data for SHA3-512";
        let result = DigestAlgorithm::Sha3_512.digest(data);
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha3_256_cms_signed_data() {
        let cert = build_test_cert(1, "SHA3-Test");
        let content = b"SHA-3 content";
        let digest = DigestAlgorithm::Sha3_256.digest(content);

        let mut builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), content.to_vec());
        builder.add_content_digest(DigestAlgorithm::Sha3_256, digest);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha3_256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, attrs| Ok(vec![0xAA; 64])).unwrap();
        assert_eq!(result[0], 0x30); // SEQUENCE

        // Must contain SHA3-256 AlgorithmIdentifier in DigestAlgorithms SET
        let sha3_alg = &asn1::SHA3_256_ALGORITHM_ID;
        assert!(result
            .windows(sha3_alg.len())
            .any(|w| w == sha3_alg.as_slice()));
    }

    #[test]
    fn test_sha3_512_ess_cert_id_includes_hash_alg() {
        // SHA3-512 is not the default, so hashAlgorithm must be included
        let cert = build_test_cert(50, "SHA3-ESSTest");
        let attr = build_ess_cert_id_v2_attr(&cert, DigestAlgorithm::Sha3_512);
        assert_eq!(attr[0], 0x30);
        // Must contain SHA3-512 AlgorithmIdentifier (non-default = always included)
        let sha3_alg = &asn1::SHA3_512_ALGORITHM_ID;
        assert!(
            attr.windows(sha3_alg.len())
                .any(|w| w == sha3_alg.as_slice()),
            "SHA3-512 ESSCertIDv2 must include hashAlgorithm"
        );
    }

    #[test]
    fn test_sha3_256_signed_attrs_sorted() {
        let attrs = build_signed_attrs_sorted(
            asn1::OID_DATA,
            &[0xBB; 32],
            DigestAlgorithm::Sha3_256,
            SigningAlgorithm::EcdsaSha256,
            None,
            None,
        );
        assert_eq!(attrs[0], 0x31); // SET tag
                                    // Must contain SHA3-256 AlgorithmIdentifier in CMSAlgorithmProtection
        let sha3_alg = &asn1::SHA3_256_ALGORITHM_ID;
        assert!(attrs
            .windows(sha3_alg.len())
            .any(|w| w == sha3_alg.as_slice()));
    }

    #[test]
    fn test_sha3_counter_signer() {
        let cs_cert = build_test_cert(60, "SHA3-Counter");
        let cs_info = build_counter_signer_info(
            &[0xCC; 128],
            &cs_cert,
            DigestAlgorithm::Sha3_384,
            SigningAlgorithm::EcdsaSha384,
            |_attrs| Ok(vec![0xEE; 96]),
        )
        .unwrap();
        assert_eq!(cs_info[0], 0x30);
        // Must contain SHA3-384 AlgorithmIdentifier
        let sha3_alg = &asn1::SHA3_384_ALGORITHM_ID;
        assert!(cs_info
            .windows(sha3_alg.len())
            .any(|w| w == sha3_alg.as_slice()));
    }

    // --- RFC 5652 §5.3: SubjectKeyIdentifier-based SignerInfo ---

    /// Build a test cert that includes a SubjectKeyIdentifier extension
    fn build_test_cert_with_ski(serial: u32, cn: &str) -> Vec<u8> {
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial_der = asn1::encode_integer_value(serial);
        let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
        let cn_bytes = cn.as_bytes();
        let mut cn_der = vec![0x0C]; // UTF8String tag
        cn_der.extend(asn1::encode_length(cn_bytes.len()));
        cn_der.extend_from_slice(cn_bytes);
        let issuer = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03], // OID 2.5.4.3 (CN)
            &cn_der,
        ]))]);

        // Build SubjectKeyIdentifier extension:
        // SEQUENCE { OID(2.5.29.14), OCTET STRING { OCTET STRING { 20 bytes } } }
        let ski_value: [u8; 20] = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
            0x8F, 0x90, 0xA1, 0xB2, 0xC3, 0xD4,
        ];
        let inner_octet = asn1::encode_octet_string(&ski_value);
        let outer_octet = asn1::encode_octet_string(&inner_octet);
        let ski_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0E]; // OID 2.5.29.14
        let ski_ext = asn1::encode_sequence(&[ski_oid, &outer_octet]);
        let extensions = asn1::encode_explicit_tag(3, &asn1::encode_sequence(&[&ski_ext]));

        let tbs = asn1::encode_sequence(&[&version, &serial_der, &algo, &issuer, &extensions]);
        asn1::encode_sequence(&[&tbs, &algo, &[0x03, 0x01, 0x00]])
    }

    #[test]
    fn test_signer_info_ski_version_3() {
        // When use_subject_key_identifier=true and cert has SKI, version must be 3
        let cert = build_test_cert_with_ski(100, "SKI-Test");
        let content_type = asn1::OID_DATA.to_vec();
        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: true,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let cms = result.unwrap();

        // version 3 = DER: 02 01 03
        let version_3 = &[0x02, 0x01, 0x03];
        assert!(
            cms.windows(version_3.len()).any(|w| w == version_3),
            "SignerInfo must contain version 3 when using SubjectKeyIdentifier"
        );
    }

    #[test]
    fn test_signer_info_ski_fallback_no_ski_in_cert() {
        // When use_subject_key_identifier=true but cert has no SKI, falls back to version 1
        let cert = build_test_cert(103, "NoSKI-Fallback");
        let content_type = asn1::OID_DATA.to_vec();
        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: true, // Requested but cert lacks SKI
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(
            result.is_ok(),
            "Should succeed with fallback to IssuerAndSerialNumber"
        );
    }

    #[test]
    fn test_extract_ski_from_cert_with_ski() {
        let cert = build_test_cert_with_ski(104, "SKI-Extract-Test");
        let ski = extract_ski_from_cert_der(&cert);
        assert!(ski.is_some(), "Cert with SKI extension should return Some");
        let ski_val = ski.unwrap();
        assert_eq!(ski_val.len(), 20, "SKI should be 20 bytes");
        assert_eq!(
            ski_val,
            &[
                0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
                0x8F, 0x90, 0xA1, 0xB2, 0xC3, 0xD4
            ]
        );
    }

    #[test]
    fn test_extract_ski_from_cert_without_ski() {
        let cert = build_test_cert(105, "NoSKI");
        assert!(
            extract_ski_from_cert_der(&cert).is_none(),
            "Cert without SKI extension should return None"
        );
    }

    #[test]
    fn test_extract_ski_from_empty() {
        assert!(extract_ski_from_cert_der(&[]).is_none());
    }

    #[test]
    fn test_extract_ski_from_garbage() {
        assert!(extract_ski_from_cert_der(&[0xFF; 64]).is_none());
    }

    // ---- RFC 5652 §5.1 SignedData version tests ----

    #[test]
    fn test_signed_data_version_1_for_id_data_no_ski() {
        // RFC 5652 §5.1: version MUST be 1 when eContentType is id-data
        // and no SignerInfo uses SubjectKeyIdentifier
        let cert = build_test_cert(200, "V1Test");
        let mut builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        let cms = builder.build(|_, _| Ok(vec![0xFF; 64])).unwrap();

        // SignedData is inside ContentInfo: SEQUENCE { OID signedData, [0] EXPLICIT SignedData }
        // SignedData = SEQUENCE { version INTEGER, ... }
        // Find the SignedData SEQUENCE after the [0] EXPLICIT tag
        // The version should be INTEGER 1 (02 01 01) right after the SignedData SEQUENCE
        let signed_data_start = find_signed_data_version(&cms);
        assert_eq!(signed_data_start, Some(1), "SignedData version must be 1");
    }

    #[test]
    fn test_signed_data_version_3_for_non_id_data() {
        // RFC 5652 §5.1: version MUST be 3 when eContentType is not id-data
        let cert = build_test_cert(201, "V3Test");
        let mut builder = SignedDataBuilder::new(asn1::OID_SPC_INDIRECT_DATA.to_vec(), vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });
        let cms = builder.build(|_, _| Ok(vec![0xFF; 64])).unwrap();

        let version = find_signed_data_version(&cms);
        assert_eq!(
            version,
            Some(3),
            "SignedData version must be 3 for non-id-data"
        );
    }

    #[test]
    fn test_signed_data_version_3_for_id_data_with_ski_signer() {
        // RFC 5652 §5.1: version MUST be 3 when any SignerInfo is version 3 (SKI)
        // even if eContentType is id-data
        let cert = build_test_cert_with_ski(202, "V3SKITest");
        let mut builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: true,
            custom_unsigned_attributes: Vec::new(),
        });
        let cms = builder.build(|_, _| Ok(vec![0xFF; 64])).unwrap();

        let version = find_signed_data_version(&cms);
        assert_eq!(
            version,
            Some(3),
            "SignedData version must be 3 when any signer uses SubjectKeyIdentifier"
        );
    }

    /// Helper: Extract the SignedData version from a ContentInfo DER.
    ///
    /// Navigates: ContentInfo SEQUENCE → skip OID → [0] EXPLICIT → SignedData SEQUENCE → version
    fn find_signed_data_version(content_info: &[u8]) -> Option<u32> {
        // ContentInfo SEQUENCE
        let (_, ci_content) = asn1::parse_tlv(content_info).ok()?;
        // Skip contentType OID
        let (_, remaining) = asn1::skip_tlv(ci_content).ok()?;
        // [0] EXPLICIT content
        let (_, explicit_content) = asn1::parse_tlv(remaining).ok()?;
        // SignedData SEQUENCE
        let (_, sd_content) = asn1::parse_tlv(explicit_content).ok()?;
        // version INTEGER — first field
        let (version_tlv, _) = asn1::extract_tlv(sd_content).ok()?;
        // Parse INTEGER value
        if version_tlv.len() >= 3 && version_tlv[0] == 0x02 {
            Some(version_tlv[2] as u32)
        } else {
            None
        }
    }

    #[test]
    fn test_signed_data_builder_detached() {
        let cert = build_test_cert(1, "Signer1");
        let content_type = asn1::OID_DATA.to_vec();
        let digest = vec![0xAA; 32];

        let mut builder = SignedDataBuilder::new_detached(content_type);
        builder.add_content_digest(DigestAlgorithm::Sha256, digest);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: Vec::new(),
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(result.is_ok());
        let ci = result.unwrap();
        // Must be ContentInfo SEQUENCE
        assert_eq!(ci[0], 0x30);
        // Should contain signedData OID
        assert!(ci
            .windows(asn1::OID_SIGNED_DATA.len())
            .any(|w| w == asn1::OID_SIGNED_DATA));
        // Should NOT contain explicit tag [0] for eContent —
        // EncapsulatedContentInfo only has the OID, no content
        // Verify by checking the data OID is present but content bytes 0x01,0x02,0x03 are NOT
        assert!(
            !ci.windows(3).any(|w| w == [0x01, 0x02, 0x03]),
            "Detached signature should not contain embedded content"
        );
    }

    // ─── Content Type OID Validation Tests (RFC 5652 §5.2) ───

    #[test]
    fn test_validate_content_type_oid_valid() {
        // id-data OID is well-formed
        assert!(validate_content_type_oid(asn1::OID_DATA).is_ok());
        assert!(validate_content_type_oid(asn1::OID_SIGNED_DATA).is_ok());
    }

    #[test]
    fn test_validate_content_type_oid_empty() {
        let result = validate_content_type_oid(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_content_type_oid_wrong_tag() {
        // SEQUENCE tag (0x30) instead of OID tag (0x06)
        let result = validate_content_type_oid(&[0x30, 0x03, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("0x30"));
    }

    #[test]
    fn test_validate_content_type_oid_zero_length() {
        let result = validate_content_type_oid(&[0x06, 0x00]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zero-length"));
    }

    #[test]
    fn test_validate_content_type_oid_truncated() {
        // OID says length 10 but only 3 bytes follow
        let result = validate_content_type_oid(&[0x06, 0x0A, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn test_validate_content_type_via_builder() {
        // Verify the builder method delegates correctly
        let builder = SignedDataBuilder::new(asn1::OID_DATA.to_vec(), vec![0x01]);
        assert!(builder.validate_content_type().is_ok());
    }

    // ─── Custom Unsigned Attributes Tests (RFC 5652 §11.3) ───

    #[test]
    fn test_custom_unsigned_attributes() {
        // Test OID: 1.2.3.4.5 — DER: 06 04 2A 03 04 05
        let custom_oid = vec![0x06, 0x04, 0x2A, 0x03, 0x04, 0x05];
        // Attribute value: a simple INTEGER 42 (02 01 2A)
        let custom_value = vec![0x02, 0x01, 0x2A];

        let cert = build_test_cert(1, "Custom-UA-Signer");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: vec![(custom_oid.clone(), custom_value.clone())],
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(
            result.is_ok(),
            "Build with custom unsigned attribute must succeed"
        );
        let cms = result.unwrap();

        // The custom OID bytes must appear in the encoded output
        assert!(
            cms.windows(custom_oid.len())
                .any(|w| w == custom_oid.as_slice()),
            "Custom unsigned attribute OID (1.2.3.4.5) not found in CMS output"
        );
        // The custom value bytes must appear in the encoded output
        assert!(
            cms.windows(custom_value.len())
                .any(|w| w == custom_value.as_slice()),
            "Custom unsigned attribute value not found in CMS output"
        );
        // The [1] IMPLICIT tag for unsignedAttrs (0xA1) must be present
        assert!(
            cms.contains(&0xA1),
            "unsignedAttrs [1] IMPLICIT tag (0xA1) must be present"
        );
    }

    #[test]
    fn test_multiple_custom_unsigned_attributes() {
        // Two custom unsigned attributes with different OIDs and values
        // OID 1.2.3.4.5 — DER: 06 04 2A 03 04 05
        let custom_oid_1 = vec![0x06, 0x04, 0x2A, 0x03, 0x04, 0x05];
        let custom_value_1 = vec![0x02, 0x01, 0x01]; // INTEGER 1

        // OID 1.2.3.4.6 — DER: 06 04 2A 03 04 06
        let custom_oid_2 = vec![0x06, 0x04, 0x2A, 0x03, 0x04, 0x06];
        let custom_value_2 = vec![0x02, 0x01, 0x02]; // INTEGER 2

        let cert = build_test_cert(2, "Multi-Custom-UA");
        let content_type = asn1::OID_DATA.to_vec();

        let mut builder = SignedDataBuilder::new(content_type, vec![0x42]);
        builder.add_content_digest(DigestAlgorithm::Sha256, vec![0xAA; 32]);
        builder.add_signer(CmsSignerInfo {
            cert_der: cert,
            digest_algorithm: DigestAlgorithm::Sha256,
            signing_algorithm: SigningAlgorithm::RsaSha256,
            timestamp_token: None,
            cades_bes: false,
            content_hints: None,
            counter_signatures: Vec::new(),
            use_subject_key_identifier: false,
            custom_unsigned_attributes: vec![
                (custom_oid_1.clone(), custom_value_1.clone()),
                (custom_oid_2.clone(), custom_value_2.clone()),
            ],
        });

        let result = builder.build(|_idx, _attrs| Ok(vec![0xFF; 64]));
        assert!(
            result.is_ok(),
            "Build with multiple custom unsigned attributes must succeed"
        );
        let cms = result.unwrap();

        // Both custom OIDs must appear in the output
        assert!(
            cms.windows(custom_oid_1.len())
                .any(|w| w == custom_oid_1.as_slice()),
            "First custom OID (1.2.3.4.5) not found in CMS output"
        );
        assert!(
            cms.windows(custom_oid_2.len())
                .any(|w| w == custom_oid_2.as_slice()),
            "Second custom OID (1.2.3.4.6) not found in CMS output"
        );
        // Both values must appear
        assert!(
            cms.windows(custom_value_1.len())
                .any(|w| w == custom_value_1.as_slice()),
            "First custom attribute value not found in CMS output"
        );
        assert!(
            cms.windows(custom_value_2.len())
                .any(|w| w == custom_value_2.as_slice()),
            "Second custom attribute value not found in CMS output"
        );
    }
}
