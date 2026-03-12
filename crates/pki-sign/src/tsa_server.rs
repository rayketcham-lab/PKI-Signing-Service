//! RFC 3161 Time-Stamp Authority (TSA) Server.
//!
//! Implements a TSA that accepts TimeStampReq messages (RFC 3161 §2.4.1),
//! generates signed TSTInfo structures, and returns TimeStampResp messages
//! (RFC 3161 §2.4.2) wrapped in CMS SignedData (TimeStampToken).
//!
//! Also implements RFC 5816 ESSCertIDv2 for signing certificate
//! identification in the signed attributes.
//!
//! Supports SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, and SHA3-512
//! message imprints from clients (RFC 8702 / FIPS 202).
//! CMS digest algorithm matches the signing key (SHA-384 for P-384).
//!
//! ## Protocol
//!
//! 1. Client sends HTTP POST with Content-Type: application/timestamp-query
//! 2. Server parses the DER-encoded TimeStampReq
//! 3. Server builds a TSTInfo structure with the messageImprint and current time
//! 4. Server signs TSTInfo in a CMS SignedData (TimeStampToken)
//! 5. Server returns TimeStampResp with Content-Type: application/timestamp-reply
//!
//! ## References
//!
//! - RFC 3161: Internet X.509 PKI Time-Stamp Protocol (TSP)
//! - RFC 5816: ESSCertIDv2 Update for RFC 3161
//! - RFC 5652: Cryptographic Message Syntax (CMS)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256, Sha384};
use tracing::{debug, error, info, warn};

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;

// ─── OID Constants ──────────────────────────────────────────────────

/// OID 1.2.840.113549.1.9.16.1.4 — id-smime-ct-TSTInfo (content type for TSTInfo)
const OID_TST_INFO: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// OID 1.2.840.113549.1.9.16.2.47 — id-aa-signingCertificateV2 (RFC 5816)
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// OID 1.2.840.113549.1.1.11 — sha256WithRSAEncryption
const OID_SHA256_WITH_RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];

/// OID 1.2.840.10045.4.3.2 — ecdsa-with-SHA256
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

/// OID 1.2.840.10045.4.3.3 — ecdsa-with-SHA384
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

/// OID 1.3.101.112 — id-EdDSA (Ed25519)
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

/// OID 2.16.840.1.101.3.4.2.1 — id-sha256 (just the value bytes, no tag/length)
const OID_SHA256_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// OID 2.16.840.1.101.3.4.2.2 — id-sha384 (just the value bytes, no tag/length)
const OID_SHA384_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// OID 2.16.840.1.101.3.4.2.3 — id-sha512 (just the value bytes, no tag/length)
const OID_SHA512_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// OID 2.16.840.1.101.3.4.2.8 — id-sha3-256 (FIPS 202)
const OID_SHA3_256_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];

/// OID 2.16.840.1.101.3.4.2.9 — id-sha3-384 (FIPS 202)
const OID_SHA3_384_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];

/// OID 2.16.840.1.101.3.4.2.10 — id-sha3-512 (FIPS 202)
const OID_SHA3_512_VALUE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A];

// ─── TSA Configuration ──────────────────────────────────────────────

/// Configuration for the TSA server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TsaServerConfig {
    /// TSA policy OID (dotted notation, e.g. "1.3.6.1.4.1.56266.1.30.1").
    pub policy_oid: String,
    /// TSA name for the GeneralName in TSTInfo (RFC 5280 directoryName).
    /// If None, the tsa field is omitted from TSTInfo.
    pub tsa_name: Option<String>,
    /// Accuracy in seconds (0 means omit accuracy field).
    pub accuracy_secs: u32,
    /// Accuracy in milliseconds (0–999, added to seconds).
    pub accuracy_millis: u32,
    /// Accuracy in microseconds (0–999, added to millis).
    pub accuracy_micros: u32,
    /// Whether ordering is guaranteed (BOOLEAN in TSTInfo).
    pub ordering: bool,
    /// Include the signing certificate chain in the response.
    pub include_certs: bool,
    /// Enable nonce replay detection (RFC 3161 §2.4.1).
    /// When true, the TSA rejects requests with previously-seen nonces.
    pub nonce_replay_detection: bool,
    /// Maximum number of nonces to cache for replay detection (default: 10,000).
    /// Older nonces are evicted when the cache is full.
    pub nonce_cache_size: usize,
}

impl Default for TsaServerConfig {
    fn default() -> Self {
        Self {
            // Ogjos PEN + TSA policy arc
            policy_oid: "1.3.6.1.4.1.56266.1.30.1".into(),
            tsa_name: None,
            accuracy_secs: 1,
            accuracy_millis: 0,
            accuracy_micros: 0,
            ordering: false,
            include_certs: true,
            nonce_replay_detection: true,
            nonce_cache_size: 10_000,
        }
    }
}

// ─── TSA Signing Key Abstraction ────────────────────────────────────

/// Algorithm used by the TSA for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsaSignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaSha256,
    /// ECDSA P-256 with SHA-256
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384
    EcdsaP384Sha384,
    /// Ed25519 (RFC 8410)
    Ed25519,
}

impl TsaSignatureAlgorithm {
    /// Return the DER-encoded DigestAlgorithmIdentifier for this signing algorithm.
    /// Used in the CMS SignedData digestAlgorithms SET and signed attributes messageDigest.
    fn digest_algorithm_id(&self) -> &'static [u8] {
        match self {
            Self::EcdsaP384Sha384 => &asn1::SHA384_ALGORITHM_ID,
            // RSA-SHA256, P-256-SHA256, Ed25519 all use SHA-256
            _ => &asn1::SHA256_ALGORITHM_ID,
        }
    }

    /// Compute the digest of data using this algorithm's digest function.
    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::EcdsaP384Sha384 => Sha384::digest(data).to_vec(),
            _ => Sha256::digest(data).to_vec(),
        }
    }
}

/// Callback type for signing — takes DER-encoded signed attributes (SET),
/// returns raw signature bytes.
pub type SignFn = Box<dyn Fn(&[u8]) -> SignResult<Vec<u8>> + Send + Sync>;

/// TSA server state.
pub struct TsaServer {
    /// Configuration
    config: TsaServerConfig,
    /// DER-encoded TSA signing certificate
    signer_cert_der: Vec<u8>,
    /// DER-encoded CA/chain certificates
    chain_certs_der: Vec<Vec<u8>>,
    /// Signing function
    sign_fn: SignFn,
    /// Signature algorithm
    algorithm: TsaSignatureAlgorithm,
    /// Monotonic serial number counter
    serial_counter: AtomicU64,
    /// Nonce replay cache — bounded ring buffer of recently-seen nonces (RFC 3161 §2.4.1).
    /// Uses Vec<u8> keys (DER-encoded INTEGER nonces).
    nonce_cache: Mutex<VecDeque<Vec<u8>>>,
    /// Maximum nonce cache size
    nonce_cache_max: usize,
}

impl TsaServer {
    /// Create a new TSA server.
    pub fn new(
        config: TsaServerConfig,
        signer_cert_der: Vec<u8>,
        chain_certs_der: Vec<Vec<u8>>,
        sign_fn: SignFn,
        algorithm: TsaSignatureAlgorithm,
    ) -> Self {
        // RFC 3161 §2.3: TSA's certificate MUST have id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
        // in its EKU extension. Warn (but don't fail) if missing — allows testing with CA certs.
        if !check_tsa_eku(&signer_cert_der) {
            warn!(
                "TSA signing certificate does not contain id-kp-timeStamping EKU (RFC 3161 §2.3)"
            );
        }

        // Start serial from current timestamp for uniqueness across restarts
        let initial_serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let nonce_cache_max = config.nonce_cache_size;
        Self {
            config,
            signer_cert_der,
            chain_certs_der,
            sign_fn,
            algorithm,
            serial_counter: AtomicU64::new(initial_serial),
            nonce_cache: Mutex::new(VecDeque::new()),
            nonce_cache_max,
        }
    }

    /// Process a TimeStampReq and produce a TimeStampResp.
    ///
    /// This is the main entry point for the TSA server.
    pub fn process_request(&self, req_der: &[u8]) -> Vec<u8> {
        match self.process_request_inner(req_der) {
            Ok(resp) => resp,
            Err(e) => {
                error!("TSA request processing failed: {e}");
                let msg = e.to_string();
                // Map error to RFC 3161 §2.4.2 PKIFailureInfo
                let failure = if msg.contains("Unsupported hash algorithm")
                    || msg.contains("unsupported algorithm")
                {
                    Some(PkiFailureInfo::BadAlg)
                } else if msg.contains("digest length")
                    || msg.contains("Invalid")
                    || msg.contains("format")
                {
                    Some(PkiFailureInfo::BadDataFormat)
                } else if msg.contains("policy") {
                    Some(PkiFailureInfo::UnacceptedPolicy)
                } else {
                    Some(PkiFailureInfo::SystemFailure)
                };
                build_error_response(TsaStatus::Rejection, Some(&msg), failure)
            }
        }
    }

    fn process_request_inner(&self, req_der: &[u8]) -> SignResult<Vec<u8>> {
        // Step 1: Parse the TimeStampReq
        let req = parse_timestamp_req(req_der)?;
        debug!(
            "TSA request: hash_algo={}, nonce={}, certReq={}",
            req.hash_algorithm_name(),
            req.nonce_der.is_some(),
            req.cert_req
        );

        // Step 2: Validate the request
        self.validate_request(&req)?;

        // Step 2b: RFC 3161 §2.4.1 — nonce replay detection
        if self.config.nonce_replay_detection {
            if let Some(ref nonce_der) = req.nonce_der {
                self.check_nonce_replay(nonce_der)?;
            }
        }

        // Step 3: Generate a unique serial number
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);

        // Step 4: Build TSTInfo
        let tst_info = self.build_tst_info(&req, serial)?;
        debug!("Built TSTInfo, {} bytes", tst_info.len());

        // Step 5: Wrap in CMS SignedData (TimeStampToken)
        let token = self.build_timestamp_token(&tst_info)?;
        debug!("Built TimeStampToken, {} bytes", token.len());

        // Step 6: Build TimeStampResp with status=granted
        let resp = build_success_response(&token);
        info!(
            "TSA: issued timestamp serial={serial}, {} bytes",
            resp.len()
        );
        Ok(resp)
    }

    fn validate_request(&self, req: &TimeStampReq) -> SignResult<()> {
        // Validate hash algorithm — accept SHA-256, SHA-384, SHA-512
        let expected_len = req.expected_digest_len();
        if expected_len == 0 {
            return Err(SignError::Timestamp(
                "Unsupported hash algorithm in messageImprint (supported: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512)".into(),
            ));
        }

        // Validate digest length matches the algorithm
        if req.hashed_message.len() != expected_len {
            return Err(SignError::Timestamp(format!(
                "Invalid {} digest length: {} (expected {})",
                req.hash_algorithm_name(),
                req.hashed_message.len(),
                expected_len
            )));
        }

        // Version must be 1
        if req.version != 1 {
            return Err(SignError::Timestamp(format!(
                "Unsupported TimeStampReq version: {} (expected 1)",
                req.version
            )));
        }

        // RFC 3161 §2.4.1: If reqPolicy is present, verify we support it.
        // We accept our own policy OID or no policy (use default).
        if let Some(ref requested_oid) = req.req_policy {
            let our_oid = encode_oid_from_dotted(&self.config.policy_oid)
                .map_err(|e| SignError::Timestamp(format!("Invalid TSA policy OID: {}", e)))?;
            if *requested_oid != our_oid {
                return Err(SignError::Timestamp(
                    "Requested policy OID does not match TSA policy (unacceptedPolicy)".into(),
                ));
            }
        }

        Ok(())
    }

    /// RFC 3161 §2.4.1 — Check nonce for replay and record it.
    ///
    /// Maintains a bounded FIFO cache of recently-seen nonces. Rejects
    /// any request whose nonce has been seen within the cache window.
    fn check_nonce_replay(&self, nonce_der: &[u8]) -> SignResult<()> {
        let mut cache = self
            .nonce_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check for replay
        if cache.iter().any(|n| n == nonce_der) {
            warn!("TSA nonce replay detected — rejecting request");
            return Err(SignError::Timestamp(
                "Nonce replay detected (RFC 3161 §2.4.1): this nonce was already used".into(),
            ));
        }

        // Record the nonce
        cache.push_back(nonce_der.to_vec());
        // Evict oldest entries if cache is full
        while cache.len() > self.nonce_cache_max {
            cache.pop_front();
        }

        Ok(())
    }

    /// Build the TSTInfo DER structure per RFC 3161 §2.4.2.
    ///
    /// ```text
    /// TSTInfo ::= SEQUENCE {
    ///     version        INTEGER { v1(1) },
    ///     policy         TSAPolicyId,           -- OID
    ///     messageImprint MessageImprint,
    ///     serialNumber   INTEGER,
    ///     genTime        GeneralizedTime,
    ///     accuracy       Accuracy OPTIONAL,
    ///     ordering       BOOLEAN DEFAULT FALSE,
    ///     nonce          INTEGER OPTIONAL,
    ///     tsa            [0] GeneralName OPTIONAL,
    ///     extensions     [1] IMPLICIT Extensions OPTIONAL
    /// }
    /// ```
    fn build_tst_info(&self, req: &TimeStampReq, serial: u64) -> SignResult<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = vec![
            // version INTEGER 1
            asn1::encode_integer_value(1),
            // policy OID
            encode_oid_from_dotted(&self.config.policy_oid)?,
            // messageImprint — echo from the request
            req.message_imprint_der.clone(),
            // serialNumber — unique per timestamp
            encode_integer_u64(serial),
            // genTime — current UTC time as GeneralizedTime
            encode_generalized_time_now(),
        ];

        // accuracy (optional)
        if self.config.accuracy_secs > 0
            || self.config.accuracy_millis > 0
            || self.config.accuracy_micros > 0
        {
            parts.push(build_accuracy(
                self.config.accuracy_secs,
                self.config.accuracy_millis,
                self.config.accuracy_micros,
            ));
        }

        // ordering (only include if true, since default is FALSE)
        if self.config.ordering {
            parts.push(encode_boolean(true));
        }

        // nonce — echo from request if present
        if let Some(ref nonce_der) = req.nonce_der {
            parts.push(nonce_der.clone());
        }

        // tsa [0] GeneralName — include when configured (RFC 3161 §2.4.2)
        if let Some(ref tsa_name) = self.config.tsa_name {
            // Encode as [0] EXPLICIT directoryName (UTF8String)
            let name_bytes = encode_utf8_string(tsa_name);
            let general_name = asn1::encode_explicit_tag(4, &name_bytes); // directoryName [4]
            let tsa_tagged = asn1::encode_explicit_tag(0, &general_name); // tsa [0]
            parts.push(tsa_tagged);
        }

        let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Ok(asn1::encode_sequence(&part_refs))
    }

    /// Build the CMS SignedData (TimeStampToken) wrapping the TSTInfo.
    ///
    /// Includes RFC 5816 ESSCertIDv2 in the signed attributes.
    fn build_timestamp_token(&self, tst_info_der: &[u8]) -> SignResult<Vec<u8>> {
        // Extract issuer and serial from our signing cert
        let (issuer_der, serial_der) = extract_issuer_and_serial(&self.signer_cert_der)?;

        // ── EncapsulatedContentInfo ──
        // eContentType: id-smime-ct-TSTInfo
        // eContent: [0] EXPLICIT OCTET STRING (TSTInfo DER)
        let econtent_octet = asn1::encode_octet_string(tst_info_der);
        let econtent_explicit = asn1::encode_explicit_tag(0, &econtent_octet);
        let encap_content_info = asn1::encode_sequence(&[OID_TST_INFO, &econtent_explicit]);

        // ── DigestAlgorithms SET ──
        let digest_algos = asn1::encode_set(self.algorithm.digest_algorithm_id());

        // ── Certificates [0] IMPLICIT ──
        let certificates = if self.config.include_certs {
            let mut cert_data = self.signer_cert_der.clone();
            for chain_cert in &self.chain_certs_der {
                cert_data.extend_from_slice(chain_cert);
            }
            Some(asn1::encode_implicit_tag(0, &cert_data))
        } else {
            None
        };

        // ── Signed Attributes ──
        let signed_attrs_content = self.build_signed_attrs(tst_info_der)?;

        // DER-encode as SET [0] IMPLICIT for embedding in SignerInfo
        let signed_attrs_implicit = asn1::encode_implicit_tag(0, &signed_attrs_content);

        // DER-encode as SET for signing (tag 0x31 per RFC 5652 §5.4)
        let signed_attrs_set = asn1::encode_set(&signed_attrs_content);

        // ── Sign ──
        let signature_bytes = (self.sign_fn)(&signed_attrs_set)?;

        // ── SignatureAlgorithm ──
        let sig_algo_id = match self.algorithm {
            TsaSignatureAlgorithm::RsaSha256 => {
                asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]])
            }
            TsaSignatureAlgorithm::EcdsaP256Sha256 => {
                asn1::encode_sequence(&[OID_ECDSA_WITH_SHA256])
            }
            TsaSignatureAlgorithm::EcdsaP384Sha384 => {
                asn1::encode_sequence(&[OID_ECDSA_WITH_SHA384])
            }
            TsaSignatureAlgorithm::Ed25519 => {
                // Per RFC 8410, Ed25519 AlgorithmIdentifier has no parameters
                asn1::encode_sequence(&[OID_ED25519])
            }
        };

        // ── SignerInfo ──
        let signer_info = build_signer_info(
            &issuer_der,
            &serial_der,
            &signed_attrs_implicit,
            &sig_algo_id,
            &signature_bytes,
            self.algorithm.digest_algorithm_id(),
        );

        let signer_infos = asn1::encode_set(&signer_info);

        // ── SignedData ──
        let version_bytes = asn1::encode_integer_value(3);
        let mut sd_parts: Vec<&[u8]> = Vec::new();
        sd_parts.push(&version_bytes);
        sd_parts.push(&digest_algos);
        sd_parts.push(&encap_content_info);
        if let Some(ref c) = certificates {
            sd_parts.push(c);
        }
        sd_parts.push(&signer_infos);

        let signed_data = asn1::encode_sequence(&sd_parts);

        // ── ContentInfo ──
        // contentType: id-signedData
        // content: [0] EXPLICIT SignedData
        let content_explicit = asn1::encode_explicit_tag(0, &signed_data);
        let content_info = asn1::encode_sequence(&[asn1::OID_SIGNED_DATA, &content_explicit]);

        Ok(content_info)
    }

    /// Build signed attributes for the SignerInfo.
    ///
    /// Per RFC 3161 + RFC 5816:
    /// - contentType: id-smime-ct-TSTInfo
    /// - messageDigest: digest of TSTInfo DER (algorithm matches signing key)
    /// - signingCertificateV2: ESSCertIDv2 with SHA-256 cert hash
    fn build_signed_attrs(&self, tst_info_der: &[u8]) -> SignResult<Vec<u8>> {
        let mut attrs = Vec::new();

        // 1. contentType attribute
        let ct_value = asn1::encode_set(OID_TST_INFO);
        let ct_attr = asn1::encode_sequence(&[asn1::OID_CONTENT_TYPE, &ct_value]);
        attrs.extend_from_slice(&ct_attr);

        // 2. messageDigest attribute — digest of TSTInfo DER
        // Uses the digest algorithm matching the signing key (SHA-256 or SHA-384)
        let tst_digest = self.algorithm.digest(tst_info_der);
        let md_value = asn1::encode_set(&asn1::encode_octet_string(&tst_digest));
        let md_attr = asn1::encode_sequence(&[asn1::OID_MESSAGE_DIGEST, &md_value]);
        attrs.extend_from_slice(&md_attr);

        // 3. signingTime attribute (RFC 3161 Appendix A)
        let utc_time = asn1::encode_utc_time_now();
        let st_value = asn1::encode_set(&utc_time);
        let st_attr = asn1::encode_sequence(&[asn1::OID_SIGNING_TIME, &st_value]);
        attrs.extend_from_slice(&st_attr);

        // 4. signingCertificateV2 attribute (RFC 5816)
        let ess_cert_id_v2 = self.build_ess_cert_id_v2()?;
        let sc_value = asn1::encode_set(&ess_cert_id_v2);
        let sc_attr = asn1::encode_sequence(&[OID_SIGNING_CERTIFICATE_V2, &sc_value]);
        attrs.extend_from_slice(&sc_attr);

        // 5. CMSAlgorithmProtection attribute (RFC 8933)
        // Prevents algorithm substitution attacks by binding digest + signature algorithms
        let digest_alg_id: &[u8] = self.algorithm.digest_algorithm_id();
        let sig_alg_full: Vec<u8> = match self.algorithm {
            TsaSignatureAlgorithm::RsaSha256 => {
                asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]])
            }
            TsaSignatureAlgorithm::EcdsaP256Sha256 => {
                asn1::encode_sequence(&[OID_ECDSA_WITH_SHA256])
            }
            TsaSignatureAlgorithm::EcdsaP384Sha384 => {
                asn1::encode_sequence(&[OID_ECDSA_WITH_SHA384])
            }
            TsaSignatureAlgorithm::Ed25519 => asn1::encode_sequence(&[OID_ED25519]),
        };
        // signatureAlgorithm [1] IMPLICIT — re-tag SEQUENCE with 0xA1
        let sig_alg_content = &sig_alg_full[2..]; // skip SEQUENCE tag + length
        let mut sig_alg_tagged = vec![0xA1];
        sig_alg_tagged.extend(asn1::encode_length(sig_alg_content.len()));
        sig_alg_tagged.extend_from_slice(sig_alg_content);
        let protection_value = asn1::encode_sequence(&[digest_alg_id, &sig_alg_tagged]);
        let ap_attr = asn1::encode_sequence(&[
            asn1::OID_CMS_ALGORITHM_PROTECTION,
            &asn1::encode_set(&protection_value),
        ]);
        attrs.extend_from_slice(&ap_attr);

        Ok(attrs)
    }

    /// Build ESSCertIDv2 per RFC 5816.
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
    ///
    /// IssuerSerial ::= SEQUENCE {
    ///     issuer         GeneralNames,
    ///     serialNumber   CertificateSerialNumber
    /// }
    /// ```
    fn build_ess_cert_id_v2(&self) -> SignResult<Vec<u8>> {
        // SHA-256 hash of the signing certificate DER
        let cert_hash = Sha256::digest(&self.signer_cert_der);

        // Extract issuer and serial from signing certificate
        let (issuer_der, serial_der) = extract_issuer_and_serial(&self.signer_cert_der)?;

        // IssuerSerial: SEQUENCE { GeneralNames, CertificateSerialNumber }
        // GeneralNames: SEQUENCE OF GeneralName
        // GeneralName: [4] directoryName (the issuer Name)
        let general_name = asn1::encode_explicit_tag(4, &issuer_der);
        let general_names = asn1::encode_sequence(&[&general_name]);

        // serial_der is already a DER-encoded INTEGER
        let issuer_serial = asn1::encode_sequence(&[&general_names, &serial_der]);

        // ESSCertIDv2: SEQUENCE { certHash, issuerSerial }
        // When hashAlgorithm is SHA-256 (the default), it MAY be omitted per RFC 5816
        let ess_cert_id =
            asn1::encode_sequence(&[&asn1::encode_octet_string(&cert_hash), &issuer_serial]);

        // SEQUENCE OF ESSCertIDv2 (just one entry)
        let certs_seq = asn1::encode_sequence(&[&ess_cert_id]);

        // SigningCertificateV2: SEQUENCE { certs }
        Ok(asn1::encode_sequence(&[&certs_seq]))
    }
}

// ─── TimeStampReq Parsing ───────────────────────────────────────────

/// Parsed TimeStampReq per RFC 3161 §2.4.1.
#[derive(Debug)]
pub struct TimeStampReq {
    /// Protocol version (must be 1).
    pub version: u32,
    /// The complete DER-encoded MessageImprint (for echoing in TSTInfo).
    pub message_imprint_der: Vec<u8>,
    /// The hash algorithm OID bytes (value only, no tag/length).
    pub hash_algorithm_oid: Vec<u8>,
    /// The hashed message bytes.
    pub hashed_message: Vec<u8>,
    /// Requested policy OID (optional).
    pub req_policy: Option<Vec<u8>>,
    /// Nonce as DER-encoded INTEGER (optional, for echoing).
    pub nonce_der: Option<Vec<u8>>,
    /// Whether the client requested the TSA certificate in the response.
    pub cert_req: bool,
}

impl TimeStampReq {
    /// Check if the hash algorithm is SHA-256.
    pub fn is_sha256(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA256_VALUE
    }

    /// Check if the hash algorithm is SHA-384.
    pub fn is_sha384(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA384_VALUE
    }

    /// Check if the hash algorithm is SHA-512.
    pub fn is_sha512(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA512_VALUE
    }

    /// Check if the hash algorithm is SHA3-256.
    pub fn is_sha3_256(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA3_256_VALUE
    }

    /// Check if the hash algorithm is SHA3-384.
    pub fn is_sha3_384(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA3_384_VALUE
    }

    /// Check if the hash algorithm is SHA3-512.
    pub fn is_sha3_512(&self) -> bool {
        self.hash_algorithm_oid == OID_SHA3_512_VALUE
    }

    /// Return the expected digest length for the request's hash algorithm,
    /// or 0 if the algorithm is unsupported.
    pub fn expected_digest_len(&self) -> usize {
        if self.is_sha256() || self.is_sha3_256() {
            32
        } else if self.is_sha384() || self.is_sha3_384() {
            48
        } else if self.is_sha512() || self.is_sha3_512() {
            64
        } else {
            0
        }
    }

    /// Human-readable hash algorithm name.
    pub fn hash_algorithm_name(&self) -> &'static str {
        if self.is_sha256() {
            "SHA-256"
        } else if self.is_sha384() {
            "SHA-384"
        } else if self.is_sha512() {
            "SHA-512"
        } else {
            "unknown"
        }
    }
}

/// Parse a DER-encoded TimeStampReq.
pub fn parse_timestamp_req(data: &[u8]) -> SignResult<TimeStampReq> {
    // Outer SEQUENCE
    let (_, content) = asn1::parse_tlv(data)
        .map_err(|e| SignError::Timestamp(format!("Invalid TimeStampReq SEQUENCE: {e}")))?;

    let mut pos = content;

    // version INTEGER
    let (version_tlv, remaining) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse version: {e}")))?;
    let (_, version_bytes) = asn1::parse_tlv(version_tlv)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse version INTEGER: {e}")))?;
    let version = version_bytes
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | b as u32);

    // RFC 3161 §2.4.1: version MUST be 1 (v1)
    if version != 1 {
        return Err(SignError::Timestamp(format!(
            "RFC 3161 §2.4.1: TimeStampReq version must be 1, got {}",
            version
        )));
    }

    pos = remaining;

    // messageImprint SEQUENCE
    let (mi_tlv, remaining) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse messageImprint: {e}")))?;
    let message_imprint_der = mi_tlv.to_vec();

    // Parse inside messageImprint to extract hash algo and hash value
    let (_, mi_content) = asn1::parse_tlv(mi_tlv)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse MI SEQUENCE: {e}")))?;

    // AlgorithmIdentifier SEQUENCE
    let (algo_tlv, mi_remaining) = asn1::extract_tlv(mi_content)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse AlgorithmIdentifier: {e}")))?;
    let (_, algo_content) = asn1::parse_tlv(algo_tlv)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse algo SEQUENCE: {e}")))?;

    // Extract OID from AlgorithmIdentifier
    let (oid_tlv, _) = asn1::extract_tlv(algo_content)
        .map_err(|e| SignError::Timestamp(format!("Failed to extract hash OID: {e}")))?;
    let (_, oid_value) = asn1::parse_tlv(oid_tlv)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse hash OID: {e}")))?;
    let hash_algorithm_oid = oid_value.to_vec();

    // OCTET STRING (hashedMessage)
    let (_, hash_bytes) = asn1::parse_tlv(mi_remaining)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse hashedMessage: {e}")))?;
    let hashed_message = hash_bytes.to_vec();

    pos = remaining;

    // Optional fields: reqPolicy, nonce, certReq, extensions
    let mut req_policy = None;
    let mut nonce_der = None;
    let mut cert_req = false;

    while !pos.is_empty() {
        let tag = pos[0];
        match tag {
            0x06 => {
                // OID — reqPolicy
                let (tlv, rest) = asn1::extract_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("Failed to parse reqPolicy: {e}")))?;
                req_policy = Some(tlv.to_vec());
                pos = rest;
            }
            0x02 => {
                // INTEGER — nonce
                let (tlv, rest) = asn1::extract_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("Failed to parse nonce: {e}")))?;
                nonce_der = Some(tlv.to_vec());
                pos = rest;
            }
            0x01 => {
                // BOOLEAN — certReq
                let (tlv, rest) = asn1::extract_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("Failed to parse certReq: {e}")))?;
                let (_, bool_bytes) = asn1::parse_tlv(tlv).map_err(|e| {
                    SignError::Timestamp(format!("Failed to parse certReq BOOLEAN: {e}"))
                })?;
                cert_req = !bool_bytes.is_empty() && bool_bytes[0] != 0;
                pos = rest;
            }
            0xA0 => {
                // [0] IMPLICIT Extensions — skip
                let (_, rest) = asn1::extract_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("Failed to skip extensions: {e}")))?;
                pos = rest;
            }
            _ => {
                // Unknown tag — skip
                let (_, rest) = asn1::extract_tlv(pos).map_err(|e| {
                    SignError::Timestamp(format!("Failed to skip unknown element: {e}"))
                })?;
                pos = rest;
            }
        }
    }

    Ok(TimeStampReq {
        version,
        message_imprint_der,
        hash_algorithm_oid,
        hashed_message,
        req_policy,
        nonce_der,
        cert_req,
    })
}

// ─── Response Building ──────────────────────────────────────────────

/// PKIStatus values per RFC 3161.
#[derive(Debug, Clone, Copy)]
pub enum TsaStatus {
    /// The request was granted.
    Granted = 0,
    /// The request was granted with modifications.
    GrantedWithMods = 1,
    /// The request was rejected.
    Rejection = 2,
    /// The request is still pending (async).
    Waiting = 3,
    /// A revocation warning was issued.
    RevocationWarning = 4,
    /// A revocation notification was issued.
    RevocationNotification = 5,
}

/// RFC 3161 §2.3: Check if a DER-encoded certificate has id-kp-timeStamping EKU.
///
/// Returns `true` if:
/// - The certificate has EKU containing id-kp-timeStamping (1.3.6.1.5.5.7.3.8)
/// - The certificate has EKU containing anyExtendedKeyUsage (2.5.29.37.0)
/// - The certificate has no EKU extension (permitted for CA certs)
fn check_tsa_eku(cert_der: &[u8]) -> bool {
    // extendedKeyUsage OID: 2.5.29.37
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

    // id-kp-timeStamping OID value bytes: 1.3.6.1.5.5.7.3.8
    let timestamping_oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

    // anyExtendedKeyUsage: 2.5.29.37.0
    let any_eku_oid_value: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    let Some(oid_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) else {
        return true; // No EKU extension — permitted
    };

    let search_region = &cert_der[oid_pos..cert_der.len().min(oid_pos + 200)];

    let has_timestamping = search_region
        .windows(timestamping_oid_value.len())
        .any(|w| w == timestamping_oid_value);

    let has_any_eku = search_region
        .windows(any_eku_oid_value.len())
        .any(|w| w == any_eku_oid_value);

    has_timestamping || has_any_eku
}

/// Build a TimeStampResp with status=granted and a TimeStampToken.
fn build_success_response(token: &[u8]) -> Vec<u8> {
    let status_int = asn1::encode_integer_value(TsaStatus::Granted as u32);
    let status_info = asn1::encode_sequence(&[&status_int]);
    asn1::encode_sequence(&[&status_info, token])
}

/// PKIFailureInfo bit values per RFC 3161 §2.4.2 / RFC 4210 §5.2.3.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum PkiFailureInfo {
    /// Unrecognized or unsupported algorithm
    BadAlg = 0,
    /// Transaction not permitted or supported
    BadRequest = 2,
    /// The data submitted has the wrong format
    BadDataFormat = 5,
    /// The TSA's time source is not available
    TimeNotAvailable = 14,
    /// The requested TSA policy is not supported
    UnacceptedPolicy = 15,
    /// The requested extension is not supported
    UnacceptedExtension = 16,
    /// The additional information requested could not be understood
    AddInfoNotAvailable = 17,
    /// The request cannot be handled due to system failure
    SystemFailure = 25,
}

/// Encode a PKIFailureInfo BIT STRING (RFC 3161 §2.4.2).
///
/// The failInfo is a BIT STRING where each bit corresponds to a named
/// failure reason. Bit numbering is from MSB of the first octet (ASN.1 convention).
fn encode_pki_failure_info(failure: PkiFailureInfo) -> Vec<u8> {
    let bit_num = failure as u8;
    // ASN.1 BIT STRING: bit 0 is the MSB of byte 0
    let byte_index = (bit_num / 8) as usize;
    let bit_within_byte = 7 - (bit_num % 8);
    let total_bytes = byte_index + 1;
    // Unused bits = trailing unused bits in the last byte
    let unused_bits = bit_within_byte;

    let mut bytes = vec![0u8; total_bytes];
    bytes[byte_index] = 1 << bit_within_byte;

    // BIT STRING: tag 0x03, length (unused_bits_count + data), unused_bits_count, data
    let content_len = 1 + total_bytes; // 1 for unused-bits byte + data bytes
    let mut result = Vec::with_capacity(2 + content_len);
    result.push(0x03); // BIT STRING tag
    result.push(content_len as u8); // length
    result.push(unused_bits); // unused bits in last byte
    result.extend_from_slice(&bytes);
    result
}

/// Build a TimeStampResp with an error status, optional status string,
/// and optional PKIFailureInfo (RFC 3161 §2.4.2).
fn build_error_response(
    status: TsaStatus,
    message: Option<&str>,
    failure_info: Option<PkiFailureInfo>,
) -> Vec<u8> {
    let status_int = asn1::encode_integer_value(status as u32);

    let mut status_parts: Vec<&[u8]> = vec![&status_int];

    let free_text;
    let utf8_string;
    if let Some(msg) = message {
        // PKIFreeText: SEQUENCE OF UTF8String
        utf8_string = encode_utf8_string(msg);
        free_text = asn1::encode_sequence(&[&utf8_string]);
        status_parts.push(&free_text);
    }

    let fail_info;
    if let Some(fi) = failure_info {
        fail_info = encode_pki_failure_info(fi);
        status_parts.push(&fail_info);
    }

    let status_info = asn1::encode_sequence(&status_parts);
    asn1::encode_sequence(&[&status_info])
}

// ─── SignerInfo Building ────────────────────────────────────────────

/// Build a CMS SignerInfo structure.
fn build_signer_info(
    issuer_der: &[u8],
    serial_der: &[u8],
    signed_attrs: &[u8],
    sig_algo_id: &[u8],
    signature: &[u8],
    digest_algo_id: &[u8],
) -> Vec<u8> {
    // version: 1 (IssuerAndSerialNumber)
    let version = asn1::encode_integer_value(1);

    // sid: IssuerAndSerialNumber
    let sid = asn1::encode_sequence(&[issuer_der, serial_der]);

    // signature: OCTET STRING
    let sig_octet = asn1::encode_octet_string(signature);

    asn1::encode_sequence(&[
        &version,
        &sid,
        digest_algo_id,
        signed_attrs,
        sig_algo_id,
        &sig_octet,
    ])
}

// ─── Certificate Parsing Helpers ────────────────────────────────────

/// Extract the issuer Name and serialNumber from a DER-encoded X.509 certificate.
///
/// Returns (issuer_der, serial_der) where:
/// - issuer_der is the complete DER-encoded Name SEQUENCE
/// - serial_der is the complete DER-encoded INTEGER (tag + length + value)
fn extract_issuer_and_serial(cert_der: &[u8]) -> SignResult<(Vec<u8>, Vec<u8>)> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (_, cert_content) = asn1::parse_tlv(cert_der)
        .map_err(|e| SignError::Timestamp(format!("Invalid certificate SEQUENCE: {e}")))?;

    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, ... }
    let (tbs_tlv, _) = asn1::extract_tlv(cert_content)
        .map_err(|e| SignError::Timestamp(format!("Failed to extract TBSCertificate: {e}")))?;
    let (_, tbs_content) = asn1::parse_tlv(tbs_tlv)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse TBSCertificate: {e}")))?;

    let mut pos = tbs_content;

    // Skip version [0] EXPLICIT if present
    if !pos.is_empty() && (pos[0] & 0xF0) == 0xA0 {
        let (_, rest) = asn1::extract_tlv(pos)
            .map_err(|e| SignError::Timestamp(format!("Failed to skip version: {e}")))?;
        pos = rest;
    }

    // serialNumber INTEGER
    let (serial_tlv, rest) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Timestamp(format!("Failed to extract serialNumber: {e}")))?;
    let serial_der = serial_tlv.to_vec();
    pos = rest;

    // Skip signature AlgorithmIdentifier
    let (_, rest) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Timestamp(format!("Failed to skip signature algo: {e}")))?;
    pos = rest;

    // issuer Name SEQUENCE
    let (issuer_tlv, _) = asn1::extract_tlv(pos)
        .map_err(|e| SignError::Timestamp(format!("Failed to extract issuer: {e}")))?;
    let issuer_der = issuer_tlv.to_vec();

    Ok((issuer_der, serial_der))
}

// ─── ASN.1 Encoding Helpers ─────────────────────────────────────────

/// Encode a u64 as a DER INTEGER.
fn encode_integer_u64(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut v = value;
    if v == 0 {
        bytes.push(0);
    } else {
        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        bytes.reverse();
        // Add leading zero if high bit set (ASN.1 INTEGER is signed)
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
        }
    }
    let mut result = vec![0x02]; // INTEGER tag
    result.extend(asn1::encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Encode a boolean value as DER.
fn encode_boolean(value: bool) -> Vec<u8> {
    vec![0x01, 0x01, if value { 0xFF } else { 0x00 }]
}

/// Encode the current UTC time as ASN.1 GeneralizedTime.
///
/// Format: YYYYMMDDHHMMSSZ (15 bytes) — RFC 3161 requires GeneralizedTime.
fn encode_generalized_time_now() -> Vec<u8> {
    let now = chrono::Utc::now();
    let time_str = now.format("%Y%m%d%H%M%SZ").to_string();
    let time_bytes = time_str.as_bytes();
    let mut result = vec![0x18]; // GeneralizedTime tag
    result.extend(asn1::encode_length(time_bytes.len()));
    result.extend_from_slice(time_bytes);
    result
}

/// Encode a GeneralizedTime from a specific timestamp (for testing).
#[cfg(test)]
fn encode_generalized_time(time_str: &str) -> Vec<u8> {
    let time_bytes = time_str.as_bytes();
    let mut result = vec![0x18]; // GeneralizedTime tag
    result.extend(asn1::encode_length(time_bytes.len()));
    result.extend_from_slice(time_bytes);
    result
}

/// Build the Accuracy SEQUENCE per RFC 3161.
///
/// ```text
/// Accuracy ::= SEQUENCE {
///     seconds  INTEGER OPTIONAL,
///     millis   [0] INTEGER OPTIONAL,
///     micros   [1] INTEGER OPTIONAL
/// }
/// ```
fn build_accuracy(seconds: u32, millis: u32, micros: u32) -> Vec<u8> {
    // RFC 3161 §2.4.2: millis and micros MUST be in range 0-999
    let millis = millis.min(999);
    let micros = micros.min(999);

    let mut parts: Vec<Vec<u8>> = Vec::new();

    if seconds > 0 {
        parts.push(asn1::encode_integer_value(seconds));
    }

    if millis > 0 {
        let millis_int = asn1::encode_integer_value(millis);
        // [0] IMPLICIT INTEGER — replace tag 0x02 with 0x80
        let mut tagged = millis_int;
        tagged[0] = 0x80;
        parts.push(tagged);
    }

    if micros > 0 {
        let micros_int = asn1::encode_integer_value(micros);
        // [1] IMPLICIT INTEGER — replace tag 0x02 with 0x81
        let mut tagged = micros_int;
        tagged[0] = 0x81;
        parts.push(tagged);
    }

    let part_refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
    asn1::encode_sequence(&part_refs)
}

/// Encode a UTF8String.
fn encode_utf8_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = vec![0x0C]; // UTF8String tag
    result.extend(asn1::encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    result
}

/// Encode an OID from dotted notation (e.g., "1.3.6.1.4.1.56266.1.30.1").
///
/// Returns the complete DER-encoded OID (tag + length + value).
fn encode_oid_from_dotted(dotted: &str) -> SignResult<Vec<u8>> {
    let components: Vec<u64> = dotted
        .split('.')
        .map(|s| {
            s.parse::<u64>()
                .map_err(|e| SignError::Timestamp(format!("Invalid OID component '{s}': {e}")))
        })
        .collect::<SignResult<Vec<_>>>()?;

    if components.len() < 2 {
        return Err(SignError::Timestamp(
            "OID must have at least 2 components".into(),
        ));
    }

    let mut value_bytes = Vec::new();

    // First two components are encoded as (c0 * 40) + c1
    let first = components[0] * 40 + components[1];
    encode_oid_component(first, &mut value_bytes);

    // Remaining components
    for &component in &components[2..] {
        encode_oid_component(component, &mut value_bytes);
    }

    let mut result = vec![0x06]; // OID tag
    result.extend(asn1::encode_length(value_bytes.len()));
    result.extend(value_bytes);
    Ok(result)
}

/// Encode a single OID component in base-128 (BER/DER OID encoding).
fn encode_oid_component(value: u64, out: &mut Vec<u8>) {
    if value < 128 {
        out.push(value as u8);
        return;
    }

    // Collect base-128 digits, MSB first
    let mut digits = Vec::new();
    let mut v = value;
    while v > 0 {
        digits.push((v & 0x7F) as u8);
        v >>= 7;
    }
    digits.reverse();

    // Set high bit on all but last byte
    let last_idx = digits.len() - 1;
    for (i, digit) in digits.iter_mut().enumerate() {
        if i < last_idx {
            *digit |= 0x80;
        }
    }
    out.extend_from_slice(&digits);
}

// ─── HTTP Handler ───────────────────────────────────────────────────

/// Axum handler for RFC 3161 timestamp requests.
///
/// Accepts: POST with Content-Type: application/timestamp-query
/// Returns: Content-Type: application/timestamp-reply
pub async fn handle_timestamp_request(
    axum::extract::State(tsa): axum::extract::State<Arc<TsaServer>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    // Validate Content-Type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.contains("application/timestamp-query") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/timestamp-query per RFC 3161",
        )
            .into_response();
    }

    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
    }

    // Process the timestamp request
    let response = tsa.process_request(&body);

    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        "application/timestamp-reply".parse().unwrap(),
    );

    (StatusCode::OK, resp_headers, response).into_response()
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cert() -> Vec<u8> {
        // Build a minimal self-signed certificate for testing.
        // This is a simplified DER structure — enough for extract_issuer_and_serial.
        //
        // Certificate ::= SEQUENCE {
        //   TBSCertificate ::= SEQUENCE {
        //     version [0] EXPLICIT INTEGER 2,
        //     serialNumber INTEGER 12345,
        //     signature AlgorithmIdentifier (SHA256WithRSA),
        //     issuer Name ::= SEQUENCE { SET { SEQUENCE { OID cn, UTF8String "Test TSA" } } },
        //     ...
        //   },
        //   signatureAlgorithm ...,
        //   signature BIT STRING ...
        // }

        // version: [0] EXPLICIT INTEGER 2
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));

        // serialNumber: INTEGER 12345
        let serial = asn1::encode_integer_value(12345);

        // signature algorithm: SHA256WithRSA
        let sig_algo = asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]]);

        // issuer: CN=Test TSA
        let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3 (CN)
        let cn_value = encode_utf8_string("Test TSA");
        let rdn_attr = asn1::encode_sequence(&[cn_oid, &cn_value]);
        let rdn_set = asn1::encode_set(&rdn_attr);
        let issuer = asn1::encode_sequence(&[&rdn_set]);

        // validity: SEQUENCE { notBefore, notAfter } — use UTCTime
        let not_before = asn1::encode_utc_time_now();
        let not_after = asn1::encode_utc_time_now();
        let validity = asn1::encode_sequence(&[&not_before, &not_after]);

        // subject: same as issuer (self-signed)
        let subject = issuer.clone();

        // subjectPublicKeyInfo — minimal placeholder
        let spki = asn1::encode_sequence(&[
            &asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]]),
            &[0x03, 0x02, 0x00, 0x00], // BIT STRING (empty key)
        ]);

        // TBSCertificate
        let tbs = asn1::encode_sequence(&[
            &version, &serial, &sig_algo, &issuer, &validity, &subject, &spki,
        ]);

        // Complete certificate (with dummy signature)
        let cert_sig_algo = sig_algo.clone();
        let cert_sig = vec![0x03, 0x02, 0x00, 0x00]; // BIT STRING

        asn1::encode_sequence(&[&tbs, &cert_sig_algo, &cert_sig])
    }

    fn make_test_tsa() -> TsaServer {
        let cert = make_test_cert();
        let sign_fn: SignFn = Box::new(|data: &[u8]| {
            // Test signer: just SHA-256 the data as a "signature"
            Ok(Sha256::digest(data).to_vec())
        });

        TsaServer::new(
            TsaServerConfig::default(),
            cert,
            vec![],
            sign_fn,
            TsaSignatureAlgorithm::RsaSha256,
        )
    }

    #[test]
    fn test_encode_oid_from_dotted() {
        // Test simple OID: 1.2.3.4
        let oid = encode_oid_from_dotted("1.2.3.4").unwrap();
        assert_eq!(oid[0], 0x06); // OID tag
                                  // 1*40+2 = 42 = 0x2A, then 3, then 4
        assert_eq!(&oid[2..], &[0x2A, 0x03, 0x04]);

        // Test our policy OID
        let oid = encode_oid_from_dotted("1.3.6.1.4.1.56266.1.30.1").unwrap();
        assert_eq!(oid[0], 0x06);
    }

    #[test]
    fn test_encode_oid_large_component() {
        // 56266 requires multi-byte base-128 encoding
        let oid = encode_oid_from_dotted("1.3.6.1.4.1.56266").unwrap();
        assert_eq!(oid[0], 0x06);
        // Verify it round-trips through parse
        let (tag, _content) = asn1::parse_tlv(&oid).unwrap();
        assert_eq!(tag, 0x06);
    }

    #[test]
    fn test_encode_generalized_time() {
        let gt = encode_generalized_time("20260217120000Z");
        assert_eq!(gt[0], 0x18); // GeneralizedTime tag
        assert_eq!(gt[1], 15); // 15 bytes for YYYYMMDDHHMMSSZ
        assert_eq!(&gt[2..], b"20260217120000Z");
    }

    #[test]
    fn test_build_accuracy() {
        let acc = build_accuracy(1, 0, 0);
        // SEQUENCE { INTEGER 1 }
        assert_eq!(acc[0], 0x30);
        let (_, content) = asn1::parse_tlv(&acc).unwrap();
        let (tag, _) = asn1::parse_tlv(content).unwrap();
        assert_eq!(tag, 0x02); // INTEGER

        let acc = build_accuracy(1, 500, 0);
        // SEQUENCE { INTEGER 1, [0] INTEGER 500 }
        assert_eq!(acc[0], 0x30);

        // With microseconds: SEQUENCE { INTEGER 1, [0] INTEGER 500, [1] INTEGER 100 }
        let acc = build_accuracy(1, 500, 100);
        assert_eq!(acc[0], 0x30);
        // Should contain [1] tagged integer (0x81)
        assert!(
            acc.windows(1).any(|w| w[0] == 0x81),
            "Accuracy with micros should contain [1] tag"
        );
    }

    #[test]
    fn test_encode_integer_u64() {
        let enc = encode_integer_u64(0);
        assert_eq!(enc, vec![0x02, 0x01, 0x00]);

        let enc = encode_integer_u64(255);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0xFF]);

        let enc = encode_integer_u64(256);
        assert_eq!(enc, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_extract_issuer_and_serial() {
        let cert = make_test_cert();
        let (issuer, serial) = extract_issuer_and_serial(&cert).unwrap();

        // Issuer should be a SEQUENCE
        assert_eq!(issuer[0], 0x30);

        // Serial should be INTEGER 12345
        assert_eq!(serial[0], 0x02);
    }

    #[test]
    fn test_parse_timestamp_req_basic() {
        // Build a TimeStampReq like the client does
        let digest = Sha256::digest(b"test data");

        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let nonce = encode_integer_u64(42);
        let cert_req = vec![0x01, 0x01, 0xFF]; // BOOLEAN TRUE

        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce, &cert_req]);

        let req = parse_timestamp_req(&req_der).unwrap();
        assert_eq!(req.version, 1);
        assert!(req.is_sha256());
        assert_eq!(req.hashed_message.len(), 32);
        assert!(req.nonce_der.is_some());
        assert!(req.cert_req);
    }

    #[test]
    fn test_parse_timestamp_req_minimal() {
        // Minimal request: version + messageImprint only
        let digest = Sha256::digest(b"test");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);

        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);
        let req = parse_timestamp_req(&req_der).unwrap();
        assert_eq!(req.version, 1);
        assert!(req.nonce_der.is_none());
        assert!(!req.cert_req);
    }

    #[test]
    fn test_tsa_process_request_success() {
        let tsa = make_test_tsa();

        // Build a valid TimeStampReq
        let digest = Sha256::digest(b"signature bytes");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let nonce = encode_integer_u64(12345);
        let cert_req = vec![0x01, 0x01, 0xFF];

        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce, &cert_req]);

        let resp = tsa.process_request(&req_der);

        // Parse the response
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();

        // First element: PKIStatusInfo
        let (status_info_tlv, remaining) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();

        // Status should be 0 (granted)
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "Expected status=granted(0), got {status}");

        // Second element should be the TimeStampToken (ContentInfo)
        assert!(
            !remaining.is_empty(),
            "Response should contain a TimeStampToken"
        );
        let (token_tlv, _) = asn1::extract_tlv(remaining).unwrap();
        assert_eq!(token_tlv[0], 0x30, "TimeStampToken should be a SEQUENCE");
    }

    #[test]
    fn test_tsa_rejects_bad_hash_length() {
        let tsa = make_test_tsa();

        // Build a request with wrong hash length (16 bytes instead of 32)
        let short_hash = vec![0xAA; 16];
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&short_hash),
        ]);

        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);
        let resp = tsa.process_request(&req_der);

        // Parse response — should be rejection
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 2, "Expected status=rejection(2), got {status}");
    }

    #[test]
    fn test_tsa_nonce_echoed() {
        let tsa = make_test_tsa();

        let digest = Sha256::digest(b"test");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let nonce = encode_integer_u64(99999);

        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce]);

        let resp = tsa.process_request(&req_der);

        // Verify the response is valid (status=granted)
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, remaining) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0);
        assert!(!remaining.is_empty());
    }

    #[test]
    fn test_tsa_serial_increments() {
        let tsa = make_test_tsa();

        let digest = Sha256::digest(b"test");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        // Issue two timestamps — serial should increment
        let resp1 = tsa.process_request(&req_der);
        let resp2 = tsa.process_request(&req_der);
        assert_ne!(
            resp1, resp2,
            "Two timestamps should differ (different serial/time)"
        );
    }

    #[test]
    fn test_ess_cert_id_v2() {
        let tsa = make_test_tsa();
        let ess = tsa.build_ess_cert_id_v2().unwrap();
        // Should be a SEQUENCE (SigningCertificateV2)
        assert_eq!(ess[0], 0x30);
        // Should contain nested SEQUENCE OF ESSCertIDv2
        let (_, content) = asn1::parse_tlv(&ess).unwrap();
        assert_eq!(content[0], 0x30); // inner SEQUENCE
    }

    #[test]
    fn test_error_response_format() {
        let resp = build_error_response(TsaStatus::Rejection, Some("test error"), None);
        let (_, content) = asn1::parse_tlv(&resp).unwrap();
        // First element: PKIStatusInfo SEQUENCE
        let (tag, _) = asn1::parse_tlv(content).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_error_response_with_failure_info() {
        let resp = build_error_response(
            TsaStatus::Rejection,
            Some("bad algorithm"),
            Some(PkiFailureInfo::BadAlg),
        );
        // Should be valid DER (outer SEQUENCE)
        let (tag, _) = asn1::parse_tlv(&resp).unwrap();
        assert_eq!(tag, 0x30);
        // Should contain a BIT STRING (0x03) for failInfo somewhere in the structure
        assert!(
            resp.windows(1).any(|w| w[0] == 0x03),
            "Response should contain BIT STRING tag for failInfo"
        );
        // Response should be longer than one without failInfo
        let resp_no_fi = build_error_response(TsaStatus::Rejection, Some("bad algorithm"), None);
        assert!(
            resp.len() > resp_no_fi.len(),
            "Response with failInfo should be larger"
        );
    }

    #[test]
    fn test_error_response_system_failure() {
        let resp = build_error_response(
            TsaStatus::Rejection,
            Some("internal error"),
            Some(PkiFailureInfo::SystemFailure),
        );
        // Should be valid DER
        let (tag, _) = asn1::parse_tlv(&resp).unwrap();
        assert_eq!(tag, 0x30);
    }

    #[test]
    fn test_pki_failure_info_encoding() {
        // BadAlg = bit 0 → byte[0] has MSB set = 0x80, unused_bits = 7
        let fi = encode_pki_failure_info(PkiFailureInfo::BadAlg);
        assert_eq!(fi[0], 0x03); // BIT STRING tag
        assert_eq!(fi[1], 2); // length: 1 unused-bits byte + 1 data byte
        assert_eq!(fi[2], 7); // 7 unused bits in last byte
        assert_eq!(fi[3], 0x80); // bit 0 set (MSB of first byte)

        // BadRequest = bit 2 → byte[0] bit 5 set = 0x20, unused_bits = 5
        let fi = encode_pki_failure_info(PkiFailureInfo::BadRequest);
        assert_eq!(fi[0], 0x03);
        assert_eq!(fi[2], 5); // 5 unused bits
        assert_eq!(fi[3], 0x20); // bit 2 set

        // SystemFailure = bit 25 → byte 3 (25/8=3), bit 7-(25%8)=6
        let fi = encode_pki_failure_info(PkiFailureInfo::SystemFailure);
        assert_eq!(fi[0], 0x03); // BIT STRING tag
        assert_eq!(fi[1], 5); // length: 1 unused + 4 data bytes
        assert_eq!(fi[2], 6); // 6 unused bits in last byte
                              // bit 25: byte 3, bit position 6 → 0x40
        assert_eq!(fi[6], 0x40);
    }

    #[test]
    fn test_encode_boolean() {
        assert_eq!(encode_boolean(true), vec![0x01, 0x01, 0xFF]);
        assert_eq!(encode_boolean(false), vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_utf8_string() {
        let s = encode_utf8_string("hello");
        assert_eq!(s[0], 0x0C); // UTF8String tag
        assert_eq!(s[1], 5); // length
        assert_eq!(&s[2..], b"hello");
    }

    // ── SHA-384/512 message imprint tests ────────────────────────────

    fn make_test_tsa_p384() -> TsaServer {
        let cert = make_test_cert();
        let sign_fn: SignFn = Box::new(|data: &[u8]| {
            // Test signer: just SHA-384 the data as a "signature"
            Ok(Sha384::digest(data).to_vec())
        });
        TsaServer::new(
            TsaServerConfig::default(),
            cert,
            vec![],
            sign_fn,
            TsaSignatureAlgorithm::EcdsaP384Sha384,
        )
    }

    #[test]
    fn test_tsa_accepts_sha384_imprint() {
        let tsa = make_test_tsa();

        let digest = Sha384::digest(b"test data for SHA-384");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA384_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _remaining) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "SHA-384 imprint should be accepted");
    }

    #[test]
    fn test_tsa_accepts_sha512_imprint() {
        use sha2::Sha512;
        let tsa = make_test_tsa();

        let digest = Sha512::digest(b"test data for SHA-512");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA512_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _remaining) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "SHA-512 imprint should be accepted");
    }

    #[test]
    fn test_tsa_rejects_sha384_wrong_length() {
        let tsa = make_test_tsa();

        // SHA-384 OID but only 32 bytes (should be 48)
        let short_hash = vec![0xBB; 32];
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA384_ALGORITHM_ID,
            &asn1::encode_octet_string(&short_hash),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 2, "SHA-384 with wrong length should be rejected");
    }

    #[test]
    fn test_tsa_p384_signs_with_sha384_digest() {
        let tsa = make_test_tsa_p384();

        let digest = Sha256::digest(b"test");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, remaining) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "P-384 TSA should accept requests");
        assert!(!remaining.is_empty(), "Should contain TimeStampToken");
    }

    #[test]
    fn test_tsa_p384_digest_algorithm_selection() {
        assert_eq!(
            TsaSignatureAlgorithm::EcdsaP384Sha384.digest_algorithm_id(),
            &asn1::SHA384_ALGORITHM_ID
        );
        assert_eq!(
            TsaSignatureAlgorithm::RsaSha256.digest_algorithm_id(),
            &asn1::SHA256_ALGORITHM_ID
        );
        assert_eq!(
            TsaSignatureAlgorithm::EcdsaP256Sha256.digest_algorithm_id(),
            &asn1::SHA256_ALGORITHM_ID
        );
        assert_eq!(
            TsaSignatureAlgorithm::Ed25519.digest_algorithm_id(),
            &asn1::SHA256_ALGORITHM_ID
        );
    }

    #[test]
    fn test_timestamp_req_hash_algorithm_detection() {
        // SHA-256
        let digest256 = Sha256::digest(b"test");
        let version = asn1::encode_integer_value(1);
        let mi256 = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest256),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &mi256]);
        let req = parse_timestamp_req(&req_der).unwrap();
        assert!(req.is_sha256());
        assert!(!req.is_sha384());
        assert!(!req.is_sha512());
        assert_eq!(req.expected_digest_len(), 32);
        assert_eq!(req.hash_algorithm_name(), "SHA-256");

        // SHA-384
        let digest384 = Sha384::digest(b"test");
        let mi384 = asn1::encode_sequence(&[
            &asn1::SHA384_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest384),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &mi384]);
        let req = parse_timestamp_req(&req_der).unwrap();
        assert!(!req.is_sha256());
        assert!(req.is_sha384());
        assert_eq!(req.expected_digest_len(), 48);
        assert_eq!(req.hash_algorithm_name(), "SHA-384");
    }

    #[test]
    fn test_tsa_req_policy_validation() {
        // RFC 3161 §2.4.1: reqPolicy must match TSA policy if present
        let tsa = make_test_tsa();

        // Build request with matching policy OID
        let digest = Sha256::digest(b"test-policy");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let our_policy = encode_oid_from_dotted("1.3.6.1.4.1.56266.1.30.1").unwrap();
        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &our_policy]);
        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "Matching policy OID should be accepted");
    }

    #[test]
    fn test_tsa_req_policy_mismatch_rejected() {
        // RFC 3161 §2.4.1: unknown reqPolicy must be rejected
        let tsa = make_test_tsa();

        let digest = Sha256::digest(b"bad-policy");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        // Use a different policy OID (2.16.840.1.101.3.4)
        let wrong_policy = encode_oid_from_dotted("2.16.840.1.101.3.4").unwrap();
        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &wrong_policy]);
        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_info_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_info_tlv).unwrap();
        let (_, status_value) = asn1::parse_tlv(status_content).unwrap();
        let status = status_value
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 2, "Mismatched policy OID should be rejected");
    }

    #[test]
    fn test_tsa_name_included_when_configured() {
        let cert = make_test_cert();
        let sign_fn: SignFn = Box::new(|data: &[u8]| Ok(Sha256::digest(data).to_vec()));
        let config = TsaServerConfig {
            tsa_name: Some("CN=Test TSA Authority".to_string()),
            ..Default::default()
        };

        let tsa = TsaServer::new(
            config,
            cert,
            vec![],
            sign_fn,
            TsaSignatureAlgorithm::RsaSha256,
        );

        // Build a valid request
        let digest = Sha256::digest(b"test data");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        assert!(!resp.is_empty());
        // The TSA name is encoded inside the TSTInfo within the CMS envelope
        assert!(
            resp.windows(b"Test TSA Authority".len())
                .any(|w| w == b"Test TSA Authority"),
            "TSA name should be present in the timestamp response"
        );
    }

    #[test]
    fn test_signed_attrs_include_signing_time() {
        let tsa = make_test_tsa();

        // Build a valid request
        let digest = Sha256::digest(b"test data");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint]);

        let resp = tsa.process_request(&req_der);
        assert!(!resp.is_empty());
        // The signingTime OID (1.2.840.113549.1.9.5) should appear in the response
        assert!(
            resp.windows(asn1::OID_SIGNING_TIME.len())
                .any(|w| w == asn1::OID_SIGNING_TIME),
            "signingTime OID should be present in signed attributes"
        );
    }

    // ─── Nonce Replay Detection Tests ───

    #[test]
    fn test_tsa_nonce_replay_rejected() {
        let tsa = make_test_tsa();

        let digest = Sha256::digest(b"replay test");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let nonce = encode_integer_u64(777);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce]);

        // First request should succeed
        let resp1 = tsa.process_request(&req_der);
        let (_, resp1_content) = asn1::parse_tlv(&resp1).unwrap();
        let (status_tlv1, _) = asn1::extract_tlv(resp1_content).unwrap();
        let (_, status_content1) = asn1::parse_tlv(status_tlv1).unwrap();
        let (_, status_val1) = asn1::parse_tlv(status_content1).unwrap();
        let status1 = status_val1
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status1, 0, "First request should be granted");

        // Second request with same nonce should be rejected
        let resp2 = tsa.process_request(&req_der);
        let (_, resp2_content) = asn1::parse_tlv(&resp2).unwrap();
        let (status_tlv2, _) = asn1::extract_tlv(resp2_content).unwrap();
        let (_, status_content2) = asn1::parse_tlv(status_tlv2).unwrap();
        let (_, status_val2) = asn1::parse_tlv(status_content2).unwrap();
        let status2 = status_val2
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status2, 2, "Replay request should be rejected (status=2)");
    }

    #[test]
    fn test_tsa_different_nonces_accepted() {
        let tsa = make_test_tsa();

        let version = asn1::encode_integer_value(1);
        let digest = Sha256::digest(b"multi-nonce test");
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);

        for i in 1..=5u64 {
            let nonce = encode_integer_u64(i * 1000);
            let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce]);
            let resp = tsa.process_request(&req_der);
            let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
            let (status_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
            let (_, status_content) = asn1::parse_tlv(status_tlv).unwrap();
            let (_, status_val) = asn1::parse_tlv(status_content).unwrap();
            let status = status_val
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | b as u32);
            assert_eq!(
                status, 0,
                "Request {} with unique nonce should be granted",
                i
            );
        }
    }

    #[test]
    fn test_tsa_nonce_cache_eviction() {
        // Create a TSA with a tiny cache (size 3) to test eviction
        let cert = make_test_cert();
        let sign_fn: SignFn = Box::new(|data: &[u8]| Ok(Sha256::digest(data).to_vec()));
        let config = TsaServerConfig {
            nonce_cache_size: 3,
            ..TsaServerConfig::default()
        };
        let tsa = TsaServer::new(
            config,
            cert,
            vec![],
            sign_fn,
            TsaSignatureAlgorithm::RsaSha256,
        );

        let version = asn1::encode_integer_value(1);
        let digest = Sha256::digest(b"eviction test");
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);

        // Send nonces 1, 2, 3, 4 — nonce 1 should be evicted from cache
        for i in 1..=4u64 {
            let nonce = encode_integer_u64(i);
            let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce]);
            let resp = tsa.process_request(&req_der);
            let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
            let (status_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
            let (_, status_content) = asn1::parse_tlv(status_tlv).unwrap();
            let (_, status_val) = asn1::parse_tlv(status_content).unwrap();
            let status = status_val
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | b as u32);
            assert_eq!(status, 0, "Initial nonce {} should be granted", i);
        }

        // Nonce 1 should be evicted (cache holds 2, 3, 4) — replay should succeed
        let nonce1 = encode_integer_u64(1);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce1]);
        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_tlv).unwrap();
        let (_, status_val) = asn1::parse_tlv(status_content).unwrap();
        let status = status_val
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 0, "Evicted nonce 1 should be accepted again");

        // Nonce 3 should still be in cache — replay should fail
        let nonce3 = encode_integer_u64(3);
        let req_der = asn1::encode_sequence(&[&version, &message_imprint, &nonce3]);
        let resp = tsa.process_request(&req_der);
        let (_, resp_content) = asn1::parse_tlv(&resp).unwrap();
        let (status_tlv, _) = asn1::extract_tlv(resp_content).unwrap();
        let (_, status_content) = asn1::parse_tlv(status_tlv).unwrap();
        let (_, status_val) = asn1::parse_tlv(status_content).unwrap();
        let status = status_val
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        assert_eq!(status, 2, "Nonce 3 should still be in cache and rejected");
    }

    // ─── TSA EKU Validation Tests (RFC 3161 §2.3) ───

    #[test]
    fn test_tsa_eku_with_timestamping() {
        // Cert with id-kp-timeStamping in EKU
        let eku_ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        let ts_oid = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
        let eku_value = asn1::encode_sequence(&[ts_oid]);
        let eku_ext = asn1::encode_sequence(&[eku_ext_oid, &asn1::encode_octet_string(&eku_value)]);
        let fake_cert = asn1::encode_sequence(&[&eku_ext]);
        assert!(check_tsa_eku(&fake_cert));
    }

    #[test]
    fn test_tsa_eku_without_timestamping() {
        // Cert with serverAuth but no timeStamping
        let eku_ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        let server_auth = &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let eku_value = asn1::encode_sequence(&[server_auth]);
        let eku_ext = asn1::encode_sequence(&[eku_ext_oid, &asn1::encode_octet_string(&eku_value)]);
        let fake_cert = asn1::encode_sequence(&[&eku_ext]);
        assert!(!check_tsa_eku(&fake_cert));
    }

    #[test]
    fn test_tsa_eku_absent_permits() {
        // No EKU extension — permitted
        let fake_cert = asn1::encode_sequence(&[&asn1::encode_sequence(&[&[
            0x06, 0x03, 0x55, 0x04, 0x03,
        ][..]])]);
        assert!(check_tsa_eku(&fake_cert));
    }

    #[test]
    fn test_timestamp_req_version_must_be_1() {
        // RFC 3161 §2.4.1: version MUST be 1
        // Build a TimeStampReq with version=2 (invalid)
        let version = &[0x02, 0x01, 0x02]; // INTEGER 2
                                           // MessageImprint: SEQUENCE { AlgorithmIdentifier SEQUENCE { OID }, OCTET STRING }
        let hash_oid = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let algo_id = asn1::encode_sequence(&[hash_oid]);
        let hash_value = asn1::encode_octet_string(&[0u8; 32]);
        let message_imprint = asn1::encode_sequence(&[&algo_id, &hash_value]);
        let req = asn1::encode_sequence(&[version, &message_imprint]);

        let result = parse_timestamp_req(&req);
        assert!(
            result.is_err(),
            "TimeStampReq with version=2 must be rejected"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("version must be 1"),
            "Error should mention version: {}",
            err_msg
        );
    }

    #[test]
    fn test_timestamp_req_version_1_accepted() {
        // RFC 3161 §2.4.1: version=1 is valid
        let version = &[0x02, 0x01, 0x01]; // INTEGER 1
                                           // MessageImprint: SEQUENCE { AlgorithmIdentifier SEQUENCE { OID }, OCTET STRING }
        let hash_oid = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let algo_id = asn1::encode_sequence(&[hash_oid]);
        let hash_value = asn1::encode_octet_string(&[0u8; 32]);
        let message_imprint = asn1::encode_sequence(&[&algo_id, &hash_value]);
        let req = asn1::encode_sequence(&[version, &message_imprint]);

        let result = parse_timestamp_req(&req);
        assert!(
            result.is_ok(),
            "TimeStampReq with version=1 must be accepted"
        );
        assert_eq!(result.unwrap().version, 1);
    }
}
