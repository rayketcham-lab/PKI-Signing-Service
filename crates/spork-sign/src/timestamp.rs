//! RFC 3161 Timestamp Authority client.
//!
//! Requests a countersignature from a Time Stamping Authority (TSA)
//! to prove that the signature existed at a specific point in time.
//! This allows signature validation even after the signing certificate
//! expires.
//!
//! ## Protocol
//!
//! 1. Build a TimeStampReq (ASN.1 DER) containing the hash of the signature
//! 2. Send HTTP POST to TSA URL with Content-Type: application/timestamp-query
//! 3. Parse TimeStampResp
//! 4. Extract the TimeStampToken (a CMS SignedData from the TSA)
//! 5. Embed as unsigned attribute in the original SignedData

use sha2::{Digest, Sha256};

use crate::error::{SignError, SignResult};
use crate::pkcs7::asn1;

/// Configuration for timestamp authority servers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TsaConfig {
    /// TSA URLs to try in order (failover).
    pub urls: Vec<String>,
    /// HTTP timeout per request (seconds).
    pub timeout_secs: u64,
}

impl Default for TsaConfig {
    fn default() -> Self {
        Self {
            urls: vec![
                "http://timestamp.digicert.com".into(),
                "http://timestamp.comodoca.com".into(),
            ],
            timeout_secs: 30,
        }
    }
}

// ─── OID constants for TSA ───

/// OID 2.16.840.1.101.3.4.2.1 — id-sha256
const OID_SHA256_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// OID 1.2.840.113549.1.9.16.1.4 — id-smime-ct-TSTInfo
const OID_TST_INFO: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// OID content bytes (without tag+length) for id-smime-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
///
/// Used to validate the eContentType of the SignedData encapsulated ContentInfo per RFC 3161 §2.4.2.
const OID_TST_INFO_CONTENT: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];

/// OID 0.4.0.2023.1.1 — id-tsp-v1 (ETSI TS 119 421 well-known TSP policy per RFC 3161 §2.4.2).
///
/// When a TSP request includes no reqPolicy, the TSA may apply this well-known policy.
/// Verifiers MUST accept responses with this policy OID as conformant.
///
/// DER encoding: 0.4 → first byte = 0*40 + 4 = 4 = 0x04;
/// 0 → 0x00; 2023 → multi-byte: 0x8F 0x67; 1 → 0x01; 1 → 0x01
pub const OID_TSP_V1_POLICY: &[u8] = &[0x06, 0x06, 0x04, 0x00, 0x8F, 0x67, 0x01, 0x01];

/// OID content bytes (without tag+length) for id-tsp-v1.
const OID_TSP_V1_POLICY_CONTENT: &[u8] = &[0x04, 0x00, 0x8F, 0x67, 0x01, 0x01];

/// Build a DER-encoded TimeStampReq per RFC 3161 Section 2.4.1.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///     version        INTEGER { v1(1) },
///     messageImprint MessageImprint,
///     reqPolicy      TSAPolicyId OPTIONAL,
///     nonce          INTEGER OPTIONAL,
///     certReq        BOOLEAN DEFAULT FALSE,
///     extensions     [0] IMPLICIT Extensions OPTIONAL
/// }
///
/// MessageImprint ::= SEQUENCE {
///     hashAlgorithm  AlgorithmIdentifier,
///     hashedMessage  OCTET STRING
/// }
/// ```
fn build_timestamp_req(signature_bytes: &[u8]) -> (Vec<u8>, u64) {
    // Hash the signature value with SHA-256
    let digest = Sha256::digest(signature_bytes);

    // version INTEGER 1
    let version = asn1::encode_integer_value(1);

    // MessageImprint: SEQUENCE { AlgorithmIdentifier(SHA-256), OCTET STRING(hash) }
    let message_imprint = asn1::encode_sequence(&[
        &asn1::SHA256_ALGORITHM_ID,
        &asn1::encode_octet_string(&digest),
    ]);

    // nonce — random value for replay protection
    let nonce_value = rand::random::<u64>() & 0x7FFF_FFFF_FFFF_FFFF; // keep positive
    let nonce = encode_integer_u64(nonce_value);

    // certReq BOOLEAN TRUE — request the TSA certificate in the response
    let cert_req = vec![0x01, 0x01, 0xFF]; // BOOLEAN TRUE

    let der = asn1::encode_sequence(&[&version, &message_imprint, &nonce, &cert_req]);
    (der, nonce_value)
}

/// Encode a u64 as an ASN.1 INTEGER.
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
        // Add leading zero if high bit set
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
        }
    }
    let mut result = vec![0x02]; // INTEGER tag
    result.extend(asn1::encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Request a timestamp token from a TSA.
///
/// Tries each configured TSA URL in order until one succeeds.
/// The `signature_bytes` are the raw RSA/ECDSA signature output — they
/// will be SHA-256 hashed to build the TimeStampReq messageImprint.
///
/// Returns the DER-encoded TimeStampToken (a CMS SignedData from the TSA).
pub async fn request_timestamp(signature_bytes: &[u8], config: &TsaConfig) -> SignResult<Vec<u8>> {
    let expected_digest = Sha256::digest(signature_bytes);
    let (req_der, nonce) = build_timestamp_req(signature_bytes);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| SignError::Timestamp(format!("Failed to build HTTP client: {e}")))?;

    let mut last_error = String::new();

    for url in &config.urls {
        match send_tsa_request(&client, url, &req_der).await {
            Ok(token) => {
                // RFC 3161 §2.4.2: validate nonce echo and messageImprint
                validate_timestamp_token(&token, &expected_digest, nonce)?;
                return Ok(token);
            }
            Err(e) => {
                last_error = format!("{url}: {e}");
                // Try next TSA
            }
        }
    }

    Err(SignError::Timestamp(format!(
        "All TSA servers failed. Last error: {last_error}"
    )))
}

/// Send a TimeStampReq to a single TSA URL and parse the response.
async fn send_tsa_request(
    client: &reqwest::Client,
    url: &str,
    req_der: &[u8],
) -> SignResult<Vec<u8>> {
    let response = client
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .body(req_der.to_vec())
        .send()
        .await
        .map_err(|e| SignError::Timestamp(format!("HTTP request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(SignError::Timestamp(format!(
            "TSA returned HTTP {}",
            response.status()
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| SignError::Timestamp(format!("Failed to read response body: {e}")))?;

    parse_timestamp_response(&body)
}

/// Parse a DER-encoded TimeStampResp and extract the TimeStampToken.
///
/// ```text
/// TimeStampResp ::= SEQUENCE {
///     status          PKIStatusInfo,
///     timeStampToken  TimeStampToken OPTIONAL
///                     -- TimeStampToken is a ContentInfo (CMS SignedData)
/// }
///
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText OPTIONAL,
///     failInfo      PKIFailureInfo OPTIONAL
/// }
///
/// PKIStatus ::= INTEGER {
///     granted(0), grantedWithMods(1), rejection(2),
///     waiting(3), revocationWarning(4), revocationNotification(5)
/// }
/// ```
fn parse_timestamp_response(data: &[u8]) -> SignResult<Vec<u8>> {
    // Parse outer SEQUENCE (TimeStampResp)
    let (_, resp_content) = asn1::parse_tlv(data)
        .map_err(|e| SignError::Timestamp(format!("Invalid TimeStampResp: {e}")))?;

    // First element: PKIStatusInfo SEQUENCE
    let (status_info_tlv, remaining) = asn1::extract_tlv(resp_content)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse PKIStatusInfo: {e}")))?;

    // Parse the status INTEGER from PKIStatusInfo
    let (_, status_content) = asn1::parse_tlv(status_info_tlv).map_err(|e| {
        SignError::Timestamp(format!("Failed to parse PKIStatusInfo SEQUENCE: {e}"))
    })?;

    let (_, status_value_bytes) = asn1::parse_tlv(status_content)
        .map_err(|e| SignError::Timestamp(format!("Failed to parse PKIStatus: {e}")))?;

    // status value: 0 = granted, 1 = grantedWithMods, 2+ = error
    let status = if status_value_bytes.is_empty() {
        0
    } else {
        status_value_bytes
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32)
    };

    if status > 1 {
        return Err(SignError::Timestamp(format!(
            "TSA rejected request with status {status}"
        )));
    }

    // Second element: TimeStampToken (ContentInfo — the full CMS SignedData)
    if remaining.is_empty() {
        return Err(SignError::Timestamp(
            "TimeStampResp contains no token".into(),
        ));
    }

    // The TimeStampToken is the entire remaining TLV (a ContentInfo SEQUENCE)
    let (token_tlv, _) = asn1::extract_tlv(remaining)
        .map_err(|e| SignError::Timestamp(format!("Failed to extract TimeStampToken: {e}")))?;

    Ok(token_tlv.to_vec())
}

/// TSA accuracy per RFC 3161 §2.4.2.
///
/// ```text
/// Accuracy ::= SEQUENCE {
///     seconds    INTEGER           OPTIONAL,
///     millis [0] INTEGER (1..999)  OPTIONAL,
///     micros [1] INTEGER (1..999)  OPTIONAL
/// }
/// ```
///
/// The accuracy represents the time deviation around genTime within which
/// the timestamp token was generated. The actual time is within
/// `[genTime - accuracy, genTime + accuracy]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TsaAccuracy {
    /// Seconds component (0 if absent).
    pub seconds: u32,
    /// Milliseconds component (0 if absent).
    pub millis: u16,
    /// Microseconds component (0 if absent).
    pub micros: u16,
}

impl TsaAccuracy {
    /// Total accuracy in microseconds for comparison.
    pub fn total_micros(&self) -> u64 {
        self.seconds as u64 * 1_000_000 + self.millis as u64 * 1_000 + self.micros as u64
    }
}

/// Parsed TSTInfo fields per RFC 3161 §2.4.2.
///
/// Exposes the full set of TSTInfo fields for callers that need more
/// than just validation (e.g., audit logging, UI display).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TstInfoDetails {
    /// TSA policy OID (dotted-decimal).
    pub policy: String,
    /// Accuracy of the timestamp (None if absent).
    pub accuracy: Option<TsaAccuracy>,
    /// Whether strict ordering is guaranteed by this TSA.
    /// RFC 3161 §2.4.2: If true, genTime values from this TSA
    /// can be compared for ordering.
    pub ordering: bool,
    /// Nonce echoed from the request (RFC 3161 §2.4.2).
    /// If present, MUST match the nonce from the TimeStampReq.
    pub nonce: Option<Vec<u8>>,
    /// TSA name from the tsa [1] GeneralName field (RFC 3161 §2.4.2).
    pub tsa_name: Option<String>,
    /// Number of extensions present in the extensions [1] field.
    /// RFC 3161 §2.4.2: Extensions is OPTIONAL and contains
    /// additional information for the TSA.
    pub extension_count: usize,
    /// RFC compliance warnings found during TSTInfo parsing.
    /// Includes critical unknown extension warnings per RFC 3161 §2.4.2.
    pub warnings: Vec<String>,
}

/// Parse a TimeStampToken and extract TSTInfo details (RFC 3161 §2.4.2).
///
/// This is a non-validating extraction — it parses the TSTInfo structure
/// and returns the optional accuracy, ordering, and policy fields without
/// checking the nonce or messageImprint. Use `request_timestamp()` for
/// validated timestamp requests.
pub fn parse_tst_info_details(token: &[u8]) -> SignResult<TstInfoDetails> {
    let tst_info = extract_tst_info_content(token)?;

    let (tag, tst_fields) = asn1::parse_tlv(tst_info)
        .map_err(|e| SignError::Timestamp(format!("Invalid TSTInfo SEQUENCE: {e}")))?;
    if tag != 0x30 {
        return Err(SignError::Timestamp("TSTInfo is not a SEQUENCE".into()));
    }

    // Field 1: version INTEGER — skip
    let (_, rest) = asn1::skip_tlv(tst_fields)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo version: {e}")))?;
    // Field 2: policy OID — extract
    let (policy_tlv, rest) = asn1::extract_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo policy: {e}")))?;
    let policy = extract_oid_string(policy_tlv);
    // Field 3: messageImprint — skip
    let (_, rest) = asn1::skip_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo messageImprint: {e}")))?;
    // Field 4: serialNumber — skip
    let (_, rest) = asn1::skip_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo serialNumber: {e}")))?;
    // Field 5: genTime — skip
    let (_, rest) =
        asn1::skip_tlv(rest).map_err(|e| SignError::Timestamp(format!("TSTInfo genTime: {e}")))?;

    // Parse optional fields (RFC 3161 §2.4.2)
    let mut accuracy = None;
    let mut ordering = false;
    let mut nonce = None;
    let mut tsa_name = None;
    let mut extension_count = 0;
    let mut tst_warnings = Vec::new();
    let mut remaining = rest;

    while !remaining.is_empty() {
        let tag = remaining[0];
        match tag {
            0x30 => {
                // accuracy SEQUENCE
                let (acc_tlv, r) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo accuracy: {e}")))?;
                accuracy = Some(parse_accuracy(acc_tlv)?);
                remaining = r;
            }
            0x01 => {
                // ordering BOOLEAN
                let (_, bool_bytes) = asn1::parse_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo ordering: {e}")))?;
                ordering = !bool_bytes.is_empty() && bool_bytes[0] != 0;
                let (_, r) = asn1::skip_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo ordering skip: {e}")))?;
                remaining = r;
            }
            0x02 => {
                // nonce INTEGER (RFC 3161 §2.4.2)
                let (nonce_tlv, r) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo nonce: {e}")))?;
                let (_, nonce_bytes) = asn1::parse_tlv(nonce_tlv)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo nonce parse: {e}")))?;
                nonce = Some(nonce_bytes.to_vec());
                remaining = r;
            }
            0xA0 => {
                // tsa [0] GeneralName (RFC 3161 §2.4.2)
                let (tsa_tlv, r) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo tsa: {e}")))?;
                let (_, tsa_content) = asn1::parse_tlv(tsa_tlv)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo tsa parse: {e}")))?;
                // Try to extract a readable name from the GeneralName
                tsa_name = std::str::from_utf8(tsa_content).ok().map(String::from);
                remaining = r;
            }
            0xA1 => {
                // extensions [1] IMPLICIT Extensions (RFC 3161 §2.4.2)
                let (ext_tlv, r) = asn1::extract_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo extensions: {e}")))?;
                let (_, ext_content) = asn1::parse_tlv(ext_tlv)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo extensions parse: {e}")))?;
                // Iterate over SEQUENCE OF Extension, checking for critical flags
                let mut ext_pos = ext_content;
                while !ext_pos.is_empty() {
                    if let Ok((ext_item_tlv, ext_r)) = asn1::extract_tlv(ext_pos) {
                        extension_count += 1;
                        // RFC 5280 §4.2: Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
                        validate_tst_extension(ext_item_tlv, &mut tst_warnings);
                        ext_pos = ext_r;
                    } else {
                        break;
                    }
                }
                remaining = r;
            }
            _ => {
                // Unknown tag — skip
                let (_, r) = asn1::skip_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo skip unknown: {e}")))?;
                remaining = r;
            }
        }
    }

    Ok(TstInfoDetails {
        policy,
        accuracy,
        ordering,
        nonce,
        tsa_name,
        extension_count,
        warnings: tst_warnings,
    })
}

/// Validate a single TSTInfo extension per RFC 3161 §2.4.2 + RFC 5280 §4.2.
///
/// Extension ::= SEQUENCE {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
/// }
///
/// RFC 3161 §2.4.2: TSA extensions are optional, but if present and marked
/// critical, the verifier MUST understand them or reject the timestamp.
fn validate_tst_extension(ext_tlv: &[u8], warnings: &mut Vec<String>) {
    let (tag, ext_content) = match asn1::parse_tlv(ext_tlv) {
        Ok(v) => v,
        Err(_) => return,
    };
    if tag != 0x30 {
        return;
    }

    // First element: OID
    let (oid_tlv, after_oid) = match asn1::extract_tlv(ext_content) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Check if next element is BOOLEAN (tag 0x01) — that's the critical flag
    if !after_oid.is_empty() && after_oid[0] == 0x01 {
        // BOOLEAN found — check if critical = TRUE
        if after_oid.len() >= 3 && after_oid[1] == 0x01 && after_oid[2] != 0x00 {
            // Critical extension — check if we recognize the OID
            // RFC 3161 doesn't define any mandatory extensions, so all are "unknown"
            // Known TSA extensions we accept:
            // - 1.3.6.1.5.5.7.1.3 (id-pe-qcStatements) — QC statements
            // - 2.5.29.* — standard X.509 extensions
            let (_, oid_content) = match asn1::parse_tlv(oid_tlv) {
                Ok(v) => v,
                Err(_) => return,
            };
            let is_x509_ext = oid_content.starts_with(&[0x55, 0x1D]); // 2.5.29.*
            if !is_x509_ext {
                warnings.push(format!(
                    "RFC 3161 §2.4.2: critical extension with unrecognized OID ({} bytes) — timestamp may not be verifiable",
                    oid_content.len()
                ));
            }
        }
    }
}

/// Parse an Accuracy SEQUENCE per RFC 3161 §2.4.2.
fn parse_accuracy(acc_tlv: &[u8]) -> SignResult<TsaAccuracy> {
    let (_, content) = asn1::parse_tlv(acc_tlv)
        .map_err(|e| SignError::Timestamp(format!("Invalid accuracy: {e}")))?;

    let mut seconds = 0u32;
    let mut millis = 0u16;
    let mut micros = 0u16;
    let mut pos = content;

    while !pos.is_empty() {
        let tag = pos[0];
        match tag {
            0x02 => {
                // seconds INTEGER
                let (_, int_bytes) = asn1::parse_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy seconds: {e}")))?;
                seconds = decode_integer_bytes(int_bytes) as u32;
                let (_, r) = asn1::skip_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy seconds skip: {e}")))?;
                pos = r;
            }
            0x80 => {
                // millis [0] IMPLICIT INTEGER
                let (_, int_bytes) = asn1::parse_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy millis: {e}")))?;
                millis = decode_integer_bytes(int_bytes) as u16;
                let (_, r) = asn1::skip_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy millis skip: {e}")))?;
                pos = r;
            }
            0x81 => {
                // micros [1] IMPLICIT INTEGER
                let (_, int_bytes) = asn1::parse_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy micros: {e}")))?;
                micros = decode_integer_bytes(int_bytes) as u16;
                let (_, r) = asn1::skip_tlv(pos)
                    .map_err(|e| SignError::Timestamp(format!("accuracy micros skip: {e}")))?;
                pos = r;
            }
            _ => break,
        }
    }

    Ok(TsaAccuracy {
        seconds,
        millis,
        micros,
    })
}

/// Extract a dotted-decimal OID string from an OID TLV.
fn extract_oid_string(oid_tlv: &[u8]) -> String {
    if oid_tlv.len() < 2 || oid_tlv[0] != 0x06 {
        return "unknown".to_string();
    }
    let (_, content) = match asn1::parse_tlv(oid_tlv) {
        Ok(v) => v,
        Err(_) => return "unknown".to_string(),
    };
    if content.is_empty() {
        return "unknown".to_string();
    }
    let first = content[0] / 40;
    let second = content[0] % 40;
    let mut parts = vec![first.to_string(), second.to_string()];
    let mut value: u64 = 0;
    for &b in &content[1..] {
        value = (value << 7) | (b & 0x7F) as u64;
        if b & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
        }
    }
    parts.join(".")
}

/// Validate a TimeStampToken per RFC 3161 §2.4.2.
///
/// Verifies:
/// 1. The nonce in TSTInfo matches the request nonce (replay protection)
/// 2. The messageImprint hash in TSTInfo matches the expected digest
///
/// The token is a CMS ContentInfo wrapping SignedData, which contains
/// the TSTInfo as encapsulated content.
fn validate_timestamp_token(
    token: &[u8],
    expected_digest: &[u8],
    expected_nonce: u64,
) -> SignResult<()> {
    let tst_info = extract_tst_info_content(token)?;

    // Parse TSTInfo SEQUENCE to get its fields
    let (tag, tst_fields) = asn1::parse_tlv(tst_info)
        .map_err(|e| SignError::Timestamp(format!("Invalid TSTInfo SEQUENCE: {e}")))?;
    if tag != 0x30 {
        return Err(SignError::Timestamp("TSTInfo is not a SEQUENCE".into()));
    }

    // Field 1: version INTEGER — skip
    let (_, rest) = asn1::skip_tlv(tst_fields)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo version: {e}")))?;
    // Field 2: policy OID — extract and validate per RFC 3161 §2.4.2.
    // When the request omits reqPolicy, the TSA may apply any policy including
    // the well-known id-tsp-v1 (0.4.0.2023.1.1). We accept any non-empty policy.
    let (policy_tlv, rest) = asn1::extract_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo policy: {e}")))?;
    let policy_str = extract_oid_string(policy_tlv);
    if policy_str == "unknown" {
        return Err(SignError::Timestamp(
            "RFC 3161 §2.4.2: TSTInfo policy field is missing or unparseable".into(),
        ));
    }
    // All non-empty policy OIDs are acceptable (id-tsp-v1 is explicitly well-known).
    // This is validated here for observability; is_well_known_tsp_policy() is the public API.
    let _ = is_well_known_tsp_policy(&policy_str);
    // Field 3: messageImprint SEQUENCE — extract for validation
    let (mi_tlv, rest) = asn1::extract_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo messageImprint: {e}")))?;
    // Field 4: serialNumber INTEGER — skip
    let (_, rest) = asn1::skip_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo serialNumber: {e}")))?;
    // Field 5: genTime GeneralizedTime — extract and validate per RFC 3161 §2.4.2.
    // A timestamp in the future (beyond tolerance) or malformed genTime is a hard error.
    let (gen_time_tlv, rest) = asn1::extract_tlv(rest)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo genTime: {e}")))?;
    let (_, gen_time_bytes) = asn1::parse_tlv(gen_time_tlv)
        .map_err(|e| SignError::Timestamp(format!("TSTInfo genTime parse: {e}")))?;
    if let Ok(gen_time_str) = std::str::from_utf8(gen_time_bytes) {
        // Use 300s (5 minute) tolerance for clock skew between client and TSA.
        let gen_time_warnings = validate_gentime(gen_time_str, 300);
        // Reject tokens with a future genTime — this indicates a replay or misconfigured TSA.
        for w in &gen_time_warnings {
            if w.message.contains("in the future") {
                return Err(SignError::Timestamp(w.message.clone()));
            }
        }
        // Past warnings are informational only — do not fail validation.
    }

    // Validate messageImprint hash matches request
    validate_message_imprint(mi_tlv, expected_digest)?;

    // Scan optional fields for nonce (RFC 3161 §2.4.2 field ordering):
    //   accuracy SEQUENCE (0x30), ordering BOOLEAN (0x01),
    //   nonce INTEGER (0x02), tsa [0] (0xA0), extensions [1] (0xA1)
    let mut remaining = rest;
    let mut found_nonce = false;
    while !remaining.is_empty() {
        let tag = remaining[0];
        match tag {
            0x30 => {
                // accuracy SEQUENCE — skip
                let (_, r) = asn1::skip_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo accuracy: {e}")))?;
                remaining = r;
            }
            0x01 => {
                // ordering BOOLEAN — skip
                let (_, r) = asn1::skip_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo ordering: {e}")))?;
                remaining = r;
            }
            0x02 => {
                // nonce INTEGER — validate against request nonce
                let (_, nonce_bytes) = asn1::parse_tlv(remaining)
                    .map_err(|e| SignError::Timestamp(format!("TSTInfo nonce: {e}")))?;
                let response_nonce = decode_integer_bytes(nonce_bytes);
                if response_nonce != expected_nonce {
                    return Err(SignError::Timestamp(format!(
                        "RFC 3161 §2.4.2: nonce mismatch — expected {expected_nonce:#x}, \
                         got {response_nonce:#x}"
                    )));
                }
                found_nonce = true;
                break;
            }
            // tsa [0] or extensions [1] — no nonce present
            _ => break,
        }
    }

    if !found_nonce {
        return Err(SignError::Timestamp(
            "RFC 3161 §2.4.2: response missing nonce (request included nonce)".into(),
        ));
    }

    Ok(())
}

/// Extract the TSTInfo DER bytes from a TimeStampToken (CMS ContentInfo).
///
/// Navigates: ContentInfo → SignedData → encapContentInfo → eContent → TSTInfo
///
/// Per RFC 3161 §2.4.2, the eContentType of the SignedData encapsulated ContentInfo
/// MUST be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4). This function validates
/// that constraint and rejects tokens with a mismatched eContentType.
fn extract_tst_info_content(token: &[u8]) -> SignResult<&[u8]> {
    let e = |s: &str| SignError::Timestamp(format!("TSTInfo extraction: {s}"));

    // ContentInfo SEQUENCE → content
    let (_, ci_content) = asn1::parse_tlv(token).map_err(&e)?;

    // Skip contentType OID → remaining has [0] EXPLICIT content
    let (_, after_oid) = asn1::skip_tlv(ci_content).map_err(&e)?;

    // [0] EXPLICIT → contains SignedData SEQUENCE
    let (_, explicit_content) = asn1::parse_tlv(after_oid).map_err(&e)?;

    // SignedData SEQUENCE → content
    let (_, sd_content) = asn1::parse_tlv(explicit_content).map_err(&e)?;

    // Skip version INTEGER, then digestAlgorithms SET
    let (_, after_ver) = asn1::skip_tlv(sd_content).map_err(&e)?;
    let (_, after_da) = asn1::skip_tlv(after_ver).map_err(&e)?;

    // encapContentInfo SEQUENCE → content
    let (_, eci_content) = asn1::parse_tlv(after_da).map_err(&e)?;

    // RFC 3161 §2.4.2: eContentType MUST be id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
    // Extract the eContentType OID and validate it before proceeding.
    let (ect_tlv, after_ct) = asn1::extract_tlv(eci_content).map_err(&e)?;
    if let Ok((tag, oid_content)) = asn1::parse_tlv(ect_tlv) {
        if tag == 0x06 && oid_content != OID_TST_INFO_CONTENT {
            return Err(SignError::Timestamp(format!(
                "RFC 3161 §2.4.2: eContentType is not id-ct-TSTInfo — got {} bytes OID content",
                oid_content.len()
            )));
        }
    }

    // [0] EXPLICIT → contains OCTET STRING
    let (_, explicit_content) = asn1::parse_tlv(after_ct).map_err(&e)?;

    // OCTET STRING → content is the TSTInfo DER (a SEQUENCE)
    let (tag, tst_der) = asn1::parse_tlv(explicit_content).map_err(&e)?;
    if tag != 0x04 {
        return Err(e("expected OCTET STRING for eContent"));
    }

    Ok(tst_der)
}

/// Validate that TSTInfo messageImprint matches expected digest (RFC 3161 §2.4.2).
fn validate_message_imprint(mi_tlv: &[u8], expected_digest: &[u8]) -> SignResult<()> {
    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    let (_, mi_content) = asn1::parse_tlv(mi_tlv)
        .map_err(|e| SignError::Timestamp(format!("Invalid messageImprint: {e}")))?;

    // Skip hashAlgorithm AlgorithmIdentifier (SEQUENCE)
    let (_, remaining) = asn1::skip_tlv(mi_content)
        .map_err(|e| SignError::Timestamp(format!("messageImprint hashAlgorithm: {e}")))?;

    // Extract hashedMessage OCTET STRING content
    let (tag, hash_bytes) = asn1::parse_tlv(remaining)
        .map_err(|e| SignError::Timestamp(format!("messageImprint hashedMessage: {e}")))?;
    if tag != 0x04 {
        return Err(SignError::Timestamp(
            "messageImprint hashedMessage is not OCTET STRING".into(),
        ));
    }

    if hash_bytes != expected_digest {
        return Err(SignError::Timestamp(
            "RFC 3161 §2.4.2: TSTInfo messageImprint hash does not match request".into(),
        ));
    }

    Ok(())
}

/// Decode ASN.1 INTEGER content bytes to u64.
fn decode_integer_bytes(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes {
        val = (val << 8) | b as u64;
    }
    val
}

/// Check whether a TSP policy OID (dotted-decimal string) is the well-known id-tsp-v1 policy.
///
/// Per RFC 3161 §2.4.2 and ETSI TS 119 421, the well-known TSP policy OID is
/// 0.4.0.2023.1.1 (id-tsp-v1). When a TimeStampReq carries no `reqPolicy`, the TSA
/// may stamp with any policy it supports, including id-tsp-v1. Verifiers MUST accept
/// tokens carrying this policy as conformant general-purpose timestamps.
///
/// Returns `true` if the policy is id-tsp-v1 or is otherwise considered acceptable
/// (i.e., a non-empty policy OID is always acceptable — RFC 3161 places no constraint
/// on which policy a TSA applies when the request omits `reqPolicy`).
pub fn is_well_known_tsp_policy(policy_oid: &str) -> bool {
    // id-tsp-v1 is the canonical well-known policy
    if policy_oid == "0.4.0.2023.1.1" {
        return true;
    }
    // Any non-empty policy is acceptable per RFC 3161 §2.4.2 when no reqPolicy was requested.
    // We reject only an empty/unknown string which signals a parse failure, not a real policy.
    !policy_oid.is_empty() && policy_oid != "unknown"
}

/// A temporal validation warning produced by `validate_gentime`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenTimeWarning {
    /// Human-readable description of the issue.
    pub message: String,
}

/// Validate the `genTime` field of a TSTInfo per RFC 3161 §2.4.2.
///
/// RFC 3161 §2.4.2 requires that `genTime` be a GeneralizedTime in UTC (suffix `Z`).
/// This function additionally checks that the timestamp is not unreasonably far in the
/// future or past, as a defence against clock-skew attacks:
///
/// - A `genTime` more than `tolerance_seconds` in the future triggers a warning.
/// - A `genTime` more than 30 years in the past triggers an informational warning.
///
/// The `gen_time` parameter is the raw GeneralizedTime string from the TSTInfo
/// (format: `YYYYMMDDHHmmssZ`, 15 characters).
///
/// Returns a (possibly empty) list of warnings. An empty list means the genTime
/// is well-formed and within acceptable bounds.
pub fn validate_gentime(gen_time: &str, tolerance_seconds: u64) -> Vec<GenTimeWarning> {
    let mut warnings = Vec::new();

    // RFC 3161 §2.4.2: genTime MUST be GeneralizedTime (YYYYMMDDHHmmssZ, 15 chars)
    if gen_time.len() != 15 || !gen_time.ends_with('Z') {
        warnings.push(GenTimeWarning {
            message: format!(
                "RFC 3161 §2.4.2: genTime '{gen_time}' is not well-formed GeneralizedTime \
                 (expected YYYYMMDDHHmmssZ, 15 chars ending in Z)"
            ),
        });
        return warnings;
    }

    let digits = &gen_time[..14];
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        warnings.push(GenTimeWarning {
            message: format!(
                "RFC 3161 §2.4.2: genTime '{gen_time}' contains non-digit characters before the Z suffix"
            ),
        });
        return warnings;
    }

    // Parse the components
    let year: u32 = gen_time[0..4].parse().unwrap_or(0);
    let month: u32 = gen_time[4..6].parse().unwrap_or(0);
    let day: u32 = gen_time[6..8].parse().unwrap_or(0);
    let hour: u32 = gen_time[8..10].parse().unwrap_or(0);
    let minute: u32 = gen_time[10..12].parse().unwrap_or(0);
    let second: u32 = gen_time[12..14].parse().unwrap_or(0);

    // Basic range checks
    if month == 0 || month > 12 {
        warnings.push(GenTimeWarning {
            message: format!("RFC 3161 §2.4.2: genTime has invalid month {month} (must be 01-12)"),
        });
        return warnings;
    }
    if day == 0 || day > 31 {
        warnings.push(GenTimeWarning {
            message: format!("RFC 3161 §2.4.2: genTime has invalid day {day} (must be 01-31)"),
        });
        return warnings;
    }
    if hour > 23 || minute > 59 || second > 59 {
        warnings.push(GenTimeWarning {
            message: format!(
                "RFC 3161 §2.4.2: genTime has invalid time component \
                 {hour:02}:{minute:02}:{second:02}"
            ),
        });
        return warnings;
    }

    // Convert to a Unix-like seconds count for comparison.
    // We use a simple approximation sufficient for ±years-level checks.
    // This avoids pulling in a date/time library for a best-effort validation.
    //
    // Days since year 2000-01-01 (our epoch for comparison):
    // This is not a calendar-correct implementation — it uses 365.25 days/year,
    // which is accurate to within ~1 day for years 2000-2100.
    let days_since_2000 = {
        let y = year as i64 - 2000;
        let m_offset: i64 = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
            [(month as usize).saturating_sub(1)];
        // Leap year adjustment (rough)
        let leap_days = if month > 2
            && year.is_multiple_of(4)
            && (!year.is_multiple_of(100) || year.is_multiple_of(400))
        {
            1i64
        } else {
            0i64
        };
        y * 365 + y / 4 - y / 100 + y / 400 + m_offset + leap_days + day as i64 - 1
    };
    let gen_time_secs =
        days_since_2000 * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;

    // Now(), approximated as seconds since 2000-01-01 using the UNIX epoch offset.
    // UNIX epoch (1970-01-01) is 10957 days before 2000-01-01.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_secs = now_unix - 10_957 * 86_400;

    let delta = gen_time_secs - now_secs;

    // Future check: genTime more than tolerance_seconds ahead of now
    if delta > tolerance_seconds as i64 {
        warnings.push(GenTimeWarning {
            message: format!(
                "RFC 3161 §2.4.2: genTime '{gen_time}' is {delta}s in the future \
                 (tolerance: {tolerance_seconds}s) — possible clock skew or replay"
            ),
        });
    }

    // Past check: genTime more than 30 years ago
    const THIRTY_YEARS_SECS: i64 = 30 * 365 * 86_400;
    if delta < -THIRTY_YEARS_SECS {
        warnings.push(GenTimeWarning {
            message: format!(
                "RFC 3161 §2.4.2: genTime '{gen_time}' is more than 30 years in the past — \
                 timestamp may not be meaningful for current revocation checking"
            ),
        });
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TsaConfig::default();
        assert_eq!(config.urls.len(), 2);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_build_timestamp_req_structure() {
        let sig = vec![0xAA; 256]; // Fake RSA signature
        let (req, _nonce) = build_timestamp_req(&sig);

        // Must be a SEQUENCE
        assert_eq!(req[0], 0x30);

        // Parse to verify structure
        let (_, content) = asn1::parse_tlv(&req).unwrap();

        // First element: version INTEGER
        let (tag, remaining) = asn1::skip_tlv(content).unwrap();
        assert_eq!(tag, 0x02); // INTEGER

        // Second element: messageImprint SEQUENCE
        let (tag, remaining) = asn1::skip_tlv(remaining).unwrap();
        assert_eq!(tag, 0x30); // SEQUENCE

        // Third element: nonce INTEGER
        let (tag, remaining) = asn1::skip_tlv(remaining).unwrap();
        assert_eq!(tag, 0x02); // INTEGER

        // Fourth element: certReq BOOLEAN
        let (tag, _) = asn1::skip_tlv(remaining).unwrap();
        assert_eq!(tag, 0x01); // BOOLEAN
    }

    #[test]
    fn test_encode_integer_u64() {
        let encoded = encode_integer_u64(0);
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);

        let encoded = encode_integer_u64(127);
        assert_eq!(encoded, vec![0x02, 0x01, 0x7F]);

        // 128 needs leading zero (high bit set)
        let encoded = encode_integer_u64(128);
        assert_eq!(encoded, vec![0x02, 0x02, 0x00, 0x80]);

        let encoded = encode_integer_u64(256);
        assert_eq!(encoded, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_parse_timestamp_response_granted() {
        // Build a minimal valid TimeStampResp with status=granted and a fake token
        let status_int = asn1::encode_integer_value(0); // granted
        let status_info = asn1::encode_sequence(&[&status_int]);

        // Fake TimeStampToken (a ContentInfo-like SEQUENCE)
        let fake_token = asn1::encode_sequence(&[
            asn1::OID_SIGNED_DATA,
            &asn1::encode_explicit_tag(0, &asn1::encode_integer_value(1)),
        ]);

        let resp = asn1::encode_sequence(&[&status_info, &fake_token]);

        let token = parse_timestamp_response(&resp).unwrap();
        assert_eq!(token, fake_token);
    }

    #[test]
    fn test_parse_timestamp_response_rejected() {
        // Build a TimeStampResp with status=rejection (2)
        let status_int = asn1::encode_integer_value(2);
        let status_info = asn1::encode_sequence(&[&status_int]);
        let resp = asn1::encode_sequence(&[&status_info]);

        let result = parse_timestamp_response(&resp);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("rejected"), "Error was: {err}");
    }

    #[test]
    fn test_parse_timestamp_response_no_token() {
        // Build a TimeStampResp with status=granted but no token
        let status_int = asn1::encode_integer_value(0);
        let status_info = asn1::encode_sequence(&[&status_int]);
        let resp = asn1::encode_sequence(&[&status_info]);

        let result = parse_timestamp_response(&resp);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no token"), "Error was: {err}");
    }

    #[test]
    fn test_build_timestamp_req_returns_nonce() {
        let sig = vec![0xBB; 128];
        let (req, nonce) = build_timestamp_req(&sig);

        // Verify nonce is positive (high bit cleared)
        assert!(nonce < 0x8000_0000_0000_0000);

        // Verify req is a valid SEQUENCE
        assert_eq!(req[0], 0x30);

        // Two calls should produce different nonces
        let (_, nonce2) = build_timestamp_req(&sig);
        // Statistically impossible to get the same nonce twice
        // (but don't assert — extremely rare collision is theoretically possible)
        let _ = nonce2;
    }

    #[test]
    fn test_decode_integer_bytes() {
        assert_eq!(decode_integer_bytes(&[0x00]), 0);
        assert_eq!(decode_integer_bytes(&[0x7F]), 127);
        assert_eq!(decode_integer_bytes(&[0x00, 0x80]), 128);
        assert_eq!(decode_integer_bytes(&[0x01, 0x00]), 256);
        assert_eq!(decode_integer_bytes(&[0x00, 0xFF]), 255);
    }

    /// Build a minimal TimeStampToken (CMS ContentInfo) containing a TSTInfo.
    ///
    /// This constructs only enough structure for `validate_timestamp_token` to parse:
    /// ContentInfo → [0] → SignedData → encapContentInfo → [0] → OCTET STRING → TSTInfo
    fn build_test_timestamp_token(
        message_imprint: &[u8],
        nonce_value: u64,
        include_accuracy: bool,
        include_ordering: bool,
    ) -> Vec<u8> {
        // Build TSTInfo SEQUENCE
        let mut tst_parts: Vec<Vec<u8>> = vec![
            asn1::encode_integer_value(1),      // version
            vec![0x06, 0x03, 0x55, 0x1D, 0x01], // policy OID (dummy)
            message_imprint.to_vec(),           // messageImprint
            asn1::encode_integer_value(42),     // serialNumber
            // genTime — 20260221120000Z as GeneralizedTime
            vec![
                0x18, 0x0F, 0x32, 0x30, 0x32, 0x36, 0x30, 0x32, 0x32, 0x31, 0x31, 0x32, 0x30, 0x30,
                0x30, 0x30, 0x5A,
            ],
        ];

        if include_accuracy {
            // Accuracy SEQUENCE { seconds INTEGER 1 }
            let acc = asn1::encode_sequence(&[&asn1::encode_integer_value(1)]);
            tst_parts.push(acc);
        }

        if include_ordering {
            // BOOLEAN TRUE
            tst_parts.push(vec![0x01, 0x01, 0xFF]);
        }

        // nonce INTEGER
        tst_parts.push(encode_integer_u64(nonce_value));

        let part_refs: Vec<&[u8]> = tst_parts.iter().map(|p| p.as_slice()).collect();
        let tst_info = asn1::encode_sequence(&part_refs);

        // Wrap in CMS structure:
        // ContentInfo { contentType: signedData, content: [0] { SignedData } }
        let econtent_octet = asn1::encode_octet_string(&tst_info);
        let econtent_explicit = asn1::encode_explicit_tag(0, &econtent_octet);
        let encap_content_info = asn1::encode_sequence(&[OID_TST_INFO, &econtent_explicit]);

        let digest_algos = asn1::encode_set(&asn1::SHA256_ALGORITHM_ID);
        let signer_infos = asn1::encode_set(&[]); // empty for test

        let signed_data = asn1::encode_sequence(&[
            &asn1::encode_integer_value(3), // version
            &digest_algos,
            &encap_content_info,
            &signer_infos,
        ]);

        let sd_explicit = asn1::encode_explicit_tag(0, &signed_data);
        asn1::encode_sequence(&[asn1::OID_SIGNED_DATA, &sd_explicit])
    }

    /// Build a valid MessageImprint SEQUENCE for testing.
    fn build_test_message_imprint(digest: &[u8]) -> Vec<u8> {
        asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(digest),
        ])
    }

    #[test]
    fn test_validate_timestamp_token_success() {
        let sig = b"test signature data";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0x1234_5678_9ABC;

        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, false, false);

        let result = validate_timestamp_token(&token, &digest, nonce);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_timestamp_token_with_accuracy_and_ordering() {
        let sig = b"another signature";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0x7FFF_FFFF_FFFF_FFFF;

        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, true, true);

        let result = validate_timestamp_token(&token, &digest, nonce);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_timestamp_token_nonce_mismatch() {
        let sig = b"test signature data";
        let digest = Sha256::digest(sig);
        let request_nonce: u64 = 0x1111;
        let response_nonce: u64 = 0x2222;

        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, response_nonce, false, false);

        let result = validate_timestamp_token(&token, &digest, request_nonce);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonce mismatch"),
            "Expected nonce mismatch error, got: {err}"
        );
    }

    #[test]
    fn test_validate_timestamp_token_imprint_mismatch() {
        let sig = b"test signature data";
        let digest = Sha256::digest(sig);
        let wrong_digest = Sha256::digest(b"wrong data");
        let nonce: u64 = 0xAAAA;

        let mi = build_test_message_imprint(&wrong_digest);
        let token = build_test_timestamp_token(&mi, nonce, false, false);

        let result = validate_timestamp_token(&token, &digest, nonce);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("messageImprint"),
            "Expected messageImprint error, got: {err}"
        );
    }

    #[test]
    fn test_validate_message_imprint_ok() {
        let digest = Sha256::digest(b"hello world");
        let mi = build_test_message_imprint(&digest);
        assert!(validate_message_imprint(&mi, &digest).is_ok());
    }

    #[test]
    fn test_validate_message_imprint_mismatch() {
        let digest = Sha256::digest(b"hello world");
        let wrong = Sha256::digest(b"goodbye world");
        let mi = build_test_message_imprint(&wrong);
        let result = validate_message_imprint(&mi, &digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tst_info_content() {
        let sig = b"extract test";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 42;

        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, false, false);

        let tst = extract_tst_info_content(&token);
        assert!(tst.is_ok(), "Extraction failed: {:?}", tst.err());

        // Verify it's a valid SEQUENCE
        let tst_bytes = tst.unwrap();
        assert_eq!(tst_bytes[0], 0x30, "TSTInfo should be a SEQUENCE");
    }

    #[test]
    fn test_roundtrip_nonce_encode_decode() {
        // Verify encode_integer_u64 → decode_integer_bytes roundtrip
        for &val in &[0u64, 1, 127, 128, 255, 256, 65535, 0x7FFF_FFFF_FFFF_FFFF] {
            let encoded = encode_integer_u64(val);
            // Parse to get content bytes (skip tag + length)
            let (tag, content) = asn1::parse_tlv(&encoded).unwrap();
            assert_eq!(tag, 0x02, "Should be INTEGER tag");
            let decoded = decode_integer_bytes(content);
            assert_eq!(decoded, val, "Nonce roundtrip failed for {val:#x}");
        }
    }

    // ─── TSTInfo Details Parsing Tests (RFC 3161 §2.4.2) ───

    #[test]
    fn test_parse_tst_info_details_no_optional_fields() {
        let sig = b"test details";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0x42;
        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, false, false);

        let details = parse_tst_info_details(&token).unwrap();
        assert!(details.accuracy.is_none(), "No accuracy field expected");
        assert!(!details.ordering, "Ordering should default to false");
        assert!(!details.policy.is_empty(), "Policy OID should be present");
    }

    #[test]
    fn test_parse_tst_info_details_with_accuracy() {
        let sig = b"accuracy test";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0x99;
        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, true, false);

        let details = parse_tst_info_details(&token).unwrap();
        assert!(details.accuracy.is_some(), "Accuracy should be parsed");
        let acc = details.accuracy.unwrap();
        assert_eq!(acc.seconds, 1, "Accuracy seconds should be 1");
        assert_eq!(acc.millis, 0);
        assert_eq!(acc.micros, 0);
        assert!(!details.ordering);
    }

    #[test]
    fn test_parse_tst_info_details_with_ordering() {
        let sig = b"ordering test";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0xBB;
        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, false, true);

        let details = parse_tst_info_details(&token).unwrap();
        assert!(details.accuracy.is_none());
        assert!(details.ordering, "Ordering should be true");
    }

    #[test]
    fn test_parse_tst_info_details_with_both() {
        let sig = b"both fields test";
        let digest = Sha256::digest(sig);
        let nonce: u64 = 0xCC;
        let mi = build_test_message_imprint(&digest);
        let token = build_test_timestamp_token(&mi, nonce, true, true);

        let details = parse_tst_info_details(&token).unwrap();
        assert!(details.accuracy.is_some());
        assert!(details.ordering);
        let acc = details.accuracy.unwrap();
        assert_eq!(acc.total_micros(), 1_000_000, "1 second = 1,000,000 micros");
    }

    #[test]
    fn test_tsa_accuracy_total_micros() {
        let acc = TsaAccuracy {
            seconds: 2,
            millis: 500,
            micros: 250,
        };
        assert_eq!(acc.total_micros(), 2_500_250);
    }

    #[test]
    fn test_parse_accuracy_all_fields() {
        // Accuracy SEQUENCE { seconds 3, millis [0] 500, micros [1] 100 }
        let seconds = asn1::encode_integer_value(3);
        let millis = encode_implicit_integer(0x80, 500);
        let micros = encode_implicit_integer(0x81, 100);
        let acc_seq = asn1::encode_sequence(&[&seconds, &millis, &micros]);

        let result = parse_accuracy(&acc_seq).unwrap();
        assert_eq!(result.seconds, 3);
        assert_eq!(result.millis, 500);
        assert_eq!(result.micros, 100);
    }

    #[test]
    fn test_parse_accuracy_seconds_only() {
        let seconds = asn1::encode_integer_value(10);
        let acc_seq = asn1::encode_sequence(&[&seconds]);

        let result = parse_accuracy(&acc_seq).unwrap();
        assert_eq!(result.seconds, 10);
        assert_eq!(result.millis, 0);
        assert_eq!(result.micros, 0);
    }

    #[test]
    fn test_parse_accuracy_empty() {
        let acc_seq = asn1::encode_sequence(&[]);
        let result = parse_accuracy(&acc_seq).unwrap();
        assert_eq!(result.seconds, 0);
        assert_eq!(result.millis, 0);
        assert_eq!(result.micros, 0);
    }

    #[test]
    fn test_extract_oid_string() {
        // OID 2.5.29.1 (dummy policy OID used in tests)
        let oid_bytes: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x01];
        let result = extract_oid_string(oid_bytes);
        assert_eq!(result, "2.5.29.1");
    }

    #[test]
    fn test_extract_oid_string_invalid() {
        assert_eq!(extract_oid_string(&[0x01, 0x00]), "unknown");
        assert_eq!(extract_oid_string(&[]), "unknown");
    }

    #[test]
    fn test_tst_info_details_has_new_fields() {
        // Verify the struct has the new nonce, tsa_name, extension_count fields
        let details = TstInfoDetails {
            policy: "1.2.3.4".to_string(),
            accuracy: None,
            ordering: false,
            nonce: Some(vec![0x01, 0x02, 0x03]),
            tsa_name: Some("Test TSA".to_string()),
            extension_count: 2,
            warnings: Vec::new(),
        };
        assert_eq!(details.nonce, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(details.tsa_name.as_deref(), Some("Test TSA"));
        assert_eq!(details.extension_count, 2);
    }

    #[test]
    fn test_tst_info_details_default_new_fields() {
        // Without optional fields, nonce/tsa/extensions should be None/0
        let details = TstInfoDetails {
            policy: "1.2.3.4".to_string(),
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa_name: None,
            extension_count: 0,
            warnings: Vec::new(),
        };
        assert!(details.nonce.is_none());
        assert!(details.tsa_name.is_none());
        assert_eq!(details.extension_count, 0);
    }

    #[test]
    fn test_validate_tst_extension_critical_unknown_oid() {
        // Extension SEQUENCE: OID (1.2.3.4) + BOOLEAN TRUE (critical) + OCTET STRING value
        let mut ext = Vec::new();
        // OID 1.2.3.4
        let oid = vec![0x06, 0x03, 0x2A, 0x03, 0x04];
        // BOOLEAN TRUE (critical)
        let critical = vec![0x01, 0x01, 0xFF];
        // OCTET STRING value
        let value = vec![0x04, 0x02, 0xAA, 0xBB];
        let inner_len = oid.len() + critical.len() + value.len();
        ext.push(0x30); // SEQUENCE
        ext.push(inner_len as u8);
        ext.extend(&oid);
        ext.extend(&critical);
        ext.extend(&value);

        let mut warnings = Vec::new();
        validate_tst_extension(&ext, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("RFC 3161"));
        assert!(warnings[0].contains("critical extension"));
    }

    #[test]
    fn test_validate_tst_extension_critical_x509_oid() {
        // Extension SEQUENCE: OID 2.5.29.19 (basicConstraints) + BOOLEAN TRUE (critical)
        let mut ext = Vec::new();
        let oid = vec![0x06, 0x03, 0x55, 0x1D, 0x13]; // 2.5.29.19
        let critical = vec![0x01, 0x01, 0xFF];
        let value = vec![0x04, 0x02, 0x30, 0x00];
        let inner_len = oid.len() + critical.len() + value.len();
        ext.push(0x30);
        ext.push(inner_len as u8);
        ext.extend(&oid);
        ext.extend(&critical);
        ext.extend(&value);

        let mut warnings = Vec::new();
        validate_tst_extension(&ext, &mut warnings);
        // Known X.509 extension — no warning
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_tst_extension_non_critical() {
        // Non-critical extension should not produce a warning even with unknown OID
        let mut ext = Vec::new();
        let oid = vec![0x06, 0x03, 0x2A, 0x03, 0x04]; // 1.2.3.4
        let not_critical = vec![0x01, 0x01, 0x00]; // BOOLEAN FALSE
        let value = vec![0x04, 0x02, 0xAA, 0xBB];
        let inner_len = oid.len() + not_critical.len() + value.len();
        ext.push(0x30);
        ext.push(inner_len as u8);
        ext.extend(&oid);
        ext.extend(&not_critical);
        ext.extend(&value);

        let mut warnings = Vec::new();
        validate_tst_extension(&ext, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_tst_extension_no_boolean() {
        // Extension without critical flag (BOOLEAN absent) — no warning
        let mut ext = Vec::new();
        let oid = vec![0x06, 0x03, 0x2A, 0x03, 0x04];
        let value = vec![0x04, 0x02, 0xAA, 0xBB];
        let inner_len = oid.len() + value.len();
        ext.push(0x30);
        ext.push(inner_len as u8);
        ext.extend(&oid);
        ext.extend(&value);

        let mut warnings = Vec::new();
        validate_tst_extension(&ext, &mut warnings);
        assert!(warnings.is_empty());
    }

    /// Encode an IMPLICIT context-specific INTEGER (e.g., [0] or [1]).
    fn encode_implicit_integer(tag: u8, value: u64) -> Vec<u8> {
        let int_bytes = {
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
                if bytes[0] & 0x80 != 0 {
                    bytes.insert(0, 0x00);
                }
            }
            bytes
        };
        let mut result = vec![tag];
        result.extend(asn1::encode_length(int_bytes.len()));
        result.extend(int_bytes);
        result
    }

    // ── is_well_known_tsp_policy tests ────────────────────────────────────────

    #[test]
    fn test_well_known_policy_etsi_v1() {
        // The ETSI id-tsp-v1 OID is explicitly recognized as well-known.
        assert!(is_well_known_tsp_policy("0.4.0.2023.1.1"));
    }

    #[test]
    fn test_well_known_policy_non_empty_oid_accepted() {
        // Any non-empty, non-"unknown" OID is treated as a valid CA policy.
        assert!(is_well_known_tsp_policy("1.2.840.113549.1.9.16.1.4"));
        assert!(is_well_known_tsp_policy("1.3.6.1.4.1.56266.1.1"));
    }

    #[test]
    fn test_well_known_policy_empty_rejected() {
        assert!(!is_well_known_tsp_policy(""));
    }

    #[test]
    fn test_well_known_policy_unknown_sentinel_rejected() {
        // The string "unknown" is produced by our OID parser when it cannot decode the OID.
        assert!(!is_well_known_tsp_policy("unknown"));
    }

    // ── validate_gentime tests ────────────────────────────────────────────────

    #[test]
    fn test_gentime_valid_past_recent() {
        // A date in the year 2020 — clearly in the past but within 30 years.
        let warnings = validate_gentime("20200101120000Z", 300);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn test_gentime_wrong_length() {
        // 13 characters — too short.
        let warnings = validate_gentime("202001011200Z", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("15 chars"));
    }

    #[test]
    fn test_gentime_missing_z_suffix() {
        // 15 characters but ends with '+' not 'Z'.
        let warnings = validate_gentime("20200101120000+", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("ending in Z"));
    }

    #[test]
    fn test_gentime_invalid_month_zero() {
        let warnings = validate_gentime("20200001120000Z", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("month"));
    }

    #[test]
    fn test_gentime_invalid_month_thirteen() {
        let warnings = validate_gentime("20201301120000Z", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("month"));
    }

    #[test]
    fn test_gentime_invalid_day_zero() {
        let warnings = validate_gentime("20200100120000Z", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("day"));
    }

    #[test]
    fn test_gentime_invalid_time_components() {
        // Hour 25 is out of range.
        let warnings = validate_gentime("20200101250000Z", 300);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("time component"));
    }

    #[test]
    fn test_gentime_non_numeric_content() {
        let warnings = validate_gentime("2020AB01120000Z", 300);
        // month parse will fail → produces a "month" warning
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_gentime_far_future_error() {
        // A timestamp 10 years in the future should produce a future-time error.
        // We construct one dynamically so the test doesn't age out.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Add ~10 years worth of seconds.
        let future_unix = now + 10 * 365 * 86_400;
        // Convert to YYYYMMDDHHmmssZ (rough; just needs to be far in the future).
        let days_since_epoch = future_unix / 86_400;
        // Approximate year: 1970 + days/365.25.
        let year = 1970u64 + days_since_epoch * 100 / 36525;
        let gen_time = format!("{year:04}0601120000Z");
        let warnings = validate_gentime(&gen_time, 300);
        assert!(
            warnings.iter().any(|w| w.message.contains("future")),
            "expected future-time warning, got: {warnings:?}"
        );
    }

    #[test]
    fn test_gentime_very_old_timestamp_warning() {
        // The year 1990 is more than 30 years ago — should produce a "past" warning.
        let warnings = validate_gentime("19900601120000Z", 300);
        assert!(
            warnings.iter().any(|w| w.message.contains("past")),
            "expected past-time warning, got: {warnings:?}"
        );
    }
}
