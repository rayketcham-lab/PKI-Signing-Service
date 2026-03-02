//! ESS (Enhanced Security Services) S/MIME Attributes (RFC 2634, RFC 5035)
//!
//! Implements the ESS extensions for S/MIME:
//! - `ReceiptRequest` (RFC 2634 §2.7) — requests a signed receipt
//! - `SecurityLabel` (RFC 2634 §3.7) — security classification labels
//! - `MLExpansionHistory` (RFC 2634 §4.2) — mailing list expansion tracking
//! - `smimeCapabilities` (RFC 8551 §2.5.2) — advertises supported algorithms
//!
//! These are encoded as CMS signed attributes using the DER encoding helpers
//! from `pkcs7::asn1`.

use crate::pkcs7::asn1;

// ─── ReceiptRequest (RFC 2634 §2.7) ───

/// Content identifier types for ReceiptRequest.
///
/// Used to reference the message that requires a receipt.
#[derive(Debug, Clone)]
pub struct ContentIdentifier {
    /// Random bytes that uniquely identify the content (8-32 bytes recommended).
    pub identifier_bytes: Vec<u8>,
}

impl ContentIdentifier {
    /// Create a new random ContentIdentifier (16 bytes).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            identifier_bytes: bytes,
        }
    }

    /// Encode as OCTET STRING.
    pub fn to_der(&self) -> Vec<u8> {
        asn1::encode_octet_string(&self.identifier_bytes)
    }
}

/// ReceiptsFrom specifies who should send receipts.
#[derive(Debug, Clone)]
pub enum ReceiptsFrom {
    /// Receipt from all recipients (integer 0).
    AllOrFirstTier,
    /// Receipt only from first-tier recipients (integer 1).
    FirstTierOnly,
    /// Receipt from specific recipients (explicit list of GeneralNames).
    Explicit(Vec<Vec<u8>>), // DER-encoded GeneralName entries
}

/// ReceiptRequest attribute (RFC 2634 §2.7).
///
/// ```text
/// ReceiptRequest ::= SEQUENCE {
///   signedContentIdentifier ContentIdentifier,
///   receiptsFrom ReceiptsFrom,
///   receiptsTo SEQUENCE OF GeneralNames
/// }
/// ```
///
/// When included as a signed attribute, requests that certain recipients
/// return a signed receipt (RFC 2634 §2.4).
#[derive(Debug, Clone)]
pub struct ReceiptRequest {
    /// Content identifier for the message being signed.
    pub signed_content_identifier: ContentIdentifier,
    /// Who should send receipts.
    pub receipts_from: ReceiptsFrom,
    /// Where receipts should be sent (list of DER-encoded GeneralNames SEQUENCE).
    pub receipts_to: Vec<Vec<u8>>,
}

impl ReceiptRequest {
    /// Create a simple receipt request for all recipients.
    ///
    /// Uses a randomly generated content identifier and requests receipts
    /// from all recipients. `receipts_to` specifies the email address
    /// (as an rfc822Name GeneralName) where receipts should be sent.
    pub fn for_all_recipients(receipts_to_email: &str) -> Self {
        Self {
            signed_content_identifier: ContentIdentifier::generate(),
            receipts_from: ReceiptsFrom::AllOrFirstTier,
            receipts_to: vec![encode_rfc822_general_names(receipts_to_email)],
        }
    }

    /// Encode as the DER value of the `id-smime-aa-receiptRequest` signed attribute.
    pub fn to_der(&self) -> Vec<u8> {
        // signedContentIdentifier OCTET STRING
        let content_id_der = self.signed_content_identifier.to_der();

        // receiptsFrom: [0] INTEGER or [1] SEQUENCE OF GeneralNames
        let receipts_from_der = match &self.receipts_from {
            ReceiptsFrom::AllOrFirstTier => {
                // [0] INTEGER 0
                let int_val = asn1::encode_integer_value(0);
                asn1::encode_explicit_tag(0, &int_val)
            }
            ReceiptsFrom::FirstTierOnly => {
                // [0] INTEGER 1
                let int_val = asn1::encode_integer_value(1);
                asn1::encode_explicit_tag(0, &int_val)
            }
            ReceiptsFrom::Explicit(names) => {
                // [1] SEQUENCE OF GeneralNames
                let mut names_content = Vec::new();
                for name in names {
                    names_content.extend_from_slice(name);
                }
                let names_seq = asn1::encode_sequence(&[&names_content]);
                asn1::encode_explicit_tag(1, &names_seq)
            }
        };

        // receiptsTo SEQUENCE OF GeneralNames
        let mut receipts_to_content = Vec::new();
        for gn_seq in &self.receipts_to {
            receipts_to_content.extend_from_slice(gn_seq);
        }
        let receipts_to_der = asn1::encode_sequence(&[&receipts_to_content]);

        asn1::encode_sequence(&[&content_id_der, &receipts_from_der, &receipts_to_der])
    }

    /// Encode as a complete CMS signed attribute (OID + SET { value }).
    pub fn to_signed_attribute(&self) -> Vec<u8> {
        let value = self.to_der();
        let value_set = asn1::encode_set(&value);
        asn1::encode_sequence(&[asn1::OID_ESS_RECEIPT_REQUEST, &value_set])
    }
}

/// Encode an email address as a GeneralNames SEQUENCE containing one rfc822Name.
///
/// GeneralNames ::= SEQUENCE OF GeneralName
/// GeneralName  ::= [1] IMPLICIT IA5String (rfc822Name)
fn encode_rfc822_general_names(email: &str) -> Vec<u8> {
    let email_bytes = email.as_bytes();
    // rfc822Name = [1] IMPLICIT IA5String
    let mut rfc822 = vec![0x81]; // [1] IMPLICIT primitive
    rfc822.extend(asn1::encode_length(email_bytes.len()));
    rfc822.extend_from_slice(email_bytes);
    // GeneralNames SEQUENCE OF GeneralName
    asn1::encode_sequence(&[&rfc822])
}

// ─── SecurityLabel (RFC 2634 §3.7) ───

/// Security policy OID — identifies the security policy under which the label applies.
pub type SecurityPolicyOid = Vec<u8>; // DER-encoded OID

/// Security classification value (RFC 2634 §3.7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityClassification {
    /// Unmarked (0)
    Unmarked,
    /// Unclassified (1)
    Unclassified,
    /// Restricted (2)
    Restricted,
    /// Confidential (3)
    Confidential,
    /// Secret (4)
    Secret,
    /// Top Secret (5)
    TopSecret,
    /// Custom value (6-32767)
    Custom(u16),
}

impl SecurityClassification {
    /// Return the numeric value of this classification level.
    pub fn value(&self) -> u32 {
        match self {
            Self::Unmarked => 0,
            Self::Unclassified => 1,
            Self::Restricted => 2,
            Self::Confidential => 3,
            Self::Secret => 4,
            Self::TopSecret => 5,
            Self::Custom(v) => *v as u32,
        }
    }
}

impl PartialOrd for SecurityClassification {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecurityClassification {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

/// SecurityLabel attribute (RFC 2634 §3.7).
///
/// ```text
/// SecurityLabel ::= SET {
///   security-policy-identifier SecurityPolicyIdentifier,
///   security-classification SecurityClassification OPTIONAL,
///   privacy-mark    PrivacyMark OPTIONAL,
///   security-categories SecurityCategories OPTIONAL
/// }
/// ```
///
/// Provides structured security classification marking for S/MIME messages.
#[derive(Debug, Clone)]
pub struct SecurityLabel {
    /// DER-encoded security policy OID.
    pub policy_id: Vec<u8>,
    /// Security classification level.
    pub classification: SecurityClassification,
    /// Optional human-readable privacy mark string.
    pub privacy_mark: Option<String>,
}

impl SecurityLabel {
    /// Create a new SecurityLabel with a given classification.
    ///
    /// `policy_oid_der` is the DER-encoded OID for the security policy
    /// (including tag 0x06 and length byte).
    pub fn new(policy_oid_der: Vec<u8>, classification: SecurityClassification) -> Self {
        Self {
            policy_id: policy_oid_der,
            classification,
            privacy_mark: None,
        }
    }

    /// Set the privacy mark (human-readable classification label).
    pub fn with_privacy_mark(mut self, mark: impl Into<String>) -> Self {
        self.privacy_mark = Some(mark.into());
        self
    }

    /// Encode as the DER value of the `id-smime-aa-securityLabel` signed attribute.
    pub fn to_der(&self) -> Vec<u8> {
        // security-policy-identifier OID
        let policy_der = &self.policy_id;

        // security-classification INTEGER
        let class_int = asn1::encode_integer_value(self.classification.value());

        // privacy-mark PrintableString or UTF8String (optional)
        let privacy_mark_der = if let Some(mark) = &self.privacy_mark {
            asn1::encode_utf8_string(mark)
        } else {
            vec![]
        };

        // SecurityLabel is a SET
        if privacy_mark_der.is_empty() {
            asn1::encode_set(
                &[policy_der.as_slice(), &class_int]
                    .iter()
                    .flat_map(|b| b.iter().copied())
                    .collect::<Vec<u8>>(),
            )
        } else {
            let mut content = Vec::new();
            content.extend_from_slice(policy_der);
            content.extend_from_slice(&class_int);
            content.extend_from_slice(&privacy_mark_der);
            asn1::encode_set(&content)
        }
    }

    /// Encode as a complete CMS signed attribute (OID + SET { value }).
    pub fn to_signed_attribute(&self) -> Vec<u8> {
        let value = self.to_der();
        let value_set = asn1::encode_set(&value);
        asn1::encode_sequence(&[asn1::OID_ESS_SECURITY_LABEL, &value_set])
    }
}

// ─── MLExpansionHistory (RFC 2634 §4.2) ───

/// A single mailing list entry in the expansion history.
///
/// ```text
/// MLData ::= SEQUENCE {
///   mailListIdentifier EntityIdentifier,
///   expansionTime     GeneralizedTime,
///   mlReceiptPolicy    MLReceiptPolicy OPTIONAL
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MlData {
    /// Email address of the mailing list (as rfc822Name).
    pub mail_list_address: String,
    /// Time when the mailing list expanded the message.
    pub expansion_time: chrono::DateTime<chrono::Utc>,
}

impl MlData {
    /// Create a new MLData entry.
    pub fn new(mail_list_address: impl Into<String>) -> Self {
        Self {
            mail_list_address: mail_list_address.into(),
            expansion_time: chrono::Utc::now(),
        }
    }

    /// Encode as DER MLData SEQUENCE.
    pub fn to_der(&self) -> Vec<u8> {
        // EntityIdentifier CHOICE rfc822Name [0] IMPLICIT IA5String
        let email_bytes = self.mail_list_address.as_bytes();
        let mut rfc822 = vec![0x81]; // [1] IMPLICIT rfc822Name
        rfc822.extend(asn1::encode_length(email_bytes.len()));
        rfc822.extend_from_slice(email_bytes);
        // Wrap in GeneralNames SEQUENCE for EntityIdentifier
        let entity_id = asn1::encode_sequence(&[&rfc822]);

        // expansionTime GeneralizedTime
        let time_der = asn1::encode_utc_time(self.expansion_time);

        asn1::encode_sequence(&[&entity_id, &time_der])
    }
}

/// MLExpansionHistory attribute (RFC 2634 §4.2).
///
/// ```text
/// MLExpansionHistory ::= SEQUENCE SIZE (1..MAX) OF MLData
/// ```
///
/// Records the chain of mailing lists through which a message has been
/// forwarded, enabling loop detection and receipt routing.
#[derive(Debug, Clone)]
pub struct MLExpansionHistory {
    /// List of mailing list expansions.
    pub entries: Vec<MlData>,
}

impl MLExpansionHistory {
    /// Create a new empty expansion history.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a mailing list expansion entry.
    pub fn add_entry(mut self, entry: MlData) -> Self {
        self.entries.push(entry);
        self
    }

    /// Encode as the DER value of the `id-smime-aa-mlExpansionHistory` signed attribute.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for entry in &self.entries {
            content.extend_from_slice(&entry.to_der());
        }
        asn1::encode_sequence(&[&content])
    }

    /// Encode as a complete CMS signed attribute.
    pub fn to_signed_attribute(&self) -> Vec<u8> {
        let value = self.to_der();
        let value_set = asn1::encode_set(&value);
        asn1::encode_sequence(&[asn1::OID_ESS_ML_EXPANSION_HISTORY, &value_set])
    }
}

impl Default for MLExpansionHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ─── smimeCapabilities (RFC 8551 §2.5.2) ───

/// A single S/MIME capability entry.
///
/// ```text
/// SMIMECapability ::= SEQUENCE {
///   capabilityID OBJECT IDENTIFIER,
///   parameters ANY DEFINED BY capabilityID OPTIONAL
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SmimeCapability {
    /// DER-encoded OID for this capability (including tag + length).
    pub capability_oid: Vec<u8>,
    /// Optional DER-encoded parameters.
    pub parameters: Option<Vec<u8>>,
}

impl SmimeCapability {
    /// AES-256-GCM capability (RFC 5084).
    pub fn aes256_gcm() -> Self {
        Self {
            capability_oid: asn1::OID_AES256_GCM.to_vec(),
            parameters: None,
        }
    }

    /// AES-128-GCM capability (RFC 5084).
    pub fn aes128_gcm() -> Self {
        Self {
            capability_oid: asn1::OID_AES128_GCM.to_vec(),
            parameters: None,
        }
    }

    /// AES-256-CBC capability (RFC 3370).
    pub fn aes256_cbc() -> Self {
        Self {
            capability_oid: asn1::OID_AES256_CBC.to_vec(),
            parameters: None,
        }
    }

    /// AES-128-CBC capability (RFC 3370).
    pub fn aes128_cbc() -> Self {
        Self {
            capability_oid: asn1::OID_AES128_CBC.to_vec(),
            parameters: None,
        }
    }

    /// Encode as DER SMIMECapability SEQUENCE.
    pub fn to_der(&self) -> Vec<u8> {
        if let Some(params) = &self.parameters {
            asn1::encode_sequence(&[&self.capability_oid, params])
        } else {
            asn1::encode_sequence(&[&self.capability_oid])
        }
    }
}

/// smimeCapabilities signed attribute (RFC 8551 §2.5.2).
///
/// Lists the S/MIME content encryption algorithms supported by the sender,
/// in order of preference (most preferred first). This allows senders to
/// choose the strongest algorithm the recipient supports.
///
/// ```text
/// SMIMECapabilities ::= SEQUENCE OF SMIMECapability
/// ```
#[derive(Debug, Clone)]
pub struct SmimeCapabilities {
    /// Capabilities in order of preference (most preferred first).
    pub capabilities: Vec<SmimeCapability>,
}

impl SmimeCapabilities {
    /// Create a default set of capabilities (AES-256-GCM preferred).
    ///
    /// Advertises in preference order:
    /// 1. AES-256-GCM (strongest AEAD)
    /// 2. AES-128-GCM
    /// 3. AES-256-CBC (wide compatibility)
    /// 4. AES-128-CBC
    pub fn default_capabilities() -> Self {
        Self {
            capabilities: vec![
                SmimeCapability::aes256_gcm(),
                SmimeCapability::aes128_gcm(),
                SmimeCapability::aes256_cbc(),
                SmimeCapability::aes128_cbc(),
            ],
        }
    }

    /// Create a new empty capabilities list.
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
        }
    }

    /// Append a capability to the list.
    pub fn push(mut self, cap: SmimeCapability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Encode as the DER value of the smimeCapabilities signed attribute.
    ///
    /// Returns the DER SEQUENCE OF SMIMECapability.
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for cap in &self.capabilities {
            content.extend_from_slice(&cap.to_der());
        }
        asn1::encode_sequence(&[&content])
    }

    /// Encode as a complete CMS signed attribute (OID + SET { value }).
    pub fn to_signed_attribute(&self) -> Vec<u8> {
        let value = self.to_der();
        let value_set = asn1::encode_set(&value);
        asn1::encode_sequence(&[asn1::OID_SMIME_CAPABILITIES, &value_set])
    }
}

impl Default for SmimeCapabilities {
    fn default() -> Self {
        Self::default_capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_identifier_generate_length() {
        let ci = ContentIdentifier::generate();
        assert_eq!(ci.identifier_bytes.len(), 16);
        let der = ci.to_der();
        assert_eq!(der[0], 0x04); // OCTET STRING tag
        assert_eq!(der[1], 16); // length
    }

    #[test]
    fn test_receipt_request_all_recipients() {
        let rr = ReceiptRequest::for_all_recipients("sender@example.com");
        let der = rr.to_der();
        // Should be a SEQUENCE
        assert_eq!(der[0], 0x30);
        assert!(!der.is_empty());
    }

    #[test]
    fn test_receipt_request_signed_attribute() {
        let rr = ReceiptRequest::for_all_recipients("test@example.com");
        let attr = rr.to_signed_attribute();
        // Should start with SEQUENCE
        assert_eq!(attr[0], 0x30);
        // Should contain the OID 1.2.840.113549.1.9.16.2.1
        assert!(attr
            .windows(asn1::OID_ESS_RECEIPT_REQUEST.len())
            .any(|w| w == asn1::OID_ESS_RECEIPT_REQUEST));
    }

    #[test]
    fn test_receipt_request_explicit_recipients() {
        let rr = ReceiptRequest {
            signed_content_identifier: ContentIdentifier::generate(),
            receipts_from: ReceiptsFrom::Explicit(vec![encode_rfc822_general_names(
                "list@example.com",
            )]),
            receipts_to: vec![encode_rfc822_general_names("admin@example.com")],
        };
        let der = rr.to_der();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_security_label_unclassified() {
        // Use a simple OID for testing: 2.5.4.0
        let policy_oid = vec![0x06, 0x03, 0x55, 0x04, 0x00];
        let label = SecurityLabel::new(policy_oid, SecurityClassification::Unclassified);
        let der = label.to_der();
        // Should be a SET
        assert_eq!(der[0], 0x31);
    }

    #[test]
    fn test_security_label_with_privacy_mark() {
        let policy_oid = vec![0x06, 0x03, 0x55, 0x04, 0x00];
        let label = SecurityLabel::new(policy_oid, SecurityClassification::Confidential)
            .with_privacy_mark("COMPANY CONFIDENTIAL");
        let der = label.to_der();
        assert_eq!(der[0], 0x31); // SET
                                  // Should contain the privacy mark string bytes
        let mark_bytes = b"COMPANY CONFIDENTIAL";
        assert!(der.windows(mark_bytes.len()).any(|w| w == mark_bytes));
    }

    #[test]
    fn test_security_label_signed_attribute() {
        let policy_oid = vec![0x06, 0x03, 0x55, 0x04, 0x00];
        let label = SecurityLabel::new(policy_oid, SecurityClassification::Secret);
        let attr = label.to_signed_attribute();
        assert_eq!(attr[0], 0x30);
        assert!(attr
            .windows(asn1::OID_ESS_SECURITY_LABEL.len())
            .any(|w| w == asn1::OID_ESS_SECURITY_LABEL));
    }

    #[test]
    fn test_security_classification_ordering() {
        assert!(SecurityClassification::Unclassified < SecurityClassification::Secret);
        assert!(SecurityClassification::Secret < SecurityClassification::TopSecret);
        assert_eq!(SecurityClassification::Confidential.value(), 3);
        assert_eq!(SecurityClassification::TopSecret.value(), 5);
    }

    #[test]
    fn test_ml_expansion_history_empty() {
        let history = MLExpansionHistory::new();
        let der = history.to_der();
        // Empty SEQUENCE
        assert_eq!(der, vec![0x30, 0x00]);
    }

    #[test]
    fn test_ml_expansion_history_one_entry() {
        let history = MLExpansionHistory::new().add_entry(MlData::new("list@example.com"));
        let der = history.to_der();
        assert_eq!(der[0], 0x30);
        assert!(der.len() > 4);
    }

    #[test]
    fn test_ml_expansion_history_signed_attribute() {
        let history = MLExpansionHistory::new().add_entry(MlData::new("announce@corp.example"));
        let attr = history.to_signed_attribute();
        assert_eq!(attr[0], 0x30);
        assert!(attr
            .windows(asn1::OID_ESS_ML_EXPANSION_HISTORY.len())
            .any(|w| w == asn1::OID_ESS_ML_EXPANSION_HISTORY));
    }

    #[test]
    fn test_ml_data_contains_email() {
        let entry = MlData::new("ml@example.com");
        let der = entry.to_der();
        let email_bytes = b"ml@example.com";
        assert!(der.windows(email_bytes.len()).any(|w| w == email_bytes));
    }

    #[test]
    fn test_smime_capability_aes256_gcm() {
        let cap = SmimeCapability::aes256_gcm();
        let der = cap.to_der();
        assert_eq!(der[0], 0x30); // SEQUENCE
                                  // Should contain the AES-256-GCM OID
        assert!(der
            .windows(asn1::OID_AES256_GCM.len())
            .any(|w| w == asn1::OID_AES256_GCM));
    }

    #[test]
    fn test_smime_capabilities_default() {
        let caps = SmimeCapabilities::default_capabilities();
        assert_eq!(caps.capabilities.len(), 4);
        let der = caps.to_der();
        assert_eq!(der[0], 0x30);
        // Should contain all four OIDs
        assert!(der
            .windows(asn1::OID_AES256_GCM.len())
            .any(|w| w == asn1::OID_AES256_GCM));
        assert!(der
            .windows(asn1::OID_AES128_GCM.len())
            .any(|w| w == asn1::OID_AES128_GCM));
        assert!(der
            .windows(asn1::OID_AES256_CBC.len())
            .any(|w| w == asn1::OID_AES256_CBC));
        assert!(der
            .windows(asn1::OID_AES128_CBC.len())
            .any(|w| w == asn1::OID_AES128_CBC));
    }

    #[test]
    fn test_smime_capabilities_signed_attribute() {
        let caps = SmimeCapabilities::default_capabilities();
        let attr = caps.to_signed_attribute();
        assert_eq!(attr[0], 0x30);
        // Should contain the smimeCapabilities OID
        assert!(attr
            .windows(asn1::OID_SMIME_CAPABILITIES.len())
            .any(|w| w == asn1::OID_SMIME_CAPABILITIES));
    }

    #[test]
    fn test_smime_capabilities_preference_order() {
        let caps = SmimeCapabilities::default_capabilities();
        let der = caps.to_der();
        // AES-256-GCM OID should appear before AES-128-GCM OID
        let pos256gcm = der
            .windows(asn1::OID_AES256_GCM.len())
            .position(|w| w == asn1::OID_AES256_GCM)
            .unwrap();
        let pos128gcm = der
            .windows(asn1::OID_AES128_GCM.len())
            .position(|w| w == asn1::OID_AES128_GCM)
            .unwrap();
        assert!(
            pos256gcm < pos128gcm,
            "AES-256-GCM should be listed before AES-128-GCM"
        );
    }

    #[test]
    fn test_smime_capabilities_custom() {
        let caps = SmimeCapabilities::new()
            .push(SmimeCapability::aes256_gcm())
            .push(SmimeCapability::aes256_cbc());
        assert_eq!(caps.capabilities.len(), 2);
        let der = caps.to_der();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_encode_rfc822_general_names() {
        let gns = encode_rfc822_general_names("user@example.com");
        // Should be a SEQUENCE
        assert_eq!(gns[0], 0x30);
        // Should contain the email bytes
        let email = b"user@example.com";
        assert!(gns.windows(email.len()).any(|w| w == email));
        // Second element should be [1] IMPLICIT (0x81)
        assert!(gns.contains(&0x81));
    }
}
