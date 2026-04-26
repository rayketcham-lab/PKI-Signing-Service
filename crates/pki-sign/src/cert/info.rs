//! Certificate information parsing for the admin API.

use sha2::{Digest, Sha256};

/// Parsed certificate information for the admin API.
#[derive(Debug, serde::Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub chain_length: usize,
}

/// Extract the extensions SEQUENCE from a DER-encoded X.509 certificate.
///
/// Walks the TBSCertificate structure to find the [3] EXPLICIT extensions field.
/// Returns the content of the SEQUENCE OF Extension, or None if no extensions.
pub fn extract_extensions_from_cert(cert_der: &[u8]) -> Option<&[u8]> {
    use crate::pkcs7::asn1;

    let (_, cert_content) = asn1::parse_tlv(cert_der).ok()?;
    let (_, tbs_content) = asn1::parse_tlv(cert_content).ok()?;

    let mut pos = tbs_content;

    // Skip: version [0] EXPLICIT (if present)
    if !pos.is_empty() && pos[0] == 0xA0 {
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    // Skip: serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    for _ in 0..6 {
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    // Now pos should be at optional fields: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
    while !pos.is_empty() {
        let tag = pos[0];
        if tag == 0xA3 {
            // [3] EXPLICIT → contains SEQUENCE OF Extension
            let (_, explicit_content) = asn1::parse_tlv(pos).ok()?;
            let (_, seq_content) = asn1::parse_tlv(explicit_content).ok()?;
            return Some(seq_content);
        }
        pos = asn1::skip_tlv(pos).ok()?.1;
    }

    None
}

/// Parse X.509 certificate DER to extract displayable information.
pub fn parse_certificate_info(cert_der: &[u8]) -> CertificateInfo {
    use crate::pkcs7::asn1;

    let fingerprint = hex::encode(Sha256::digest(cert_der));

    // Try to parse the TBSCertificate fields
    let mut subject = String::from("(unknown)");
    let mut issuer = String::from("(unknown)");
    let mut serial_number = String::from("(unknown)");
    let mut not_before = String::from("(unknown)");
    let mut not_after = String::from("(unknown)");
    let mut key_usage = Vec::new();
    let mut extended_key_usage = Vec::new();

    if let Ok((_tag, cert_content)) = asn1::parse_tlv(cert_der) {
        // TBSCertificate SEQUENCE
        if let Ok((_tag, tbs_content)) = asn1::parse_tlv(cert_content) {
            let mut pos = tbs_content;

            // version [0] EXPLICIT
            if !pos.is_empty() && pos[0] == 0xA0 {
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // serialNumber INTEGER
            if let Ok((_tag, serial_content)) = asn1::parse_tlv(pos) {
                serial_number = hex::encode(serial_content);
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // signature AlgorithmIdentifier — skip
            if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                pos = remaining;
            }

            // issuer Name
            if let Ok((_tag, issuer_content)) = asn1::parse_tlv(pos) {
                issuer = extract_dn_string(issuer_content);
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // validity SEQUENCE
            if let Ok((_tag, validity_content)) = asn1::parse_tlv(pos) {
                if let Ok((_tag, nb_content)) = asn1::parse_tlv(validity_content) {
                    not_before = String::from_utf8_lossy(nb_content).to_string();
                    if let Ok((_tag, rest)) = asn1::skip_tlv(validity_content) {
                        if let Ok((_tag, na_content)) = asn1::parse_tlv(rest) {
                            not_after = String::from_utf8_lossy(na_content).to_string();
                        }
                    }
                }
                if let Ok((_tag, remaining)) = asn1::skip_tlv(pos) {
                    pos = remaining;
                }
            }

            // subject Name
            if let Ok((_tag, subject_content)) = asn1::parse_tlv(pos) {
                subject = extract_dn_string(subject_content);
            }
        }
    }

    // #14 fix: Parse extensions via proper ASN.1 traversal instead of byte scanning.
    // Walk through TBSCertificate extensions [3] EXPLICIT SEQUENCE OF Extension.
    if let Some(extensions_data) = extract_extensions_from_cert(cert_der) {
        // Iterate over each Extension SEQUENCE
        let mut ext_pos = extensions_data;
        while !ext_pos.is_empty() {
            let ext_content = match asn1::parse_tlv(ext_pos) {
                Ok((_, content)) => content,
                Err(_) => break,
            };
            ext_pos = match asn1::skip_tlv(ext_pos) {
                Ok((_, remaining)) => remaining,
                Err(_) => break,
            };

            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
            let (_, oid_bytes) = match asn1::parse_tlv(ext_content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut after_oid = match asn1::skip_tlv(ext_content) {
                Ok((_, r)) => r,
                Err(_) => continue,
            };

            // Skip optional BOOLEAN (critical)
            if !after_oid.is_empty() && after_oid[0] == 0x01 {
                after_oid = match asn1::skip_tlv(after_oid) {
                    Ok((_, r)) => r,
                    Err(_) => continue,
                };
            }

            // extnValue is OCTET STRING containing the extension-specific DER
            let (_, extn_value) = match asn1::parse_tlv(after_oid) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // keyUsage OID: 2.5.29.15
            if oid_bytes == [0x55, 0x1D, 0x0F] {
                // extnValue contains BIT STRING
                if let Ok((_, bit_content)) = asn1::parse_tlv(extn_value) {
                    if bit_content.len() >= 2 {
                        let bits = bit_content[1];
                        if bits & 0x80 != 0 {
                            key_usage.push("digitalSignature".into());
                        }
                        if bits & 0x40 != 0 {
                            key_usage.push("contentCommitment".into());
                        }
                        if bits & 0x20 != 0 {
                            key_usage.push("keyEncipherment".into());
                        }
                        if bits & 0x10 != 0 {
                            key_usage.push("dataEncipherment".into());
                        }
                        if bits & 0x08 != 0 {
                            key_usage.push("keyAgreement".into());
                        }
                        if bits & 0x04 != 0 {
                            key_usage.push("keyCertSign".into());
                        }
                        if bits & 0x02 != 0 {
                            key_usage.push("cRLSign".into());
                        }
                    }
                }
            }

            // extendedKeyUsage OID: 2.5.29.37
            if oid_bytes == [0x55, 0x1D, 0x25] {
                // extnValue contains SEQUENCE OF OID
                if let Ok((_, eku_seq)) = asn1::parse_tlv(extn_value) {
                    let mut eku_pos = eku_seq;
                    while !eku_pos.is_empty() {
                        if let Ok((_, eku_oid)) = asn1::parse_tlv(eku_pos) {
                            match eku_oid {
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03] => {
                                    extended_key_usage.push("codeSigning".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01] => {
                                    extended_key_usage.push("serverAuth".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04] => {
                                    extended_key_usage.push("emailProtection".into());
                                }
                                [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08] => {
                                    extended_key_usage.push("timeStamping".into());
                                }
                                _ => {}
                            }
                        }
                        eku_pos = match asn1::skip_tlv(eku_pos) {
                            Ok((_, r)) => r,
                            Err(_) => break,
                        };
                    }
                }
            }
        }
    }

    CertificateInfo {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        fingerprint_sha256: fingerprint,
        key_usage,
        extended_key_usage,
        chain_length: 0, // Caller should set this from chain_certs_der.len()
    }
}

/// Extract a human-readable DN string from DER-encoded Name (SEQUENCE of SET of SEQUENCE).
pub fn extract_dn_string(name_der: &[u8]) -> String {
    use crate::pkcs7::asn1;

    let mut parts = Vec::new();
    let mut pos = name_der;

    while !pos.is_empty() {
        // Each RDN is a SET — extract its content and advance past it
        let (set_tag, set_content) = match asn1::parse_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        let (_, remaining) = match asn1::skip_tlv(pos) {
            Ok(v) => v,
            Err(_) => break,
        };
        pos = remaining;
        let _ = set_tag;

        // Each SET contains one or more SEQUENCE (AttributeTypeAndValue)
        let mut set_pos = set_content;
        while !set_pos.is_empty() {
            let (_, seq_content) = match asn1::parse_tlv(set_pos) {
                Ok(v) => v,
                Err(_) => break,
            };
            let (_, seq_remaining) = match asn1::skip_tlv(set_pos) {
                Ok(v) => v,
                Err(_) => break,
            };
            set_pos = seq_remaining;

            // SEQUENCE: OID + value
            // parse_tlv on the OID returns (tag=0x06, oid_bytes)
            if let Ok((_oid_tag, oid_content)) = asn1::parse_tlv(seq_content) {
                // Get remainder after OID TLV
                let value_remaining = match asn1::skip_tlv(seq_content) {
                    Ok((_, rem)) => rem,
                    Err(_) => continue,
                };
                let attr_name = match oid_content {
                    [0x55, 0x04, 0x03] => "CN",
                    [0x55, 0x04, 0x06] => "C",
                    [0x55, 0x04, 0x07] => "L",
                    [0x55, 0x04, 0x08] => "ST",
                    [0x55, 0x04, 0x0A] => "O",
                    [0x55, 0x04, 0x0B] => "OU",
                    _ => "?",
                };
                if let Ok((_val_tag, value_content)) = asn1::parse_tlv(value_remaining) {
                    let value = String::from_utf8_lossy(value_content);
                    parts.push(format!("{attr_name}={value}"));
                }
            }
        }
    }

    if parts.is_empty() {
        "(unknown)".into()
    } else {
        parts.join(", ")
    }
}

/// Parse an ASN.1 UTCTime or GeneralizedTime string to a DateTime.
///
/// UTCTime (tag 0x17): "YYMMDDHHMMSSZ" — years 00-49 → 2000-2049, 50-99 → 1950-1999
/// GeneralizedTime (tag 0x18): "YYYYMMDDHHMMSSZ"
pub fn parse_asn1_time(tag: u8, s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::{NaiveDateTime, TimeZone};

    let s = s.trim_end_matches('Z');

    if tag == 0x17 {
        // UTCTime: YYMMDDHHMMSS
        if s.len() < 12 {
            return None;
        }
        let yy: i32 = s[0..2].parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        let mm: u32 = s[2..4].parse().ok()?;
        let dd: u32 = s[4..6].parse().ok()?;
        let hh: u32 = s[6..8].parse().ok()?;
        let mi: u32 = s[8..10].parse().ok()?;
        let ss: u32 = s[10..12].parse().ok()?;
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, mm, dd)?,
            chrono::NaiveTime::from_hms_opt(hh, mi, ss)?,
        );
        Some(chrono::Utc.from_utc_datetime(&naive))
    } else if tag == 0x18 {
        // GeneralizedTime: YYYYMMDDHHMMSS
        if s.len() < 14 {
            return None;
        }
        let year: i32 = s[0..4].parse().ok()?;
        let mm: u32 = s[4..6].parse().ok()?;
        let dd: u32 = s[6..8].parse().ok()?;
        let hh: u32 = s[8..10].parse().ok()?;
        let mi: u32 = s[10..12].parse().ok()?;
        let ss: u32 = s[12..14].parse().ok()?;
        let naive = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(year, mm, dd)?,
            chrono::NaiveTime::from_hms_opt(hh, mi, ss)?,
        );
        Some(chrono::Utc.from_utc_datetime(&naive))
    } else {
        None
    }
}
