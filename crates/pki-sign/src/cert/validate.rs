//! Certificate validation for signing operations.

use crate::cert::info::parse_asn1_time;
use crate::error::{SignError, SignResult};

/// RFC 5280 §4.2.1.3: Validate that a signing certificate's keyUsage extension,
/// if present, includes the digitalSignature bit (bit 0).
///
/// If the extension is absent, we permit signing (many certs omit keyUsage).
/// If present, digitalSignature MUST be set for code signing.
pub fn validate_key_usage_for_signing(cert_der: &[u8]) -> SignResult<()> {
    use crate::pkcs7::asn1;

    // keyUsage OID: 2.5.29.15
    let key_usage_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x0F];

    // Search for the keyUsage extension OID in the certificate DER.
    // If not found, the extension is absent — signing is permitted.
    let Some(oid_pos) = cert_der
        .windows(key_usage_oid.len())
        .position(|w| w == key_usage_oid)
    else {
        return Ok(()); // No keyUsage extension — permitted
    };

    // After the OID, we expect: [BOOLEAN critical], OCTET STRING { BIT STRING { bits } }
    // Scan forward from the OID to find the BIT STRING containing the usage bits.
    let after_oid = &cert_der[oid_pos + key_usage_oid.len()..];

    // Skip optional BOOLEAN (critical flag) and OCTET STRING wrapper to find BIT STRING
    for window_start in 0..after_oid.len().min(20) {
        if after_oid[window_start] == 0x03 && window_start + 3 < after_oid.len() {
            // BIT STRING found — tag 0x03, then length, then unused-bits count, then value
            let (_, bit_content) = match asn1::parse_tlv(&after_oid[window_start..]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if bit_content.is_empty() {
                continue;
            }
            // bit_content[0] = number of unused bits, bit_content[1..] = key usage flags
            if bit_content.len() >= 2 {
                let usage_byte = bit_content[1];
                // digitalSignature is bit 0 (MSB) = 0x80
                if usage_byte & 0x80 == 0 {
                    return Err(SignError::Certificate(
                        "RFC 5280 §4.2.1.3: signing certificate keyUsage does not include digitalSignature".into(),
                    ));
                }
                return Ok(());
            }
        }
    }

    // Could not parse keyUsage — permit signing (defensive)
    Ok(())
}

/// RFC 5280 §4.2.1.12: Validate that a signing certificate's extendedKeyUsage
/// extension, if present, includes the id-kp-codeSigning OID (1.3.6.1.5.5.7.3.3).
///
/// If the extension is absent, we permit signing (many CA certs omit EKU).
/// If present, codeSigning MUST be listed for code signing operations.
pub fn validate_eku_for_code_signing(cert_der: &[u8]) -> SignResult<()> {
    // extendedKeyUsage OID: 2.5.29.37
    let eku_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x25];

    // id-kp-codeSigning OID value bytes: 1.3.6.1.5.5.7.3.3
    let code_signing_oid_value: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

    // anyExtendedKeyUsage OID value bytes: 2.5.29.37.0
    let any_eku_oid_value: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    // Search for the EKU extension OID in the certificate DER.
    let Some(oid_pos) = cert_der.windows(eku_oid.len()).position(|w| w == eku_oid) else {
        return Ok(()); // No EKU extension — permitted
    };

    // Scan the region after the EKU OID for the codeSigning or anyExtendedKeyUsage OID
    let search_region = &cert_der[oid_pos..cert_der.len().min(oid_pos + 200)];

    let has_code_signing = search_region
        .windows(code_signing_oid_value.len())
        .any(|w| w == code_signing_oid_value);

    let has_any_eku = search_region
        .windows(any_eku_oid_value.len())
        .any(|w| w == any_eku_oid_value);

    if has_code_signing || has_any_eku {
        return Ok(());
    }

    Err(SignError::MissingCodeSigningEku)
}

/// Validate that a certificate's validity period covers the current time.
///
/// Parses the notBefore and notAfter fields from the TBSCertificate and checks
/// that the current time falls within this window. Supports both UTCTime and
/// GeneralizedTime encodings per RFC 5280 §4.1.2.5.
pub fn validate_cert_validity(cert_der: &[u8]) -> SignResult<()> {
    use crate::pkcs7::asn1;

    // Parse: Certificate → TBSCertificate → fields
    let (_, cert_content) = asn1::parse_tlv(cert_der)
        .map_err(|e| SignError::Certificate(format!("Failed to parse certificate: {e}")))?;
    let (_, tbs_content) = asn1::parse_tlv(cert_content)
        .map_err(|e| SignError::Certificate(format!("Failed to parse TBSCertificate: {e}")))?;

    let mut pos = tbs_content;

    // Skip: version [0] EXPLICIT (if present)
    if !pos.is_empty() && pos[0] == 0xA0 {
        if let Ok((_, remaining)) = asn1::skip_tlv(pos) {
            pos = remaining;
        }
    }

    // Skip: serialNumber, signature (AlgorithmIdentifier), issuer
    for _ in 0..3 {
        if let Ok((_, remaining)) = asn1::skip_tlv(pos) {
            pos = remaining;
        }
    }

    // Validity SEQUENCE { notBefore, notAfter }
    let (_, validity_content) = asn1::parse_tlv(pos)
        .map_err(|e| SignError::Certificate(format!("Failed to parse validity: {e}")))?;

    // Parse notBefore
    let (nb_tag, nb_content) = asn1::parse_tlv(validity_content)
        .map_err(|e| SignError::Certificate(format!("Failed to parse notBefore: {e}")))?;
    let nb_str = std::str::from_utf8(nb_content).unwrap_or("");
    let not_before = parse_asn1_time(nb_tag, nb_str);

    // Parse notAfter
    let (_, rest) = asn1::skip_tlv(validity_content)
        .map_err(|e| SignError::Certificate(format!("Failed to skip notBefore: {e}")))?;
    let (na_tag, na_content) = asn1::parse_tlv(rest)
        .map_err(|e| SignError::Certificate(format!("Failed to parse notAfter: {e}")))?;
    let na_str = std::str::from_utf8(na_content).unwrap_or("");
    let not_after = parse_asn1_time(na_tag, na_str);

    let now = chrono::Utc::now();

    if let Some(nb) = not_before {
        if now < nb {
            return Err(SignError::Certificate(format!(
                "Certificate is not yet valid (notBefore: {nb})"
            )));
        }
    }

    if let Some(na) = not_after {
        if now > na {
            return Err(SignError::Certificate(format!(
                "Certificate has expired (notAfter: {na})"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Key Usage Validation Tests ───

    #[test]
    fn test_key_usage_no_extension_permits_signing() {
        // A minimal cert without any extensions — should be allowed
        let cert = build_minimal_test_cert(None);
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    #[test]
    fn test_key_usage_digital_signature_set() {
        // Cert with keyUsage = digitalSignature (bit 0 = 0x80) — should be allowed
        let ku_ext = build_key_usage_extension(0x80, true); // digitalSignature
        let cert = build_minimal_test_cert(Some(&ku_ext));
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    #[test]
    fn test_key_usage_key_cert_sign_only_rejected() {
        // Cert with keyUsage = keyCertSign only (bit 5 = 0x04) — should be rejected
        let ku_ext = build_key_usage_extension(0x04, true); // keyCertSign only
        let cert = build_minimal_test_cert(Some(&ku_ext));
        let result = validate_key_usage_for_signing(&cert);
        assert!(result.is_err(), "keyCertSign-only cert should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("digitalSignature"),
            "Error should mention digitalSignature: {}",
            err
        );
    }

    #[test]
    fn test_key_usage_both_digital_sig_and_cert_sign() {
        // Cert with keyUsage = digitalSignature + keyCertSign (0x84) — should be allowed
        let ku_ext = build_key_usage_extension(0x84, true);
        let cert = build_minimal_test_cert(Some(&ku_ext));
        assert!(validate_key_usage_for_signing(&cert).is_ok());
    }

    /// Build a minimal DER-encoded certificate with optional extensions.
    fn build_minimal_test_cert(extensions_der: Option<&[u8]>) -> Vec<u8> {
        use crate::pkcs7::asn1;
        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial = asn1::encode_integer_value(1);
        let algo = asn1::SHA256_ALGORITHM_ID.to_vec();
        let name = asn1::encode_sequence(&[&asn1::encode_set(&asn1::encode_sequence(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            &[0x0C, 0x04, 0x54, 0x65, 0x73, 0x74], // UTF8String "Test"
        ]))]);
        let validity =
            asn1::encode_sequence(&[&asn1::encode_utc_time_now(), &asn1::encode_utc_time_now()]);
        let spki = asn1::encode_sequence(&[
            &algo,
            &[0x03, 0x03, 0x00, 0x04, 0x04][..], // BIT STRING (stub public key)
        ]);

        let mut tbs_parts: Vec<&[u8]> =
            vec![&version, &serial, &algo, &name, &validity, &name, &spki];
        let ext_wrapper;
        if let Some(ext) = extensions_der {
            ext_wrapper = asn1::encode_explicit_tag(3, &asn1::encode_sequence(&[ext]));
            tbs_parts.push(&ext_wrapper);
        }
        let tbs = asn1::encode_sequence(&tbs_parts);
        let sig = [0x03, 0x03, 0x00, 0x00, 0x00]; // BIT STRING (stub signature)
        asn1::encode_sequence(&[&tbs, &algo, &sig])
    }

    /// Build a DER-encoded keyUsage extension.
    fn build_key_usage_extension(usage_bits: u8, critical: bool) -> Vec<u8> {
        use crate::pkcs7::asn1;
        // keyUsage OID: 2.5.29.15
        let oid = &[0x06, 0x03, 0x55, 0x1D, 0x0F];
        let critical_bool = if critical {
            vec![0x01, 0x01, 0xFF] // BOOLEAN TRUE
        } else {
            vec![]
        };
        // BIT STRING: tag=0x03, len=0x02, unused_bits=0x00, value=usage_bits
        let bit_string = vec![0x03, 0x02, 0x00, usage_bits];
        // OCTET STRING wrapping the BIT STRING
        let octet_wrapper = asn1::encode_octet_string(&bit_string);
        let mut parts: Vec<&[u8]> = vec![oid];
        if !critical_bool.is_empty() {
            parts.push(&critical_bool);
        }
        parts.push(&octet_wrapper);
        asn1::encode_sequence(&parts)
    }

    /// Build a DER-encoded extendedKeyUsage extension with the given EKU OIDs.
    fn build_eku_extension(eku_oids: &[&[u8]]) -> Vec<u8> {
        use crate::pkcs7::asn1;
        // extendedKeyUsage OID: 2.5.29.37
        let ext_oid = &[0x06, 0x03, 0x55, 0x1D, 0x25];
        // Build SEQUENCE OF OBJECT IDENTIFIER
        let mut eku_seq_content = Vec::new();
        for oid_value in eku_oids {
            // Encode as OID TLV
            eku_seq_content.push(0x06);
            eku_seq_content.push(oid_value.len() as u8);
            eku_seq_content.extend_from_slice(oid_value);
        }
        let _eku_seq = asn1::encode_sequence(
            &eku_seq_content
                .chunks(1)
                .collect::<Vec<_>>()
                .iter()
                .map(|_| &[][..])
                .collect::<Vec<_>>(),
        );
        // Simpler: just build the SEQUENCE manually
        let mut seq = vec![0x30];
        if eku_seq_content.len() < 0x80 {
            seq.push(eku_seq_content.len() as u8);
        } else {
            seq.push(0x81);
            seq.push(eku_seq_content.len() as u8);
        }
        seq.extend_from_slice(&eku_seq_content);

        let octet_wrapper = asn1::encode_octet_string(&seq);
        asn1::encode_sequence(&[ext_oid, &octet_wrapper])
    }

    // ─── EKU Validation Tests ───

    // id-kp-codeSigning OID value: 1.3.6.1.5.5.7.3.3
    const CODE_SIGNING_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    // id-kp-serverAuth OID value: 1.3.6.1.5.5.7.3.1
    const SERVER_AUTH_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    // id-kp-emailProtection OID value: 1.3.6.1.5.5.7.3.4
    const EMAIL_PROTECTION_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    // anyExtendedKeyUsage OID value: 2.5.29.37.0
    const ANY_EKU_OID: &[u8] = &[0x55, 0x1D, 0x25, 0x00];

    #[test]
    fn test_eku_no_extension_permits_signing() {
        let cert = build_minimal_test_cert(None);
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_code_signing_present() {
        let eku_ext = build_eku_extension(&[CODE_SIGNING_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_server_auth_only_rejected() {
        let eku_ext = build_eku_extension(&[SERVER_AUTH_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        let result = validate_eku_for_code_signing(&cert);
        assert!(
            result.is_err(),
            "serverAuth-only EKU should be rejected for code signing"
        );
        match result.unwrap_err() {
            SignError::MissingCodeSigningEku => {}
            other => panic!("Expected MissingCodeSigningEku, got: {:?}", other),
        }
    }

    #[test]
    fn test_eku_multiple_with_code_signing() {
        let eku_ext =
            build_eku_extension(&[SERVER_AUTH_OID, CODE_SIGNING_OID, EMAIL_PROTECTION_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }

    #[test]
    fn test_eku_any_extended_key_usage_permits() {
        let eku_ext = build_eku_extension(&[ANY_EKU_OID]);
        let cert = build_minimal_test_cert(Some(&eku_ext));
        assert!(validate_eku_for_code_signing(&cert).is_ok());
    }
}
