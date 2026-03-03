//! CMS/PKCS#7 SignedData construction for Authenticode.
//!
//! Builds the PKCS#7 SignedData structure that wraps the Authenticode
//! signature. This is the core cryptographic envelope that contains:
//!
//! - The SPC_INDIRECT_DATA_CONTENT (Authenticode-specific content)
//! - Signed attributes (content type, message digest, signing time)
//! - The RSA/ECDSA signature over the signed attributes
//! - The signing certificate and chain
//! - Optional unsigned attributes (RFC 3161 timestamp token)
//!
//! ## Key OIDs
//!
//! - `1.2.840.113549.1.7.2` — SignedData
//! - `1.3.6.1.4.1.311.2.1.4` — SPC_INDIRECT_DATA_CONTENT
//! - `1.3.6.1.4.1.311.2.1.15` — SPC_PE_IMAGE_DATAOBJ
//! - `1.2.840.113549.1.9.3` — contentType (signed attr)
//! - `1.2.840.113549.1.9.4` — messageDigest (signed attr)
//! - `1.2.840.113549.1.9.5` — signingTime (signed attr)
//! - `1.2.840.113549.1.9.6` — counterSignature (unsigned attr, legacy)
//! - `1.2.840.113549.1.9.16.2.14` — id-smime-aa-timeStampToken (RFC 3161)

pub mod asn1;
pub mod builder;
pub mod digested;
pub mod ecdh;
pub mod enveloped;
pub mod ess;
pub mod kem;

pub use builder::{
    build_counter_signer_info, CmsSignerInfo, ContentHints, DigestAlgorithm, Pkcs7Builder,
    SignedDataBuilder, SigningAlgorithm,
};

pub use digested::{verify_digested_data, DigestedDataBuilder, DigestedDataInfo};

pub use crate::crypto::rsa_oaep::OaepHash;
pub use enveloped::{
    decrypt_enveloped_data, decrypt_enveloped_data_ecdh, decrypt_enveloped_data_kem,
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyAgreeRecipientInfo, KeyTransRecipientInfo,
};

pub use ecdh::{EcdhCurve, KeyWrapAlgorithm};

pub use kem::{
    build_kem_recipient_info, decrypt_kem_cek, KemAlgorithm, KemKdf, KemRecipientInfo,
    ParsedKemRecipientInfo,
};

pub use ess::{
    ContentIdentifier, MLExpansionHistory, MlData, ReceiptRequest, ReceiptsFrom,
    SecurityClassification, SecurityLabel, SmimeCapabilities, SmimeCapability,
};
