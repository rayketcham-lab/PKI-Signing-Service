//! Error types for the spork-sign crate.

use thiserror::Error;

/// Result type alias for spork-sign operations.
pub type SignResult<T> = Result<T, SignError>;

/// Errors that can occur during code signing operations.
#[derive(Debug, Error)]
pub enum SignError {
    /// The file is not a valid PE executable.
    #[error("Invalid PE file: {0}")]
    InvalidPe(String),

    /// The file is already signed and re-signing is not allowed.
    #[error("File is already signed: {0}")]
    AlreadySigned(String),

    /// Failed to load PFX/PKCS#12 certificate.
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// The certificate does not have the Code Signing EKU.
    #[error("Certificate missing Code Signing EKU")]
    MissingCodeSigningEku,

    /// Failed to compute Authenticode hash.
    #[error("Hash computation failed: {0}")]
    Hash(String),

    /// Failed to build CMS/PKCS#7 signature.
    #[error("PKCS#7 construction failed: {0}")]
    Pkcs7(String),

    /// Failed to embed signature in PE file.
    #[error("Signature embedding failed: {0}")]
    Embed(String),

    /// Timestamp authority request failed.
    #[error("Timestamping failed: {0}")]
    Timestamp(String),

    /// All configured TSA servers failed.
    #[error("All timestamp servers failed")]
    AllTsaFailed,

    /// PowerShell script signing error.
    #[error("PowerShell signing error: {0}")]
    PowerShell(String),

    /// File type is not supported for signing.
    #[error("Unsupported file type: {0}")]
    UnsupportedFileType(String),

    /// File exceeds maximum allowed size.
    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Authentication/authorization error.
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Web API error wrapper that implements `IntoResponse`.
pub struct AppError {
    pub error: SignError,
    pub request_id: uuid::Uuid,
}

impl AppError {
    pub fn new(error: SignError) -> Self {
        Self {
            error,
            request_id: uuid::Uuid::new_v4(),
        }
    }
}

impl From<SignError> for AppError {
    fn from(error: SignError) -> Self {
        Self::new(error)
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, code) = match &self.error {
            SignError::InvalidPe(_) => (StatusCode::BAD_REQUEST, "invalid_pe"),
            SignError::AlreadySigned(_) => (StatusCode::BAD_REQUEST, "already_signed"),
            SignError::UnsupportedFileType(_) => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_type")
            }
            SignError::FileTooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "file_too_large"),
            SignError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            // Return 404 for auth failures to prevent endpoint enumeration
            SignError::Unauthorized(_) => (StatusCode::NOT_FOUND, "not_found"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let body = serde_json::json!({
            "error": code,
            "message": self.error.to_string(),
            "request_id": self.request_id.to_string(),
        });

        (status, axum::Json(body)).into_response()
    }
}
