//! Web API error type that maps `SignError` to HTTP responses.
//!
//! `AppError` is intentionally kept in the `web` module so that the core
//! library error type (`SignError`) has no dependency on the web framework.

use axum::response::IntoResponse;

use crate::error::SignError;

/// Web API error wrapper that implements [`IntoResponse`].
///
/// Wraps a [`SignError`] with a per-request UUID so clients can correlate
/// log entries with error responses without leaking internal details.
pub struct AppError {
    pub error: SignError,
    pub request_id: uuid::Uuid,
}

impl AppError {
    /// Create a new `AppError` wrapping the given `SignError`.
    ///
    /// A fresh UUID is generated for each call.
    #[must_use]
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

impl IntoResponse for AppError {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn test_app_error_from_sign_error() {
        let sign_err = SignError::InvalidPe("bad header".into());
        let app_err = AppError::from(sign_err);
        assert!(matches!(app_err.error, SignError::InvalidPe(_)));
    }

    #[test]
    fn test_app_error_into_response_unauthorized_returns_404() {
        // Endpoint-enumeration protection: auth failures must surface as 404
        let app_err = AppError::new(SignError::Unauthorized("bad token".into()));
        let response = app_err.into_response();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Unauthorized errors must return 404 to prevent endpoint enumeration"
        );
    }

    #[test]
    fn test_app_error_into_response_invalid_pe_returns_400() {
        let app_err = AppError::new(SignError::InvalidPe("truncated".into()));
        let response = app_err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
