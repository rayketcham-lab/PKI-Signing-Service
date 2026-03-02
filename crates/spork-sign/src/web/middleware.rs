//! Authentication and security middleware.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use super::AppState;

/// Admin authentication middleware.
///
/// Returns 404 (not 401) on auth failure to prevent endpoint enumeration.
/// If no admin token hash is configured, all requests are allowed (development mode).
pub async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(ref expected_hash) = state.config.admin_token_hash {
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|token| {
                let hash = hex::encode(Sha256::digest(token.as_bytes()));
                constant_time_eq(hash.as_bytes(), expected_hash.as_bytes())
            })
            .unwrap_or(false);

        if !authorized {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": "not_found",
                    "message": "The requested endpoint was not found"
                })),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Security headers middleware.
///
/// Adds standard security headers to all responses and removes the Server header.
pub async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(
        "X-XSS-Protection"
            .parse::<axum::http::HeaderName>()
            .unwrap(),
        "0".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.remove(header::SERVER);

    response
}

/// Constant-time byte slice comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
