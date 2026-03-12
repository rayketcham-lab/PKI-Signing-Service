//! Authentication and security middleware.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
};
use sha2::{Digest, Sha256};

use super::ldap::UserInfo;
use super::AppState;

/// LDAP authentication middleware.
///
/// In dev mode: all requests are allowed without authentication.
/// In production mode (dev_mode=false): LDAP headers are required.
/// Stores `UserInfo` as a request extension for downstream handlers.
pub async fn ldap_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Dev mode: bypass LDAP entirely
    if state.config.dev_mode {
        return next.run(request).await;
    }

    // Production mode: require LDAP authentication
    if state.config.ldap.enabled {
        let user_info =
            super::ldap::extract_user_from_headers(request.headers(), &state.config.ldap);

        match user_info {
            Some(info) => {
                request.extensions_mut().insert(info);
            }
            None => {
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
    }

    next.run(request).await
}

/// Admin authentication middleware.
///
/// In dev mode: all admin requests are allowed (full access).
/// In production mode (dev_mode=false): admin endpoints are blocked entirely
/// unless the user is in the LDAP admin group or provides a valid bearer token.
/// Returns 404 (not 401) on auth failure to prevent endpoint enumeration.
pub async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Dev mode: allow all admin access
    if state.config.dev_mode {
        return next.run(request).await;
    }

    // Production mode: enforce strict admin auth

    // If LDAP is enabled, check admin group membership
    if state.config.ldap.enabled {
        let authorized = request
            .extensions()
            .get::<UserInfo>()
            .map(|info| info.is_admin)
            .unwrap_or(false);

        if !authorized {
            // Try to extract from headers directly (admin routes may not have LDAP middleware upstream)
            let user_info =
                super::ldap::extract_user_from_headers(request.headers(), &state.config.ldap);
            let is_admin = user_info.map(|u| u.is_admin).unwrap_or(false);

            if !is_admin {
                return not_found_response();
            }
        }

        return next.run(request).await;
    }

    // Fallback: bearer token authentication
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
            return not_found_response();
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

/// Standard 404 response to prevent endpoint enumeration.
fn not_found_response() -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "error": "not_found",
            "message": "The requested endpoint was not found"
        })),
    )
        .into_response()
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
