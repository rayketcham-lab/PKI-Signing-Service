//! Authentication and security middleware.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use sha2::{Digest, Sha256};

use super::ldap::UserInfo;
use super::AppState;

/// Check whether the connecting client IP is in the trusted proxies list.
///
/// Returns `true` if the trusted_proxies list is empty (no restriction) or
/// if the client IP matches one of the trusted addresses.
fn is_trusted_proxy(client_ip: &str, trusted_proxies: &[String]) -> bool {
    if trusted_proxies.is_empty() {
        return true; // No restriction configured
    }
    trusted_proxies.iter().any(|proxy| proxy == client_ip)
}

/// Returns true only in debug builds (dev_mode allowed).
/// In release builds, dev_mode is always forced off.
pub fn is_dev_mode_allowed(config_dev_mode: bool) -> bool {
    if !config_dev_mode {
        return false;
    }
    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        tracing::warn!("dev_mode=true in config is IGNORED in release builds");
        false
    }
}

/// LDAP authentication middleware.
///
/// In dev mode (debug builds only): all requests are allowed without authentication.
/// In production mode (dev_mode=false or release build): LDAP headers are required.
/// When trusted_proxies is configured, only accepts LDAP headers from listed IPs.
/// Stores `UserInfo` as a request extension for downstream handlers.
pub async fn ldap_auth_middleware(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Dev mode: bypass LDAP entirely (debug builds only)
    if is_dev_mode_allowed(state.config.dev_mode) {
        return next.run(request).await;
    }

    // Production mode: require LDAP authentication
    if state.config.ldap.enabled {
        // #6 fix: Validate trusted proxy IP before accepting LDAP headers
        if !state.config.ldap.trusted_proxies.is_empty() {
            let client_ip = connect_info
                .as_ref()
                .map(|ci| ci.0.ip().to_string())
                .unwrap_or_default();
            if !is_trusted_proxy(&client_ip, &state.config.ldap.trusted_proxies) {
                tracing::warn!(
                    client_ip = %client_ip,
                    "LDAP auth rejected: request not from trusted proxy"
                );
                return not_found_response();
            }
        }

        let user_info =
            super::ldap::extract_user_from_headers(request.headers(), &state.config.ldap);

        match user_info {
            Some(info) => {
                request.extensions_mut().insert(info);
            }
            None => {
                return not_found_response();
            }
        }
    }

    next.run(request).await
}

/// Admin authentication middleware.
///
/// In dev mode (debug builds only): all admin requests are allowed (full access).
/// In production mode: admin endpoints are blocked entirely unless the user is in
/// the LDAP admin group or provides a valid bearer token.
/// When no auth mechanism is configured, admin access is DENIED by default.
/// Returns 404 (not 401) on auth failure to prevent endpoint enumeration.
pub async fn admin_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Dev mode: allow all admin access (debug builds only)
    if is_dev_mode_allowed(state.config.dev_mode) {
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

        return next.run(request).await;
    }

    // #10 fix: No auth mechanism configured — deny access by default
    tracing::warn!("Admin access denied: no authentication mechanism configured");
    not_found_response()
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
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_trusted_proxy_empty_list_allows_all() {
        assert!(is_trusted_proxy("192.168.1.1", &[]));
    }

    #[test]
    fn test_is_trusted_proxy_match() {
        let trusted = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
        assert!(is_trusted_proxy("10.0.0.1", &trusted));
        assert!(is_trusted_proxy("10.0.0.2", &trusted));
    }

    #[test]
    fn test_is_trusted_proxy_no_match() {
        let trusted = vec!["10.0.0.1".to_string()];
        assert!(!is_trusted_proxy("192.168.1.1", &trusted));
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn test_dev_mode_allowed_when_false() {
        assert!(!is_dev_mode_allowed(false));
    }

    #[test]
    fn test_dev_mode_allowed_in_debug() {
        // In test builds (debug_assertions is on), dev_mode=true should work
        #[cfg(debug_assertions)]
        assert!(is_dev_mode_allowed(true));
        #[cfg(not(debug_assertions))]
        assert!(!is_dev_mode_allowed(true));
    }
}
