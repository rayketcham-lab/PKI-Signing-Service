//! HTTP server for the RFC 3161 Time-Stamp Authority.
//!
//! Exposes two routes:
//! - `POST /timestamp` — RFC 3161 timestamp request (application/timestamp-query)
//! - `GET  /health`    — Health check (returns 200 JSON)
//!
//! ## Usage
//!
//! ```bash
//! spork-sign tsa serve \
//!     --cert tsa.pem \
//!     --key  tsa.key \
//!     --bind 0.0.0.0 \
//!     --port 3318
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::routing::{get, post};
use axum::Router;
use pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use signature::Signer as _;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::error::{SignError, SignResult};
use crate::tsa_server::{
    handle_timestamp_request, TsaServer, TsaServerConfig, TsaSignatureAlgorithm,
};

/// Configuration for the TSA HTTP server.
#[derive(Debug, Clone)]
pub struct TsaHttpConfig {
    /// Bind address.
    pub bind: String,
    /// Port (default 3318, IANA assigned for TSP over HTTP).
    pub port: u16,
    /// Path to the TSA signing certificate (PEM).
    pub cert_path: std::path::PathBuf,
    /// Path to the TSA signing key (PEM PKCS#8 or SEC1).
    pub key_path: std::path::PathBuf,
    /// Optional chain certificate(s) PEM path.
    pub chain_path: Option<std::path::PathBuf>,
    /// TSA policy OID (dotted notation).
    pub policy_oid: String,
    /// Accuracy in seconds.
    pub accuracy_secs: u32,
}

impl Default for TsaHttpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 3318,
            cert_path: std::path::PathBuf::from("tsa.pem"),
            key_path: std::path::PathBuf::from("tsa.key"),
            chain_path: None,
            policy_oid: "1.3.6.1.4.1.56266.1.30.1".into(),
            accuracy_secs: 1,
        }
    }
}

/// Health check handler — GET /health
async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(serde_json::json!({
        "status": "ok",
        "service": "spork-tsa",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// 405 Method Not Allowed handler for non-POST requests on /timestamp.
async fn method_not_allowed() -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [
            (header::CONTENT_TYPE, "text/plain"),
            (header::ALLOW, "POST"),
        ],
        "TSA endpoint only accepts POST requests per RFC 3161",
    )
        .into_response()
}

/// Middleware that assigns or propagates an `X-Request-Id` header.
async fn request_id_middleware(request: Request, next: Next) -> axum::response::Response {
    let id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':'
                })
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    tracing::debug!(request_id = %id, method = %request.method(), uri = %request.uri(), "TSA request");
    let mut response = next.run(request).await;
    if let Ok(val) = id.parse() {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

/// Build the axum router for the TSA server.
pub fn build_tsa_router(tsa: Arc<TsaServer>) -> Router {
    Router::new()
        .route(
            "/timestamp",
            post(handle_timestamp_request)
                .get(method_not_allowed)
                .put(method_not_allowed)
                .delete(method_not_allowed),
        )
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(request_id_middleware))
        .layer(axum::middleware::map_response(
            |mut response: axum::response::Response| async move {
                let headers = response.headers_mut();
                headers.insert(
                    "X-Content-Type-Options",
                    "nosniff".parse().expect("static header"),
                );
                response
            },
        ))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024)) // 256KB — TSA requests are small
        .with_state(tsa)
}

/// Load a DER-encoded certificate from a PEM file.
fn load_cert_der(path: &Path) -> SignResult<Vec<u8>> {
    let pem = std::fs::read_to_string(path).map_err(|e| {
        SignError::Certificate(format!("Failed to read cert {}: {}", path.display(), e))
    })?;

    // Find the certificate PEM block
    if let Some(pem_block) = rustls_pemfile::certs(&mut pem.as_bytes()).next() {
        let der = pem_block.map_err(|e| {
            SignError::Certificate(format!(
                "Failed to parse cert PEM {}: {}",
                path.display(),
                e
            ))
        })?;
        return Ok(der.to_vec());
    }

    Err(SignError::Certificate(format!(
        "No certificate found in {}",
        path.display()
    )))
}

/// Load chain certificates (all certs) from a PEM file.
fn load_chain_der(path: &Path) -> SignResult<Vec<Vec<u8>>> {
    let pem = std::fs::read_to_string(path).map_err(|e| {
        SignError::Certificate(format!("Failed to read chain {}: {}", path.display(), e))
    })?;

    let mut certs = Vec::new();
    for pem_block in rustls_pemfile::certs(&mut pem.as_bytes()) {
        let der = pem_block.map_err(|e| {
            SignError::Certificate(format!(
                "Failed to parse chain PEM {}: {}",
                path.display(),
                e
            ))
        })?;
        certs.push(der.to_vec());
    }

    Ok(certs)
}

/// Supported signing key types for TSA.
enum TsaSigningKey {
    Rsa(Box<RsaPrivateKey>),
    EcP256(p256::ecdsa::SigningKey),
    EcP384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

/// Load a private key from a PEM file (PKCS#8 or SEC1 format, RSA or EC).
fn load_signing_key(path: &Path) -> SignResult<TsaSigningKey> {
    let pem_str = std::fs::read_to_string(path).map_err(|e| {
        SignError::Certificate(format!("Failed to read key {}: {}", path.display(), e))
    })?;

    // Try RSA PKCS#8 first
    if let Ok(rsa_key) = RsaPrivateKey::from_pkcs8_pem(&pem_str) {
        return Ok(TsaSigningKey::Rsa(Box::new(rsa_key)));
    }

    // Try EC P-256 PKCS#8
    if let Ok(ec_key) = <p256::SecretKey as DecodePrivateKey>::from_pkcs8_pem(&pem_str) {
        return Ok(TsaSigningKey::EcP256(p256::ecdsa::SigningKey::from(
            &ec_key,
        )));
    }

    // Try EC P-384 PKCS#8
    if let Ok(ec_key) = <p384::SecretKey as DecodePrivateKey>::from_pkcs8_pem(&pem_str) {
        return Ok(TsaSigningKey::EcP384(p384::ecdsa::SigningKey::from(
            &ec_key,
        )));
    }

    // Try Ed25519 PKCS#8
    if pem_str.contains("BEGIN PRIVATE KEY") {
        let b64: String = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        if let Ok(der) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64) {
            // Ed25519 PKCS#8 has OID 1.3.101.112 near the start
            if der.len() >= 16 && der.windows(3).any(|w| w == [0x2B, 0x65, 0x70]) {
                // Extract 32-byte private key from PKCS#8 (last 32 bytes of the OCTET STRING)
                if let Ok(signing_key) = ed25519_dalek::SigningKey::from_pkcs8_der(&der) {
                    return Ok(TsaSigningKey::Ed25519(signing_key));
                }
            }
        }
    }

    // Try EC P-256 SEC1 (from PEM header) — decode base64 between headers manually
    if pem_str.contains("BEGIN EC PRIVATE KEY") {
        // Extract base64 content between PEM headers
        let b64: String = pem_str
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .map_err(|e| {
                SignError::Certificate(format!(
                    "Failed to decode SEC1 PEM from {}: {}",
                    path.display(),
                    e
                ))
            })?;
        // Try P-384 SEC1 first (longer key), then P-256
        if let Ok(secret_key) = p384::SecretKey::from_sec1_der(&der) {
            return Ok(TsaSigningKey::EcP384(p384::ecdsa::SigningKey::from(
                &secret_key,
            )));
        }
        let secret_key = p256::SecretKey::from_sec1_der(&der).map_err(|e| {
            SignError::Certificate(format!(
                "Failed to parse SEC1 EC key from {}: {}",
                path.display(),
                e
            ))
        })?;
        return Ok(TsaSigningKey::EcP256(p256::ecdsa::SigningKey::from(
            &secret_key,
        )));
    }

    Err(SignError::Certificate(format!(
        "Unsupported key format in {}: expected RSA, EC P-256/P-384, or Ed25519 in PKCS#8 or SEC1 format",
        path.display()
    )))
}

/// Start the TSA HTTP server.
///
/// Loads signing certificate and key, creates a `TsaServer`, and serves
/// RFC 3161 timestamp requests on `POST /timestamp`.
pub async fn run_tsa_server(config: TsaHttpConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Load signing certificate
    let signer_cert_der = load_cert_der(&config.cert_path)?;
    info!(path = %config.cert_path.display(), "Loaded TSA signing certificate");

    // Load chain certificates (optional)
    let chain_certs_der = if let Some(ref chain_path) = config.chain_path {
        let chain = load_chain_der(chain_path)?;
        info!(
            path = %chain_path.display(),
            count = chain.len(),
            "Loaded chain certificates"
        );
        chain
    } else {
        Vec::new()
    };

    // Load signing key (RSA or EC)
    let signing_key = load_signing_key(&config.key_path)?;
    let (key_type, sig_algo) = match &signing_key {
        TsaSigningKey::Rsa(_) => ("RSA", TsaSignatureAlgorithm::RsaSha256),
        TsaSigningKey::EcP256(_) => ("ECDSA P-256", TsaSignatureAlgorithm::EcdsaP256Sha256),
        TsaSigningKey::EcP384(_) => ("ECDSA P-384", TsaSignatureAlgorithm::EcdsaP384Sha384),
        TsaSigningKey::Ed25519(_) => ("Ed25519", TsaSignatureAlgorithm::Ed25519),
    };
    info!(path = %config.key_path.display(), algorithm = key_type, "Loaded TSA signing key");

    // Build the signing function based on key type
    let sign_fn: crate::tsa_server::SignFn = match signing_key {
        TsaSigningKey::Rsa(rsa_key) => Box::new(move |data: &[u8]| {
            let signing_key = SigningKey::<Sha256>::new((*rsa_key).clone());
            let signature = signing_key.sign(data);
            let sig_bytes: Box<[u8]> = signature.into();
            Ok(sig_bytes.into_vec())
        }),
        TsaSigningKey::EcP256(ec_key) => Box::new(move |data: &[u8]| {
            use p256::ecdsa::signature::Signer;
            let signature: p256::ecdsa::Signature = ec_key.sign(data);
            Ok(signature.to_der().as_bytes().to_vec())
        }),
        TsaSigningKey::EcP384(ec_key) => Box::new(move |data: &[u8]| {
            use p384::ecdsa::signature::Signer;
            let signature: p384::ecdsa::Signature = ec_key.sign(data);
            Ok(signature.to_der().as_bytes().to_vec())
        }),
        TsaSigningKey::Ed25519(ed_key) => Box::new(move |data: &[u8]| {
            use ed25519_dalek::Signer;
            let signature = ed_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }),
    };

    // Build TsaServerConfig
    let tsa_config = TsaServerConfig {
        policy_oid: config.policy_oid.clone(),
        accuracy_secs: config.accuracy_secs,
        include_certs: true,
        ..TsaServerConfig::default()
    };

    // Create TsaServer
    let tsa = Arc::new(TsaServer::new(
        tsa_config,
        signer_cert_der,
        chain_certs_der,
        sign_fn,
        sig_algo,
    ));

    // Build router
    let router = build_tsa_router(tsa);

    // Bind and serve
    let bind_addr = format!("{}:{}", config.bind, config.port);
    let socket_addr: SocketAddr = bind_addr
        .parse()
        .map_err(|e| SignError::Config(format!("Invalid bind address '{bind_addr}': {e}")))?;

    info!(%socket_addr, "Starting TSA HTTP server");
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use sha2::Digest;
    use tower::ServiceExt;

    use crate::pkcs7::asn1;
    use crate::tsa_server::{TsaServer, TsaServerConfig, TsaSignatureAlgorithm};

    /// Build a minimal test TsaServer (same approach as tsa_server tests).
    fn make_test_tsa_server() -> Arc<TsaServer> {
        // Minimal self-signed cert DER for testing (reused from tsa_server tests)
        let cert = make_test_cert_der();

        let sign_fn: crate::tsa_server::SignFn = Box::new(|data: &[u8]| {
            // Test signer: SHA-256 of input as fake "signature"
            Ok(Sha256::digest(data).to_vec())
        });

        Arc::new(TsaServer::new(
            TsaServerConfig::default(),
            cert,
            vec![],
            sign_fn,
            TsaSignatureAlgorithm::RsaSha256,
        ))
    }

    fn make_test_cert_der() -> Vec<u8> {
        // OID constants for test cert
        const OID_SHA256_WITH_RSA: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];

        fn encode_utf8_string(s: &str) -> Vec<u8> {
            let bytes = s.as_bytes();
            let mut result = vec![0x0C];
            result.extend(asn1::encode_length(bytes.len()));
            result.extend_from_slice(bytes);
            result
        }

        let version = asn1::encode_explicit_tag(0, &asn1::encode_integer_value(2));
        let serial = asn1::encode_integer_value(12345);
        let sig_algo = asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]]);
        let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let cn_value = encode_utf8_string("Test TSA");
        let rdn_attr = asn1::encode_sequence(&[cn_oid, &cn_value]);
        let rdn_set = asn1::encode_set(&rdn_attr);
        let issuer = asn1::encode_sequence(&[&rdn_set]);
        let not_before = asn1::encode_utc_time_now();
        let not_after = asn1::encode_utc_time_now();
        let validity = asn1::encode_sequence(&[&not_before, &not_after]);
        let subject = issuer.clone();
        let spki = asn1::encode_sequence(&[
            &asn1::encode_sequence(&[OID_SHA256_WITH_RSA, &[0x05, 0x00]]),
            &[0x03, 0x02, 0x00, 0x00][..],
        ]);
        let tbs = asn1::encode_sequence(&[
            &version, &serial, &sig_algo, &issuer, &validity, &subject, &spki,
        ]);
        let cert_sig = vec![0x03, 0x02, 0x00, 0x00];
        asn1::encode_sequence(&[&tbs, &sig_algo, &cert_sig])
    }

    fn build_timestamp_req_bytes() -> Vec<u8> {
        let digest = Sha256::digest(b"hello world");
        let version = asn1::encode_integer_value(1);
        let message_imprint = asn1::encode_sequence(&[
            &asn1::SHA256_ALGORITHM_ID,
            &asn1::encode_octet_string(&digest),
        ]);
        let cert_req = vec![0x01, 0x01, 0xFF]; // BOOLEAN TRUE
        asn1::encode_sequence(&[&version, &message_imprint, &cert_req])
    }

    #[tokio::test]
    async fn test_health_check_returns_200() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_returns_json() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "Expected JSON content-type, got: {content_type}"
        );
    }

    #[tokio::test]
    async fn test_timestamp_valid_request_returns_200() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_timestamp_response_content_type() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(content_type, "application/timestamp-reply");
    }

    #[tokio::test]
    async fn test_timestamp_wrong_content_type_returns_415() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/octet-stream")
            .body(Body::from(vec![0x01, 0x02, 0x03]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_timestamp_empty_body_returns_400() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_timestamp_no_content_type_returns_415() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_timestamp_response_is_valid_der() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        assert!(!body_bytes.is_empty(), "Response body should not be empty");

        // First byte should be 0x30 (SEQUENCE tag) — valid DER
        assert_eq!(
            body_bytes[0], 0x30,
            "Response should start with DER SEQUENCE tag"
        );
    }

    #[tokio::test]
    async fn test_tsa_get_returns_405_with_allow_header() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/timestamp")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        let allow = resp
            .headers()
            .get("allow")
            .expect("405 response must include Allow header per RFC 7231 §6.5.5");
        assert_eq!(allow.to_str().unwrap(), "POST");
    }

    #[tokio::test]
    async fn test_tsa_response_has_nosniff_header() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let nosniff = resp
            .headers()
            .get("x-content-type-options")
            .expect("TSA response must include X-Content-Type-Options header");
        assert_eq!(nosniff.to_str().unwrap(), "nosniff");
    }

    #[tokio::test]
    async fn test_tsa_response_has_request_id() {
        let tsa = make_test_tsa_server();
        let app = build_tsa_router(tsa);

        let req_bytes = build_timestamp_req_bytes();

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/timestamp")
            .header("content-type", "application/timestamp-query")
            .body(Body::from(req_bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let request_id = resp
            .headers()
            .get("x-request-id")
            .expect("TSA response must include X-Request-Id header");
        assert!(
            !request_id.to_str().unwrap().is_empty(),
            "X-Request-Id must not be empty"
        );
    }
}
