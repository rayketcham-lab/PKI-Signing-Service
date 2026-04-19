//! Web server for Code Signing as a Service.
//!
//! Provides an axum-based HTTP API for uploading files, signing them,
//! and downloading the signed results.
//!
//! ## Public API Routes
//!
//! - `POST /api/v1/sign` — Upload and sign file (multipart)
//! - `POST /api/v1/sign-detached` — Create detached CMS signature
//! - `POST /api/v1/sign-batch` — Sign multiple files, return ZIP archive
//! - `POST /api/v1/verify` — Upload and verify file signature
//! - `POST /api/v1/verify-detached` — Verify a detached signature
//! - `GET /api/v1/status` — Server status and statistics
//! - `GET /api/v1/health` — Health check
//! - `GET /api/v1/certificate` — Public signing certificate info
//! - `POST /api/v1/report-issue` — Report an issue (creates GitHub issue)
//!
//! ## Admin Routes (Bearer token or LDAP admin group)
//!
//! - `GET /admin/stats` — Detailed statistics
//! - `GET /admin/audit` — Recent audit log entries
//! - `POST /admin/reload` — Reload PFX credentials
//! - `GET /admin/certs` — List all certificates
//! - `GET /admin/certs/:name` — Detailed certificate info
//! - `POST /admin/certs/:name/default` — Set default certificate

pub mod audit;
pub mod error;
pub mod gh_issues;
mod handlers;
pub mod ldap;
pub(crate) mod middleware;

pub use audit::AuditLogger;
pub use error::AppError;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{middleware as axum_middleware, Router};
use tokio::sync::RwLock;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::SignConfig;
use crate::error::SignError;
use crate::signer::SigningCredentials;

/// Shared application state.
pub struct AppState {
    /// Server configuration.
    pub config: SignConfig,
    /// Loaded signing credentials (supports hot-reload via RwLock).
    pub credentials: RwLock<Vec<(String, SigningCredentials)>>,
    /// Default credential index.
    pub default_credential: RwLock<usize>,
    /// Audit log writer.
    pub audit: AuditLogger,
    /// Server start time (for uptime calculation).
    pub started_at: Instant,
    /// Atomic signing statistics.
    pub stats: SigningStats,
    /// GitHub issue reporter for auto-error reporting.
    pub gh_reporter: Option<gh_issues::GitHubIssueReporter>,
}

/// Atomic counters for signing statistics.
pub struct SigningStats {
    pub files_signed: AtomicU64,
    pub files_verified: AtomicU64,
    pub bytes_signed: AtomicU64,
    pub sign_errors: AtomicU64,
    pub sign_duration_total_ms: AtomicU64,
}

impl Default for SigningStats {
    fn default() -> Self {
        Self {
            files_signed: AtomicU64::new(0),
            files_verified: AtomicU64::new(0),
            bytes_signed: AtomicU64::new(0),
            sign_errors: AtomicU64::new(0),
            sign_duration_total_ms: AtomicU64::new(0),
        }
    }
}

/// Determine the path to the static files directory.
///
/// Checks in order:
/// 1. `PKI_SIGN_STATIC_DIR` environment variable
/// 2. Development path (`crates/pki-sign/static`)
/// 3. Installed path (next to binary)
/// 4. Fallback (`static`)
fn static_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("PKI_SIGN_STATIC_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let dev_path = std::path::PathBuf::from("crates/pki-sign/static");
    if dev_path.exists() {
        return dev_path;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let installed = parent.join("static");
            if installed.exists() {
                return installed;
            }
        }
    }
    std::path::PathBuf::from("static")
}

/// Build the axum router with all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    // Admin routes — protected by bearer token auth or LDAP admin group
    let admin_router = Router::new()
        .route("/admin/stats", get(handlers::admin_stats))
        .route("/admin/audit", get(handlers::admin_audit))
        .route("/admin/reload", post(handlers::admin_reload))
        .route("/admin/certs", get(handlers::admin_list_certs))
        .route("/admin/certs/:name", get(handlers::admin_cert_info))
        .route(
            "/admin/certs/:name/default",
            post(handlers::admin_set_default_cert),
        )
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_auth_middleware,
        ))
        // gh #19: CSRF Origin guard on state-changing admin routes.
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf_origin_middleware,
        ));

    // Signing routes with concurrency limiting (#54)
    // Signing is CPU-intensive; limit concurrent operations to prevent exhaustion.
    let max_concurrent = state.config.rate_limit_rps;
    let signing_router = Router::new()
        .route("/api/v1/sign", post(handlers::sign_file))
        .route("/api/v1/sign-detached", post(handlers::sign_detached))
        .route("/api/v1/sign-batch", post(handlers::sign_batch));

    // Apply concurrency limit only if configured (>0)
    let signing_router = if max_concurrent > 0 {
        signing_router.layer(tower::limit::ConcurrencyLimitLayer::new(
            max_concurrent as usize,
        ))
    } else {
        signing_router
    };

    // Read-only API routes (no concurrency limit needed)
    let api_router = signing_router
        .route("/api/v1/verify", post(handlers::verify_file))
        .route("/api/v1/verify-detached", post(handlers::verify_detached))
        .route("/api/v1/status", get(handlers::server_status))
        .route("/api/v1/certificate", get(handlers::certificate_info))
        .route("/api/v1/report-issue", post(handlers::report_issue))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::ldap_auth_middleware,
        ))
        // gh #19: CSRF Origin guard on every state-changing API route.
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf_origin_middleware,
        ));

    // Assemble the full router
    let max_body = state.config.max_upload_size as usize;

    Router::new()
        // Health check is unauthenticated
        .route("/api/v1/health", get(handlers::health_check))
        // Authenticated API routes
        .merge(api_router)
        // Admin routes
        .merge(admin_router)
        // Serve static files (web UI)
        .nest_service("/static", ServeDir::new(static_dir()))
        // Redirect root to the sign page
        .route(
            "/",
            get(|| async { axum::response::Redirect::permanent("/static/index.html") }),
        )
        // Catch-all
        .fallback(handlers::fallback)
        // Layers (applied bottom-up: trace first, then security headers, then body limit).
        //
        // `RequestBodyLimitLayer` returns 413 Payload Too Large when `Content-Length`
        // exceeds `max_upload_size`, rejecting the request BEFORE any body is
        // buffered — the P1 security fix. `DefaultBodyLimit::max` is also set so
        // axum-extra's `Multipart` extractor uses the same limit (instead of its
        // internal 2 MB default) for mid-stream (chunked/no-CL) overflow bounding.
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(axum_middleware::from_fn(
            middleware::security_headers_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start the signing web server.
///
/// Loads PFX credentials, initializes audit logging, and serves HTTP(S).
pub async fn run_server(config: SignConfig) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Install rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // 2. Extract TLS paths before moving config
    let tls_cert_path = config.tls_cert.clone();
    let tls_key_path = config.tls_key.clone();
    let bind_addr = format!("{}:{}", config.bind_addr, config.bind_port);
    let use_tls = tls_cert_path.is_some() && tls_key_path.is_some();

    // 3. Load signing credentials (gracefully skip unsupported key types)
    let mut credentials = Vec::new();
    for cert_config in &config.cert_configs {
        let password = match std::env::var(&cert_config.pfx_password_env) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    cert = %cert_config.name,
                    env = %cert_config.pfx_password_env,
                    "Skipping certificate: password env var not set"
                );
                continue;
            }
        };
        match SigningCredentials::from_pfx(&cert_config.pfx_path, &password) {
            Ok(cred) => {
                info!(
                    cert = %cert_config.name,
                    pfx = %cert_config.pfx_path.display(),
                    "Loaded signing certificate"
                );
                credentials.push((cert_config.name.clone(), cred));
            }
            Err(e) => {
                tracing::warn!(
                    cert = %cert_config.name,
                    error = %e,
                    "Skipping certificate: failed to load"
                );
            }
        }
    }

    if credentials.is_empty() {
        tracing::warn!("No signing certificates configured — sign endpoint will reject requests");
    }

    // 4. Initialize audit logger
    let audit = AuditLogger::new(&config.audit_log).map_err(|e| {
        SignError::Config(format!(
            "Failed to open audit log {}: {}",
            config.audit_log.display(),
            e
        ))
    })?;
    info!(path = %config.audit_log.display(), "Audit logger initialized");

    // 5. Initialize GitHub issue reporter
    let gh_reporter = if config.github.enabled {
        info!(repo = %config.github.repo, "GitHub issue reporter enabled");
        Some(gh_issues::GitHubIssueReporter::new(
            config.github.repo.clone(),
            config.github.dedup_window_secs,
        ))
    } else {
        None
    };

    if config.dev_mode {
        tracing::warn!("Development mode ENABLED — LDAP bypassed, admin routes open");
    }

    if config.ldap.enabled && config.ldap.trusted_proxies.is_empty() {
        tracing::warn!(
            "SECURITY: LDAP enabled but trusted_proxies is empty — \
             LDAP headers will be accepted from ANY client IP. \
             Configure trusted_proxies to restrict header trust to your reverse proxy."
        );
    }

    // 6. Build shared state
    let state = Arc::new(AppState {
        config,
        credentials: RwLock::new(credentials),
        default_credential: RwLock::new(0),
        audit,
        started_at: Instant::now(),
        stats: SigningStats::default(),
        gh_reporter,
    });

    // 7. Build router
    let router = build_router(state);

    // 8. Bind and serve
    let socket_addr: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| SignError::Config(format!("Invalid bind address '{}': {}", bind_addr, e)))?;

    if use_tls {
        let cert_path = tls_cert_path.expect("tls_cert_path checked by use_tls guard");
        let key_path = tls_key_path.expect("tls_key_path checked by use_tls guard");
        info!(%socket_addr, tls = true, "Starting HTTPS server");
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path).await?;
        axum_server::bind_rustls(socket_addr, tls_config)
            .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        info!(%socket_addr, tls = false, "Starting HTTP server");
        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}
