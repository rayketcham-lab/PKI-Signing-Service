//! Web server for Code Signing as a Service.
//!
//! Provides an axum-based HTTP API for uploading files, signing them,
//! and downloading the signed results.
//!
//! ## Public API Routes
//!
//! - `POST /api/v1/sign` — Upload and sign file (multipart)
//! - `POST /api/v1/verify` — Upload and verify file signature
//! - `GET /api/v1/status` — Server status and statistics
//! - `GET /api/v1/health` — Health check
//! - `GET /api/v1/certificate` — Public signing certificate info
//!
//! ## Admin Routes (Bearer token auth)
//!
//! - `GET /admin/stats` — Detailed statistics
//! - `GET /admin/audit` — Recent audit log entries
//! - `POST /admin/reload` — Reload PFX credentials

pub mod audit;
mod handlers;
mod middleware;

pub use audit::AuditLogger;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{middleware as axum_middleware, Router};
use tokio::sync::RwLock;
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
    pub default_credential: usize,
    /// Audit log writer.
    pub audit: AuditLogger,
    /// Server start time (for uptime calculation).
    pub started_at: Instant,
    /// Atomic signing statistics.
    pub stats: SigningStats,
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

/// Build the axum router with all routes.
pub fn build_router(state: Arc<AppState>) -> Router {
    // Admin routes — protected by bearer token auth
    let admin_router = Router::new()
        .route("/admin/stats", get(handlers::admin_stats))
        .route("/admin/audit", get(handlers::admin_audit))
        .route("/admin/reload", post(handlers::admin_reload))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_auth_middleware,
        ));

    // Assemble the full router
    let max_body = state.config.max_upload_size as usize;

    Router::new()
        // Public API routes
        .route("/api/v1/sign", post(handlers::sign_file))
        .route("/api/v1/verify", post(handlers::verify_file))
        .route("/api/v1/status", get(handlers::server_status))
        .route("/api/v1/health", get(handlers::health_check))
        .route("/api/v1/certificate", get(handlers::certificate_info))
        // Admin routes
        .merge(admin_router)
        // Catch-all
        .fallback(handlers::fallback)
        // Layers (applied bottom-up: trace first, then security headers, then body limit)
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

    // 3. Load signing credentials
    let mut credentials = Vec::new();
    for cert_config in &config.cert_configs {
        let password = std::env::var(&cert_config.pfx_password_env).map_err(|_| {
            SignError::Config(format!(
                "Environment variable '{}' not set for certificate '{}'",
                cert_config.pfx_password_env, cert_config.name
            ))
        })?;
        let cred = SigningCredentials::from_pfx(&cert_config.pfx_path, &password)?;
        info!(
            cert = %cert_config.name,
            pfx = %cert_config.pfx_path.display(),
            "Loaded signing certificate"
        );
        credentials.push((cert_config.name.clone(), cred));
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

    // 5. Build shared state
    let state = Arc::new(AppState {
        config,
        credentials: RwLock::new(credentials),
        default_credential: 0,
        audit,
        started_at: Instant::now(),
        stats: SigningStats::default(),
    });

    // 6. Build router
    let router = build_router(state);

    // 7. Bind and serve
    let socket_addr: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| SignError::Config(format!("Invalid bind address '{}': {}", bind_addr, e)))?;

    if use_tls {
        let cert_path = tls_cert_path.unwrap();
        let key_path = tls_key_path.unwrap();
        info!(%socket_addr, tls = true, "Starting HTTPS server");
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path).await?;
        axum_server::bind_rustls(socket_addr, tls_config)
            .serve(router.into_make_service())
            .await?;
    } else {
        info!(%socket_addr, tls = false, "Starting HTTP server");
        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        axum::serve(listener, router).await?;
    }

    Ok(())
}
