//! Route handler functions for the signing web service.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::AuditEntry;
use super::AppState;
use crate::error::{AppError, SignError};

// ─── Public API Handlers ─────────────────────────────────────────────

/// GET /api/v1/health — Simple health check.
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// GET /api/v1/status — Server status and statistics.
pub async fn server_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime = state.started_at.elapsed().as_secs();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "uptime_seconds": uptime,
        "files_signed": state.stats.files_signed.load(Ordering::Relaxed),
        "files_verified": state.stats.files_verified.load(Ordering::Relaxed),
        "bytes_signed": state.stats.bytes_signed.load(Ordering::Relaxed),
        "sign_errors": state.stats.sign_errors.load(Ordering::Relaxed),
        "allowed_extensions": state.config.allowed_extensions,
        "max_upload_size": state.config.max_upload_size,
        "timestamp_enabled": state.config.require_timestamp,
    }))
}

/// GET /api/v1/certificate — Public signing certificate information.
pub async fn certificate_info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let credentials = state.credentials.read().await;
    if credentials.is_empty() {
        return Json(serde_json::json!({
            "error": "no_certificates",
            "message": "No signing certificates configured"
        }));
    }

    let mut certs = Vec::new();
    for (name, cred) in credentials.iter() {
        let fingerprint = hex::encode(Sha256::digest(cred.signer_cert_der()));
        certs.push(serde_json::json!({
            "name": name,
            "fingerprint_sha256": fingerprint,
            "cert_size_bytes": cred.signer_cert_der().len(),
            "chain_length": cred.chain_certs_der().len(),
        }));
    }

    Json(serde_json::json!({
        "certificates": certs,
        "default_index": state.default_credential,
    }))
}

/// POST /api/v1/sign — Upload and sign a file.
pub async fn sign_file(
    State(state): State<Arc<AppState>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    // Extract fields from multipart
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::new(SignError::Internal(format!("Multipart error: {e}"))))?
    {
        let field_name = field.name().unwrap_or("").to_string();
        if field_name.as_str() == "file" {
            file_name = field.file_name().map(|s| s.to_string());
            let bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::new(SignError::Internal(format!("Read error: {e}"))))?;
            file_data = Some(bytes.to_vec());
        }
    }

    let data =
        file_data.ok_or_else(|| AppError::new(SignError::Internal("No file uploaded".into())))?;
    let filename = file_name.unwrap_or_else(|| "unknown".into());

    // Validate file size
    if data.len() as u64 > state.config.max_upload_size {
        state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
        return Err(AppError::new(SignError::FileTooLarge {
            size: data.len() as u64,
            max: state.config.max_upload_size,
        }));
    }

    // Validate file extension
    let ext = std::path::Path::new(&filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !state.config.allowed_extensions.contains(&ext) {
        state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
        return Err(AppError::new(SignError::UnsupportedFileType(ext)));
    }

    // Validate magic bytes
    if matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "drv"
    ) && (data.len() < 2 || data[0] != b'M' || data[1] != b'Z')
    {
        state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
        return Err(AppError::new(SignError::InvalidPe(
            "File does not have MZ header".into(),
        )));
    }

    // Compute input hash
    let input_hash = hex::encode(Sha256::digest(&data));

    // Write to tempfile and sign
    let temp_input = tempfile::Builder::new()
        .prefix("spork-sign-in-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| tempfile::Builder::new().prefix("spork-sign-in-").tempfile())
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    let temp_output = tempfile::Builder::new()
        .prefix("spork-sign-out-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| {
            tempfile::Builder::new()
                .prefix("spork-sign-out-")
                .tempfile()
        })
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    std::fs::write(temp_input.path(), &data).map_err(|e| AppError::new(SignError::Io(e)))?;

    // Get signing credentials
    let credentials = state.credentials.read().await;
    if credentials.is_empty() {
        return Err(AppError::new(SignError::Config(
            "No signing credentials loaded".into(),
        )));
    }
    let (cert_name, cred) = &credentials[state.default_credential];

    // Sign the file
    let tsa_config = if state.config.require_timestamp {
        Some(&state.config.tsa)
    } else {
        None
    };

    let result = crate::signer::sign_file(temp_input.path(), temp_output.path(), cred, tsa_config)
        .await
        .map_err(|e| {
            state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
            let duration = start.elapsed().as_millis() as u64;
            state.audit.log(&AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: request_id.to_string(),
                action: "sign".into(),
                client_ip: None,
                filename: Some(filename.clone()),
                file_size: Some(data.len() as u64),
                file_hash: Some(input_hash.clone()),
                signed_hash: None,
                signer_subject: Some(cert_name.clone()),
                timestamped: None,
                duration_ms: duration,
                status: "error".into(),
                error_message: Some(e.to_string()),
            });
            AppError::new(e)
        })?;

    let duration = start.elapsed().as_millis() as u64;

    // Update stats
    state.stats.files_signed.fetch_add(1, Ordering::Relaxed);
    state
        .stats
        .bytes_signed
        .fetch_add(data.len() as u64, Ordering::Relaxed);
    state
        .stats
        .sign_duration_total_ms
        .fetch_add(duration, Ordering::Relaxed);

    // Audit log
    state.audit.log(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id: request_id.to_string(),
        action: "sign".into(),
        client_ip: None,
        filename: Some(filename.clone()),
        file_size: Some(data.len() as u64),
        file_hash: Some(input_hash),
        signed_hash: Some(result.signed_hash.clone()),
        signer_subject: Some(cert_name.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
    });

    // Build response with custom headers
    let mut headers = HeaderMap::new();
    headers.insert("X-Request-Id", request_id.to_string().parse().unwrap());
    headers.insert("X-Spork-Sign-Hash", result.signed_hash.parse().unwrap());
    headers.insert("X-Spork-Sign-Algorithm", "RSA-SHA256".parse().unwrap());
    headers.insert("X-Spork-Sign-Certificate", cert_name.parse().unwrap());
    headers.insert(
        "X-Spork-Sign-Timestamp",
        result.timestamped.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-Spork-Sign-Duration-Ms",
        duration.to_string().parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename)
            .parse()
            .unwrap(),
    );

    Ok((headers, Bytes::from(result.signed_data)))
}

/// POST /api/v1/verify — Upload and verify a signed file.
pub async fn verify_file(
    State(state): State<Arc<AppState>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    // Extract file from multipart
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::new(SignError::Internal(format!("Multipart error: {e}"))))?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().map(|s| s.to_string());
            let bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::new(SignError::Internal(format!("Read error: {e}"))))?;
            file_data = Some(bytes.to_vec());
        }
    }

    let data =
        file_data.ok_or_else(|| AppError::new(SignError::Internal("No file uploaded".into())))?;
    let filename = file_name.unwrap_or_else(|| "unknown".into());

    // Write to tempfile and verify
    let ext = std::path::Path::new(&filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_else(|| "bin".into());

    let temp_file = tempfile::Builder::new()
        .prefix("spork-verify-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| tempfile::Builder::new().prefix("spork-verify-").tempfile())
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    std::fs::write(temp_file.path(), &data).map_err(|e| AppError::new(SignError::Io(e)))?;

    let result = crate::verifier::verify_file(temp_file.path()).map_err(|e| {
        let duration = start.elapsed().as_millis() as u64;
        state.audit.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            action: "verify".into(),
            client_ip: None,
            filename: Some(filename.clone()),
            file_size: Some(data.len() as u64),
            file_hash: None,
            signed_hash: None,
            signer_subject: None,
            timestamped: None,
            duration_ms: duration,
            status: "error".into(),
            error_message: Some(e.to_string()),
        });
        AppError::new(e)
    })?;

    let duration = start.elapsed().as_millis() as u64;

    // Update stats
    state.stats.files_verified.fetch_add(1, Ordering::Relaxed);

    // Audit log
    state.audit.log(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id: request_id.to_string(),
        action: "verify".into(),
        client_ip: None,
        filename: Some(filename),
        file_size: Some(data.len() as u64),
        file_hash: None,
        signed_hash: None,
        signer_subject: Some(result.signer_subject.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
    });

    Ok(Json(serde_json::json!({
        "request_id": request_id.to_string(),
        "signature_valid": result.signature_valid,
        "chain_valid": result.chain_valid,
        "timestamped": result.timestamped,
        "signer_subject": result.signer_subject,
        "signer_issuer": result.signer_issuer,
        "algorithm": result.algorithm,
        "digest_algorithm": result.digest_algorithm,
        "computed_digest": result.computed_digest,
        "signed_digest": result.signed_digest,
        "timestamp_time": result.timestamp_time,
    })))
}

// ─── Admin Handlers ──────────────────────────────────────────────────

/// GET /admin/stats — Detailed signing statistics.
pub async fn admin_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime = state.started_at.elapsed().as_secs();
    let files_signed = state.stats.files_signed.load(Ordering::Relaxed);
    let total_duration = state.stats.sign_duration_total_ms.load(Ordering::Relaxed);
    let avg_duration = if files_signed > 0 {
        total_duration / files_signed
    } else {
        0
    };

    let credentials = state.credentials.read().await;
    let cert_names: Vec<&str> = credentials.iter().map(|(name, _)| name.as_str()).collect();

    Json(serde_json::json!({
        "uptime_seconds": uptime,
        "files_signed": files_signed,
        "files_verified": state.stats.files_verified.load(Ordering::Relaxed),
        "bytes_signed": state.stats.bytes_signed.load(Ordering::Relaxed),
        "sign_errors": state.stats.sign_errors.load(Ordering::Relaxed),
        "total_sign_duration_ms": total_duration,
        "average_sign_duration_ms": avg_duration,
        "loaded_certificates": cert_names,
        "auth_mode": format!("{:?}", state.config.auth_mode),
        "tls_enabled": state.config.tls_cert.is_some(),
    }))
}

/// GET /admin/audit — Recent audit log entries.
pub async fn admin_audit(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let entries = state.audit.tail(100);
    Json(serde_json::json!({
        "count": entries.len(),
        "entries": entries,
    }))
}

/// POST /admin/reload — Reload PFX credentials without restart.
pub async fn admin_reload(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut new_credentials = Vec::new();

    for cert_config in &state.config.cert_configs {
        let password = match std::env::var(&cert_config.pfx_password_env) {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "reload_failed",
                        "message": format!("Environment variable '{}' not set", cert_config.pfx_password_env),
                    })),
                )
                    .into_response();
            }
        };

        match crate::signer::SigningCredentials::from_pfx(&cert_config.pfx_path, &password) {
            Ok(cred) => new_credentials.push((cert_config.name.clone(), cred)),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "reload_failed",
                        "message": format!("Failed to load '{}': {}", cert_config.name, e),
                    })),
                )
                    .into_response();
            }
        }
    }

    // Replace credentials under write lock
    let mut credentials = state.credentials.write().await;
    *credentials = new_credentials;
    let count = credentials.len();
    drop(credentials);

    // Audit log
    state.audit.log(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id: Uuid::new_v4().to_string(),
        action: "admin_reload".into(),
        client_ip: None,
        filename: None,
        file_size: None,
        file_hash: None,
        signed_hash: None,
        signer_subject: None,
        timestamped: None,
        duration_ms: 0,
        status: "success".into(),
        error_message: None,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "reloaded",
            "certificates_loaded": count,
        })),
    )
        .into_response()
}

/// Catch-all handler — returns JSON 404.
pub async fn fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "not_found",
            "message": "The requested endpoint was not found"
        })),
    )
}
