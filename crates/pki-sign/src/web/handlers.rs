//! Route handler functions for the signing web service.

use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::AuditEntry;
use super::error::AppError;
use super::ldap::UserInfo;
use super::AppState;
use crate::error::SignError;

/// Map a multipart parsing error to an [`AppError`], preserving the
/// HTTP status chosen by axum-extra. A `PAYLOAD_TOO_LARGE` rejection from
/// the underlying body-limit layer surfaces as `SignError::FileTooLarge`
/// (413), not as a generic 500 Internal. Every other multipart fault
/// (malformed headers, aborted stream, …) is treated as internal.
///
/// Without this mapping, a streaming/chunked upload that trips the
/// `DefaultBodyLimit` mid-stream would leak through as a 500, which both
/// misleads clients and masks the body-limit enforcement from security
/// scanners.
fn multipart_error_to_app(err: axum_extra::extract::multipart::MultipartError) -> AppError {
    if err.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return AppError::new(SignError::FileTooLarge { size: 0, max: 0 });
    }
    // Walk the error source chain looking for a LengthLimitError.
    // axum-extra/multer only map a narrow subset (StreamSizeExceeded, and
    // one specific `StreamReadFailed` downcast path) to 413, which misses
    // the case where `RequestBodyLimitLayer` trips the body mid-stream and
    // the `http_body_util::LengthLimitError` is wrapped deeper — leaving
    // chunked/no-CL uploads returning 500 instead of 413.
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&err);
    while let Some(e) = src {
        if e.downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
        {
            return AppError::new(SignError::FileTooLarge { size: 0, max: 0 });
        }
        src = e.source();
    }
    AppError::new(SignError::Internal(format!("Multipart error: {err}")))
}

/// Check whether the authenticated user is authorized to use the requested certificate.
///
/// When LDAP is enabled and `cert_groups` is configured, the user must belong to
/// the LDAP group mapped to the requested certificate name. Admins bypass this check.
/// Returns `Ok(())` if authorized or if cert-group enforcement is not configured.
fn check_cert_authorization(
    user_info: Option<&UserInfo>,
    cert_name: &str,
    config: &crate::config::SignConfig,
) -> Result<(), AppError> {
    // No enforcement if LDAP is disabled or no cert_groups configured
    if !config.ldap.enabled || config.ldap.cert_groups.is_empty() {
        return Ok(());
    }

    let user = match user_info {
        Some(u) => u,
        None => {
            // LDAP enabled but no user info — deny
            return Err(AppError::new(SignError::Unauthorized(
                "Authentication required".into(),
            )));
        }
    };

    // Admins can use any certificate
    if user.is_admin {
        return Ok(());
    }

    // If the cert has a group mapping, user must be in the allowed list
    if config.ldap.cert_groups.contains_key(cert_name)
        && !user.allowed_cert_names.iter().any(|c| c == cert_name)
    {
        tracing::warn!(
            user = %user.username,
            cert = %cert_name,
            "Certificate access denied: user not in required group"
        );
        return Err(AppError::new(SignError::Unauthorized(format!(
            "Not authorized to use certificate '{cert_name}'"
        ))));
    }

    Ok(())
}

/// Sanitize a user-supplied filename for use in Content-Disposition headers.
///
/// Strips directory separators, control characters, quotes, and newlines
/// to prevent header injection. Truncates to 255 bytes.
fn sanitize_filename(name: &str) -> String {
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let sanitized: String = basename
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\'' && *c != ';')
        .collect();
    if sanitized.len() > 255 {
        sanitized[..255].to_string()
    } else if sanitized.is_empty() {
        "download".to_string()
    } else {
        sanitized
    }
}

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
        "default_index": *state.default_credential.read().await,
    }))
}

/// POST /api/v1/sign — Upload and sign a file.
pub async fn sign_file(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    user_info: Option<axum::Extension<UserInfo>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());

    // Extract fields from multipart
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut cert_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_error_to_app)?
    {
        let field_name = field.name().unwrap_or("").to_string();
        match field_name.as_str() {
            "file" => {
                file_name = field.file_name().map(|s| s.to_string());
                let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
                file_data = Some(bytes.to_vec());
            }
            "cert_type" => {
                let text = field.text().await.map_err(multipart_error_to_app)?;
                if !text.is_empty() {
                    cert_type = Some(text);
                }
            }
            _ => {}
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
        .prefix("pki-sign-in-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| tempfile::Builder::new().prefix("pki-sign-in-").tempfile())
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    let temp_output = tempfile::Builder::new()
        .prefix("pki-sign-out-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| tempfile::Builder::new().prefix("pki-sign-out-").tempfile())
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    std::fs::write(temp_input.path(), &data).map_err(|e| AppError::new(SignError::Io(e)))?;

    // Get signing credentials
    let credentials = state.credentials.read().await;
    if credentials.is_empty() {
        return Err(AppError::new(SignError::Config(
            "No signing credentials loaded".into(),
        )));
    }
    let (cert_name, cred) = if let Some(ref ct) = cert_type {
        credentials
            .iter()
            .find(|(name, _)| name == ct)
            .ok_or_else(|| {
                AppError::new(SignError::Config(format!("Certificate '{}' not found", ct)))
            })?
    } else {
        let default_idx = *state.default_credential.read().await;
        &credentials[default_idx]
    };

    // #9 fix: Enforce LDAP cert-group authorization
    check_cert_authorization(user_info.as_ref().map(|e| &e.0), cert_name, &state.config)?;

    // Sign the file
    let tsa_config = if state.config.require_timestamp {
        Some(&state.config.tsa)
    } else {
        None
    };

    let sign_options = crate::signer::SignOptions::default();

    let result = crate::signer::sign_file_with_options(
        temp_input.path(),
        temp_output.path(),
        cred,
        tsa_config,
        &sign_options,
    )
    .await
    .map_err(|e| {
        state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
        let duration = start.elapsed().as_millis() as u64;
        state.audit.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            action: "sign".into(),
            client_ip: client_ip.clone(),
            filename: Some(filename.clone()),
            file_size: Some(data.len() as u64),
            file_hash: Some(input_hash.clone()),
            signed_hash: None,
            signer_subject: Some(cert_name.clone()),
            timestamped: None,
            duration_ms: duration,
            status: "error".into(),
            error_message: Some(e.to_string()),
            cert_type: None,
            signed_filename: None,
            file_type: None,
        });

        // Auto-report to GitHub if enabled
        if state.gh_reporter.is_some() {
            let error_type = format!("{:?}", e)
                .split('(')
                .next()
                .unwrap_or("Unknown")
                .to_string();
            let error_msg = e.to_string();
            let fname = filename.clone();
            let fsize = data.len() as u64;
            let state_clone = Arc::clone(&state);
            // Fire-and-forget: spawn a task to create the issue
            drop(tokio::spawn(async move {
                if let Some(ref reporter) = state_clone.gh_reporter {
                    reporter
                        .report_signing_error(&error_type, &error_msg, Some(&fname), Some(fsize))
                        .await;
                }
            }));
        }

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
        client_ip,
        filename: Some(filename.clone()),
        file_size: Some(data.len() as u64),
        file_hash: Some(input_hash),
        signed_hash: Some(result.signed_hash.clone()),
        signer_subject: Some(cert_name.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
        cert_type: None,
        signed_filename: None,
        file_type: None,
    });

    // Build response with custom headers
    let mut headers = HeaderMap::new();
    headers.insert("X-Request-Id", request_id.to_string().parse().unwrap());
    headers.insert("X-PKI-Sign-Hash", result.signed_hash.parse().unwrap());
    headers.insert("X-PKI-Sign-Algorithm", "RSA-SHA256".parse().unwrap());
    headers.insert("X-PKI-Sign-Certificate", cert_name.parse().unwrap());
    headers.insert(
        "X-PKI-Sign-Timestamp",
        result.timestamped.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-PKI-Sign-Duration-Ms",
        duration.to_string().parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!(
            "attachment; filename=\"signed_{}\"",
            sanitize_filename(&filename)
        )
        .parse()
        .unwrap(),
    );

    Ok((headers, Bytes::from(result.signed_data)))
}

/// POST /api/v1/sign-detached — Create a detached CMS/PKCS#7 signature.
pub async fn sign_detached(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    user_info: Option<axum::Extension<UserInfo>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());

    // Extract file from multipart
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut cert_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_error_to_app)?
    {
        match field.name() {
            Some("file") => {
                file_name = field.file_name().map(|s| s.to_string());
                let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
                file_data = Some(bytes.to_vec());
            }
            Some("cert_type") => {
                let text = field.text().await.map_err(multipart_error_to_app)?;
                if !text.is_empty() {
                    cert_type = Some(text);
                }
            }
            _ => {}
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

    let input_hash = hex::encode(Sha256::digest(&data));

    // Write to tempfile for signing
    let temp_input = tempfile::Builder::new()
        .prefix("pki-sign-detached-")
        .tempfile_in("/dev/shm")
        .or_else(|_| {
            tempfile::Builder::new()
                .prefix("pki-sign-detached-")
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
    let (cert_name, cred) = if let Some(ref ct) = cert_type {
        credentials
            .iter()
            .find(|(name, _)| name == ct)
            .ok_or_else(|| {
                AppError::new(SignError::Config(format!("Certificate '{}' not found", ct)))
            })?
    } else {
        let default_idx = *state.default_credential.read().await;
        &credentials[default_idx]
    };

    // #9 fix: Enforce LDAP cert-group authorization
    check_cert_authorization(user_info.as_ref().map(|e| &e.0), cert_name, &state.config)?;

    let tsa_config = if state.config.require_timestamp {
        Some(&state.config.tsa)
    } else {
        None
    };

    let result = crate::signer::sign_detached(temp_input.path(), cred, tsa_config)
        .await
        .map_err(|e| {
            state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
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
        action: "sign_detached".into(),
        client_ip,
        filename: Some(filename.clone()),
        file_size: Some(data.len() as u64),
        file_hash: Some(input_hash),
        signed_hash: Some(result.p7s_hash.clone()),
        signer_subject: Some(cert_name.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
        cert_type: None,
        signed_filename: None,
        file_type: None,
    });

    // Return based on Accept header
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        let p7s_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &result.p7s_data);
        Ok(Json(serde_json::json!({
            "request_id": request_id.to_string(),
            "p7s": p7s_base64,
            "file_hash": result.file_hash,
            "p7s_hash": result.p7s_hash,
            "timestamped": result.timestamped,
            "certificate": cert_name,
            "duration_ms": duration,
        }))
        .into_response())
    } else {
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("X-Request-Id", request_id.to_string().parse().unwrap());
        resp_headers.insert("X-PKI-Sign-File-Hash", result.file_hash.parse().unwrap());
        resp_headers.insert("X-PKI-Sign-P7s-Hash", result.p7s_hash.parse().unwrap());
        resp_headers.insert(
            "X-PKI-Sign-Timestamp",
            result.timestamped.to_string().parse().unwrap(),
        );
        resp_headers.insert(
            header::CONTENT_TYPE,
            "application/pkcs7-signature".parse().unwrap(),
        );
        resp_headers.insert(
            header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"signed_{}.p7s\"",
                sanitize_filename(
                    std::path::Path::new(&filename)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("signature")
                )
            )
            .parse()
            .unwrap(),
        );
        Ok((resp_headers, Bytes::from(result.p7s_data)).into_response())
    }
}

/// POST /api/v1/verify — Upload and verify a signed file.
pub async fn verify_file(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());

    // Extract file from multipart
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_error_to_app)?
    {
        if field.name() == Some("file") {
            file_name = field.file_name().map(|s| s.to_string());
            let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
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
        .prefix("pki-verify-")
        .suffix(&format!(".{ext}"))
        .tempfile_in("/dev/shm")
        .or_else(|_| tempfile::Builder::new().prefix("pki-verify-").tempfile())
        .map_err(|e| AppError::new(SignError::Io(e)))?;

    std::fs::write(temp_file.path(), &data).map_err(|e| AppError::new(SignError::Io(e)))?;

    let result = crate::verifier::verify_file(temp_file.path()).map_err(|e| {
        let duration = start.elapsed().as_millis() as u64;
        state.audit.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            action: "verify".into(),
            client_ip: client_ip.clone(),
            filename: Some(filename.clone()),
            file_size: Some(data.len() as u64),
            file_hash: None,
            signed_hash: None,
            signer_subject: None,
            timestamped: None,
            duration_ms: duration,
            status: "error".into(),
            error_message: Some(e.to_string()),
            cert_type: None,
            signed_filename: None,
            file_type: None,
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
        client_ip,
        filename: Some(filename),
        file_size: Some(data.len() as u64),
        file_hash: None,
        signed_hash: None,
        signer_subject: Some(result.signer_subject.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
        cert_type: None,
        signed_filename: None,
        file_type: None,
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

/// POST /api/v1/verify-detached — Verify a detached CMS/PKCS#7 signature.
pub async fn verify_detached(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());

    let mut file_data: Option<Vec<u8>> = None;
    let mut sig_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_error_to_app)?
    {
        match field.name() {
            Some("file") => {
                file_name = field.file_name().map(|s| s.to_string());
                let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
                file_data = Some(bytes.to_vec());
            }
            Some("signature") => {
                let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
                sig_data = Some(bytes.to_vec());
            }
            _ => {}
        }
    }

    let data =
        file_data.ok_or_else(|| AppError::new(SignError::Internal("No file uploaded".into())))?;
    let p7s = sig_data.ok_or_else(|| {
        AppError::new(SignError::Internal(
            "No signature uploaded (use field name 'signature')".into(),
        ))
    })?;
    let filename = file_name.unwrap_or_else(|| "unknown".into());

    let result = crate::verifier::verify_detached(&data, &p7s).map_err(|e| {
        let duration = start.elapsed().as_millis() as u64;
        state.audit.log(&AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            action: "verify_detached".into(),
            client_ip: client_ip.clone(),
            filename: Some(filename.clone()),
            file_size: Some(data.len() as u64),
            file_hash: None,
            signed_hash: None,
            signer_subject: None,
            timestamped: None,
            duration_ms: duration,
            status: "error".into(),
            error_message: Some(e.to_string()),
            cert_type: None,
            signed_filename: None,
            file_type: None,
        });
        AppError::new(e)
    })?;

    let duration = start.elapsed().as_millis() as u64;
    state.stats.files_verified.fetch_add(1, Ordering::Relaxed);

    state.audit.log(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id: request_id.to_string(),
        action: "verify_detached".into(),
        client_ip,
        filename: Some(filename),
        file_size: Some(data.len() as u64),
        file_hash: None,
        signed_hash: None,
        signer_subject: Some(result.signer_subject.clone()),
        timestamped: Some(result.timestamped),
        duration_ms: duration,
        status: "success".into(),
        error_message: None,
        cert_type: None,
        signed_filename: None,
        file_type: None,
    });

    Ok(Json(serde_json::json!({
        "request_id": request_id.to_string(),
        "signature_valid": result.signature_valid,
        "signer_subject": result.signer_subject,
        "signer_issuer": result.signer_issuer,
        "algorithm": result.algorithm,
        "digest_algorithm": result.digest_algorithm,
        "computed_digest": result.computed_digest,
        "signed_digest": result.signed_digest,
    })))
}

/// POST /api/v1/report-issue — Submit a user issue report.
pub async fn report_issue(
    State(state): State<Arc<AppState>>,
    axum::Extension(user_info): axum::Extension<UserInfo>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let reporter = match state.gh_reporter {
        Some(ref r) => r,
        None => {
            return Err(AppError::new(SignError::Config(
                "Issue reporting is not configured".into(),
            )));
        }
    };

    let title = payload["title"]
        .as_str()
        .ok_or_else(|| AppError::new(SignError::Internal("Missing 'title' field".into())))?;
    let body = payload["body"]
        .as_str()
        .ok_or_else(|| AppError::new(SignError::Internal("Missing 'body' field".into())))?;

    // Sanitize: prevent markdown injection by escaping HTML
    let clean_title = title.replace('<', "&lt;").replace('>', "&gt;");
    let clean_body = body.replace('<', "&lt;").replace('>', "&gt;");

    match reporter
        .create_user_report(&clean_title, &clean_body, Some(&user_info.username))
        .await
    {
        Ok(url) => Ok(Json(serde_json::json!({
            "status": "created",
            "url": url,
        }))),
        Err(e) => Err(AppError::new(SignError::Internal(format!(
            "Failed to create issue: {e}"
        )))),
    }
}

/// Classify a file for signing based on extension.
fn classify_file_type(filename: &str) -> (&'static str, bool) {
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "drv" => ("Authenticode", false),
        "ps1" => ("PowerShell", false),
        "msi" => ("MSI Authenticode", false),
        "cab" => ("CAB Authenticode", false),
        _ => ("Detached CMS", true),
    }
}

/// POST /api/v1/sign-batch — Sign multiple files and return a ZIP archive.
///
/// Accepts multipart with multiple `file` fields (max 10) and optional `cert_type`.
/// Returns a ZIP containing all signed files (with `signed_` prefix) plus a
/// `signing_summary.csv` with standardized audit columns.
pub async fn sign_batch(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    user_info: Option<axum::Extension<UserInfo>>,
    mut multipart: axum_extra::extract::Multipart,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();
    let request_id = Uuid::new_v4();
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());

    // Extract files and cert_type from multipart
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut cert_type: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_error_to_app)?
    {
        match field.name() {
            Some("file") => {
                let name = field.file_name().unwrap_or("unknown").to_string();
                let bytes = field.bytes().await.map_err(multipart_error_to_app)?;
                if files.len() < 10 {
                    files.push((name, bytes.to_vec()));
                }
            }
            Some("cert_type") => {
                let text = field.text().await.map_err(multipart_error_to_app)?;
                if !text.is_empty() {
                    cert_type = Some(text);
                }
            }
            _ => {}
        }
    }

    if files.is_empty() {
        return Err(AppError::new(SignError::Internal(
            "No files uploaded".into(),
        )));
    }

    // Get signing credentials
    let credentials = state.credentials.read().await;
    if credentials.is_empty() {
        return Err(AppError::new(SignError::Config(
            "No signing credentials loaded".into(),
        )));
    }
    let (cert_name, cred) = if let Some(ref ct) = cert_type {
        credentials
            .iter()
            .find(|(name, _)| name == ct)
            .ok_or_else(|| {
                AppError::new(SignError::Config(format!("Certificate '{}' not found", ct)))
            })?
    } else {
        let default_idx = *state.default_credential.read().await;
        &credentials[default_idx]
    };

    // #9 fix: Enforce LDAP cert-group authorization
    check_cert_authorization(user_info.as_ref().map(|e| &e.0), cert_name, &state.config)?;

    let tsa_config = if state.config.require_timestamp {
        Some(&state.config.tsa)
    } else {
        None
    };

    // Sign each file and collect results
    struct BatchResult {
        original_filename: String,
        signed_filename: String,
        original_hash: String,
        signed_hash: String,
        size_bytes: u64,
        file_type: String,
        datetime: String,
        status: String,
        error_message: Option<String>,
        signed_data: Option<Vec<u8>>,
    }

    let mut results: Vec<BatchResult> = Vec::new();

    for (filename, data) in &files {
        let input_hash = hex::encode(Sha256::digest(data));
        let (file_type_str, use_detached) = classify_file_type(filename);
        let signed_name = format!("signed_{}", sanitize_filename(filename));
        let now = chrono::Utc::now();
        let datetime_str = now.to_rfc3339();

        // Validate file size
        if data.len() as u64 > state.config.max_upload_size {
            results.push(BatchResult {
                original_filename: filename.clone(),
                signed_filename: signed_name,
                original_hash: input_hash,
                signed_hash: String::new(),
                size_bytes: data.len() as u64,
                file_type: file_type_str.to_string(),
                datetime: datetime_str,
                status: "FAILED".to_string(),
                error_message: Some("File exceeds maximum upload size".to_string()),
                signed_data: None,
            });
            continue;
        }

        if use_detached {
            // Detached CMS signing
            let temp_input = tempfile::Builder::new()
                .prefix("pki-sign-batch-")
                .tempfile_in("/dev/shm")
                .or_else(|_| {
                    tempfile::Builder::new()
                        .prefix("pki-sign-batch-")
                        .tempfile()
                })
                .map_err(|e| AppError::new(SignError::Io(e)))?;

            std::fs::write(temp_input.path(), data).map_err(|e| AppError::new(SignError::Io(e)))?;

            match crate::signer::sign_detached(temp_input.path(), cred, tsa_config).await {
                Ok(result) => {
                    let p7s_name = format!(
                        "signed_{}.p7s",
                        std::path::Path::new(filename)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("file")
                    );
                    results.push(BatchResult {
                        original_filename: filename.clone(),
                        signed_filename: p7s_name,
                        original_hash: input_hash,
                        signed_hash: result.p7s_hash,
                        size_bytes: result.p7s_data.len() as u64,
                        file_type: file_type_str.to_string(),
                        datetime: datetime_str,
                        status: "OK".to_string(),
                        error_message: None,
                        signed_data: Some(result.p7s_data),
                    });
                    state.stats.files_signed.fetch_add(1, Ordering::Relaxed);
                    state
                        .stats
                        .bytes_signed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
                    results.push(BatchResult {
                        original_filename: filename.clone(),
                        signed_filename: signed_name,
                        original_hash: input_hash,
                        signed_hash: String::new(),
                        size_bytes: data.len() as u64,
                        file_type: file_type_str.to_string(),
                        datetime: datetime_str,
                        status: "FAILED".to_string(),
                        error_message: Some(e.to_string()),
                        signed_data: None,
                    });
                }
            }
        } else {
            // Authenticode / PowerShell / MSI / CAB signing
            let ext = std::path::Path::new(filename)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                .unwrap_or_default();

            // Validate PE magic bytes
            if matches!(
                ext.as_str(),
                "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "drv"
            ) && (data.len() < 2 || data[0] != b'M' || data[1] != b'Z')
            {
                results.push(BatchResult {
                    original_filename: filename.clone(),
                    signed_filename: signed_name,
                    original_hash: input_hash,
                    signed_hash: String::new(),
                    size_bytes: data.len() as u64,
                    file_type: file_type_str.to_string(),
                    datetime: datetime_str,
                    status: "FAILED".to_string(),
                    error_message: Some("File does not have MZ header".to_string()),
                    signed_data: None,
                });
                continue;
            }

            let temp_input = tempfile::Builder::new()
                .prefix("pki-sign-batch-in-")
                .suffix(&format!(".{ext}"))
                .tempfile_in("/dev/shm")
                .or_else(|_| {
                    tempfile::Builder::new()
                        .prefix("pki-sign-batch-in-")
                        .tempfile()
                })
                .map_err(|e| AppError::new(SignError::Io(e)))?;

            let temp_output = tempfile::Builder::new()
                .prefix("pki-sign-batch-out-")
                .suffix(&format!(".{ext}"))
                .tempfile_in("/dev/shm")
                .or_else(|_| {
                    tempfile::Builder::new()
                        .prefix("pki-sign-batch-out-")
                        .tempfile()
                })
                .map_err(|e| AppError::new(SignError::Io(e)))?;

            std::fs::write(temp_input.path(), data).map_err(|e| AppError::new(SignError::Io(e)))?;

            let batch_sign_options = crate::signer::SignOptions::default();

            match crate::signer::sign_file_with_options(
                temp_input.path(),
                temp_output.path(),
                cred,
                tsa_config,
                &batch_sign_options,
            )
            .await
            {
                Ok(result) => {
                    results.push(BatchResult {
                        original_filename: filename.clone(),
                        signed_filename: signed_name,
                        original_hash: input_hash,
                        signed_hash: result.signed_hash,
                        size_bytes: result.signed_data.len() as u64,
                        file_type: file_type_str.to_string(),
                        datetime: datetime_str,
                        status: "OK".to_string(),
                        error_message: None,
                        signed_data: Some(result.signed_data),
                    });
                    state.stats.files_signed.fetch_add(1, Ordering::Relaxed);
                    state
                        .stats
                        .bytes_signed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    state.stats.sign_errors.fetch_add(1, Ordering::Relaxed);
                    results.push(BatchResult {
                        original_filename: filename.clone(),
                        signed_filename: signed_name,
                        original_hash: input_hash,
                        signed_hash: String::new(),
                        size_bytes: data.len() as u64,
                        file_type: file_type_str.to_string(),
                        datetime: datetime_str,
                        status: "FAILED".to_string(),
                        error_message: Some(e.to_string()),
                        signed_data: None,
                    });
                }
            }
        }
    }

    let duration = start.elapsed().as_millis() as u64;
    state
        .stats
        .sign_duration_total_ms
        .fetch_add(duration, Ordering::Relaxed);

    // Build ZIP archive in memory
    let buf = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Add signed files to ZIP
    for r in &results {
        if let Some(ref data) = r.signed_data {
            zip.start_file(&r.signed_filename, options)
                .map_err(|e| AppError::new(SignError::Internal(format!("ZIP error: {e}"))))?;
            zip.write_all(data)
                .map_err(|e| AppError::new(SignError::Internal(format!("ZIP write error: {e}"))))?;
        }
    }

    // Build signing_summary.csv
    let mut csv_buf = Vec::new();
    {
        let mut wtr = csv::Writer::from_writer(&mut csv_buf);
        wtr.write_record([
            "Original Filename",
            "Signed Filename",
            "Original Hash",
            "Signed Hash",
            "Size (bytes)",
            "Type",
            "Date/Time",
            "Status",
            "Error",
        ])
        .map_err(|e| AppError::new(SignError::Internal(format!("CSV error: {e}"))))?;
        for r in &results {
            wtr.write_record([
                &r.original_filename,
                &r.signed_filename,
                &r.original_hash,
                &r.signed_hash,
                &r.size_bytes.to_string(),
                &r.file_type,
                &r.datetime,
                &r.status,
                r.error_message.as_deref().unwrap_or(""),
            ])
            .map_err(|e| AppError::new(SignError::Internal(format!("CSV error: {e}"))))?;
        }
        wtr.flush()
            .map_err(|e| AppError::new(SignError::Internal(format!("CSV flush error: {e}"))))?;
    }

    zip.start_file("signing_summary.csv", options)
        .map_err(|e| AppError::new(SignError::Internal(format!("ZIP error: {e}"))))?;
    zip.write_all(&csv_buf)
        .map_err(|e| AppError::new(SignError::Internal(format!("ZIP write error: {e}"))))?;

    let zip_data = zip
        .finish()
        .map_err(|e| AppError::new(SignError::Internal(format!("ZIP finish error: {e}"))))?
        .into_inner();

    // Emit per-file audit entries
    for r in &results {
        state.audit.log(&AuditEntry {
            timestamp: r.datetime.clone(),
            request_id: request_id.to_string(),
            action: "sign_batch".into(),
            client_ip: client_ip.clone(),
            filename: Some(r.original_filename.clone()),
            file_size: Some(r.size_bytes),
            file_hash: Some(r.original_hash.clone()),
            signed_hash: if r.signed_hash.is_empty() {
                None
            } else {
                Some(r.signed_hash.clone())
            },
            signer_subject: Some(cert_name.clone()),
            timestamped: None,
            duration_ms: duration,
            status: r.status.to_lowercase(),
            error_message: r.error_message.clone(),
            cert_type: cert_type.clone(),
            signed_filename: Some(r.signed_filename.clone()),
            file_type: Some(r.file_type.clone()),
        });
    }

    // Build response
    let mut headers = HeaderMap::new();
    headers.insert("X-Request-Id", request_id.to_string().parse().unwrap());
    headers.insert(
        "X-PKI-Sign-Files-Total",
        results.len().to_string().parse().unwrap(),
    );
    let ok_count = results.iter().filter(|r| r.status == "OK").count();
    headers.insert(
        "X-PKI-Sign-Files-Signed",
        ok_count.to_string().parse().unwrap(),
    );
    headers.insert(
        "X-PKI-Sign-Duration-Ms",
        duration.to_string().parse().unwrap(),
    );
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        "attachment; filename=\"signed_files.zip\"".parse().unwrap(),
    );

    Ok((headers, Bytes::from(zip_data)))
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
        "ldap_enabled": state.config.ldap.enabled,
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
pub async fn admin_reload(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> impl IntoResponse {
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());
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
        client_ip,
        filename: None,
        file_size: None,
        file_hash: None,
        signed_hash: None,
        signer_subject: None,
        timestamped: None,
        duration_ms: 0,
        status: "success".into(),
        error_message: None,
        cert_type: None,
        signed_filename: None,
        file_type: None,
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

/// GET /admin/certs — List all loaded certificates with info.
pub async fn admin_list_certs(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let credentials = state.credentials.read().await;
    let default_idx = *state.default_credential.read().await;

    let mut certs = Vec::new();
    for (idx, (name, cred)) in credentials.iter().enumerate() {
        let fingerprint = hex::encode(Sha256::digest(cred.signer_cert_der()));
        let cert_info = crate::signer::parse_certificate_info(cred.signer_cert_der());

        certs.push(serde_json::json!({
            "name": name,
            "fingerprint_sha256": fingerprint,
            "is_default": idx == default_idx,
            "subject": cert_info.subject,
            "issuer": cert_info.issuer,
            "serial_number": cert_info.serial_number,
            "not_before": cert_info.not_before,
            "not_after": cert_info.not_after,
            "key_usage": cert_info.key_usage,
            "extended_key_usage": cert_info.extended_key_usage,
            "chain_length": cred.chain_certs_der().len(),
        }));
    }

    Json(serde_json::json!({
        "certificates": certs,
        "total": certs.len(),
    }))
}

/// GET /admin/certs/:name — Detailed info for a specific certificate.
pub async fn admin_cert_info(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let credentials = state.credentials.read().await;
    let default_idx = *state.default_credential.read().await;

    let entry = credentials
        .iter()
        .enumerate()
        .find(|(_, (n, _))| n == &name);

    match entry {
        Some((idx, (_, cred))) => {
            let fingerprint = hex::encode(Sha256::digest(cred.signer_cert_der()));
            let cert_info = crate::signer::parse_certificate_info(cred.signer_cert_der());

            Ok(Json(serde_json::json!({
                "name": name,
                "fingerprint_sha256": fingerprint,
                "is_default": idx == default_idx,
                "subject": cert_info.subject,
                "issuer": cert_info.issuer,
                "serial_number": cert_info.serial_number,
                "not_before": cert_info.not_before,
                "not_after": cert_info.not_after,
                "key_usage": cert_info.key_usage,
                "extended_key_usage": cert_info.extended_key_usage,
                "chain_length": cert_info.chain_length,
                "cert_size_bytes": cred.signer_cert_der().len(),
            })))
        }
        None => Err(AppError::new(SignError::Internal(format!(
            "Certificate '{}' not found",
            name
        )))),
    }
}

/// POST /admin/certs/:name/default — Set a certificate as the default.
pub async fn admin_set_default_cert(
    State(state): State<Arc<AppState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let client_ip = connect_info.map(|ci| ci.0.ip().to_string());
    let credentials = state.credentials.read().await;
    let idx = credentials.iter().position(|(n, _)| n == &name);

    match idx {
        Some(i) => {
            drop(credentials);
            let mut default = state.default_credential.write().await;
            *default = i;

            state.audit.log(&AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: Uuid::new_v4().to_string(),
                action: "admin_set_default_cert".into(),
                client_ip,
                filename: None,
                file_size: None,
                file_hash: None,
                signed_hash: None,
                signer_subject: Some(name.clone()),
                timestamped: None,
                duration_ms: 0,
                status: "success".into(),
                error_message: None,
                cert_type: None,
                signed_filename: None,
                file_type: None,
            });

            Ok(Json(serde_json::json!({
                "status": "ok",
                "default_certificate": name,
            })))
        }
        None => Err(AppError::new(SignError::Internal(format!(
            "Certificate '{}' not found",
            name
        )))),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LdapConfig, SignConfig};

    // ─── E2E HTTP tests ──────────────────────────────────────────────────────

    /// Build a minimal [`AppState`] suitable for HTTP handler tests.
    ///
    /// `dev_mode = true` is set so LDAP middleware is bypassed in debug builds,
    /// which is always the case when running `cargo test`.
    ///
    /// The audit log is written to a temporary file so tests are self-contained.
    fn make_test_state(
        credentials: Vec<(String, crate::signer::SigningCredentials)>,
    ) -> Arc<AppState> {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let audit_path = tmp.path().to_path_buf();
        // Keep the NamedTempFile alive by leaking it for the test lifetime.
        // In tests the process exits shortly after anyway.
        std::mem::forget(tmp);

        // dev_mode=true bypasses LDAP middleware in debug (test) builds.
        let config = SignConfig {
            dev_mode: true,
            require_timestamp: false,
            audit_log: audit_path.clone(),
            ..SignConfig::default()
        };

        Arc::new(AppState {
            config,
            credentials: tokio::sync::RwLock::new(credentials),
            default_credential: tokio::sync::RwLock::new(0),
            audit: crate::web::audit::AuditLogger::new(&audit_path).expect("audit logger"),
            started_at: std::time::Instant::now(),
            stats: crate::web::SigningStats::default(),
            gh_reporter: None,
        })
    }

    /// Load the RSA-2048 test fixture credential.
    fn load_test_credential() -> (String, crate::signer::SigningCredentials) {
        // Path is relative to the workspace root during `cargo test`.
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rsa2048.pfx");
        let cred = crate::signer::SigningCredentials::from_pfx(&fixture, "test")
            .expect("rsa2048.pfx with password 'test'");
        ("test".to_string(), cred)
    }

    /// Issue a GET request against the router and return the response.
    async fn get(state: Arc<AppState>, uri: &str) -> axum::response::Response {
        use tower::ServiceExt as _;

        let router = crate::web::build_router(state);
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap();
        router.oneshot(request).await.unwrap()
    }

    /// Issue a POST request with an arbitrary body against the router.
    ///
    /// Sets `Content-Length` from `body.len()` to match realistic clients —
    /// without it, the body-limit layer cannot pre-reject oversized uploads.
    async fn post_raw(
        state: Arc<AppState>,
        uri: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> axum::response::Response {
        use tower::ServiceExt as _;

        let router = crate::web::build_router(state);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .header(axum::http::header::CONTENT_LENGTH, body.len())
            .body(axum::body::Body::from(body))
            .unwrap();
        router.oneshot(request).await.unwrap()
    }

    /// Build a minimal multipart/form-data body with a single `file` field.
    ///
    /// Returns `(content_type_header, body_bytes)`.
    fn build_multipart_with_file(filename: &str, data: &[u8]) -> (String, Vec<u8>) {
        let boundary = "testboundary1234567890";
        let content_type = format!("multipart/form-data; boundary={boundary}");

        let mut body = Vec::new();
        // Part header
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        (content_type, body)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = make_test_state(vec![]);
        let resp = get(state, "/api/v1/health").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        use http_body_util::BodyExt as _;

        let state = make_test_state(vec![]);
        let resp = get(state, "/api/v1/status").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Body must be valid JSON with the expected fields.
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("status body is JSON");
        assert_eq!(json["status"], "running");
        assert!(json["uptime_seconds"].is_number());
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_sign_endpoint_no_file_returns_400() {
        // Posting with the wrong content-type causes the multipart extractor to
        // reject the request with 400 Bad Request before any handler logic runs.
        let state = make_test_state(vec![]);
        let resp = post_raw(state, "/api/v1/sign", "application/json", b"{}".to_vec()).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_endpoint_no_file_returns_400() {
        // Same as sign: wrong content-type produces a multipart rejection (400).
        let state = make_test_state(vec![]);
        let resp = post_raw(state, "/api/v1/verify", "application/json", b"{}".to_vec()).await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_certificate_endpoint_no_credentials() {
        use http_body_util::BodyExt as _;

        let state = make_test_state(vec![]);
        let resp = get(state, "/api/v1/certificate").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("certificate body is JSON");
        // No credentials — should report the error key.
        assert_eq!(json["error"], "no_certificates");
    }

    #[tokio::test]
    async fn test_certificate_endpoint_with_credentials() {
        use http_body_util::BodyExt as _;

        let cred = load_test_credential();
        let state = make_test_state(vec![cred]);
        let resp = get(state, "/api/v1/certificate").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("certificate body is JSON");

        let certs = json["certificates"].as_array().expect("certificates array");
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0]["name"], "test");
        assert!(certs[0]["fingerprint_sha256"].is_string());
        assert!(certs[0]["cert_size_bytes"].is_number());
    }

    #[tokio::test]
    async fn test_sign_endpoint_empty_multipart_returns_500() {
        // A valid multipart request with no `file` field reaches the handler and
        // returns 500 (Internal: "No file uploaded").
        let state = make_test_state(vec![load_test_credential()]);
        let boundary = "testbnd";
        let content_type = format!("multipart/form-data; boundary={boundary}");
        // Empty multipart — just the closing delimiter.
        let body = format!("--{boundary}--\r\n").into_bytes();

        let resp = post_raw(state, "/api/v1/sign", &content_type, body).await;
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_fallback_returns_404() {
        use http_body_util::BodyExt as _;

        let state = make_test_state(vec![]);
        let resp = get(state, "/api/v1/nonexistent-endpoint").await;
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).expect("fallback body is JSON");
        assert_eq!(json["error"], "not_found");
    }

    // ─── Body-limit enforcement tests (P1 security fix) ─────────────────────

    /// Build an [`AppState`] with a tiny `max_upload_size` so tests can exceed
    /// the limit without allocating huge buffers.
    fn make_test_state_with_max(max_upload_size: u64) -> Arc<AppState> {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let audit_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);

        let config = SignConfig {
            dev_mode: true,
            require_timestamp: false,
            audit_log: audit_path.clone(),
            max_upload_size,
            ..SignConfig::default()
        };

        Arc::new(AppState {
            config,
            credentials: tokio::sync::RwLock::new(vec![]),
            default_credential: tokio::sync::RwLock::new(0),
            audit: crate::web::audit::AuditLogger::new(&audit_path).expect("audit logger"),
            started_at: std::time::Instant::now(),
            stats: crate::web::SigningStats::default(),
            gh_reporter: None,
        })
    }

    /// POST a multipart body larger than `max_upload_size` — must be rejected
    /// at the axum layer with 413 Payload Too Large, NOT 500 Internal.
    ///
    /// Without pre-buffer enforcement the oversized body is streamed through
    /// the multipart extractor and the resulting error was mapped to 500,
    /// letting attackers observe internal error messages and forcing the
    /// server to read significant data before rejecting.
    #[tokio::test]
    async fn test_sign_oversized_body_rejected_with_413() {
        let max = 1024u64;
        let state = make_test_state_with_max(max);
        // Build a multipart body whose payload exceeds `max`.
        let oversized = vec![0xAAu8; (max as usize) * 4];
        let (ct, body) = build_multipart_with_file("big.exe", &oversized);
        assert!(body.len() as u64 > max);

        let resp = post_raw(state, "/api/v1/sign", &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "oversized upload must return 413, got {}",
            resp.status()
        );
    }

    /// Same for `/api/v1/verify` — every multipart endpoint must enforce the
    /// limit uniformly.
    #[tokio::test]
    async fn test_verify_oversized_body_rejected_with_413() {
        let max = 1024u64;
        let state = make_test_state_with_max(max);
        let oversized = vec![0xAAu8; (max as usize) * 4];
        let (ct, body) = build_multipart_with_file("big.exe", &oversized);

        let resp = post_raw(state, "/api/v1/verify", &ct, body).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "oversized verify upload must return 413, got {}",
            resp.status()
        );
    }

    /// A request whose declared `Content-Length` exceeds the limit must be
    /// rejected BEFORE the body is read (pre-buffer enforcement). This is
    /// the defining property of the P1 fix: no bytes of a lying client's
    /// payload are buffered when the header already reveals the overflow.
    #[tokio::test]
    async fn test_content_length_header_exceeds_limit_rejected_with_413() {
        use tower::ServiceExt as _;

        let max = 1024u64;
        let state = make_test_state_with_max(max);
        let router = crate::web::build_router(state);

        // Craft a tiny body but a Content-Length header that claims it's huge.
        // axum will compare CL against the limit and reject with 413 before
        // streaming. We test with a legitimately oversized body to avoid
        // ambiguous framing; the point is Content-Length > max.
        let body_bytes = vec![0u8; (max as usize) * 2];
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/sign")
            .header(
                axum::http::header::CONTENT_TYPE,
                "multipart/form-data; boundary=xxxx",
            )
            .header(axum::http::header::CONTENT_LENGTH, body_bytes.len())
            .body(axum::body::Body::from(body_bytes))
            .unwrap();

        let resp = router.oneshot(request).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "Content-Length > max_upload_size must return 413 pre-buffer"
        );
    }

    /// Requests within the limit must NOT be rejected by the body-limit
    /// layer (regression guard: over-eager enforcement would 413 legit uploads).
    #[tokio::test]
    async fn test_under_limit_multipart_not_413() {
        let max = 64 * 1024u64;
        let state = make_test_state_with_max(max);
        let small = vec![0u8; 256]; // well under max
        let (ct, body) = build_multipart_with_file("small.exe", &small);
        assert!((body.len() as u64) < max);

        let resp = post_raw(state, "/api/v1/sign", &ct, body).await;
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "under-limit request must not be rejected as too large"
        );
    }

    /// Oversized body WITHOUT a `Content-Length` header — the mid-stream
    /// (chunked transfer-encoding) path must also be bounded. The Content-Length
    /// pre-buffer rejection protects honest clients, but a lying client can
    /// omit CL entirely and stream arbitrary bytes. `RequestBodyLimitLayer`
    /// must close the connection / return 413 once the streamed bytes exceed
    /// `max_upload_size`.
    #[tokio::test]
    async fn test_sign_oversized_no_content_length_rejected() {
        use tower::ServiceExt as _;

        let max = 1024u64;
        let state = make_test_state_with_max(max);
        let router = crate::web::build_router(state);

        // Valid multipart body but 4× the limit, and NO Content-Length header.
        let oversized = vec![0xAAu8; (max as usize) * 4];
        let (ct, body) = build_multipart_with_file("big.exe", &oversized);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/sign")
            .header(axum::http::header::CONTENT_TYPE, ct)
            // Deliberately no CONTENT_LENGTH.
            .body(axum::body::Body::from(body))
            .unwrap();

        let resp = router.oneshot(request).await.unwrap();
        // Without CL, the stream path must still reject oversized payloads.
        // axum/tower-http returns 413 once the cumulative body exceeds the limit.
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "streaming (no Content-Length) oversized body must return 413, got {}",
            resp.status()
        );
    }

    /// Exact-boundary test: a request whose Content-Length equals
    /// `max_upload_size` must be ACCEPTED by the body-limit layer (not 413).
    /// Off-by-one in the limit check would reject legitimate uploads sitting
    /// on the boundary.
    #[tokio::test]
    async fn test_exact_boundary_content_length_not_413() {
        use tower::ServiceExt as _;

        // Pick a max large enough that a valid multipart body exists with
        // total length exactly `max`.
        let max = 4096u64;
        let state = make_test_state_with_max(max);
        let router = crate::web::build_router(state);

        // Construct a multipart body whose total length equals `max`.
        // Start with a zero-byte payload, measure wrapper overhead, then
        // pad the payload so the full body is exactly `max` bytes.
        let (_ct0, wrapper_only) = build_multipart_with_file("exact.bin", &[]);
        let overhead = wrapper_only.len() as u64;
        assert!(overhead < max, "wrapper overhead must fit within max");
        let pad = (max - overhead) as usize;
        let payload = vec![0x42u8; pad];
        let (ct, body) = build_multipart_with_file("exact.bin", &payload);
        assert_eq!(
            body.len() as u64,
            max,
            "constructed body must exactly match the boundary"
        );

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/sign")
            .header(axum::http::header::CONTENT_TYPE, ct)
            .header(axum::http::header::CONTENT_LENGTH, body.len())
            .body(axum::body::Body::from(body))
            .unwrap();

        let resp = router.oneshot(request).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "body of length == max_upload_size must not be rejected as too large"
        );
    }

    fn make_user(groups: Vec<String>, is_admin: bool) -> UserInfo {
        let config = LdapConfig {
            cert_groups: [("server".into(), "cn=server-signers".into())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let allowed_cert_names: Vec<String> = config
            .cert_groups
            .iter()
            .filter(|(_, group_dn)| groups.iter().any(|g| g == *group_dn))
            .map(|(cert_name, _)| cert_name.clone())
            .collect();
        UserInfo {
            username: "testuser".into(),
            email: None,
            display_name: None,
            groups,
            is_admin,
            allowed_cert_names,
        }
    }

    fn config_with_cert_groups() -> SignConfig {
        let mut config = SignConfig::default();
        config.ldap.enabled = true;
        config.ldap.cert_groups = [("server".into(), "cn=server-signers".into())]
            .into_iter()
            .collect();
        config
    }

    #[test]
    fn cert_auth_no_ldap_allows_all() {
        let config = SignConfig::default();
        assert!(check_cert_authorization(None, "server", &config).is_ok());
    }

    #[test]
    fn cert_auth_no_cert_groups_allows_all() {
        let mut config = SignConfig::default();
        config.ldap.enabled = true;
        let user = make_user(vec![], false);
        assert!(check_cert_authorization(Some(&user), "server", &config).is_ok());
    }

    #[test]
    fn cert_auth_admin_bypasses_groups() {
        let config = config_with_cert_groups();
        let user = make_user(vec![], true);
        assert!(check_cert_authorization(Some(&user), "server", &config).is_ok());
    }

    #[test]
    fn cert_auth_user_in_group_allowed() {
        let config = config_with_cert_groups();
        let user = make_user(vec!["cn=server-signers".into()], false);
        assert!(check_cert_authorization(Some(&user), "server", &config).is_ok());
    }

    #[test]
    fn cert_auth_user_not_in_group_denied() {
        let config = config_with_cert_groups();
        let user = make_user(vec!["cn=other-group".into()], false);
        assert!(check_cert_authorization(Some(&user), "server", &config).is_err());
    }

    #[test]
    fn cert_auth_unmapped_cert_allowed() {
        let config = config_with_cert_groups();
        let user = make_user(vec![], false);
        // "desktop" has no group mapping, so anyone can use it
        assert!(check_cert_authorization(Some(&user), "desktop", &config).is_ok());
    }

    #[test]
    fn cert_auth_no_user_with_ldap_denied() {
        let config = config_with_cert_groups();
        assert!(check_cert_authorization(None, "server", &config).is_err());
    }

    // ── Web UI connectivity tests ──
    // These tests prove all frontend components are connected to the backend.

    #[tokio::test]
    async fn test_root_redirects_to_index() {
        let state = make_test_state(vec![]);
        let resp = get(state, "/").await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::PERMANENT_REDIRECT,
            "Root must redirect to /static/index.html"
        );
        let location = resp
            .headers()
            .get("location")
            .expect("redirect must have location");
        assert_eq!(
            location.to_str().unwrap(),
            "/static/index.html",
            "Root must redirect to /static/index.html"
        );
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        let state = make_test_state(vec![]);
        let resp = get(state, "/api/v1/health").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let headers = resp.headers();

        // HSTS
        assert!(
            headers.contains_key("strict-transport-security"),
            "HSTS header must be present"
        );

        // X-Frame-Options
        assert_eq!(
            headers.get("x-frame-options").unwrap().to_str().unwrap(),
            "DENY",
            "X-Frame-Options must be DENY"
        );

        // X-Content-Type-Options
        assert_eq!(
            headers
                .get("x-content-type-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff",
            "X-Content-Type-Options must be nosniff"
        );

        // CSP must be present and must NOT contain unsafe-inline
        let csp = headers
            .get("content-security-policy")
            .expect("CSP header must be present")
            .to_str()
            .unwrap();
        assert!(
            !csp.contains("unsafe-inline"),
            "CSP must not contain 'unsafe-inline'"
        );
        assert!(
            csp.contains("default-src 'self'"),
            "CSP must have default-src 'self'"
        );

        // Referrer-Policy
        assert!(
            headers.contains_key("referrer-policy"),
            "Referrer-Policy header must be present"
        );

        // Server header must be removed
        assert!(
            !headers.contains_key("server"),
            "Server header must be removed"
        );
    }

    #[tokio::test]
    async fn test_admin_stats_returns_json() {
        use http_body_util::BodyExt as _;

        // Admin stats should work in dev_mode (debug build)
        let mut state = make_test_state(vec![]);
        Arc::get_mut(&mut state).unwrap().config.dev_mode = true;
        let resp = get(state, "/admin/stats").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("stats body is JSON");
        assert!(
            json["uptime_seconds"].is_number(),
            "stats must include uptime_seconds"
        );
        assert!(
            json["files_signed"].is_number(),
            "stats must include files_signed"
        );
    }

    #[tokio::test]
    async fn test_admin_audit_returns_json() {
        use http_body_util::BodyExt as _;

        let mut state = make_test_state(vec![]);
        Arc::get_mut(&mut state).unwrap().config.dev_mode = true;
        let resp = get(state, "/admin/audit").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("audit body is JSON");
        assert!(json["entries"].is_array(), "audit must have entries array");
    }

    #[tokio::test]
    async fn test_admin_certs_returns_json() {
        use http_body_util::BodyExt as _;

        let cred = load_test_credential();
        let mut state = make_test_state(vec![cred]);
        Arc::get_mut(&mut state).unwrap().config.dev_mode = true;
        let resp = get(state, "/admin/certs").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("certs body is JSON");
        let certs = json["certificates"].as_array().expect("certificates array");
        assert_eq!(certs.len(), 1, "must list the loaded test certificate");
    }

    #[tokio::test]
    async fn test_admin_no_auth_denied() {
        // Without dev_mode and without auth tokens, admin endpoints must be denied.
        // We must explicitly create a state with dev_mode=false since
        // make_test_state sets dev_mode=true for LDAP bypass in tests.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let audit_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);

        let config = SignConfig {
            dev_mode: false, // Production mode — no dev bypass
            require_timestamp: false,
            audit_log: audit_path.clone(),
            ..SignConfig::default()
        };
        let state = Arc::new(crate::web::AppState {
            config,
            credentials: tokio::sync::RwLock::new(vec![]),
            default_credential: tokio::sync::RwLock::new(0),
            audit: crate::web::audit::AuditLogger::new(&audit_path).expect("audit logger"),
            started_at: std::time::Instant::now(),
            stats: crate::web::SigningStats::default(),
            gh_reporter: None,
        });

        let resp = get(state, "/admin/stats").await;
        // Returns 404 (not 401/403) to prevent endpoint enumeration
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "Admin without auth must return 404"
        );
    }

    #[tokio::test]
    async fn test_verify_detached_no_file_returns_400() {
        let state = make_test_state(vec![]);
        let resp = post_raw(
            state,
            "/api/v1/verify-detached",
            "application/json",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sign_batch_no_file_returns_400() {
        let state = make_test_state(vec![]);
        let resp = post_raw(
            state,
            "/api/v1/sign-batch",
            "application/json",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_sign_detached_no_file_returns_400() {
        let state = make_test_state(vec![]);
        let resp = post_raw(
            state,
            "/api/v1/sign-detached",
            "application/json",
            b"{}".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_classify_file_type_pe() {
        assert_eq!(classify_file_type("test.exe"), ("Authenticode", false));
        assert_eq!(classify_file_type("test.dll"), ("Authenticode", false));
        assert_eq!(classify_file_type("test.sys"), ("Authenticode", false));
    }

    #[test]
    fn test_classify_file_type_powershell() {
        assert_eq!(classify_file_type("script.ps1"), ("PowerShell", false));
    }

    #[test]
    fn test_classify_file_type_msi_cab() {
        assert_eq!(classify_file_type("setup.msi"), ("MSI Authenticode", false));
        assert_eq!(
            classify_file_type("archive.cab"),
            ("CAB Authenticode", false)
        );
    }

    #[test]
    fn test_classify_file_type_unknown_is_detached() {
        assert_eq!(classify_file_type("data.bin"), ("Detached CMS", true));
        assert_eq!(classify_file_type("readme.txt"), ("Detached CMS", true));
        assert_eq!(classify_file_type("noext"), ("Detached CMS", true));
    }
}
