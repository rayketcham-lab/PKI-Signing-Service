//! LDAP header pass-through authentication.
//!
//! Extracts user identity and group membership from HTTP headers set by a
//! reverse proxy that handles LDAP authentication (e.g., Apache mod_authnz_ldap,
//! nginx auth_request with ldap-auth-daemon).
//!
//! When LDAP is disabled, all access is permitted (development mode).

use axum::http::HeaderMap;

use crate::config::LdapConfig;

/// Authenticated user information extracted from LDAP proxy headers.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Authenticated username.
    pub username: String,
    /// User's email address (if provided).
    pub email: Option<String>,
    /// User's display name (if provided).
    pub display_name: Option<String>,
    /// User's group memberships.
    pub groups: Vec<String>,
    /// Whether the user is in the admin group.
    pub is_admin: bool,
    /// Certificate names the user is authorized to use (based on group mappings).
    pub allowed_cert_names: Vec<String>,
}

/// Extract user information from reverse proxy headers.
///
/// Returns `None` if the user header is missing (unauthenticated request).
pub fn extract_user_from_headers(
    headers: &HeaderMap,
    ldap_config: &LdapConfig,
) -> Option<UserInfo> {
    let username = headers
        .get(&ldap_config.user_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())?;

    let email = headers
        .get(&ldap_config.email_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let display_name = headers
        .get(&ldap_config.display_name_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let groups: Vec<String> = headers
        .get(&ldap_config.groups_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(&ldap_config.groups_delimiter)
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let is_admin =
        !ldap_config.admin_group.is_empty() && groups.iter().any(|g| g == &ldap_config.admin_group);

    let allowed_cert_names: Vec<String> = ldap_config
        .cert_groups
        .iter()
        .filter(|(_, group_dn)| groups.iter().any(|g| g == *group_dn))
        .map(|(cert_name, _)| cert_name.clone())
        .collect();

    Some(UserInfo {
        username,
        email,
        display_name,
        groups,
        is_admin,
        allowed_cert_names,
    })
}
