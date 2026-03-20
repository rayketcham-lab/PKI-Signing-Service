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

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::*;
    use crate::config::LdapConfig;

    fn default_ldap_config() -> LdapConfig {
        LdapConfig::default()
    }

    fn ldap_config_with_admin_group(group: &str) -> LdapConfig {
        LdapConfig {
            admin_group: group.to_string(),
            ..LdapConfig::default()
        }
    }

    #[test]
    fn test_extract_user_all_headers() {
        let cfg = default_ldap_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            cfg.user_header.parse::<axum::http::HeaderName>().unwrap(),
            "alice".parse().unwrap(),
        );
        headers.insert(
            cfg.email_header.parse::<axum::http::HeaderName>().unwrap(),
            "alice@example.com".parse().unwrap(),
        );
        headers.insert(
            cfg.display_name_header
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            "Alice Smith".parse().unwrap(),
        );
        headers.insert(
            cfg.groups_header.parse::<axum::http::HeaderName>().unwrap(),
            "cn=devs,dc=example,dc=com".parse().unwrap(),
        );

        let user = extract_user_from_headers(&headers, &cfg).expect("must return Some");
        assert_eq!(user.username, "alice");
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
        assert_eq!(user.display_name.as_deref(), Some("Alice Smith"));
        assert_eq!(user.groups, vec!["cn=devs,dc=example,dc=com"]);
    }

    #[test]
    fn test_extract_user_missing_required() {
        // No user header — function must return None.
        let cfg = default_ldap_config();
        let headers = HeaderMap::new();
        let result = extract_user_from_headers(&headers, &cfg);
        assert!(result.is_none(), "missing user header must result in None");
    }

    #[test]
    fn test_extract_admin_group_match() {
        let admin_dn = "cn=admins,dc=example,dc=com";
        let cfg = ldap_config_with_admin_group(admin_dn);

        let mut headers = HeaderMap::new();
        headers.insert(
            cfg.user_header.parse::<axum::http::HeaderName>().unwrap(),
            "bob".parse().unwrap(),
        );
        // Groups header contains the admin group separated by the default delimiter (";").
        let groups_value = format!("cn=devs,dc=example,dc=com;{admin_dn}");
        headers.insert(
            cfg.groups_header.parse::<axum::http::HeaderName>().unwrap(),
            groups_value.parse().unwrap(),
        );

        let user = extract_user_from_headers(&headers, &cfg).expect("must return Some");
        assert!(user.is_admin, "user in admin group must have is_admin=true");
    }

    #[test]
    fn test_extract_admin_group_no_match() {
        let cfg = ldap_config_with_admin_group("cn=admins,dc=example,dc=com");

        let mut headers = HeaderMap::new();
        headers.insert(
            cfg.user_header.parse::<axum::http::HeaderName>().unwrap(),
            "carol".parse().unwrap(),
        );
        headers.insert(
            cfg.groups_header.parse::<axum::http::HeaderName>().unwrap(),
            "cn=devs,dc=example,dc=com".parse().unwrap(),
        );

        let user = extract_user_from_headers(&headers, &cfg).expect("must return Some");
        assert!(
            !user.is_admin,
            "user not in admin group must have is_admin=false"
        );
    }
}
