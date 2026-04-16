//! Supply-chain regression tests.
//!
//! These tests guard against silent downgrades of security-critical
//! dependencies by inspecting the workspace `Cargo.lock`. They run as a
//! normal integration test so CI catches drift automatically.

use std::path::PathBuf;

/// Locate the workspace `Cargo.lock` starting from this crate's manifest.
fn workspace_lockfile() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..4 {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    panic!("Cargo.lock not found walking up from CARGO_MANIFEST_DIR");
}

/// Return the `version = "..."` string for a named crate in Cargo.lock,
/// or `None` if the crate is not in the dependency graph.
fn locked_version(lock: &str, crate_name: &str) -> Option<String> {
    let needle = format!("name = \"{crate_name}\"");
    let block = lock.split("\n[[package]]").find(|b| b.contains(&needle))?;
    for line in block.lines() {
        if let Some(rest) = line.strip_prefix("version = \"") {
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

/// Parse a "major.minor.patch" string into a comparable tuple.
fn parse_semver(v: &str) -> (u64, u64, u64) {
    let mut parts = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// rustls-webpki must stay at or above the version that patches the
/// March 2026 CVE cluster (malformed certificate chain panic / unbounded
/// recursion). A downgrade via lockfile churn would silently reintroduce
/// those vulnerabilities.
#[test]
fn rustls_webpki_has_cve_patch() {
    let lock_path = workspace_lockfile();
    let lock = std::fs::read_to_string(&lock_path).expect("read Cargo.lock");
    let version = locked_version(&lock, "rustls-webpki")
        .expect("rustls-webpki must appear in the workspace dependency graph");

    let min = (0, 103, 12);
    let got = parse_semver(&version);
    assert!(
        got >= min,
        "rustls-webpki {version} is below the CVE-patched floor 0.103.12 — \
         upgrading to a fixed version is required before shipping"
    );
}
