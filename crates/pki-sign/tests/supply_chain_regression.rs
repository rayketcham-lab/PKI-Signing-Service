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
///
/// Fails loudly on malformed input: a silent `unwrap_or(0)` here would let a
/// version string like "0.103.x-beta" quietly become `(0, 0, 0)` and always
/// compare *below* the floor, which would mask a real downgrade behind a
/// spurious test failure instead of revealing it.
fn parse_semver(v: &str) -> (u64, u64, u64) {
    let mut parts = v.split('.').map(|p| {
        p.split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .unwrap_or_else(|_| {
                panic!("supply-chain regression: cannot parse version component `{p}` in `{v}`")
            })
    });
    let major = parts
        .next()
        .unwrap_or_else(|| panic!("supply-chain regression: version `{v}` missing major"));
    let minor = parts
        .next()
        .unwrap_or_else(|| panic!("supply-chain regression: version `{v}` missing minor"));
    let patch = parts
        .next()
        .unwrap_or_else(|| panic!("supply-chain regression: version `{v}` missing patch"));
    (major, minor, patch)
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

/// `ring` is the hash / signature / RNG primitive behind rustls, Authenticode,
/// and CMS signing. 0.17.14 is the first release to incorporate the upstream
/// fixes for the 2025 constant-time / aarch64 regressions; any downgrade below
/// that floor would silently bring those back.
#[test]
fn ring_at_or_above_security_floor() {
    let lock_path = workspace_lockfile();
    let lock = std::fs::read_to_string(&lock_path).expect("read Cargo.lock");
    let version =
        locked_version(&lock, "ring").expect("ring must appear in the workspace dependency graph");

    let min = (0, 17, 14);
    let got = parse_semver(&version);
    assert!(
        got >= min,
        "ring {version} is below the security floor 0.17.14 — a downgrade \
         would reintroduce the 2025 constant-time / aarch64 fixes regressions"
    );
}

/// `rustls` anchors TLS for the HTTPS listener and every outbound TSA/OCSP
/// call. 0.23.37 is the baseline that pulls in the fixed rustls-webpki and
/// matches the currently-audited posture; a downgrade would silently revert
/// both the webpki CVE patches and the rustls-level hardening that ships
/// alongside.
#[test]
fn rustls_at_or_above_security_floor() {
    let lock_path = workspace_lockfile();
    let lock = std::fs::read_to_string(&lock_path).expect("read Cargo.lock");
    let version = locked_version(&lock, "rustls")
        .expect("rustls must appear in the workspace dependency graph");

    let min = (0, 23, 37);
    let got = parse_semver(&version);
    assert!(
        got >= min,
        "rustls {version} is below the security floor 0.23.37 — a downgrade \
         would pair with an older rustls-webpki and revert audited hardening"
    );
}

/// deny.toml ignores RUSTSEC-2023-0071 (rsa Marvin timing sidechannel) on the
/// justification that v0.6.0 deleted the entire CMS EnvelopedData / OAEP
/// surface. This test grepscans the `pki-sign` source tree and fails CI if
/// any `oaep_decrypt` fn, `Oaep` import, or `pkcs7::enveloped` reference
/// leaks back in. The advisory ignore is only sound while this invariant
/// holds.
#[test]
fn rsa_no_oaep_decrypt_reachable_from_web() {
    let mut src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    src_root.push("src");
    assert!(
        src_root.is_dir(),
        "expected {} to be a directory",
        src_root.display()
    );

    let forbidden: &[&str] = &[
        "oaep_decrypt",
        "rsa::Oaep",
        "rsa::oaep::",
        "pkcs7::enveloped",
        "crypto::rsa_oaep",
        "crypto::hkdf",
        "crypto::kem",
    ];

    let mut offenders: Vec<(PathBuf, String, String)> = Vec::new();
    walk_rs_files(&src_root, &mut |path| {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    offenders.push((
                        path.to_path_buf(),
                        needle.to_string(),
                        format!("line {}: {}", lineno + 1, line.trim()),
                    ));
                }
            }
        }
    });

    assert!(
        offenders.is_empty(),
        "RUSTSEC-2023-0071 ignore invariant broken: OAEP / EnvelopedData surface \
         resurfaced in production code. Either re-gate the advisory or remove \
         these references. Offenders: {offenders:#?}"
    );
}

/// `rustls-webpki` is a *transitive* dependency — it comes in via `rustls` for
/// HTTPS to TSA / OCSP / LDAP endpoints, not via any direct API call in this
/// crate. That means the `rustls_webpki_has_cve_patch` version-floor test is
/// the correct shape for the CVE regression: we don't exercise webpki code
/// paths directly, so a behavioral test would be testing upstream, not us.
///
/// This test guards the "transitive-only" invariant: if a future change
/// introduces a direct `webpki::` / `rustls_webpki::` import into the pki-sign
/// source tree, the advisory posture changes (direct callsites might exercise
/// CVE paths), and this test will fail so the change can be reviewed and the
/// regression story updated.
#[test]
fn rustls_webpki_stays_transitive_only() {
    let mut src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    src_root.push("src");
    assert!(
        src_root.is_dir(),
        "expected {} to be a directory",
        src_root.display()
    );

    let forbidden: &[&str] = &[
        "use webpki",
        "use rustls_webpki",
        "rustls_webpki::",
        " webpki::", // leading space avoids matching "rustls-webpki" in comments / strings
    ];

    let mut offenders: Vec<(PathBuf, String, String)> = Vec::new();
    walk_rs_files(&src_root, &mut |path| {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        for (lineno, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    offenders.push((
                        path.to_path_buf(),
                        (*needle).to_string(),
                        format!("line {}: {}", lineno + 1, line.trim()),
                    ));
                }
            }
        }
    });

    assert!(
        offenders.is_empty(),
        "webpki transitive-only invariant broken: a direct webpki API call appeared. \
         A behavioral CVE regression test is now required to accompany any direct \
         callsite. Offenders: {offenders:#?}"
    );
}

fn walk_rs_files(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs_files(&path, visit);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            visit(&path);
        }
    }
}
