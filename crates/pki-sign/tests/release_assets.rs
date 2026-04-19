//! Release-asset smoke test.
//!
//! Parses the README install block and the release workflow, then asserts
//! that every asset the README tells users to download is actually produced
//! by `release.yml`. This catches README/asset-name drift before publishing,
//! the same class of bug that shipped broken install links in v0.5.8.

use std::path::PathBuf;

/// Locate a repo-root file starting from this crate's manifest directory.
fn repo_root_file(relative: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..4 {
        let candidate = dir.join(relative);
        if candidate.is_file() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    panic!("{relative} not found walking up from CARGO_MANIFEST_DIR");
}

/// Pull every `pki-sign-*` asset name referenced in `releases/latest/download/`
/// URLs in the README.
fn readme_asset_names(readme: &str) -> Vec<String> {
    let marker = "releases/latest/download/";
    let mut out = Vec::new();
    for line in readme.lines() {
        let mut rest = line;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            // Asset name terminates at whitespace, `)`, `]`, or backtick.
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ']' | '`' | '"'))
                .unwrap_or(after.len());
            let name = &after[..end];
            if name.starts_with("pki-sign-") {
                out.push(name.to_string());
            }
            rest = &after[end..];
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Derive the set of asset *basenames* published by `release.yml` by looking
/// at the Package/Copy-Item lines for `dist/`. Each `pki-sign-*` binary gets
/// a `.sha256` sibling from the packaging step and a `.cosign-bundle` sibling
/// from the cosign signing step (cosign 2.x --new-bundle-format is
/// self-contained — no separate .sig is produced).
fn release_workflow_assets(workflow: &str) -> Vec<String> {
    let mut binaries: Vec<String> = Vec::new();
    for line in workflow.lines() {
        for token in line.split_whitespace() {
            // Tokens of interest look like:
            //   dist/pki-sign-linux-x86_64
            //   dist\pki-sign-windows-x86_64.exe
            let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | '\\' | '(' | ')'));
            if let Some(rest) = token
                .strip_prefix("dist/")
                .or_else(|| token.strip_prefix("dist\\"))
            {
                if rest.starts_with("pki-sign-")
                    && !rest.contains('*')
                    && !rest.ends_with(".sha256")
                {
                    binaries.push(rest.to_string());
                }
            }
        }
    }
    binaries.sort();
    binaries.dedup();

    let cosign_signs = workflow.contains("cosign sign-blob");

    let mut all: Vec<String> = Vec::new();
    for name in &binaries {
        all.push(name.clone());
        all.push(format!("{name}.sha256"));
        if cosign_signs {
            all.push(format!("{name}.cosign-bundle"));
        }
    }
    all.sort();
    all.dedup();
    all
}

#[test]
fn readme_asset_names_match_release_workflow() {
    let readme = std::fs::read_to_string(repo_root_file("README.md")).expect("read README.md");
    let workflow = std::fs::read_to_string(repo_root_file(".github/workflows/release.yml"))
        .expect("read release.yml");

    let readme_names = readme_asset_names(&readme);
    assert!(
        !readme_names.is_empty(),
        "README must reference at least one release asset"
    );

    let published = release_workflow_assets(&workflow);
    assert!(
        !published.is_empty(),
        "release.yml must publish at least one pki-sign-* asset"
    );

    for name in &readme_names {
        assert!(
            published.iter().any(|p| p == name),
            "README references asset `{name}` that release.yml does not publish. \
             Published assets: {published:?}"
        );
    }
}

/// Regression test for gh #69: cosign sign-blob in release.yml previously
/// silently succeeded even when no signatures were produced because the loop
/// was not guarded with `set -e` + an existence check. This test asserts both
/// guards remain wired so a revert would fail CI instead of shipping an
/// unsigned release.
#[test]
fn cosign_guard_loop_prevents_silent_sig_fail() {
    let workflow = std::fs::read_to_string(repo_root_file(".github/workflows/release.yml"))
        .expect("read release.yml");

    assert!(
        workflow.contains("set -euo pipefail"),
        "release.yml cosign step must start with `set -euo pipefail` so sign-blob \
         failures abort the job (gh #69 regression)"
    );

    assert!(
        workflow.contains("cosign sign-blob"),
        "release.yml must invoke `cosign sign-blob` to produce signatures"
    );

    let has_existence_guard =
        workflow.contains(r#"if [[ ! -f "${f}.cosign-bundle" ]]"#);
    assert!(
        has_existence_guard,
        "release.yml must verify `${{f}}.cosign-bundle` exists after signing \
         (gh #69 regression — prevents silently shipping unsigned assets)"
    );

    assert!(
        workflow.contains("missing cosign bundle") && workflow.contains("exit 1"),
        "release.yml's cosign guard loop must `exit 1` with a clear error when \
         the cosign bundle is missing (gh #69 regression)"
    );
}
