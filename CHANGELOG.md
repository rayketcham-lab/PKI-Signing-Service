# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-04-19

### Removed
- **CMS EnvelopedData encryption surface** — `pkcs7/enveloped.rs`, `pkcs7/ecdh.rs`, `pkcs7/kem.rs`, `crypto/rsa_oaep.rs`, `crypto/hkdf.rs` deleted (~3.3k LOC). This is a signing service, not a key-agreement / confidentiality product. `POST /api/v1/sign-detached` (CMS SignedData via `Pkcs7Builder::new_detached()`) already covers the "wrap any file for transport + later verify" workflow. Dep graph drops `aes-gcm`, `aes`, `aes-kw`, `cbc`, `hkdf`, and the `ecdh` feature from p256/p384/p521.
- **RFC 4998 Evidence Record Syntax (`ers.rs`)** — ~1.4k LOC removed. Long-term archive timestamps are a separate product scope; this repo ships RFC 3161 client + TSA server only.

### Changed
- Roadmap renumbered: v0.6 → v0.7 (structural clean-up), v0.7 → v0.8 (hybrid/composite).

## [0.5.11] - 2026-04-19

### Fixed
- **rustfmt violation in `tests/release_assets.rs`** — v0.5.10 CI Gate failed the Format check because the `has_existence_guard` line was split manually; rustfmt wants it on one line. Reverts to single-line form.

## [0.5.10] - 2026-04-19

### Fixed
- **Release workflow cosign step (#69 follow-up)** — cosign 2.x with `--new-bundle-format` ignores `--output-signature`, so the `.sig` file was never produced and the v0.5.9 release job failed at the post-sign existence guard. Removed the deprecated `--output-signature` flag, the `.sig` existence check, and the `.sig` upload glob. The `.cosign-bundle` is self-contained (signature + Fulcio certificate) — no separate detached signature is needed.
- `tests/release_assets.rs` updated to assert the single-bundle invariant and the simplified guard-loop error message.
- README, SECURITY.md, and CHANGELOG 0.5.9 entries corrected to describe the self-contained `.cosign-bundle` (no stray `.sig` references).

## [0.5.9] - 2026-04-19

### Security
- **CSRF Origin guard on state-changing routes (#19)** — `POST /api/v1/*` and `/admin/*` now reject browser requests whose `Origin` does not match the server's `Host` or the configured `trusted_origins` allowlist. Missing `Origin` (curl / non-browser) is allowed; cross-origin browser POSTs are rejected with a generic `404` to avoid oracle behavior. Ten unit tests in `web::middleware` pin the state machine.
- **`trusted_origins` config field** — new `SignConfig` field (default empty list → same-origin fallback) lets operators whitelist additional Origins for legitimate cross-origin browser clients.
- **`SigningAlgorithm` and `PrivateKey` marked `#[non_exhaustive]` (#20)** — external crates can no longer write exhaustive matches that silently break when new algorithms land.
- **Multipart streaming body-limit now returns 413** — uploads without a `Content-Length` header (chunked transfer-encoding) that exceed `max_upload_size` are rejected with `413 Payload Too Large` instead of `500 Internal Server Error`. The fix walks the multipart error source chain for `http_body_util::LengthLimitError` and maps it to `SignError::FileTooLarge`, closing the 500-leakage gap the pre-buffer layer left behind.
- **Release ci-gate now runs cargo-audit + cargo-deny (#70)** — vulnerable dependencies can no longer ship via the release workflow, even if admin-bypass is used on `main`.
- **Cosign signing failures now fail the release (#69)** — removed `|| echo` fallback on `gh release upload` and added a post-sign presence check for every `.cosign-bundle` (0.5.10 dropped the legacy `.sig` from the guard after cosign 2.x made it a no-op). v0.5.8 shipped without supply-chain signatures because of this silent-fail; `cosign_guard_loop_prevents_silent_sig_fail` regression test asserts the `set -euo pipefail` + existence check survive.
- **ML-DSA / SLH-DSA moved behind `pq-experimental` feature flag (#72)** — the `ml-dsa` crate and all `PrivateKey::MlDsa*` / `SigningAlgorithm::MlDsa*` / `SigningAlgorithm::SlhDsa*` variants are now gated. The default build does not resolve `ml-dsa`, which removes RUSTSEC-2025-0144 (timing side-channel), CVE-2026-22705, CVE-2026-24850, and GHSA-h37v-hp6w-2pp8 from the default dep graph. `tests/pq_feature_gate.rs` asserts the invariant at CI time via exhaustive match + `cargo tree --no-default-features --invert ml-dsa`.
- **Supply-chain version floors** — `tests/supply_chain_regression.rs` asserts locked versions `rustls-webpki >= 0.103.12`, `rustls >= 0.23.37`, `ring >= 0.17.14`; a silent downgrade via lockfile churn now fails CI.
- **SECURITY.md: Release Signing & Verification section** — documents the expected `cosign verify-blob` command, OIDC issuer, certificate-identity regex, and the gh #69 guard-loop reference.

### Fixed
- **README factual drift corrected** — rate-limit overclaim ("per-endpoint, per-IP") replaced with accurate "global in-flight concurrency cap"; stale closed-issue references (#42, #45, #46) removed; shipped `pq-experimental` gate moved from v0.6 future-roadmap to "Recently shipped"; CSRF Origin guard added to the Security feature list; `cargo test --all` standardized to `cargo test --workspace`.
- `.github/dependabot.yml` `rand` ignore rule used unsupported `versions: ["0.8.x"]` syntax (silent no-op); replaced with `update-types: [version-update:semver-major]`.
- README release-asset URLs drift guard — integration test parses README install block and asserts every `pki-sign-*` asset name is actually produced by `release.yml`.
- `sanitize_filename` UTF-8 panic on multi-byte boundary truncation; now uses `str::is_char_boundary` and has adversarial tests.
- Removed unused `SlhDsa*` match arms from `pkcs7/builder.rs` that were unreachable under the new `pq-experimental` gate.
- Clippy `manual_repeat_n`: `std::iter::repeat('a').take(N)` → `std::iter::repeat_n('a', N)` in test helpers.

### Added
- `pq-experimental` feature matrix leg in CI (#17) — `cargo test --features pq-experimental` runs on every push alongside the default build.
- `RUSTSEC-2026-0097` entry in `deny.toml` ignores with rationale comment.
- `yaml-lint` CI job covering `.github/workflows` and `.github/dependabot.yml`.
- `test_sign_oversized_no_content_length_rejected` — chunked/no-CL path 413 regression.
- `test_exact_boundary_content_length_not_413` — off-by-one regression on `body == max_upload_size`.
- `tests/supply_chain_regression.rs` — Cargo.lock version-floor assertions (rustls-webpki, rustls, ring).
- `tests/release_assets.rs` — README/release.yml asset-name drift guard + cosign guard-loop regression test.
- `tests/pq_feature_gate.rs` — compile-time + dep-tree assertions for the `pq-experimental` gate.

## [0.5.8] - 2026-04-16

### Security
- **P1 hardening: multipart body-limit pre-buffer enforcement** — added `tower_http::limit::RequestBodyLimitLayer` so `Content-Length` exceeding `max_upload_size` returns `413 Payload Too Large` before any body bytes are buffered. Prevents memory-exhaustion via lying/huge uploads at multipart-extractor edge.
- **CVE: rustls-webpki name-constraint bypasses** (RUSTSEC-2026-0098, RUSTSEC-2026-0099) — bumped `rustls-webpki` from 0.103.10 to 0.103.12 via `cargo update`. URI-name and wildcard name-constraint validation is now correct.

### Added
- Four body-limit regression tests in `web::handlers` covering sign/verify oversized-body 413, Content-Length pre-buffer 413, and under-limit negative assertion.
- Interactive demos landing page at `docs/demo.html` with six asciinema scenarios.

## [0.5.7] - 2026-03-25

### Fixed
- **CAB Authenticode interop** (#45) — reserve-header magic must be `00 00 10 00` (not `14 00 00 00`); hash covers selective fields `[0..4]+[8..34]+[56..60]+[60..sigOffset]` so osslsigncode/signtool accept output.
- **MSI Authenticode interop** (#46) — hash includes root CLSID (16 bytes) after stream contents; stream order uses raw UTF-16LE byte sort.
- CI test-coverage expansion for CAB/MSI interop.

## [0.5.6] - 2026-03-23

### Added
- **P-521 ECDSA signing** end-to-end with web e2e tests.
- **CIDR-aware reverse-proxy trust** for `X-Forwarded-For` / `X-Real-IP` — only trusted CIDRs may set `client_ip`.
- **Rate limiting** middleware per-endpoint / per-IP.
- **Cosign signing** support (keyless + key-pair) for OCI artifacts.
- **Secret scanning** pre-commit hook and CI gate.
- `client_ip` field on all audit-log records.
- Unit tests for `config`, `audit`, `ldap` modules.

### Changed
- **Error-handling refactor** — unified `AppError` variants across the web layer; consistent 4xx/5xx mapping.
- All GitHub Actions pinned to commit SHAs.

### Security
- Team-review fixes: dead-code removal, key `Zeroize` on drop paths, CI permission hardening.
- CSP hardening and fail-closed auth middleware.
- Assorted CVE patches (see commit `21879da`).

## [0.5.4] - 2026-03-20

### Added
- MSRV declared at Rust 1.88 with CI verification job
- Interop test suite: detached CMS verification via `openssl cms -verify`, RFC 3161 timestamp structure validation, CAB/MSI osslsigncode cross-verification (known gaps tracked in #45, #46)
- Daily Health Check workflow (cron 06:00 UTC) --- build, test, clippy, fmt, security audit, outdated deps
- Interop Tests workflow --- Linux (osslsigncode + openssl) and Windows runners
- README badge dashboard: CI, Daily Check, Interop, Security Regression, cargo-audit, cargo-deny, license scan, no-unsafe, clippy, rustfmt, PQC, static binary, Windows
- SECURITY.md and CHANGELOG.md

### Fixed
- **CVE: quinn-proto DoS** (RUSTSEC-2026-0037, severity 8.7) --- updated 0.11.13 to 0.11.14
- GitHub Pages deployment --- added `enablement: true` to `configure-pages`, pinned all actions to commit SHAs
- `cargo-deny` config cleanup --- removed 18 stale skip entries, 2 unused sha1 wrappers
- OpenSSL CMS interop tests skip on Windows (no `/dev/null`)
- Interop workflow uses `continue-on-error` for known-failing CAB/MSI tests

### Changed
- Version bump from 0.5.3 to 0.5.4
- Renamed "Code Signing Service" to "PKI Signing Service" across all files
- License badge and metadata updated to Apache-2.0
- `cargo-audit` CI now ignores RUSTSEC-2025-0144 (ml-dsa timing side-channel, blocked on ecosystem upgrade)

## [0.5.3] - 2026-03-13

### Added
- GitHub Pages landing page and deployment workflow
- Test PFX fixtures for CI (RSA-2048/3072/4096, ECDSA P-256/P-384)
- `cargo-deny` configuration with license, advisory, and ban checks
- rustls-pemfile advisory ignore in cargo-deny

### Fixed
- Authenticode Windows compatibility: SpcStatementType, includeResources, valid PE headers
- Authenticode signature verification: messageDigest, SpcPeImageData, SignerInfo fixes
- Insecure HTTP TSA URL warning (#12)
- Authenticode messageDigest and PS1 hash computation (#24)
- Content-Disposition header injection (#7)
- Filesystem path removal from PFX error messages

### Changed
- Switched to GitHub-hosted runners
- Replaced third-party CI actions with inline commands
- CI timeout increases for GitHub-hosted runners

## [0.5.2] - 2026-03-10

### Added
- MSI/CAB signing support
- Web UI for Code Signing as a Service
- Certificate group enforcement via LDAP
- Security hardening across web endpoints

## [0.5.1] - 2026-03-08

### Fixed
- Windows runner CI compatibility (WSL, PowerShell, rustup bootstrap)
- HTTP TSA default URL fixes

### Added
- Multi-runner CI matrix across org runners
- End-to-end signing tests in CI

## [0.5.0] - 2026-03-06

### Added
- Initial standalone release as PKI-Signing-Service
- Authenticode signing for PE (EXE, DLL, SYS), CAB, MSI
- Detached CMS/PKCS#7 signing for any file type
- PowerShell script signing with Base64 PKCS#7 blocks
- RFC 3161 timestamping with failover across multiple TSA servers
- Standalone RFC 3161 TSA server (port 3318)
- Multi-algorithm support: RSA (2048-4096), ECDSA P-256/P-384, Ed25519, ML-DSA-44/65/87
- Signature verification for Authenticode and detached CMS
- PFX/PKCS#12 import with key zeroization
- Web service mode with REST API
- LDAP authentication via header pass-through
- Certificate management API (hot-reload, listing, rotation)
- Audit logging with request ID, hash, and duration
- Evidence Record Syntax (RFC 4998) support
- Static binary via musl target
- Interactive setup wizard
- CI pipeline: fmt, clippy, test, build, musl, security audit, cargo-deny

[Unreleased]: https://github.com/rayketcham-lab/PKI-Signing-Service/compare/v0.5.4...HEAD
[0.5.4]: https://github.com/rayketcham-lab/PKI-Signing-Service/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/rayketcham-lab/PKI-Signing-Service/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/rayketcham-lab/PKI-Signing-Service/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/rayketcham-lab/PKI-Signing-Service/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/rayketcham-lab/PKI-Signing-Service/releases/tag/v0.5.0
