# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
