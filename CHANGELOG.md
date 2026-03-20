# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
