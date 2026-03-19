# PKI Signing Service — Code Signing Engine

Standalone code signing engine — Authenticode, PKCS#7, RFC 3161 timestamping, detached CMS signing, PowerShell SIP.

**Version:** 0.5.4 | **License:** Apache-2.0 | **Date:** 2026-03-19

## MANDATORY Rules
### Bash Commands: NO CHAINING (CRITICAL)
- NEVER use && || or ; to chain commands

### Code Provenance
- ALL code is original — written from scratch
- NEVER copy code from GitHub, Stack Overflow, or other projects

## Architecture
- `crates/pki-sign/` — Code signing engine: PFX import, Authenticode (PE/CAB/MSI), PowerShell SIP, TSA, detached CMS, LDAP auth, Web UI

## Quick Reference
```bash
cargo build --release
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

## Shared Rules
Project-wide coding standards are loaded from `/opt/vmdata/system-opt/claude/.claude/rules/`:
- `language-rust.md` — Rust standards (clippy, thiserror, no hand-rolled crypto)
- `project-standards.md` — Conventional commits, no warnings, test coverage
- `language-shell.md` — Shell standards (no chaining)
