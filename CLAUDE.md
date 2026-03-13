# Code Signing Service -- Code Signing Engine

Standalone code signing engine -- Authenticode, PKCS#7, RFC 3161 timestamping, detached CMS signing.

**Version:** 0.5.0 | **License:** MIT | **Date:** 2026-03-12

## MANDATORY Rules
### Bash Commands: NO CHAINING (CRITICAL)
- NEVER use && || or ; to chain commands

### Code Provenance
- ALL code is original -- written from scratch
- NEVER copy code from GitHub, Stack Overflow, or other projects

## Architecture
- `crates/pki-sign/` -- Code signing engine, PFX import, Authenticode, PowerShell, TSA, detached CMS, LDAP auth

## Quick Reference
```bash
cargo build --release
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```
