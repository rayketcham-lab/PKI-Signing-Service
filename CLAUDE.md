# SPORK Sign -- Code Signing Engine

Standalone code signing engine -- Authenticode, PKCS#7, RFC 3161 timestamping.

**Version:** 0.3.0-beta.1 | **Extracted from:** spork-ca engine | **Date:** 2026-03-02

## MANDATORY Rules
### Bash Commands: NO CHAINING (CRITICAL)
- NEVER use && || or ; to chain commands

### Code Provenance
- ALL code is original -- written from scratch
- NEVER copy code from GitHub, Stack Overflow, or other projects

## Architecture
- `crates/spork-sign/` -- Code signing engine, PFX import, Authenticode, PowerShell, TSA

## Quick Reference
```bash
cargo build --release
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```
