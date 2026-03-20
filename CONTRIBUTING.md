# Contributing

Contributions are welcome. This document covers the essentials.

## Getting Started

```bash
git clone https://github.com/rayketcham-lab/PKI-Signing-Service.git
cd PKI-Signing-Service
cargo build
cargo test --all
```

## Requirements

- Rust 1.88+ (see [MSRV policy](#msrv-policy))
- `osslsigncode` for interop tests (`apt install osslsigncode`)
- `openssl` CLI for CMS/timestamp verification tests

## Before Submitting

Run all checks:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

All three must pass with zero warnings.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add CAB signing support
fix: correct PE checksum after signature embedding
test: add ECDSA P-384 interop verification
ci: add MSRV check to CI pipeline
security: patch quinn-proto DoS vulnerability
docs: update API reference for detached signing
refactor: extract timestamp client into module
```

## Code Standards

- **No warnings** --- `cargo clippy -- -D warnings` is enforced
- **No unsafe** --- zero unsafe code policy
- **No OpenSSL** --- `cargo-deny` blocks openssl/native-tls crates
- **Error handling** --- `thiserror` for library errors, `anyhow` for application errors
- **Tests required** --- new features and bug fixes must include tests
- **Security tests** --- security-critical code requires adversarial tests
- **No hand-rolled crypto** --- use `ring`, `rustls`, `aws-lc-rs`, or RustCrypto crates

## MSRV Policy

The minimum supported Rust version is declared in `Cargo.toml` (`rust-version` field) and verified in CI. MSRV bumps are treated as breaking changes and noted in the changelog.

## Security Issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license.
