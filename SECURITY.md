# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email security reports to: **security@quantumnexum.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Impact assessment (if known)

You should receive an acknowledgment within 48 hours. We aim to release a fix within 7 days for critical issues.

## Security Design

- **No OpenSSL dependency** --- pure Rust TLS/crypto stack (`rustls`, `aws-lc-rs`, `ring`)
- **No unsafe code** in application or library crates
- **Zero warnings** policy enforced in CI (`clippy -D warnings`)
- **Dependency auditing** via `cargo-audit` and `cargo-deny` on every commit
- **Security regression tests** run on every push (dedicated CI workflow)
- **Input validation** at all trust boundaries (file parsing, network input, CLI args)
- **Content-Disposition sanitization** prevents header injection in web API responses
- **No filesystem path leakage** in error messages
- **Key zeroization** --- private keys wrapped in `Zeroizing<>` for secure memory cleanup
- **Dev mode gated** --- `PKI_SIGN_DEV_MODE` only accepted in debug builds

## Cryptographic Standards

- RSA: 2048, 3072, 4096-bit keys
- ECDSA: P-256, P-384, P-521 (NIST curves)
- EdDSA: Ed25519
- Post-quantum: ML-DSA-44/65/87 (FIPS 204)
- Hash algorithms: SHA-256, SHA-384, SHA-512, SHA3-256/384/512
- SHA-1: allowed only for legacy PKCS#12/PFX compatibility, banned for new signatures
- TLS: rustls with aws-lc-rs backend (no OpenSSL)

## Banned Dependencies

The following crates are blocked by `cargo-deny`:

| Crate | Reason |
|-------|--------|
| `openssl` | Pure Rust crypto only |
| `openssl-sys` | No C OpenSSL bindings |
| `native-tls` | Use rustls instead |
| `rust-crypto` | Unmaintained, insecure |
| `failure` | Deprecated error handling |
