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

## Release Signing & Verification

Every release artifact is signed with [cosign](https://github.com/sigstore/cosign)
keyless signing, driven by the `release.yml` workflow using GitHub Actions OIDC.
Each binary ships with a `.sig` (detached signature) and `.cosign-bundle`
(signing certificate + transparency-log entry) alongside the binary in the
GitHub release.

**Verify the canonical signer identity before installing:**

```bash
cosign verify-blob pki-sign-linux-x86_64-static \
  --bundle pki-sign-linux-x86_64-static.cosign-bundle \
  --certificate-identity-regexp 'https://github.com/rayketcham-lab/PKI-Signing-Service/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

| Field | Expected value |
|-------|----------------|
| `--certificate-oidc-issuer` | `https://token.actions.githubusercontent.com` (GitHub Actions OIDC — anything else means the artifact was NOT signed by this repo's release workflow) |
| `--certificate-identity-regexp` | `https://github.com/rayketcham-lab/PKI-Signing-Service/.*` (matches `.github/workflows/release.yml@refs/tags/v*` — use the pinned `--certificate-identity` form to require an exact tag) |
| Signing workflow | `.github/workflows/release.yml`, `release` job, `Sign release artifacts with cosign (#62)` step |
| Guard against silent failure | Release job contains an explicit `if [[ ! -f "${f}.sig" || ! -f "${f}.cosign-bundle" ]]; then exit 1` loop (gh #69) — enforced by `cosign_guard_loop_prevents_silent_sig_fail` integration test |

Any verification failure — missing bundle, mismatched identity, or unknown OIDC
issuer — means the artifact must be rejected. Do not install unverified binaries.

## Banned Dependencies

The following crates are blocked by `cargo-deny`:

| Crate | Reason |
|-------|--------|
| `openssl` | Pure Rust crypto only |
| `openssl-sys` | No C OpenSSL bindings |
| `native-tls` | Use rustls instead |
| `rust-crypto` | Unmaintained, insecure |
| `failure` | Deprecated error handling |
