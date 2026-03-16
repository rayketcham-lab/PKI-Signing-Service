# Code Signing Service

![Version](https://img.shields.io/badge/version-0.5.3-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Language](https://img.shields.io/badge/language-Rust-orange) ![Dependencies](https://img.shields.io/badge/openssl-none-brightgreen) ![CI](https://img.shields.io/github/actions/workflow/status/rayketcham-lab/PKI-Signing-Service/ci.yml?branch=main&label=CI)

Pure Rust code signing engine. Authenticode for Windows PE/CAB/MSI, detached CMS/PKCS#7, PowerShell scripts, RFC 3161 timestamping. Multi-algorithm: RSA, ECDSA P-256/P-384, Ed25519, ML-DSA (FIPS 204).

No OpenSSL. No `signtool.exe`. No external dependencies. One binary.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
  - [Install](#install)
  - [Sign a file](#sign-a-file)
  - [Verify a signature](#verify-a-signature)
- [Web Service Mode](#web-service-mode)
  - [Configuration](#configuration)
  - [API Reference](#api-reference)
- [TSA Server](#tsa-server)
- [CLI Reference](#cli-reference)
- [Architecture](#architecture)
- [Security](#security)
- [Building from Source](#building-from-source)
- [License](#license)

## Features

- **PE Authenticode signing** --- EXE, DLL, SYS, OCX, SCR, CPL, DRV
- **MSI/CAB signing** --- Windows Installer and Cabinet archives
- **Detached CMS/PKCS#7** --- Sign any file with a `.p7s` detached signature
- **PowerShell signing** --- PS1 scripts with Base64 PKCS#7 signature blocks
- **RFC 3161 timestamping** --- Counter-signatures for long-term validity
- **Multi-algorithm** --- RSA (2048-4096), ECDSA P-256/P-384, Ed25519, ML-DSA-44/65/87
- **Signature verification** --- Validate Authenticode and detached CMS signatures
- **PFX/PKCS#12 import** --- Load signing credentials from `.pfx` files
- **Web service mode** --- REST API for Code Signing as a Service
- **Built-in TSA server** --- RFC 3161 Time-Stamp Authority on port 3318
- **LDAP authentication** --- Header-based auth via reverse proxy
- **Certificate management** --- Admin API for hot-reload, listing, and rotation
- **Audit logging** --- Every signing operation logged with request ID, hash, and duration
- **Evidence Record Syntax** --- RFC 4998 long-term archive timestamps
- **Static binary** --- `x86_64-unknown-linux-musl` target, zero runtime dependencies

> [!TIP]
> One binary handles CLI signing, a REST API server, and a standalone TSA server. Deploy however you need it.

## Quick Start

### Install

Download the latest release binary:

```bash
curl -LO https://github.com/rayketcham-lab/PKI-Signing-Service/releases/latest/download/pki-sign
chmod +x pki-sign
sudo mv pki-sign /usr/local/bin/
```

Or build from source:

```bash
cargo install --git https://github.com/rayketcham-lab/PKI-Signing-Service.git
```

### Sign a file

```bash
# Set the PFX password
export PKI_SIGN_PFX_PASSWORD="your-password"

# Sign a Windows executable (Authenticode)
pki-sign sign --pfx cert.pfx input.exe -o signed.exe

# Detached CMS signature (any file)
pki-sign sign-detached --pfx cert.pfx document.pdf -o document.p7s

# Skip timestamping (offline/testing)
pki-sign sign --pfx cert.pfx --no-timestamp input.dll -o signed.dll

# Custom TSA server
pki-sign sign --pfx cert.pfx --tsa http://timestamp.digicert.com input.exe
```

### Verify a signature

```bash
# Verify Authenticode signature
pki-sign verify signed.exe

# Verify with certificate details
pki-sign verify --verbose signed.exe

# Verify detached signature
pki-sign verify-detached --signature document.p7s document.pdf
```

Output:

```
Verifying: signed.exe
  Signature:   VALID
  Timestamped: true
  Signer:      CN=My Code Signing Cert, O=My Org
  Issuer:      CN=My Issuing CA
  Algorithm:   RSA-SHA256
  Digest:      SHA-256
  Content:     SPC_INDIRECT_DATA
```

---

## Web Service Mode

Run as a signing REST API. Upload files, get signed files back. HTTPS with TLS, LDAP auth, audit logging, certificate hot-reload.

```bash
# Start with config file
pki-sign serve --config /etc/pki/sign.toml

# Start with defaults (port 6447)
pki-sign serve

# Custom bind address
pki-sign serve --bind 127.0.0.1 --port 8443
```

### Configuration

```toml
# /etc/pki/sign.toml

bind_addr = "0.0.0.0"
bind_port = 6447
tls_cert = "/etc/pki/tls/server.pem"
tls_key = "/etc/pki/tls/server-key.pem"
max_upload_size = 524288000   # 500 MB
require_timestamp = true
audit_log = "/var/log/pki-sign/audit.log"
output_dir = "/var/lib/pki-sign/signed"

# Signing certificates (multiple supported)
[[cert_configs]]
name = "desktop"
pfx_path = "/etc/pki/certs/desktop.pfx"
pfx_password_env = "PFX_PASSWORD_DESKTOP"

[[cert_configs]]
name = "server"
pfx_path = "/etc/pki/certs/server.pfx"
pfx_password_env = "PFX_PASSWORD_SERVER"

# Timestamp Authority
[tsa]
urls = ["http://timestamp.digicert.com", "http://timestamp.comodoca.com"]
timeout_secs = 30

# Authentication
auth_mode = "header"  # none, header, mtls, apikey

[ldap]
enabled = true
user_header = "X-Remote-User"
groups_header = "X-Remote-Groups"
email_header = "X-Remote-Email"
admin_group = "CN=PKI Admins,OU=Groups,DC=corp,DC=example,DC=com"

[ldap.cert_groups]
desktop = "CN=Desktop Signers,OU=Groups,DC=corp,DC=example,DC=com"
server = "CN=Server Signers,OU=Groups,DC=corp,DC=example,DC=com"
```

### API Reference

#### Public endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sign` | Upload and sign a file (multipart) |
| `POST` | `/api/v1/sign-detached` | Create detached CMS signature |
| `POST` | `/api/v1/verify` | Verify an Authenticode signature |
| `POST` | `/api/v1/verify-detached` | Verify a detached signature |
| `GET` | `/api/v1/status` | Server status and statistics |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/certificate` | Public signing certificate info |
| `POST` | `/api/v1/report-issue` | Submit a user issue report |

#### Admin endpoints (bearer token or LDAP admin group)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/stats` | Detailed signing statistics |
| `GET` | `/admin/audit` | Recent audit log entries |
| `POST` | `/admin/reload` | Hot-reload PFX credentials |
| `GET` | `/admin/certs` | List all loaded certificates |
| `GET` | `/admin/certs/:name` | Detailed certificate info |
| `POST` | `/admin/certs/:name/default` | Set default signing certificate |

<details>
<summary><strong>Sign a file (curl)</strong></summary>

```bash
curl -X POST https://sign.example.com/api/v1/sign \
  -H "X-Remote-User: jdoe" \
  -F "file=@myapp.exe" \
  -o myapp-signed.exe

# Response headers include:
#   X-Request-Id: <uuid>
#   X-PKI-Sign-Hash: <sha256>
#   X-PKI-Sign-Algorithm: RSA-SHA256
#   X-PKI-Sign-Certificate: desktop
#   X-PKI-Sign-Timestamp: true
#   X-PKI-Sign-Duration-Ms: 342
```

</details>

<details>
<summary><strong>Detached signature (curl)</strong></summary>

```bash
# Binary response (default)
curl -X POST https://sign.example.com/api/v1/sign-detached \
  -H "X-Remote-User: jdoe" \
  -F "file=@document.pdf" \
  -o document.p7s

# JSON response
curl -X POST https://sign.example.com/api/v1/sign-detached \
  -H "X-Remote-User: jdoe" \
  -H "Accept: application/json" \
  -F "file=@document.pdf"
```

```json
{
  "request_id": "a1b2c3d4-...",
  "p7s": "<base64-encoded-signature>",
  "file_hash": "abcdef123456...",
  "p7s_hash": "789abc...",
  "timestamped": true,
  "certificate": "desktop",
  "duration_ms": 287
}
```

</details>

<details>
<summary><strong>Verify a file (curl)</strong></summary>

```bash
curl -X POST https://sign.example.com/api/v1/verify \
  -F "file=@signed.exe"
```

```json
{
  "request_id": "...",
  "signature_valid": true,
  "chain_valid": true,
  "timestamped": true,
  "signer_subject": "CN=My Code Signing Cert, O=My Org",
  "signer_issuer": "CN=My Issuing CA",
  "algorithm": "RSA-SHA256",
  "digest_algorithm": "SHA-256",
  "timestamp_time": "2026-03-12T14:30:00Z"
}
```

</details>

<details>
<summary><strong>Admin: hot-reload certificates (curl)</strong></summary>

```bash
curl -X POST https://sign.example.com/admin/reload \
  -H "Authorization: Bearer <admin-token>"
```

```json
{
  "status": "reloaded",
  "certificates_loaded": 2
}
```

</details>

---

## TSA Server

Standalone RFC 3161 Time-Stamp Authority server. IANA-assigned port 3318.

```bash
pki-sign tsa serve \
  --cert /etc/pki/tsa/tsa.pem \
  --key /etc/pki/tsa/tsa-key.pem \
  --policy-oid 1.3.6.1.4.1.56266.1.30.1 \
  --port 3318
```

Compatible with any RFC 3161 client --- `signtool.exe`, `openssl ts`, or this tool's own `--tsa` flag.

---

## CLI Reference

```
pki-sign 0.5.3
Code Signing Service - Pure Rust Code Signing Engine

USAGE:
    pki-sign <COMMAND>

COMMANDS:
    serve            Start the web server for Code Signing as a Service
    sign             Sign a file using Authenticode
    sign-detached    Create a detached CMS/PKCS#7 signature (.p7s)
    verify           Verify an Authenticode signature
    verify-detached  Verify a detached CMS/PKCS#7 signature
    setup            Interactive setup wizard
    tsa              Time-Stamp Authority (RFC 3161) server commands
    help             Print help
```

| Flag | Command | Description |
|------|---------|-------------|
| `--pfx` | `sign`, `sign-detached` | Path to PFX/PKCS#12 certificate file |
| `--password-env` | `sign`, `sign-detached` | Env var with PFX password (default: `PKI_SIGN_PFX_PASSWORD`) |
| `--tsa` | `sign`, `sign-detached` | TSA URL for timestamping |
| `--no-timestamp` | `sign`, `sign-detached` | Skip timestamping |
| `-o, --output` | `sign`, `sign-detached` | Output file path |
| `--verbose` | `verify`, `verify-detached` | Show detailed certificate info |
| `--signature` | `verify-detached` | Path to `.p7s` signature file |
| `-c, --config` | `serve` | Config file path (default: `/etc/pki/sign.toml`) |
| `-p, --port` | `serve`, `tsa serve` | Bind port |
| `--bind` | `serve`, `tsa serve` | Bind address (default: `0.0.0.0`) |

---

## Architecture

```
                        ┌─────────────────────────────┐
                        │         pki-sign CLI         │
                        │  sign | verify | serve | tsa │
                        └──────────────┬──────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
     ┌────────▼────────┐    ┌─────────▼─────────┐    ┌────────▼────────┐
     │   Web Server     │    │      Signer        │    │   TSA Server    │
     │   (axum)         │    │   (orchestrator)    │    │  (RFC 3161)     │
     │                  │    │                     │    │  port 3318      │
     │  LDAP auth       │    │  PFX → key + cert   │    └─────────────────┘
     │  Audit logging   │    │  File type detect    │
     │  Cert mgmt API   │    │  Hash → Sign → Embed │
     │  GitHub issues   │    │                     │
     └──────────────────┘    └──────────┬──────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
           ┌────────▼──────┐   ┌───────▼───────┐   ┌──────▼──────┐
           │  PE Parser     │   │  PKCS#7/CMS   │   │  Timestamper │
           │                │   │  Builder       │   │  (RFC 3161)  │
           │  Authenticode  │   │                │   │              │
           │  hash compute  │   │  SignedData    │   │  TSA client  │
           │  sig embed     │   │  DigestedData  │   │  failover    │
           │  cert table    │   │  EnvelopedData │   └──────────────┘
           └────────────────┘   │  ECDH / KEM    │
                                └────────────────┘
```

### Modules

| Module | Description |
|--------|-------------|
| `pe/` | PE/COFF parser, Authenticode hash, signature embedding |
| `pkcs7/` | CMS/PKCS#7 ASN.1 builder --- SignedData, DigestedData, EnvelopedData, ECDH, KEM |
| `signer` | Signing orchestrator --- PFX load, file type detection, pipeline coordination |
| `verifier` | Signature verification --- digest comparison, chain validation, EKU checking |
| `timestamp` | RFC 3161 TSA client with failover across multiple servers |
| `tsa_http` | Standalone TSA HTTP server |
| `tsa_server` | TSA token generation engine |
| `ers` | Evidence Record Syntax (RFC 4998) --- long-term archive timestamps |
| `powershell` | PowerShell script signing with Base64 PKCS#7 blocks |
| `crypto/` | HKDF key derivation, RSA-OAEP encryption |
| `web/` | axum HTTP server, LDAP middleware, audit logging, admin API |
| `config` | TOML configuration with env var and CLI overrides |

---

## Security

- **No OpenSSL** --- Pure Rust crypto stack (`rsa`, `p256`, `p384`, `ed25519-dalek`, `ml-dsa`, `sha2`, `aes-gcm`). TLS via `rustls` with `aws-lc-rs` backend.
- **OpenSSL banned** --- `cargo-deny` blocks `openssl`, `openssl-sys`, and `native-tls` crate usage.
- **Key zeroization** --- Private keys wrapped in `Zeroizing<>` for secure memory cleanup.
- **Audit trail** --- Every sign/verify operation logged with request ID, file hash, signer, timestamp status, and duration.
- **Auth modes** --- None (dev), LDAP header pass-through, mTLS, API key.
- **Security headers** --- Applied via middleware on all responses.
- **CI hardening** --- `cargo-audit` + `cargo-deny` on every push. Pinned action SHAs.
- **Static binary** --- musl target for minimal attack surface in production.

> [!IMPORTANT]
> Always run with `auth_mode = "header"` or `"mtls"` in production. The default `"none"` mode is for development only.

---

## Building from Source

```bash
git clone https://github.com/rayketcham-lab/PKI-Signing-Service.git
cd PKI-Signing-Service
cargo build --release
```

The binary is at `target/release/pki-sign`.

### Static binary (musl)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Run checks

```bash
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

### Run as systemd service

```ini
# /etc/systemd/system/pki-sign.service
[Unit]
Description=Code Signing Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pki-sign serve --config /etc/pki/sign.toml
Restart=on-failure
User=pki-sign
Group=pki-sign
EnvironmentFile=/etc/pki/sign.env

[Install]
WantedBy=multi-user.target
```

---

## License

MIT
