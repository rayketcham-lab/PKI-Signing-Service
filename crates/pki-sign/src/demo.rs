//! `pki-sign demo` — self-contained, in-process signing demo.
//!
//! Runs against a bundled throwaway RSA-2048 PFX so new users can watch
//! pki-sign sign and verify a Windows PE end-to-end in under a second,
//! without needing their own cert.
//!
//! Gated behind the `demo` feature (default-on). Build hardened releases
//! that exclude the bundled test PFX with:
//!   cargo build --release --no-default-features

use anyhow::{Context, Result};
use colored::Colorize;
use std::time::Instant;

const DEMO_PFX: &[u8] = include_bytes!("../tests/fixtures/rsa2048.pfx");
const DEMO_PFX_PASSWORD: &str = "test";

/// Run the scripted signing demo. Writes its own temp working dir and
/// cleans it up on return.
pub async fn run() -> Result<()> {
    println!();
    println!(
        "{}",
        "  pki-sign demo — end-to-end sign + verify in-process"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "  (bundled throwaway RSA-2048 cert — not a real signing key)".dimmed()
    );
    println!();

    let tempdir = tempfile::tempdir().context("create tempdir")?;

    let t0 = Instant::now();
    let pfx_path = tempdir.path().join("demo.pfx");
    std::fs::write(&pfx_path, DEMO_PFX).context("write bundled pfx")?;
    let credentials = crate::signer::SigningCredentials::from_pfx(&pfx_path, DEMO_PFX_PASSWORD)
        .context("load bundled demo credentials")?;
    println!(
        "  {} credentials loaded {}",
        "✔".green().bold(),
        format!("({:.0?})", t0.elapsed()).dimmed()
    );

    let t1 = Instant::now();
    let pe_bytes = make_minimal_pe();
    let pe_path = tempdir.path().join("demo.exe");
    std::fs::write(&pe_path, &pe_bytes).context("write demo PE")?;
    println!(
        "  {} generated minimal PE32 ({} bytes) {}",
        "✔".green().bold(),
        pe_bytes.len(),
        format!("({:.0?})", t1.elapsed()).dimmed()
    );

    let t2 = Instant::now();
    let signed_path = tempdir.path().join("demo-signed.exe");
    let sign_result = crate::signer::sign_file(&pe_path, &signed_path, &credentials, None)
        .await
        .context("sign demo PE")?;
    println!(
        "  {} signed — original SHA-256 {}…, signed SHA-256 {}… {}",
        "✔".green().bold(),
        &sign_result.original_hash[..12],
        &sign_result.signed_hash[..12],
        format!("({:.0?})", t2.elapsed()).dimmed()
    );

    let t3 = Instant::now();
    let verify_result = crate::verifier::verify_file(&signed_path).context("verify signed PE")?;
    if !verify_result.signature_valid {
        anyhow::bail!("demo signature failed self-verification — this should never happen");
    }
    println!(
        "  {} verified — digest {} {}",
        "✔".green().bold(),
        verify_result.digest_algorithm,
        format!("({:.0?})", t3.elapsed()).dimmed()
    );
    println!(
        "      {} {}",
        "signer:".dimmed(),
        verify_result.signer_subject
    );

    let total = t0.elapsed();
    println!();
    println!(
        "  {} {}",
        "Total round-trip:".bold(),
        format!("{:.0?}", total).green().bold()
    );
    println!();
    println!("  {}", "Next steps:".bold());
    println!("    1. Use your own code-signing PFX:");
    println!(
        "       {}",
        "export PKI_SIGN_PFX_PASSWORD='your-password'".dimmed()
    );
    println!(
        "       {}",
        "pki-sign sign --pfx your-cert.pfx your-app.exe".dimmed()
    );
    println!(
        "    2. Verify: {}",
        "pki-sign verify your-app-signed.exe".dimmed()
    );
    println!();
    Ok(())
}

/// Build a minimal valid PE32 file suitable for demo signing.
///
/// Mirrors the private `make_minimal_pe32()` helper in
/// `crate::pe::parser` (which is `#[cfg(test)]` and therefore not
/// reachable from a release build).
fn make_minimal_pe() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0] = b'M';
    data[1] = b'Z';
    data[0x3C] = 0x80;
    data[0x80] = b'P';
    data[0x81] = b'E';
    data[0x86] = 1;
    data[0x94] = 0xE0;
    data[0x98] = 0x0B;
    data[0x99] = 0x01;
    data[0xF4] = 16;
    data[0x189] = 0x02;
    data[0x18D] = 0x02;
    data
}
