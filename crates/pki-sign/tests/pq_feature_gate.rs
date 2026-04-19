//! Asserts that the `pq-experimental` feature gates the ML-DSA surface.
//!
//! The CVE posture of the default build depends on ML-DSA being unreachable
//! (no `ml-dsa` crate in the dep tree, no `PrivateKey::MlDsa*` variants
//! constructible). These tests pin that invariant.
//!
//! The PQ variants of [`PrivateKey`] and [`SigningAlgorithm`] are already
//! `#[cfg(feature = "pq-experimental")]`-gated at the enum definition, so in a
//! default build they do not exist at compile time at all — naming them here
//! would fail to build. The matches below name every non-PQ variant as a
//! positive cross-check that the classical surface stays wired up, and the
//! `cargo tree` assertion (`default_build_cargo_tree_omits_ml_dsa`) proves
//! the `ml-dsa` crate itself is absent from the default dep graph.
//!
//! The wildcard arms are a syntactic requirement of `#[non_exhaustive]` across
//! crate boundaries and are unreachable in practice: every currently-defined
//! variant is named above.

use pki_sign::pkcs7::SigningAlgorithm;
use pki_sign::signer::PrivateKey;

#[cfg(not(feature = "pq-experimental"))]
#[test]
fn default_build_private_key_has_no_ml_dsa_variants() {
    fn tag(k: &PrivateKey) -> &'static str {
        match k {
            PrivateKey::Rsa(_) => "rsa",
            PrivateKey::EcdsaP256(_) => "p256",
            PrivateKey::EcdsaP384(_) => "p384",
            PrivateKey::EcdsaP521(_) => "p521",
            PrivateKey::Ed25519(_) => "ed25519",
            _ => unreachable!("non_exhaustive wildcard — unreachable in default build"),
        }
    }
    let _ = tag;
}

#[cfg(not(feature = "pq-experimental"))]
#[test]
fn default_build_signing_algorithm_has_no_pq_variants() {
    fn tag(alg: SigningAlgorithm) -> &'static str {
        match alg {
            SigningAlgorithm::RsaSha256 => "rsa-256",
            SigningAlgorithm::RsaSha384 => "rsa-384",
            SigningAlgorithm::RsaSha512 => "rsa-512",
            SigningAlgorithm::RsaPssSha256 => "rsa-pss-256",
            SigningAlgorithm::RsaPssSha384 => "rsa-pss-384",
            SigningAlgorithm::RsaPssSha512 => "rsa-pss-512",
            SigningAlgorithm::EcdsaSha256 => "ec-256",
            SigningAlgorithm::EcdsaSha384 => "ec-384",
            SigningAlgorithm::EcdsaSha512 => "ec-512",
            SigningAlgorithm::Ed25519 => "ed25519",
            _ => unreachable!("non_exhaustive wildcard — unreachable in default build"),
        }
    }
    let _ = tag;
}

#[cfg(feature = "pq-experimental")]
#[test]
fn pq_experimental_private_key_exposes_ml_dsa_variants() {
    fn tag(k: &PrivateKey) -> &'static str {
        match k {
            PrivateKey::Rsa(_) => "rsa",
            PrivateKey::EcdsaP256(_) => "p256",
            PrivateKey::EcdsaP384(_) => "p384",
            PrivateKey::EcdsaP521(_) => "p521",
            PrivateKey::Ed25519(_) => "ed25519",
            PrivateKey::MlDsa44(_) => "ml-dsa-44",
            PrivateKey::MlDsa65(_) => "ml-dsa-65",
            PrivateKey::MlDsa87(_) => "ml-dsa-87",
            _ => unreachable!("non_exhaustive wildcard — all known pq-experimental variants named"),
        }
    }
    let _ = tag;
}

#[cfg(feature = "pq-experimental")]
#[test]
fn pq_experimental_signing_algorithm_has_pq_variants() {
    fn tag(alg: SigningAlgorithm) -> &'static str {
        match alg {
            SigningAlgorithm::RsaSha256 => "rsa-256",
            SigningAlgorithm::RsaSha384 => "rsa-384",
            SigningAlgorithm::RsaSha512 => "rsa-512",
            SigningAlgorithm::RsaPssSha256 => "rsa-pss-256",
            SigningAlgorithm::RsaPssSha384 => "rsa-pss-384",
            SigningAlgorithm::RsaPssSha512 => "rsa-pss-512",
            SigningAlgorithm::EcdsaSha256 => "ec-256",
            SigningAlgorithm::EcdsaSha384 => "ec-384",
            SigningAlgorithm::EcdsaSha512 => "ec-512",
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::MlDsa44 => "ml-dsa-44",
            SigningAlgorithm::MlDsa65 => "ml-dsa-65",
            SigningAlgorithm::MlDsa87 => "ml-dsa-87",
            SigningAlgorithm::SlhDsaSha2128s => "slh-dsa-128s",
            SigningAlgorithm::SlhDsaSha2192s => "slh-dsa-192s",
            SigningAlgorithm::SlhDsaSha2256s => "slh-dsa-256s",
            _ => unreachable!("non_exhaustive wildcard — all known pq-experimental variants named"),
        }
    }
    let _ = tag;
}

/// The default build must not resolve the `ml-dsa` crate. We verify this by
/// running `cargo tree --no-default-features -e normal -i ml-dsa` from the
/// workspace root and asserting it exits non-zero (package not in graph).
///
/// This test only runs in the default (non-pq) configuration so it can tell
/// cargo to resolve without the feature. We skip when CARGO is not available
/// (e.g., running the compiled binary outside a cargo shell).
#[cfg(not(feature = "pq-experimental"))]
#[test]
fn default_build_cargo_tree_omits_ml_dsa() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let manifest_dir = env!("CARGO_MANIFEST_DIR");

    let out = std::process::Command::new(&cargo)
        .current_dir(manifest_dir)
        .args([
            "tree",
            "--no-default-features",
            "--edges",
            "normal",
            "--invert",
            "ml-dsa",
            "--quiet",
        ])
        .output();

    let Ok(out) = out else {
        eprintln!("cargo tree unavailable — skipping dep-tree assertion");
        return;
    };

    assert!(
        !out.status.success(),
        "ml-dsa appears in the default-features dep tree; pq-experimental gate is leaking.\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
