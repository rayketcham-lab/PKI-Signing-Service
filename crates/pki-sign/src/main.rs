//! pki-sign — Pure Rust Code Signing Engine
//!
//! Run as a web service or use CLI mode for direct file signing.
//!
//! ## Usage
//!
//! ```bash
//! # Start web server
//! pki-sign serve --config /etc/pki/sign.toml
//!
//! # Sign a file directly (CLI mode)
//! pki-sign sign --pfx cert.pfx --password-env PKI_SIGN_PFX_PASSWORD input.exe -o signed.exe
//!
//! # Detached CMS signing (any file type)
//! pki-sign sign-detached --pfx cert.pfx -o output.p7s input.txt
//!
//! # Verify a signed file
//! pki-sign verify signed.exe
//!
//! # Verify a detached signature
//! pki-sign verify-detached --signature output.p7s input.txt
//!
//! # Interactive setup wizard
//! pki-sign setup
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use pki_sign::tsa_http::TsaHttpConfig;

#[derive(Parser)]
#[command(
    name = "pki-sign",
    about = "PKI Signing Service - Pure Rust Code Signing Engine",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the web server for Code Signing as a Service
    Serve {
        /// Path to configuration file
        #[arg(short, long, default_value = "/etc/pki/sign.toml")]
        config: PathBuf,

        /// Bind address
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,

        /// Bind port
        #[arg(short, long, default_value = "6447")]
        port: u16,
    },

    /// Sign a file using Authenticode
    Sign {
        /// Path to PFX/PKCS#12 certificate file
        #[arg(long)]
        pfx: PathBuf,

        /// Environment variable containing PFX password
        #[arg(long, default_value = "PKI_SIGN_PFX_PASSWORD")]
        password_env: String,

        /// Input file to sign
        input: PathBuf,

        /// Output path for signed file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// TSA URL for timestamping
        #[arg(long)]
        tsa: Option<String>,

        /// Skip timestamping
        #[arg(long)]
        no_timestamp: bool,
    },

    /// Create a detached CMS/PKCS#7 signature (.p7s)
    SignDetached {
        /// Path to PFX/PKCS#12 certificate file
        #[arg(long)]
        pfx: PathBuf,

        /// Environment variable containing PFX password
        #[arg(long, default_value = "PKI_SIGN_PFX_PASSWORD")]
        password_env: String,

        /// Input file to sign
        input: PathBuf,

        /// Output path for .p7s signature file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// TSA URL for timestamping
        #[arg(long)]
        tsa: Option<String>,

        /// Skip timestamping
        #[arg(long)]
        no_timestamp: bool,
    },

    /// Verify an Authenticode signature
    Verify {
        /// File to verify
        input: PathBuf,

        /// Show detailed certificate info
        #[arg(long)]
        verbose: bool,
    },

    /// Verify a detached CMS/PKCS#7 signature
    VerifyDetached {
        /// File that was signed
        input: PathBuf,

        /// Path to .p7s signature file
        #[arg(long)]
        signature: PathBuf,

        /// Show detailed certificate info
        #[arg(long)]
        verbose: bool,
    },

    /// Interactive setup wizard
    Setup {
        /// Installation directory
        #[arg(long, default_value = "/etc/pki")]
        prefix: PathBuf,
    },

    /// Run an end-to-end sign + verify demo against a bundled throwaway cert
    #[cfg(feature = "demo")]
    Demo,

    /// Time-Stamp Authority (RFC 3161) server commands
    Tsa {
        #[command(subcommand)]
        command: TsaCommands,
    },
}

#[derive(Subcommand)]
enum TsaCommands {
    /// Start the TSA HTTP server
    Serve {
        /// Bind address
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,

        /// Port (IANA assigned 3318 for TSP over HTTP)
        #[arg(short, long, default_value = "3318")]
        port: u16,

        /// TSA signing certificate (PEM)
        #[arg(long)]
        cert: PathBuf,

        /// TSA signing key (PEM PKCS#8)
        #[arg(long)]
        key: PathBuf,

        /// Chain certificate PEM (optional)
        #[arg(long)]
        chain: Option<PathBuf>,

        /// TSA policy OID
        #[arg(long, default_value = "1.3.6.1.4.1.56266.1.30.1")]
        policy_oid: String,

        /// Accuracy in seconds
        #[arg(long, default_value = "1")]
        accuracy_secs: u32,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { config, bind, port } => {
            // Initialize tracing (RUST_LOG env var or PKI_SIGN_LOG_LEVEL)
            let log_level = std::env::var("PKI_SIGN_LOG_LEVEL").unwrap_or_else(|_| "info".into());
            let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level));
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .init();

            // Load config from TOML file, or use defaults if the file doesn't exist
            let mut sign_config = if config.exists() {
                match pki_sign::config::SignConfig::load_from_file(&config) {
                    Ok(c) => {
                        tracing::info!(path = %config.display(), "Loaded configuration");
                        c
                    }
                    Err(e) => {
                        eprintln!("Error loading config {}: {}", config.display(), e);
                        std::process::exit(1);
                    }
                }
            } else {
                tracing::info!("No config file found, using defaults");
                pki_sign::config::SignConfig::default()
            };

            // CLI overrides
            sign_config.bind_addr = bind;
            sign_config.bind_port = port;

            // Environment variable override for dev mode (PKI_SIGN_DEV_MODE=1)
            if let Ok(val) = std::env::var("PKI_SIGN_DEV_MODE") {
                sign_config.dev_mode = matches!(val.as_str(), "1" | "true" | "yes");
            }

            // Start the multi-threaded async runtime
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            if let Err(e) = rt.block_on(pki_sign::web::run_server(sign_config)) {
                eprintln!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Sign {
            pfx,
            password_env,
            input,
            output,
            tsa,
            no_timestamp,
        } => {
            // Read PFX password from environment variable
            let password = match std::env::var(&password_env) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Error: environment variable '{}' not set", password_env);
                    eprintln!("Set it with: export {}=<your-pfx-password>", password_env);
                    std::process::exit(1);
                }
            };

            // Load signing credentials
            eprintln!("Loading PFX: {}", pfx.display());
            let credentials = match pki_sign::signer::SigningCredentials::from_pfx(&pfx, &password)
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error loading PFX: {}", e);
                    std::process::exit(1);
                }
            };

            // Determine output path
            let output_path = output.unwrap_or_else(|| {
                let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                let ext = input.extension().unwrap_or_default().to_string_lossy();
                input.with_file_name(format!("{}-signed.{}", stem, ext))
            });

            eprintln!("Signing: {}", input.display());
            eprintln!("Output:  {}", output_path.display());

            // Build TSA config from CLI flags
            let tsa_config = if no_timestamp {
                None
            } else {
                let config = if let Some(url) = tsa {
                    pki_sign::timestamp::TsaConfig::new(vec![url])
                } else {
                    pki_sign::timestamp::TsaConfig::default()
                };
                eprintln!("Timestamp: {}", config.urls.join(", "));
                Some(config)
            };

            // Run the async signing operation
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            match rt.block_on(pki_sign::signer::sign_file(
                &input,
                &output_path,
                &credentials,
                tsa_config.as_ref(),
            )) {
                Ok(result) => {
                    eprintln!("Signed successfully!");
                    eprintln!("  Original SHA-256: {}", result.original_hash);
                    eprintln!("  Signed SHA-256:   {}", result.signed_hash);
                    eprintln!("  Timestamped:      {}", result.timestamped);
                    eprintln!("  Output: {}", output_path.display());
                }
                Err(e) => {
                    eprintln!("Signing failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::SignDetached {
            pfx,
            password_env,
            input,
            output,
            tsa,
            no_timestamp,
        } => {
            let password = match std::env::var(&password_env) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("Error: environment variable '{}' not set", password_env);
                    eprintln!("Set it with: export {}=<your-pfx-password>", password_env);
                    std::process::exit(1);
                }
            };

            eprintln!("Loading PFX: {}", pfx.display());
            let credentials =
                match pki_sign::signer::SigningCredentials::from_pfx_detached(&pfx, &password) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error loading PFX: {}", e);
                        std::process::exit(1);
                    }
                };

            let output_path = output.unwrap_or_else(|| input.with_extension("p7s"));

            eprintln!("Signing (detached): {}", input.display());
            eprintln!("Output:             {}", output_path.display());

            let tsa_config = if no_timestamp {
                None
            } else {
                let config = if let Some(url) = tsa {
                    pki_sign::timestamp::TsaConfig::new(vec![url])
                } else {
                    pki_sign::timestamp::TsaConfig::default()
                };
                eprintln!("Timestamp: {}", config.urls.join(", "));
                Some(config)
            };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            match rt.block_on(pki_sign::signer::sign_detached(
                &input,
                &credentials,
                tsa_config.as_ref(),
            )) {
                Ok(result) => {
                    std::fs::write(&output_path, &result.p7s_data).unwrap_or_else(|e| {
                        eprintln!("Failed to write signature: {}", e);
                        std::process::exit(1);
                    });
                    eprintln!("Detached signature created!");
                    eprintln!("  File SHA-256:      {}", result.file_hash);
                    eprintln!("  Signature SHA-256: {}", result.p7s_hash);
                    eprintln!("  Timestamped:       {}", result.timestamped);
                    eprintln!("  Output: {}", output_path.display());
                }
                Err(e) => {
                    eprintln!("Signing failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Verify { input, verbose } => {
            eprintln!("Verifying: {}", input.display());
            match pki_sign::verifier::verify_file(&input) {
                Ok(result) => {
                    if result.signature_valid {
                        eprintln!("  Signature:   VALID");
                    } else {
                        eprintln!("  Signature:   INVALID");
                    }
                    eprintln!("  Timestamped: {}", result.timestamped);
                    eprintln!("  Signer:      {}", result.signer_subject);
                    eprintln!("  Issuer:      {}", result.signer_issuer);
                    eprintln!("  Algorithm:   {}", result.algorithm);
                    eprintln!("  Digest:      {}", result.digest_algorithm);
                    eprintln!("  Content:     {}", result.content_type);
                    if verbose {
                        eprintln!("  Computed digest: {}", result.computed_digest);
                        eprintln!("  Signed digest:   {}", result.signed_digest);
                        if let Some(ts) = &result.timestamp_time {
                            eprintln!("  Timestamp time:  {}", ts);
                        }
                    }
                    if !result.signature_valid {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::VerifyDetached {
            input,
            signature,
            verbose,
        } => {
            eprintln!("Verifying detached signature: {}", input.display());
            eprintln!("  Signature file: {}", signature.display());

            let data = match std::fs::read(&input) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to read input file: {}", e);
                    std::process::exit(1);
                }
            };
            let p7s = match std::fs::read(&signature) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to read signature file: {}", e);
                    std::process::exit(1);
                }
            };

            match pki_sign::verifier::verify_detached(&data, &p7s) {
                Ok(result) => {
                    if result.signature_valid {
                        eprintln!("  Signature:   VALID");
                    } else {
                        eprintln!("  Signature:   INVALID");
                    }
                    eprintln!("  Signer:      {}", result.signer_subject);
                    eprintln!("  Issuer:      {}", result.signer_issuer);
                    eprintln!("  Algorithm:   {}", result.algorithm);
                    eprintln!("  Digest:      {}", result.digest_algorithm);
                    if verbose {
                        eprintln!("  Computed digest: {}", result.computed_digest);
                        eprintln!("  Signed digest:   {}", result.signed_digest);
                    }
                    if !result.signature_valid {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Setup { prefix } => {
            eprintln!("Setup wizard (prefix: {})", prefix.display());
            eprintln!("Setup wizard not yet implemented");
            std::process::exit(1);
        }
        #[cfg(feature = "demo")]
        Commands::Demo => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            if let Err(e) = rt.block_on(pki_sign::demo::run()) {
                eprintln!("demo failed: {e:#}");
                std::process::exit(1);
            }
        }
        Commands::Tsa { command } => match command {
            TsaCommands::Serve {
                bind,
                port,
                cert,
                key,
                chain,
                policy_oid,
                accuracy_secs,
            } => {
                let log_level =
                    std::env::var("PKI_SIGN_LOG_LEVEL").unwrap_or_else(|_| "info".into());
                let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log_level));
                tracing_subscriber::registry()
                    .with(filter)
                    .with(tracing_subscriber::fmt::layer())
                    .init();

                let config = TsaHttpConfig {
                    bind,
                    port,
                    cert_path: cert,
                    key_path: key,
                    chain_path: chain,
                    policy_oid,
                    accuracy_secs,
                };

                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                if let Err(e) = rt.block_on(pki_sign::tsa_http::run_tsa_server(config)) {
                    eprintln!("TSA server error: {}", e);
                    std::process::exit(1);
                }
            }
        },
    }
}
