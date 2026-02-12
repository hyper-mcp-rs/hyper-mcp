use clap::Parser;
use git_version::git_version;
use std::path::PathBuf;

// Get version from git describe, fallback to Cargo.toml version
const VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = env!("CARGO_PKG_VERSION")
);

#[derive(Parser, Clone, Debug)]
#[command(
    author = "Joseph Wortmann <joseph.wortmann@gmail.com>",
    version = VERSION,
    about,
    long_about = None
)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config_file: Option<PathBuf>,

    #[arg(
        long = "insecure-skip-signature",
        help = "Skip OCI image signature verification. Will override the value in your config file if set.",
        env = "HYPER_MCP_INSECURE_SKIP_SIGNATURE"
    )]
    pub insecure_skip_signature: Option<bool>,

    #[arg(
        long = "use-sigstore-tuf-data",
        help = "Use Sigstore TUF data for OCI verification. Will override the value in your config file if set.",
        env = "HYPER_MCP_USE_SIGSTORE_TUF_DATA"
    )]
    pub use_sigstore_tuf_data: Option<bool>,

    #[arg(
        long = "rekor-pub-keys",
        help = "Path to Rekor public keys for OCI verification. Will override the value in your config file if set.",
        env = "HYPER_MCP_REKOR_PUB_KEYS"
    )]
    pub rekor_pub_keys: Option<PathBuf>,

    #[arg(
        long = "fulcio-certs",
        help = "Path to Fulcio certificates for OCI verification. Will override the value in your config file if set.",
        env = "HYPER_MCP_FULCIO_CERTS"
    )]
    pub fulcio_certs: Option<PathBuf>,

    #[arg(
        long = "cert-issuer",
        help = "Certificate issuer to verify OCI against. Will override the value in your config file if set.",
        env = "HYPER_MCP_CERT_ISSUER"
    )]
    pub cert_issuer: Option<String>,

    #[arg(
        long = "cert-email",
        help = "Certificate email to verify OCI against. Will override the value in your config file if set.",
        env = "HYPER_MCP_CERT_EMAIL"
    )]
    pub cert_email: Option<String>,

    #[arg(
        long = "cert-url",
        help = "Certificate URL to verify OCI against. Will override the value in your config file if set.",
        env = "HYPER_MCP_CERT_URL"
    )]
    pub cert_url: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config_file: None,
            insecure_skip_signature: None,
            use_sigstore_tuf_data: None,
            rekor_pub_keys: None,
            fulcio_certs: None,
            cert_issuer: None,
            cert_email: None,
            cert_url: None,
        }
    }
}
