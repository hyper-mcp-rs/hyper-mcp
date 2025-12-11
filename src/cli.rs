use clap::Parser;
use std::path::PathBuf;

pub const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:3001";

#[derive(Parser, Clone, Debug, PartialEq)]
#[command(author = "Tuan Anh Tran <me@tuananh.org>", version = env!("CARGO_PKG_VERSION"), about, long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE")]
    pub config_file: Option<PathBuf>,

    #[arg(
        long = "transport",
        value_name = "TRANSPORT",
        env = "HYPER_MCP_TRANSPORT",
        default_value = "stdio",
        value_parser = ["stdio", "sse", "streamable-http"]
    )]
    pub transport: String,

    #[arg(
        long = "bind-address",
        value_name = "ADDRESS",
        env = "HYPER_MCP_BIND_ADDRESS",
        default_value = DEFAULT_BIND_ADDRESS
    )]
    pub bind_address: String,

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
            transport: "stdio".to_string(),
            bind_address: DEFAULT_BIND_ADDRESS.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cli_values() {
        let cli = Cli::default();

        assert_eq!(cli.config_file, None);
        assert_eq!(cli.transport, "stdio");
        assert_eq!(cli.bind_address, DEFAULT_BIND_ADDRESS);
        assert_eq!(cli.insecure_skip_signature, None);
        assert_eq!(cli.use_sigstore_tuf_data, None);
        assert_eq!(cli.rekor_pub_keys, None);
        assert_eq!(cli.fulcio_certs, None);
        assert_eq!(cli.cert_issuer, None);
        assert_eq!(cli.cert_email, None);
        assert_eq!(cli.cert_url, None);
    }

    #[test]
    fn test_default_bind_address_constant() {
        assert_eq!(DEFAULT_BIND_ADDRESS, "127.0.0.1:3001");
    }

    #[test]
    fn test_cli_clone() {
        let cli = Cli {
            config_file: Some(PathBuf::from("/path/to/config.yaml")),
            transport: "sse".to_string(),
            bind_address: "0.0.0.0:8080".to_string(),
            insecure_skip_signature: Some(true),
            use_sigstore_tuf_data: Some(false),
            rekor_pub_keys: Some(PathBuf::from("/path/to/rekor.pub")),
            fulcio_certs: Some(PathBuf::from("/path/to/fulcio.crt")),
            cert_issuer: Some("issuer@example.com".to_string()),
            cert_email: Some("user@example.com".to_string()),
            cert_url: Some("https://example.com".to_string()),
        };

        let cloned = cli.clone();

        assert_eq!(cli.config_file, cloned.config_file);
        assert_eq!(cli.transport, cloned.transport);
        assert_eq!(cli.bind_address, cloned.bind_address);
        assert_eq!(cli.insecure_skip_signature, cloned.insecure_skip_signature);
        assert_eq!(cli.use_sigstore_tuf_data, cloned.use_sigstore_tuf_data);
        assert_eq!(cli.rekor_pub_keys, cloned.rekor_pub_keys);
        assert_eq!(cli.fulcio_certs, cloned.fulcio_certs);
        assert_eq!(cli.cert_issuer, cloned.cert_issuer);
        assert_eq!(cli.cert_email, cloned.cert_email);
        assert_eq!(cli.cert_url, cloned.cert_url);
    }

    #[test]
    fn test_cli_with_custom_values() {
        let config_path = PathBuf::from("/etc/config.yaml");
        let rekor_path = PathBuf::from("/etc/rekor.pub");
        let fulcio_path = PathBuf::from("/etc/fulcio.crt");

        let cli = Cli {
            config_file: Some(config_path.clone()),
            transport: "streamable-http".to_string(),
            bind_address: "192.168.1.1:9000".to_string(),
            insecure_skip_signature: Some(true),
            use_sigstore_tuf_data: Some(true),
            rekor_pub_keys: Some(rekor_path.clone()),
            fulcio_certs: Some(fulcio_path.clone()),
            cert_issuer: Some("test-issuer".to_string()),
            cert_email: Some("test@example.com".to_string()),
            cert_url: Some("https://test.example.com".to_string()),
        };

        assert_eq!(cli.config_file, Some(config_path));
        assert_eq!(cli.transport, "streamable-http");
        assert_eq!(cli.bind_address, "192.168.1.1:9000");
        assert_eq!(cli.insecure_skip_signature, Some(true));
        assert_eq!(cli.use_sigstore_tuf_data, Some(true));
        assert_eq!(cli.rekor_pub_keys, Some(rekor_path));
        assert_eq!(cli.fulcio_certs, Some(fulcio_path));
        assert_eq!(cli.cert_issuer, Some("test-issuer".to_string()));
        assert_eq!(cli.cert_email, Some("test@example.com".to_string()));
        assert_eq!(cli.cert_url, Some("https://test.example.com".to_string()));
    }

    #[test]
    fn test_cli_transport_stdio() {
        let cli = Cli {
            transport: "stdio".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.transport, "stdio");
    }

    #[test]
    fn test_cli_transport_sse() {
        let cli = Cli {
            transport: "sse".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.transport, "sse");
    }

    #[test]
    fn test_cli_transport_streamable_http() {
        let cli = Cli {
            transport: "streamable-http".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.transport, "streamable-http");
    }

    #[test]
    fn test_cli_signature_verification_flags() {
        let cli = Cli {
            insecure_skip_signature: Some(true),
            use_sigstore_tuf_data: Some(true),
            ..Default::default()
        };

        assert_eq!(cli.insecure_skip_signature, Some(true));
        assert_eq!(cli.use_sigstore_tuf_data, Some(true));
    }

    #[test]
    fn test_cli_signature_verification_flags_false() {
        let cli = Cli {
            insecure_skip_signature: Some(false),
            use_sigstore_tuf_data: Some(false),
            ..Default::default()
        };

        assert_eq!(cli.insecure_skip_signature, Some(false));
        assert_eq!(cli.use_sigstore_tuf_data, Some(false));
    }

    #[test]
    fn test_cli_certificate_fields() {
        let cli = Cli {
            cert_issuer: Some("https://github.com/login/oauth".to_string()),
            cert_email: Some("user@github.com".to_string()),
            cert_url: Some("https://github.com/user".to_string()),
            ..Default::default()
        };

        assert_eq!(
            cli.cert_issuer,
            Some("https://github.com/login/oauth".to_string())
        );
        assert_eq!(cli.cert_email, Some("user@github.com".to_string()));
        assert_eq!(cli.cert_url, Some("https://github.com/user".to_string()));
    }

    #[test]
    fn test_cli_partial_initialization() {
        let cli = Cli {
            config_file: Some(PathBuf::from("config.yaml")),
            ..Default::default()
        };

        assert_eq!(cli.config_file, Some(PathBuf::from("config.yaml")));
        assert_eq!(cli.transport, "stdio");
        assert_eq!(cli.bind_address, DEFAULT_BIND_ADDRESS);
        assert_eq!(cli.insecure_skip_signature, None);
    }

    #[test]
    fn test_cli_optional_fields_remain_none() {
        let cli = Cli::default();

        assert!(cli.config_file.is_none());
        assert!(cli.insecure_skip_signature.is_none());
        assert!(cli.use_sigstore_tuf_data.is_none());
        assert!(cli.rekor_pub_keys.is_none());
        assert!(cli.fulcio_certs.is_none());
        assert!(cli.cert_issuer.is_none());
        assert!(cli.cert_email.is_none());
        assert!(cli.cert_url.is_none());
    }

    #[test]
    fn test_cli_bind_address_formats() {
        // Test IPv4 with port
        let cli = Cli {
            bind_address: "127.0.0.1:3001".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.bind_address, "127.0.0.1:3001");

        // Test IPv4 with different port
        let cli = Cli {
            bind_address: "0.0.0.0:8080".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.bind_address, "0.0.0.0:8080");

        // Test hostname with port
        let cli = Cli {
            bind_address: "localhost:3001".to_string(),
            ..Default::default()
        };
        assert_eq!(cli.bind_address, "localhost:3001");
    }

    #[test]
    fn test_cli_derive_traits() {
        let cli1 = Cli::default();
        let cli2 = Cli::default();

        // Test Clone trait
        let cloned = cli1.clone();
        assert_eq!(cloned.transport, cli1.transport);

        // Test PartialEq (derived)
        assert_eq!(cli1, cli2);
    }

    #[test]
    fn test_cli_all_certificate_paths_set() {
        let rekor_path = PathBuf::from("/secure/rekor.pub");
        let fulcio_path = PathBuf::from("/secure/fulcio.crt");

        let cli = Cli {
            rekor_pub_keys: Some(rekor_path.clone()),
            fulcio_certs: Some(fulcio_path.clone()),
            ..Default::default()
        };

        assert!(cli.rekor_pub_keys.is_some());
        assert!(cli.fulcio_certs.is_some());
        assert_eq!(cli.rekor_pub_keys.unwrap(), rekor_path);
        assert_eq!(cli.fulcio_certs.unwrap(), fulcio_path);
    }
}
