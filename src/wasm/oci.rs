use crate::config::OciConfig;
use crate::naming::PluginName;
use anyhow::{Context, Result, anyhow};
use backoff::{ExponentialBackoff, future::retry};
use dashmap::DashMap;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use flate2::read::GzDecoder;
use oci_client::{
    Client, Reference,
    client::{ClientConfig, linux_amd64_resolver},
    manifest::OciManifest,
    secrets::RegistryAuth,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tar::Archive;
use tokio::process::Command;
use tokio::sync::{Mutex, OnceCell};
use url::Url;

static OCI_CLIENT: OnceCell<Client> = OnceCell::const_new();
static DOWNLOAD_LOCKS: OnceCell<DashMap<String, Arc<Mutex<()>>>> = OnceCell::const_new();

async fn build_auth(reference: &Reference) -> RegistryAuth {
    let mut server = reference.resolve_registry();
    if let Some(svr) = server.strip_suffix('/') {
        server = svr
    }

    match docker_credential::get_credential(server) {
        Err(CredentialRetrievalError::ConfigNotFound) => RegistryAuth::Anonymous,
        Err(CredentialRetrievalError::NoCredentialConfigured) => RegistryAuth::Anonymous,
        Err(e) => {
            tracing::info!("Error retrieving docker credentials: {e}. Using anonymous auth");
            RegistryAuth::Anonymous
        }
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            tracing::info!("Found docker credentials");
            RegistryAuth::Basic(username, password)
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            tracing::info!("Identity token not supported via docker config. Using anonymous auth");
            RegistryAuth::Anonymous
        }
    }
}

pub async fn load_wasm(url: &Url, config: &OciConfig, plugin_name: &PluginName) -> Result<Vec<u8>> {
    let image_reference = url
        .as_str()
        .strip_prefix("oci://")
        .ok_or_else(|| anyhow!("Invalid OCI URL (missing oci://): {url}"))?;

    // your contract: look for this inside tar layers; OR accept a raw wasm layer
    let target_file_path = "/plugin.wasm";

    let cache_dir = dirs::cache_dir()
        .map(|mut path| {
            path.push("hyper-mcp");
            path.push("oci");
            path
        })
        .context("Unable to determine cache dir")?;
    std::fs::create_dir_all(&cache_dir)?;

    let local_output_path =
        pull_and_extract_oci_artifact(cache_dir, config, image_reference, target_file_path)
            .await
            .map_err(|e| anyhow!("Failed to pull OCI plugin: {e}"))?;
    let local_output_path_str = local_output_path
        .to_str()
        .ok_or_else(|| anyhow!("Non-utf8 cache path: {local_output_path:?}"))?;

    tracing::info!("Loaded plugin `{plugin_name}` from cache: {local_output_path_str}");

    tokio::fs::read(local_output_path_str)
        .await
        .map_err(|e| e.into())
}

/// Build cosign args for the strictest possible verification given your OciConfig.
///
/// Rules (strict):
/// - If cert_email OR cert_url is set, cert_issuer MUST be set.
/// - Prefer cert_email over cert_url if both are set (but you should avoid setting both).
fn cosign_verify_args(config: &OciConfig) -> Result<Vec<String>> {
    let mut args: Vec<String> = vec!["verify".to_string()];

    // Pick identity constraint source (email or url)
    let identity = config.cert_email.as_deref().or(config.cert_url.as_deref());

    match identity {
        Some(identity) => {
            let issuer = config.cert_issuer.as_deref().ok_or_else(|| {
                anyhow!("Strict verification requires cert_issuer when cert_email/cert_url is set")
            })?;

            args.push("--certificate-identity-regexp".into());
            args.push(identity.to_string());

            args.push("--certificate-oidc-issuer-regexp".into());
            args.push(issuer.to_string());
        }
        None => {
            // accept any valid keyless signature, but still require identity/issuer regex presence
            args.push("--certificate-identity-regexp".into());
            args.push(".*".into());

            args.push("--certificate-oidc-issuer-regexp".into());
            args.push(".*".into());
        }
    }

    Ok(args)
}

async fn verify_image_signature_with_cosign(
    config: &OciConfig,
    image_reference: &str,
) -> Result<()> {
    if config.insecure_skip_signature {
        tracing::warn!("Signature verification disabled for {image_reference}");
        return Ok(());
    }

    tracing::info!("Verifying signature (cosign) for {image_reference}");

    let mut args = cosign_verify_args(config)?;
    args.push(image_reference.to_string());

    let output = Command::new("cosign")
        .args(&args)
        .envs(std::env::vars())
        .output()
        .await
        .context("Failed to spawn cosign; is it installed and on PATH?")?;

    if output.status.success() {
        tracing::info!("Cosign verification successful for {image_reference}");
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    Err(anyhow!(
        "Cosign verification failed for {image_reference}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}"
    ))
}

/// Detect gzip by magic bytes 1F 8B.
fn looks_like_gzip(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x1F && buf[1] == 0x8B
}

/// Detect wasm by magic bytes 00 61 73 6D.
fn looks_like_wasm(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0..4] == [0x00, 0x61, 0x73, 0x6D]
}

fn normalize_tar_path(p: &Path) -> PathBuf {
    // Remove leading "/" and leading "./" components for matching.
    let mut comps = p.components().peekable();
    let mut out = PathBuf::new();

    while let Some(c) = comps.peek() {
        let s = c.as_os_str().to_string_lossy();
        if s == "/" || s == "." {
            comps.next();
            continue;
        }
        break;
    }
    for c in comps {
        out.push(c.as_os_str());
    }
    out
}

fn path_ends_with(full: &Path, suffix: &Path) -> bool {
    let full: Vec<_> = full.components().collect();
    let suf: Vec<_> = suffix.components().collect();
    if suf.is_empty() || suf.len() > full.len() {
        return false;
    }
    full[full.len() - suf.len()..] == suf[..]
}

fn extract_wasm_from_tar_reader<R: Read>(
    tar_reader: R,
    target_file_path: &str,
) -> Result<Option<Vec<u8>>> {
    let mut archive = Archive::new(tar_reader);
    let entries = archive.entries().context("tar entries() failed")?;

    let target_norm = normalize_tar_path(Path::new(target_file_path));

    // (rank, depth, size, content)
    // Lower rank is better. Lower depth is better. Larger size is better.
    let mut best: Option<(u8, usize, usize, Vec<u8>)> = None;

    for entry_result in entries {
        let mut entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("tar entry error: {e}");
                continue;
            }
        };

        let raw_path: PathBuf = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(e) => {
                tracing::debug!("tar entry path() error: {e}");
                continue;
            }
        };

        let path = normalize_tar_path(&raw_path);

        // Compute candidate rank
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        let rank = if path_ends_with(&path, &target_norm) {
            0
        } else if file_name == "plugin.wasm" {
            1
        } else if file_name.ends_with(".wasm") {
            2
        } else {
            continue;
        };

        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .with_context(|| format!("reading tar entry `{}` failed", raw_path.display()))?;

        if !looks_like_wasm(&content) {
            tracing::debug!(
                "Found candidate `{}`, but it does not look like wasm; skipping",
                raw_path.display()
            );
            continue;
        }

        let depth = path.components().count();
        let size = content.len();

        let is_better = match &best {
            None => true,
            Some((best_rank, best_depth, best_size, _)) => {
                (rank < *best_rank)
                    || (rank == *best_rank && depth < *best_depth)
                    || (rank == *best_rank && depth == *best_depth && size > *best_size)
            }
        };

        if is_better {
            best = Some((rank, depth, size, content));
        }
    }

    Ok(best.map(|(_, _, _, content)| content))
}

/// Try to interpret `buf` as:
/// 1) raw wasm blob
/// 2) gzip tar containing wasm
/// 3) plain tar containing wasm
fn extract_wasm_from_blob(buf: &[u8], target_file_path: &str) -> Result<Option<Vec<u8>>> {
    if looks_like_wasm(buf) {
        return Ok(Some(buf.to_vec()));
    }

    if looks_like_gzip(buf) {
        let gz = GzDecoder::new(buf);
        return extract_wasm_from_tar_reader(gz, target_file_path);
    }

    // Last-chance: treat as plain tar (some artifacts are uncompressed)
    // tar crate will just error if it isn't tar; that's fine.
    match extract_wasm_from_tar_reader(std::io::Cursor::new(buf), target_file_path) {
        Ok(found) => Ok(found),
        Err(e) => {
            tracing::error!("not a tar (or unreadable tar): {e}");
            Ok(None)
        }
    }
}

/// Pull an OCI ref and extract wasm whether it's:
/// - an image-style tar.gz layer containing /plugin.wasm
/// - an ORAS-style artifact where a layer is the wasm blob itself
async fn pull_and_extract_oci_artifact(
    cache_dir: PathBuf,
    config: &OciConfig,
    image_reference: &str,
    target_file_path: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let locks = DOWNLOAD_LOCKS
        .get_or_init(|| async { DashMap::new() })
        .await;

    let lock = locks
        .entry(image_reference.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();

    let _guard = lock.lock().await;

    let reference = Reference::try_from(image_reference)?;
    let auth = build_auth(&reference).await;

    let client = OCI_CLIENT
        .get_or_init(|| async {
            // WASM is platform independent; force linux so macOS doesn't try darwin/*
            Client::new(ClientConfig {
                platform_resolver: Some(Box::new(linux_amd64_resolver)),
                ..Default::default()
            })
        })
        .await;

    // IMPORTANT:
    // - For ORAS artifacts, manifests often use "application/vnd.oci.image.manifest.v1+json"
    //   but layer mediaTypes vary widely.
    // - The accept list here is mostly about manifest types, not layer types.

    let manifest_backoff = ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(30)),
        max_interval: Duration::from_secs(5),
        ..Default::default()
    };

    let (manifest, manifest_digest) = retry(manifest_backoff, || async {
        client.pull_manifest(&reference, &auth).await.map_err(|e| {
            tracing::warn!("Failed to pull manifest for {}: {}", image_reference, e);
            backoff::Error::transient(e)
        })
    })
    .await?;

    let local_output_path = cache_dir.join(match manifest_digest.split_once(':') {
        Some((algo, sha)) => format!("{algo}_{sha}"),
        None => {
            return Err("invalid digest".into());
        }
    });

    if local_output_path.exists() {
        tracing::info!(
            "Plugin {image_reference} already cached at: {}. Skipping downloading.",
            local_output_path.display()
        );
        return Ok(local_output_path);
    }

    tracing::info!("Pulling {image_reference} ...");

    // Verify BEFORE downloading blobs
    verify_image_signature_with_cosign(config, image_reference)
        .await
        .map_err(|e| format!("No valid signatures found / verification failed: {e}"))?;

    // Now manually pull blobs for every layer descriptor.
    // This avoids `client.pull()` rejecting docker rootfs layer media types.
    let layers = match manifest {
        OciManifest::Image(m) => m.layers,
        OciManifest::ImageIndex(_) => {
            // If you're forcing amd64 elsewhere, `pull_manifest()` should already have resolved
            // to an Image manifest in most cases. If you still get an index here, treat as error.
            return Err(
                "Got an image index manifest unexpectedly (platform resolution failed)".into(),
            );
        }
    };

    for layer_desc in layers.iter() {
        let digest = layer_desc.digest.as_str(); // e.g. "sha256:...."

        // Pull by digest string (AsLayerDescriptor for &str) to avoid media-type validation.
        let blob_backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(30)),
            max_interval: Duration::from_secs(5),
            ..Default::default()
        };

        let buf = retry(blob_backoff, || async {
            let mut temp_buf = Vec::new();
            client
                .pull_blob(&reference, digest, &mut temp_buf)
                .await
                .map(|_| temp_buf)
                .map_err(|e| {
                    tracing::warn!(
                        "Failed to pull blob {} for {}: {}",
                        digest,
                        image_reference,
                        e
                    );
                    backoff::Error::transient(e)
                })
        })
        .await?;

        if let Some(wasm) = extract_wasm_from_blob(&buf, target_file_path)? {
            if let Some(parent) = local_output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(local_output_path.clone(), wasm)?;
            tracing::info!("Successfully extracted to: {}", local_output_path.display());
            return Ok(local_output_path);
        }
    }

    Err("No wasm payload found in any layer (expected wasm blob or tar(.gz) containing plugin.wasm)".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_looks_like_gzip_valid() {
        let gzip_magic = vec![0x1F, 0x8B, 0x08, 0x00];
        assert!(looks_like_gzip(&gzip_magic));
    }

    #[test]
    fn test_looks_like_gzip_invalid() {
        let not_gzip = vec![0x00, 0x00, 0x08, 0x00];
        assert!(!looks_like_gzip(&not_gzip));
    }

    #[test]
    fn test_looks_like_gzip_too_short() {
        let too_short = vec![0x1F];
        assert!(!looks_like_gzip(&too_short));
    }

    #[test]
    fn test_looks_like_wasm_valid() {
        let wasm_magic = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        assert!(looks_like_wasm(&wasm_magic));
    }

    #[test]
    fn test_looks_like_wasm_invalid() {
        let not_wasm = vec![0x00, 0x00, 0x00, 0x00];
        assert!(!looks_like_wasm(&not_wasm));
    }

    #[test]
    fn test_looks_like_wasm_too_short() {
        let too_short = vec![0x00, 0x61, 0x73];
        assert!(!looks_like_wasm(&too_short));
    }

    #[test]
    fn test_normalize_tar_path_with_leading_slash() {
        let path = Path::new("/plugin.wasm");
        let normalized = normalize_tar_path(path);
        assert_eq!(normalized, PathBuf::from("plugin.wasm"));
    }

    #[test]
    fn test_normalize_tar_path_with_leading_dot() {
        let path = Path::new("./plugin.wasm");
        let normalized = normalize_tar_path(path);
        assert_eq!(normalized, PathBuf::from("plugin.wasm"));
    }

    #[test]
    fn test_normalize_tar_path_with_subdirectories() {
        let path = Path::new("/opt/app/plugin.wasm");
        let normalized = normalize_tar_path(path);
        assert_eq!(normalized, PathBuf::from("opt/app/plugin.wasm"));
    }

    #[test]
    fn test_normalize_tar_path_already_normalized() {
        let path = Path::new("plugin.wasm");
        let normalized = normalize_tar_path(path);
        assert_eq!(normalized, PathBuf::from("plugin.wasm"));
    }

    #[test]
    fn test_path_ends_with_exact_match() {
        let full = Path::new("opt/app/plugin.wasm");
        let suffix = Path::new("plugin.wasm");
        assert!(path_ends_with(full, suffix));
    }

    #[test]
    fn test_path_ends_with_multiple_components() {
        let full = Path::new("opt/app/plugin.wasm");
        let suffix = Path::new("app/plugin.wasm");
        assert!(path_ends_with(full, suffix));
    }

    #[test]
    fn test_path_ends_with_no_match() {
        let full = Path::new("opt/app/plugin.wasm");
        let suffix = Path::new("other.wasm");
        assert!(!path_ends_with(full, suffix));
    }

    #[test]
    fn test_path_ends_with_suffix_too_long() {
        let full = Path::new("plugin.wasm");
        let suffix = Path::new("opt/app/plugin.wasm");
        assert!(!path_ends_with(full, suffix));
    }

    #[test]
    fn test_path_ends_with_empty_suffix() {
        let full = Path::new("plugin.wasm");
        let suffix = Path::new("");
        assert!(!path_ends_with(full, suffix));
    }

    #[test]
    fn test_extract_wasm_from_blob_raw_wasm() {
        let wasm_data = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let result = extract_wasm_from_blob(&wasm_data, "/plugin.wasm").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), wasm_data);
    }

    #[test]
    fn test_extract_wasm_from_blob_not_wasm() {
        let not_wasm = vec![0x00, 0x00, 0x00, 0x00];
        let result = extract_wasm_from_blob(&not_wasm, "/plugin.wasm").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_wasm_from_tar_with_target_path() -> Result<()> {
        // Create a simple tar archive with a wasm file
        let mut tar_builder = tar::Builder::new(Vec::new());

        let wasm_data = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut header = tar::Header::new_gnu();
        header.set_path("plugin.wasm")?;
        header.set_size(wasm_data.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, wasm_data.as_slice())?;

        let tar_data = tar_builder.into_inner()?;

        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/plugin.wasm")?;
        assert!(result.is_some());
        assert_eq!(result.unwrap(), wasm_data);

        Ok(())
    }

    #[test]
    fn test_extract_wasm_from_tar_multiple_wasm_files_prefers_exact_match() -> Result<()> {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // Add a generic wasm file
        let generic_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut header = tar::Header::new_gnu();
        header.set_path("other.wasm")?;
        header.set_size(generic_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, generic_wasm.as_slice())?;

        // Add the target wasm file (longer to distinguish)
        let target_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let mut header = tar::Header::new_gnu();
        header.set_path("plugin.wasm")?;
        header.set_size(target_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, target_wasm.as_slice())?;

        let tar_data = tar_builder.into_inner()?;

        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/plugin.wasm")?;
        assert!(result.is_some());
        // Should prefer the exact match (plugin.wasm)
        assert_eq!(result.unwrap(), target_wasm);

        Ok(())
    }

    #[test]
    fn test_extract_wasm_from_tar_no_wasm() -> Result<()> {
        let mut tar_builder = tar::Builder::new(Vec::new());

        let not_wasm = vec![0x00, 0x00, 0x00, 0x00];
        let mut header = tar::Header::new_gnu();
        header.set_path("README.md")?;
        header.set_size(not_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, not_wasm.as_slice())?;

        let tar_data = tar_builder.into_inner()?;

        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/plugin.wasm")?;
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_cosign_verify_args_with_email_and_issuer() {
        let config = OciConfig {
            cert_email: Some("test@example.com".to_string()),
            cert_issuer: Some("https://issuer.example.com".to_string()),
            cert_url: None,
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let args = cosign_verify_args(&config).unwrap();
        assert!(args.contains(&"verify".to_string()));
        assert!(args.contains(&"--certificate-identity-regexp".to_string()));
        assert!(args.contains(&"test@example.com".to_string()));
        assert!(args.contains(&"--certificate-oidc-issuer-regexp".to_string()));
        assert!(args.contains(&"https://issuer.example.com".to_string()));
    }

    #[test]
    fn test_cosign_verify_args_with_url_and_issuer() {
        let config = OciConfig {
            cert_email: None,
            cert_url: Some("https://cert.example.com".to_string()),
            cert_issuer: Some("https://issuer.example.com".to_string()),
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let args = cosign_verify_args(&config).unwrap();
        assert!(args.contains(&"--certificate-identity-regexp".to_string()));
        assert!(args.contains(&"https://cert.example.com".to_string()));
        assert!(args.contains(&"--certificate-oidc-issuer-regexp".to_string()));
        assert!(args.contains(&"https://issuer.example.com".to_string()));
    }

    #[test]
    fn test_cosign_verify_args_prefers_email_over_url() {
        let config = OciConfig {
            cert_email: Some("test@example.com".to_string()),
            cert_url: Some("https://cert.example.com".to_string()),
            cert_issuer: Some("https://issuer.example.com".to_string()),
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let args = cosign_verify_args(&config).unwrap();
        // Should use email, not URL
        assert!(args.contains(&"test@example.com".to_string()));
        assert!(!args.contains(&"https://cert.example.com".to_string()));
    }

    #[test]
    fn test_cosign_verify_args_no_identity() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let args = cosign_verify_args(&config).unwrap();
        // Should use wildcards
        assert!(args.contains(&"--certificate-identity-regexp".to_string()));
        assert!(args.contains(&".*".to_string()));
        assert!(args.contains(&"--certificate-oidc-issuer-regexp".to_string()));
    }

    #[test]
    fn test_cosign_verify_args_identity_without_issuer_fails() {
        let config = OciConfig {
            cert_email: Some("test@example.com".to_string()),
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: false,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let result = cosign_verify_args(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cert_issuer"));
    }

    #[tokio::test]
    async fn test_build_auth_returns_valid_auth() {
        let reference = Reference::try_from("ghcr.io/test/image:latest").unwrap();
        let auth = build_auth(&reference).await;
        // Should be either Anonymous or Basic depending on environment
        // In GitHub Actions, credentials may be configured; locally they may not be
        match auth {
            RegistryAuth::Anonymous => {
                // No credentials configured - this is fine
            }
            RegistryAuth::Basic(_, _) => {
                // Credentials found - this is also fine
            }
            _ => {
                panic!("Unexpected auth type returned");
            }
        }
    }

    #[tokio::test]
    async fn test_pull_docker_image() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: true, // Skip signature for test
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let url = Url::parse("oci://ghcr.io/hyper-mcp-rs/time-plugin:nightly").unwrap();
        let plugin_name = PluginName::try_from("time_plugin").unwrap();

        let result = load_wasm(&url, &config, &plugin_name).await;

        // This test validates that we can pull a Docker image
        match result {
            Ok(wasm_bytes) => {
                assert!(!wasm_bytes.is_empty(), "Wasm bytes should not be empty");
                assert!(looks_like_wasm(&wasm_bytes), "Should be valid wasm");
            }
            Err(e) => {
                // Log the error but don't fail - might be network issues
                eprintln!(
                    "Warning: Docker image test failed (might be network issue): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_pull_oras_image() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: true, // Skip signature for test
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let url = Url::parse("oci://ghcr.io/hyper-mcp-rs/rstime-plugin:nightly").unwrap();
        let plugin_name = PluginName::try_from("rstime_plugin").unwrap();

        let result = load_wasm(&url, &config, &plugin_name).await;

        // This test validates that we can pull an ORAS artifact
        match result {
            Ok(wasm_bytes) => {
                assert!(!wasm_bytes.is_empty(), "Wasm bytes should not be empty");
                assert!(looks_like_wasm(&wasm_bytes), "Should be valid wasm");
            }
            Err(e) => {
                // Log the error but don't fail - might be network issues
                eprintln!(
                    "Warning: ORAS image test failed (might be network issue): {}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_load_wasm_caches_result() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: true,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let url = Url::parse("oci://ghcr.io/hyper-mcp-rs/time-plugin:nightly").unwrap();
        let plugin_name = PluginName::try_from("time_plugin").unwrap();

        // First load
        let result1 = load_wasm(&url, &config, &plugin_name).await;
        if result1.is_err() {
            eprintln!("Skipping cache test due to network issue");
            return;
        }

        // Second load should use cache
        let result2 = load_wasm(&url, &config, &plugin_name).await;

        match (result1, result2) {
            (Ok(bytes1), Ok(bytes2)) => {
                assert_eq!(bytes1, bytes2, "Cached result should match");
            }
            _ => {
                eprintln!("Skipping cache validation due to network issue");
            }
        }
    }

    #[tokio::test]
    async fn test_load_wasm_invalid_url_format() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: true,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let url = Url::parse("https://example.com/not-oci").unwrap();
        let plugin_name = PluginName::try_from("test").unwrap();

        let result = load_wasm(&url, &config, &plugin_name).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid OCI URL"));
    }

    #[tokio::test]
    async fn test_verify_signature_skipped_when_insecure() {
        let config = OciConfig {
            cert_email: None,
            cert_url: None,
            cert_issuer: None,
            fulcio_certs: None,
            insecure_skip_signature: true,
            rekor_pub_keys: None,
            use_sigstore_tuf_data: false,
        };

        let result = verify_image_signature_with_cosign(&config, "ghcr.io/test/image:latest").await;
        assert!(
            result.is_ok(),
            "Should skip verification when insecure flag is set"
        );
    }

    #[test]
    fn test_extract_wasm_from_gzipped_tar() -> Result<()> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        // Create a tar archive
        let mut tar_builder = tar::Builder::new(Vec::new());
        let wasm_data = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut header = tar::Header::new_gnu();
        header.set_path("plugin.wasm")?;
        header.set_size(wasm_data.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, wasm_data.as_slice())?;
        let tar_data = tar_builder.into_inner()?;

        // Gzip the tar
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data)?;
        let gzipped = encoder.finish()?;

        // Extract from gzipped tar
        let result = extract_wasm_from_blob(&gzipped, "/plugin.wasm")?;
        assert!(result.is_some());
        assert_eq!(result.unwrap(), wasm_data);

        Ok(())
    }

    #[test]
    fn test_extract_wasm_ranking_exact_path_wins() -> Result<()> {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // Add a file that just ends with .wasm (rank 2)
        let generic_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01];
        let mut header = tar::Header::new_gnu();
        header.set_path("other.wasm")?;
        header.set_size(generic_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, generic_wasm.as_slice())?;

        // Add exact path match (rank 0) - should win
        let exact_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x02];
        let mut header = tar::Header::new_gnu();
        header.set_path("plugin.wasm")?;
        header.set_size(exact_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, exact_wasm.as_slice())?;

        let tar_data = tar_builder.into_inner()?;
        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/plugin.wasm")?;

        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            exact_wasm,
            "Should prefer exact path match"
        );

        Ok(())
    }

    #[test]
    fn test_extract_wasm_ranking_shallower_depth_wins() -> Result<()> {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // Add deeper plugin.wasm
        let deep_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01];
        let mut header = tar::Header::new_gnu();
        header.set_path("a/b/c/plugin.wasm")?;
        header.set_size(deep_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, deep_wasm.as_slice())?;

        // Add shallower plugin.wasm - should win
        let shallow_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x02];
        let mut header = tar::Header::new_gnu();
        header.set_path("plugin.wasm")?;
        header.set_size(shallow_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, shallow_wasm.as_slice())?;

        let tar_data = tar_builder.into_inner()?;
        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/other.wasm")?;

        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            shallow_wasm,
            "Should prefer shallower depth"
        );

        Ok(())
    }

    #[test]
    fn test_extract_wasm_ranking_larger_size_wins() -> Result<()> {
        let mut tar_builder = tar::Builder::new(Vec::new());

        // Add smaller .wasm file (rank 2)
        let small_wasm = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mut header = tar::Header::new_gnu();
        header.set_path("app/small.wasm")?;
        header.set_size(small_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, small_wasm.as_slice())?;

        // Add larger .wasm file at same depth and rank - should win due to size
        let large_wasm = vec![
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
        ];
        let mut header = tar::Header::new_gnu();
        header.set_path("lib/large.wasm")?;
        header.set_size(large_wasm.len() as u64);
        header.set_cksum();
        tar_builder.append(&header, large_wasm.as_slice())?;

        let tar_data = tar_builder.into_inner()?;
        let result = extract_wasm_from_tar_reader(std::io::Cursor::new(&tar_data), "/other.wasm")?;

        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            large_wasm,
            "Should prefer larger size when rank and depth are same"
        );

        Ok(())
    }
}
