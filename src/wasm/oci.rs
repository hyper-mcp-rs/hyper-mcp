use crate::config::OciConfig;
use crate::naming::PluginName;
use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use flate2::read::GzDecoder;
use oci_client::{
    Client, Reference,
    client::{ClientConfig, linux_amd64_resolver},
    manifest::OciManifest,
    secrets::RegistryAuth,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use tar::Archive;
use tokio::process::Command;
use tokio::sync::{Mutex, OnceCell};
use url::Url;

static OCI_CLIENT: OnceCell<Client> = OnceCell::const_new();
static DOWNLOAD_LOCKS: OnceCell<DashMap<String, Arc<Mutex<()>>>> = OnceCell::const_new();

fn build_auth(reference: &Reference) -> RegistryAuth {
    let server = reference
        .resolve_registry()
        .strip_suffix('/')
        .unwrap_or_else(|| reference.resolve_registry());

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

    let mut hasher = Sha256::new();
    hasher.update(image_reference);
    let hash = hex::encode(hasher.finalize());

    let cache_dir = dirs::cache_dir()
        .map(|mut path| {
            path.push("hyper-mcp");
            path
        })
        .context("Unable to determine cache dir")?;
    std::fs::create_dir_all(&cache_dir)?;

    let local_output_path = cache_dir.join(format!("{hash}.wasm"));
    let local_output_path_str = local_output_path
        .to_str()
        .ok_or_else(|| anyhow!("Non-utf8 cache path: {local_output_path:?}"))?;

    pull_and_extract_oci_artifact(
        config,
        image_reference,
        target_file_path,
        local_output_path_str,
    )
    .await
    .map_err(|e| anyhow!("Failed to pull OCI plugin: {e}"))?;

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
    config: &OciConfig,
    image_reference: &str,
    target_file_path: &str,
    local_output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let locks = DOWNLOAD_LOCKS
        .get_or_init(|| async { DashMap::new() })
        .await;

    let lock = locks
        .entry(image_reference.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();

    let _guard = lock.lock().await;

    if Path::new(local_output_path).exists() {
        tracing::info!(
            "Plugin {image_reference} already cached at: {local_output_path}. Skipping downloading."
        );
        return Ok(());
    }

    tracing::info!("Pulling {image_reference} ...");

    // Verify BEFORE downloading blobs
    verify_image_signature_with_cosign(config, image_reference)
        .await
        .map_err(|e| format!("No valid signatures found / verification failed: {e}"))?;

    let reference = Reference::try_from(image_reference)?;
    let auth = build_auth(&reference);

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

    let (manifest, _manifest_digest) = client.pull_manifest(&reference, &auth).await?;

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

        let mut buf = Vec::new();

        // Pull by digest string (AsLayerDescriptor for &str) to avoid media-type validation.
        client.pull_blob(&reference, digest, &mut buf).await?;

        if let Some(wasm) = extract_wasm_from_blob(&buf, target_file_path)? {
            if let Some(parent) = Path::new(local_output_path).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(local_output_path, wasm)?;
            tracing::info!("Successfully extracted to: {local_output_path}");
            return Ok(());
        }
    }

    Err("No wasm payload found in any layer (expected wasm blob or tar(.gz) containing plugin.wasm)".into())
}
