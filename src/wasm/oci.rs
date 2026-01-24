use crate::config::OciConfig;
use crate::naming::PluginName;
use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use flate2::read::GzDecoder;
use oci_client::{
    Client, Reference, client::ClientConfig, manifest, manifest::OciDescriptor,
    secrets::RegistryAuth,
};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path, sync::Arc};
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

    let target_file_path = "/plugin.wasm";

    let mut hasher = Sha256::new();
    hasher.update(image_reference);
    let short_hash = &hex::encode(hasher.finalize())[..7];

    let cache_dir = dirs::cache_dir()
        .map(|mut path| {
            path.push("hyper-mcp");
            path
        })
        .context("Unable to determine cache dir")?;
    std::fs::create_dir_all(&cache_dir)?;

    let local_output_path = cache_dir.join(format!("{short_hash}.wasm"));
    let local_output_path_str = local_output_path
        .to_str()
        .ok_or_else(|| anyhow!("Non-utf8 cache path: {local_output_path:?}"))?;

    pull_and_extract_oci_image(
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
            // Strictest possible when caller provides an identity:
            // require issuer too (otherwise you can get surprising matches).
            let issuer = config.cert_issuer.as_deref().ok_or_else(|| {
                anyhow!("Strict verification requires cert_issuer when cert_email/cert_url is set")
            })?;

            args.push("--certificate-identity-regexp".into());
            args.push(identity.to_string());

            args.push("--certificate-oidc-issuer-regexp".into());
            args.push(issuer.to_string());
        }
        None => {
            // Keyless verification in newer cosign requires an identity constraint.
            // Since you want to accept valid signatures from *any* signer, use match-all regexes.
            args.push("--certificate-identity-regexp".into());
            args.push(".*".into());

            // Some cosign versions also effectively require issuer constraint for keyless flows;
            // match-all keeps it permissive while still enforcing keyless + tlog.
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

    // Build args and append the image ref at the end
    let mut args = cosign_verify_args(config)?;
    args.push(image_reference.to_string());

    let output = Command::new("cosign")
        .args(&args)
        // IMPORTANT: inherit DOCKER_CONFIG etc so cosign can auth to private registries
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

async fn pull_and_extract_oci_image(
    config: &OciConfig,
    image_reference: &str,
    target_file_path: &str,
    local_output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get or create the global lock map
    let locks = DOWNLOAD_LOCKS
        .get_or_init(|| async { DashMap::new() })
        .await;

    // Get or create a lock for this specific image reference (URL)
    // This prevents concurrent downloads of the same OCI image, even if they're
    // being cached to different local paths (e.g., for different plugin names)
    let lock = locks
        .entry(image_reference.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();

    // Acquire the lock to prevent concurrent downloads of the same image
    let _guard = lock.lock().await;

    // Double-check if file exists after acquiring lock (another thread might have downloaded it)
    if Path::new(local_output_path).exists() {
        tracing::info!(
            "Plugin {image_reference} already cached at: {local_output_path}. Skipping downloading."
        );
        return Ok(());
    }

    tracing::info!("Pulling {image_reference} ...");

    // Verify BEFORE pulling layers (cosign will hit the registry itself).
    verify_image_signature_with_cosign(config, image_reference)
        .await
        .map_err(|e| format!("No valid signatures found / verification failed: {e}"))?;

    let reference = Reference::try_from(image_reference)?;
    let auth = build_auth(&reference);

    let client = OCI_CLIENT
        .get_or_init(|| async { Client::new(ClientConfig::default()) })
        .await;

    let manifest = client
        .pull(
            &reference,
            &auth,
            vec![
                manifest::IMAGE_MANIFEST_MEDIA_TYPE,
                manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
            ],
        )
        .await?;

    for layer in manifest.layers.iter() {
        let mut buf = Vec::new();
        let desc = OciDescriptor {
            digest: layer.sha256_digest().clone(),
            media_type: "application/vnd.docker.image.rootfs.diff.tar.gzip".to_string(),
            ..Default::default()
        };

        client.pull_blob(&reference, &desc, &mut buf).await?;

        let gz_extract = GzDecoder::new(&buf[..]);
        let mut archive_extract = Archive::new(gz_extract);

        for entry_result in archive_extract.entries()? {
            match entry_result {
                Ok(mut entry) => {
                    if let Ok(path) = entry.path() {
                        let path_str = path.to_string_lossy();
                        if path_str.ends_with(target_file_path) || path_str.ends_with("plugin.wasm")
                        {
                            if let Some(parent) = Path::new(local_output_path).parent() {
                                fs::create_dir_all(parent)?;
                            }
                            let mut content = Vec::new();
                            entry.read_to_end(&mut content)?;
                            fs::write(local_output_path, content)?;
                            tracing::info!("Successfully extracted to: {local_output_path}");
                            return Ok(());
                        }
                    }
                }
                Err(e) => tracing::info!("Error during extraction: {e}"),
            }
        }
    }

    Err("Target file not found in any layer".into())
}
