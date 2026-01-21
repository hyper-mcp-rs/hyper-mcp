use crate::config::OciConfig;
use crate::naming::PluginName;
use anyhow::{Result, anyhow};
use docker_credential::{CredentialRetrievalError, DockerCredential};
use flate2::read::GzDecoder;
use oci_client::{
    Client, Reference, client::ClientConfig, manifest, manifest::OciDescriptor,
    secrets::RegistryAuth,
};
use sha2::{Digest, Sha256};
use sigstore::{
    cosign::{
        ClientBuilder, CosignCapabilities,
        verification_constraint::{
            CertSubjectEmailVerifier, CertSubjectUrlVerifier, VerificationConstraintVec,
            cert_subject_email_verifier::StringVerifier,
        },
        verify_constraints,
    },
    errors::SigstoreVerifyConstraintsError,
    registry::{Auth, OciReference},
    trust::{ManualTrustRoot, TrustRoot, sigstore::SigstoreTrustRoot},
};
use std::{fs, io::Read, path::Path, str::FromStr};
use tar::Archive;
use tokio::sync::OnceCell;
use url::Url;

static OCI_CLIENT: OnceCell<Client> = OnceCell::const_new();

fn build_auth(reference: &Reference) -> RegistryAuth {
    let server = reference
        .resolve_registry()
        .strip_suffix('/')
        .unwrap_or_else(|| reference.resolve_registry());

    // if cli.anonymous {
    //     return RegistryAuth::Anonymous;
    // }

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
            tracing::info!(
                "Cannot use contents of docker config, identity token not supported. Using anonymous auth"
            );
            RegistryAuth::Anonymous
        }
    }
}

pub async fn load_wasm(url: &Url, config: &OciConfig, plugin_name: &PluginName) -> Result<Vec<u8>> {
    let image_reference = url.as_str().strip_prefix("oci://").unwrap();
    let target_file_path = "/plugin.wasm";
    let mut hasher = Sha256::new();
    hasher.update(image_reference);
    let hash = hasher.finalize();
    let short_hash = &hex::encode(hash)[..7];
    let cache_dir = dirs::cache_dir()
        .map(|mut path| {
            path.push("hyper-mcp");
            path
        })
        .unwrap();
    std::fs::create_dir_all(&cache_dir)?;

    let local_output_path = cache_dir.join(format!("{plugin_name}-{short_hash}.wasm"));
    let local_output_path = local_output_path.to_str().unwrap();

    if let Err(e) =
        pull_and_extract_oci_image(config, image_reference, target_file_path, local_output_path)
            .await
    {
        tracing::error!("Error pulling oci plugin: {e}");
        return Err(anyhow::anyhow!("Failed to pull OCI plugin: {e}"));
    }
    tracing::info!("cache plugin `{plugin_name}` to : {local_output_path}");
    tokio::fs::read(local_output_path)
        .await
        .map_err(|e| e.into())
}

async fn setup_trust_repository(config: &OciConfig) -> Result<Box<dyn TrustRoot>> {
    if config.use_sigstore_tuf_data {
        // Use Sigstore TUF data from the official repository
        tracing::info!("Using Sigstore TUF data for verification");
        match SigstoreTrustRoot::new(None).await {
            Ok(repo) => return Ok(Box::new(repo) as Box<dyn TrustRoot>),
            Err(e) => {
                tracing::error!("Failed to initialize TUF trust repository: {e}");
                if !config.insecure_skip_signature {
                    return Err(anyhow!(
                        "Failed to initialize TUF trust repository and signature verification is required"
                    ));
                }
                tracing::info!("Falling back to manual trust repository");
            }
        }
    }

    // Create a manual trust repository
    let mut data: ManualTrustRoot<'static> = ManualTrustRoot::default();

    // Add Rekor public keys if provided
    if let Some(rekor_keys_path) = &config.rekor_pub_keys {
        if rekor_keys_path.exists() {
            match fs::read(rekor_keys_path) {
                Ok(content) => {
                    tracing::info!("Added Rekor public key");
                    if let Some(path_str) = rekor_keys_path.to_str() {
                        data.rekor_keys.insert(path_str.to_string(), content);
                        tracing::info!("Added Rekor public key from: {}", path_str);
                    }
                }
                Err(e) => tracing::warn!("Failed to read Rekor public keys file: {e}"),
            }
        } else {
            tracing::warn!("Rekor public keys file not found: {rekor_keys_path:?}");
        }
    }

    // Add Fulcio certificates if provided
    if let Some(fulcio_certs_path) = &config.fulcio_certs {
        if fulcio_certs_path.exists() {
            match fs::read(fulcio_certs_path) {
                Ok(content) => {
                    let certificate = sigstore::registry::Certificate {
                        encoding: sigstore::registry::CertificateEncoding::Pem,
                        data: content,
                    };

                    match certificate.try_into() {
                        Ok(cert) => {
                            tracing::info!("Added Fulcio certificate");
                            data.fulcio_certs.push(cert);
                        }
                        Err(e) => tracing::warn!("Failed to parse Fulcio certificate: {e}"),
                    }
                }
                Err(e) => tracing::warn!("Failed to read Fulcio certificates file: {e}"),
            }
        } else {
            tracing::warn!("Fulcio certificates file not found: {fulcio_certs_path:?}");
        }
    }

    Ok(Box::new(data) as Box<dyn TrustRoot>)
}

async fn verify_image_signature(config: &OciConfig, image_reference: &str) -> Result<bool> {
    tracing::info!("Verifying signature for {image_reference}");

    // Set up the trust repository based on CLI arguments
    let repo = setup_trust_repository(config).await?;
    let auth = &Auth::Anonymous;

    // Create a client builder
    let client_builder = ClientBuilder::default();

    // Create client with trust repository
    let client_builder = match client_builder.with_trust_repository(repo.as_ref()) {
        Ok(builder) => builder,
        Err(e) => return Err(anyhow!("Failed to set up trust repository: {e}")),
    };

    // Build the client
    let mut client = match client_builder.build() {
        Ok(client) => client,
        Err(e) => return Err(anyhow!("Failed to build Sigstore client: {e}")),
    };

    // Parse the reference
    let image_ref = match OciReference::from_str(image_reference) {
        Ok(reference) => reference,
        Err(e) => return Err(anyhow!("Invalid image reference: {e}")),
    };

    // Triangulate to find the signature image and source digest
    let (cosign_signature_image, source_image_digest) =
        match client.triangulate(&image_ref, auth).await {
            Ok((sig_image, digest)) => (sig_image, digest),
            Err(e) => {
                tracing::warn!("Failed to triangulate image: {e}");
                return Ok(false); // No signatures found
            }
        };

    // Get trusted signature layers
    let signature_layers = match client
        .trusted_signature_layers(auth, &source_image_digest, &cosign_signature_image)
        .await
    {
        Ok(layers) => layers,
        Err(e) => {
            tracing::warn!("Failed to get trusted signature layers: {e}");
            return Ok(false);
        }
    };

    if signature_layers.is_empty() {
        tracing::warn!("No valid signatures found for {image_reference}");
        return Ok(false);
    }

    // Build verification constraints based on CLI options
    let mut verification_constraints: VerificationConstraintVec = Vec::new();

    if let Some(cert_email) = &config.cert_email {
        let issuer = config
            .cert_issuer
            .as_ref()
            .map(|i| StringVerifier::ExactMatch(i.to_string()));

        verification_constraints.push(Box::new(CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch(cert_email.to_string()),
            issuer,
        }));
    }

    if let Some(cert_url) = &config.cert_url {
        match config.cert_issuer.as_ref() {
            Some(issuer) => {
                verification_constraints.push(Box::new(CertSubjectUrlVerifier {
                    url: cert_url.to_string(),
                    issuer: issuer.to_string(),
                }));
            }
            None => {
                tracing::warn!("'cert-issuer' is required when 'cert-url' is specified");
            }
        }
    }

    // Verify the constraints
    match verify_constraints(&signature_layers, verification_constraints.iter()) {
        Ok(()) => {
            tracing::info!("Signature verification successful for {image_reference}");
            Ok(true)
        }
        Err(SigstoreVerifyConstraintsError {
            unsatisfied_constraints,
        }) => {
            tracing::warn!(
                "Signature verification failed for {image_reference}: {unsatisfied_constraints:?}"
            );
            Ok(false)
        }
    }
}

async fn pull_and_extract_oci_image(
    config: &OciConfig,
    image_reference: &str,
    target_file_path: &str,
    local_output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(local_output_path).exists() {
        tracing::info!(
            "Plugin {image_reference} already cached at: {local_output_path}. Skipping downloading."
        );
        return Ok(());
    }

    tracing::info!("Pulling {image_reference} ...");

    let reference = Reference::try_from(image_reference)?;
    let auth = build_auth(&reference);

    // Verify the image signature if it's an OCI image and verification is enabled
    if !config.insecure_skip_signature {
        tracing::info!("Signature verification enabled for {image_reference}");
        match verify_image_signature(config, image_reference).await {
            Ok(verified) => {
                if !verified {
                    return Err(format!(
                        "No valid signatures found for the image {image_reference}"
                    )
                    .into());
                }
            }
            Err(e) => {
                return Err(format!("Image signature verification failed: {e}").into());
            }
        }
    } else {
        tracing::warn!("Signature verification disabled for {image_reference}");
    }

    let client = OCI_CLIENT
        .get_or_init(|| async { Client::new(ClientConfig::default()) })
        .await;

    // Accept both OCI and Docker manifest types
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
        client.pull_blob(&reference, &desc, &mut buf).await.unwrap();

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
