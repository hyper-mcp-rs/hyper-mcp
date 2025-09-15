use crate::Cli;
use anyhow::anyhow;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use flate2::read::GzDecoder;
use oci_client::Reference;
use oci_client::{Client, manifest, manifest::OciDescriptor, secrets::RegistryAuth};
use serde::{Deserialize, Serialize};
use sigstore::cosign::verification_constraint::cert_subject_email_verifier::StringVerifier;
use sigstore::cosign::verification_constraint::{
    CertSubjectEmailVerifier, CertSubjectUrlVerifier, VerificationConstraintVec,
};
use sigstore::cosign::{ClientBuilder, CosignCapabilities, verify_constraints};
use sigstore::errors::SigstoreVerifyConstraintsError;
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::{ManualTrustRoot, TrustRoot};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use tar::Archive;

// Docker manifest format v2
#[derive(Debug, Serialize, Deserialize)]
struct DockerManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType")]
    media_type: String,
    config: DockerManifestConfig,
    layers: Vec<DockerManifestLayer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerManifestConfig {
    #[serde(rename = "mediaType")]
    media_type: String,
    size: u64,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DockerManifestLayer {
    #[serde(rename = "mediaType")]
    media_type: String,
    size: u64,
    digest: String,
}

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

async fn setup_trust_repository(cli: &Cli) -> Result<Box<dyn TrustRoot>, anyhow::Error> {
    if cli.use_sigstore_tuf_data {
        // Use Sigstore TUF data from the official repository
        tracing::info!("Using Sigstore TUF data for verification");
        match SigstoreTrustRoot::new(None).await {
            Ok(repo) => return Ok(Box::new(repo)),
            Err(e) => {
                tracing::error!("Failed to initialize TUF trust repository: {e}");
                if !cli.insecure_skip_signature {
                    return Err(anyhow!(
                        "Failed to initialize TUF trust repository and signature verification is required"
                    ));
                }
                tracing::info!("Falling back to manual trust repository");
            }
        }
    }

    // Create a manual trust repository
    let mut data = ManualTrustRoot::default();

    // Add Rekor public keys if provided
    if let Some(rekor_keys_path) = &cli.rekor_pub_keys {
        if rekor_keys_path.exists() {
            match fs::read(rekor_keys_path) {
                Ok(content) => {
                    tracing::info!("Added Rekor public key");
                    data.rekor_keys.push(content);
                }
                Err(e) => tracing::warn!("Failed to read Rekor public keys file: {e}"),
            }
        } else {
            tracing::warn!("Rekor public keys file not found: {rekor_keys_path:?}");
        }
    }

    // Add Fulcio certificates if provided
    if let Some(fulcio_certs_path) = &cli.fulcio_certs {
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

    Ok(Box::new(data))
}

async fn verify_image_signature(cli: &Cli, image_reference: &str) -> Result<bool, anyhow::Error> {
    tracing::info!("Verifying signature for {image_reference}");

    // Set up the trust repository based on CLI arguments
    let repo = setup_trust_repository(cli).await?;
    let auth = &Auth::Anonymous;

    // Create a client builder
    let client_builder = ClientBuilder::default();

    // Create client with trust repository
    let client_builder = match client_builder.with_trust_repository(repo.as_ref()) {
        Ok(builder) => builder,
        Err(e) => return Err(anyhow!("Failed to set up trust repository: {}", e)),
    };

    // Build the client
    let mut client = match client_builder.build() {
        Ok(client) => client,
        Err(e) => return Err(anyhow!("Failed to build Sigstore client: {}", e)),
    };

    // Parse the reference
    let image_ref = match OciReference::from_str(image_reference) {
        Ok(reference) => reference,
        Err(e) => return Err(anyhow!("Invalid image reference: {}", e)),
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

    if let Some(cert_email) = &cli.cert_email {
        let issuer = cli
            .cert_issuer
            .as_ref()
            .map(|i| StringVerifier::ExactMatch(i.to_string()));

        verification_constraints.push(Box::new(CertSubjectEmailVerifier {
            email: StringVerifier::ExactMatch(cert_email.to_string()),
            issuer,
        }));
    }

    if let Some(cert_url) = &cli.cert_url {
        match cli.cert_issuer.as_ref() {
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

pub async fn pull_and_extract_oci_image(
    cli: &Cli,
    client: &Client,
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
    if !cli.insecure_skip_signature {
        tracing::info!("Signature verification enabled for {image_reference}");
        match verify_image_signature(cli, image_reference).await {
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
