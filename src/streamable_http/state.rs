use crate::config::{AuthorizationServerUrl, Config};
use anyhow::{Context, Result, anyhow};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use rmcp::model::ClientInfo;
use rmcp::service::{RoleClient, RoleServer, RunningService, Service, serve_client, serve_server};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tokio::io::duplex;

#[derive(Debug, Deserialize)]
struct DiscoveryMetadata {
    // Required in OIDC, optional in plain OAuth metadata, but we want it.
    issuer: Option<String>,
    jwks_uri: String,
}

impl DiscoveryMetadata {
    async fn from_url(client: &Client, base_url: &AuthorizationServerUrl) -> Result<Self> {
        // Normalize base_url (no trailing slash double-ups)
        let base_url = base_url.to_string();
        let base = base_url.trim_end_matches('/');

        // 1) Try OAuth AS metadata: /.well-known/oauth-authorization-server
        let oauth_url = format!("{base}/.well-known/oauth-authorization-server");
        if let Ok(resp) = client.get(&oauth_url).send().await {
            if resp.status().is_success() {
                let mut meta = resp
                    .json::<Self>()
                    .await
                    .with_context(|| format!("failed to parse OAuth metadata from {oauth_url}"))?;
                // OAuth metadata may omit issuer, fill it in if so
                if meta.issuer.is_none() {
                    meta.issuer = Some(base_url);
                }
                return Ok(meta);
            } else {
                tracing::info!(
                    "OAuth metadata fetch from {oauth_url} returned HTTP {}",
                    resp.status()
                );
            }
        }

        // 2) Fallback to OIDC discovery: /.well-known/openid-configuration
        let oidc_url = format!("{base}/.well-known/openid-configuration");
        let resp = client
            .get(&oidc_url)
            .send()
            .await
            .with_context(|| format!("failed to GET OIDC discovery from {oidc_url}"))?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "Unable to fetch either Oauth or OIDC metadata: OIDC fetch from {oidc_url} returned HTTP {}",
                resp.status()
            );
        }

        resp.json::<Self>()
            .await
            .with_context(|| format!("failed to parse OIDC metadata from {oidc_url}"))
    }

    async fn fetch_jwks(&self, client: &Client) -> Result<JwkSet> {
        let resp = client
            .get(self.jwks_uri.clone())
            .send()
            .await
            .with_context(|| format!("failed to GET JWKS from {}", self.jwks_uri))?;

        resp.error_for_status()?
            .json::<JwkSet>()
            .await
            .with_context(|| format!("failed to parse JWKS from {}", self.jwks_uri))
    }
}

async fn create_jwks(
    config: &Config,
) -> Result<(Vec<AuthorizationServerUrl>, HashMap<String, JwkSet>)> {
    let mut auth_servers = Vec::new();
    let mut jwks = HashMap::new();

    if let Some(oauth_protected_resource) = &config.oauth_protected_resource
        && let Some(authorization_servers) = &oauth_protected_resource.authorization_servers
    {
        let client = reqwest::Client::new();
        for auth_server_url in authorization_servers {
            match DiscoveryMetadata::from_url(&client, auth_server_url).await {
                Ok(discovery_metadata) => {
                    if let Some(issuer) = &discovery_metadata.issuer {
                        match discovery_metadata.fetch_jwks(&client).await {
                            Ok(jwk_set) => {
                                auth_servers.push(auth_server_url.clone());
                                jwks.insert(issuer.clone(), jwk_set);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to fetch JWKS for issuer {}, skipping: {}",
                                    issuer,
                                    e
                                );
                            }
                        }
                    } else {
                        tracing::error!(
                            "Issuer missing in discovery metadata for authorization server {}, skipping",
                            auth_server_url
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to fetch discovery metadata for authorization server {}, skipping: {}",
                        auth_server_url,
                        e
                    );
                }
            }
        }
    }

    Ok((auth_servers, jwks))
}

#[derive(Clone)]
pub struct ServerState {
    pub auth_servers: Vec<AuthorizationServerUrl>,
    pub config: Config,
    pub docs: String,
    pub jwks: HashMap<String, JwkSet>,
    pub scopes: HashSet<String>,
}

impl ServerState {
    pub async fn new(config: &Config) -> Result<Self> {
        let (auth_servers, jwks) = create_jwks(config).await?;
        if auth_servers.is_empty() {
            if let Some(oauth_protected_resource) = &config.oauth_protected_resource
                && let Some(auth_servers_configed) = &oauth_protected_resource.authorization_servers
                && !auth_servers_configed.is_empty()
            {
                return Err(anyhow!(
                    "No valid authorization servers configured for OAuth protected resource, check logs"
                ));
            } else {
                tracing::warn!(
                    "No authorization servers configured for OAuth protected resource, this server will not be secured"
                );
            }
        }

        async fn temp_pair<S, C>(
            service: S,
            client: C,
        ) -> (RunningService<RoleServer, S>, RunningService<RoleClient, C>)
        where
            S: Service<RoleServer>,
            C: Service<RoleClient>,
        {
            let (srv_io, cli_io) = duplex(64 * 1024);
            tokio::try_join!(
                async {
                    serve_server(service, srv_io)
                        .await
                        .map_err(anyhow::Error::from)
                },
                async {
                    serve_client(client, cli_io)
                        .await
                        .map_err(anyhow::Error::from)
                }
            )
            .expect("Failed to create documentation pair")
        }

        let (server, client) = temp_pair(
            crate::service::PluginService::new(config).await?,
            ClientInfo::default(),
        )
        .await;

        let docs = server.service().generate_docs().await?;
        let scopes = server.service().generate_scopes().await?;

        server.cancel().await?;
        client.cancel().await?;

        Ok(Self {
            auth_servers,
            config: config.clone(),
            docs,
            jwks,
            scopes,
        })
    }
}
