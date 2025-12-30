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

pub async fn create_jwks(
    config: Config,
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
    pub async fn new<F, Fut>(config: &Config, create_jwks: F) -> Result<Self>
    where
        F: Fn(Config) -> Fut + Send + Sync,
        Fut: Future<Output = Result<(Vec<AuthorizationServerUrl>, HashMap<String, JwkSet>)>>,
    {
        let (auth_servers, jwks) = create_jwks(config.clone()).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper function to create a minimal valid Config for testing
    fn create_test_config() -> Config {
        Config {
            auths: None,
            oauth_protected_resource: None,
            oci: Default::default(),
            plugins: Default::default(),
        }
    }

    // Helper to create a DiscoveryMetadata for testing
    fn create_test_discovery_metadata() -> DiscoveryMetadata {
        DiscoveryMetadata {
            issuer: Some("https://example.com".to_string()),
            jwks_uri: "https://example.com/.well-known/jwks.json".to_string(),
        }
    }

    #[test]
    fn test_discovery_metadata_creation() {
        let metadata = create_test_discovery_metadata();
        assert_eq!(metadata.issuer, Some("https://example.com".to_string()));
        assert_eq!(
            metadata.jwks_uri,
            "https://example.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn test_discovery_metadata_issuer_optional() {
        let metadata = DiscoveryMetadata {
            issuer: None,
            jwks_uri: "https://example.com/.well-known/jwks.json".to_string(),
        };
        assert_eq!(metadata.issuer, None);
    }

    #[test]
    fn test_discovery_metadata_deserialization() {
        let json = json!({
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks"
        });

        let metadata: DiscoveryMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(
            metadata.issuer,
            Some("https://auth.example.com".to_string())
        );
        assert_eq!(metadata.jwks_uri, "https://auth.example.com/jwks");
    }

    #[test]
    fn test_discovery_metadata_deserialization_without_issuer() {
        let json = json!({
            "jwks_uri": "https://auth.example.com/jwks"
        });

        let metadata: DiscoveryMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(metadata.issuer, None);
        assert_eq!(metadata.jwks_uri, "https://auth.example.com/jwks");
    }

    #[test]
    fn test_server_state_clone() {
        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "test docs".to_string(),
            jwks: HashMap::new(),
            scopes: HashSet::new(),
        };

        let cloned = state.clone();
        assert_eq!(state.docs, cloned.docs);
        assert_eq!(state.auth_servers.len(), cloned.auth_servers.len());
        assert_eq!(state.jwks.len(), cloned.jwks.len());
        assert_eq!(state.scopes.len(), cloned.scopes.len());
    }

    #[test]
    fn test_server_state_with_empty_auth_servers() {
        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "documentation".to_string(),
            jwks: HashMap::new(),
            scopes: HashSet::new(),
        };

        assert!(state.auth_servers.is_empty());
        assert!(state.jwks.is_empty());
    }

    #[test]
    fn test_server_state_with_jwks() {
        let mut jwks_map = HashMap::new();
        let jwks_set = JwkSet { keys: vec![] };
        jwks_map.insert("https://example.com".to_string(), jwks_set);

        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "docs".to_string(),
            jwks: jwks_map,
            scopes: HashSet::new(),
        };

        assert_eq!(state.jwks.len(), 1);
        assert!(state.jwks.contains_key("https://example.com"));
    }

    #[test]
    fn test_server_state_with_scopes() {
        let mut scopes = HashSet::new();
        scopes.insert("read".to_string());
        scopes.insert("write".to_string());

        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "docs".to_string(),
            jwks: HashMap::new(),
            scopes,
        };

        assert_eq!(state.scopes.len(), 2);
        assert!(state.scopes.contains("read"));
        assert!(state.scopes.contains("write"));
    }

    #[tokio::test]
    async fn test_create_jwks_with_no_oauth_config() {
        let config = create_test_config();
        let (auth_servers, jwks) = create_jwks(config).await.unwrap();

        assert!(auth_servers.is_empty());
        assert!(jwks.is_empty());
    }

    #[test]
    fn test_create_test_config() {
        let config = create_test_config();
        assert!(config.oauth_protected_resource.is_none());
        assert!(config.auths.is_none());
    }

    #[test]
    fn test_server_state_fields_are_initialized() {
        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "test documentation".to_string(),
            jwks: HashMap::new(),
            scopes: HashSet::new(),
        };

        assert!(state.docs.len() > 0);
        assert_eq!(state.docs, "test documentation");
        assert!(state.auth_servers.is_empty());
        assert!(state.jwks.is_empty());
        assert!(state.scopes.is_empty());
    }

    #[test]
    fn test_multiple_scopes_in_hashset() {
        let mut scopes = HashSet::new();
        let scope_names = vec!["read", "write", "admin", "delete"];

        for scope in &scope_names {
            scopes.insert(scope.to_string());
        }

        assert_eq!(scopes.len(), scope_names.len());
        for scope in scope_names {
            assert!(scopes.contains(scope));
        }
    }

    #[test]
    fn test_server_state_with_multiple_jwks() {
        let mut jwks_map = HashMap::new();
        let issuers = vec![
            "https://auth1.example.com",
            "https://auth2.example.com",
            "https://auth3.example.com",
        ];

        for issuer in &issuers {
            let jwks_set = JwkSet { keys: vec![] };
            jwks_map.insert(issuer.to_string(), jwks_set);
        }

        let state = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "docs".to_string(),
            jwks: jwks_map,
            scopes: HashSet::new(),
        };

        assert_eq!(state.jwks.len(), issuers.len());
        for issuer in issuers {
            assert!(state.jwks.contains_key(issuer));
        }
    }

    #[test]
    fn test_server_state_clone_independence() {
        let mut scopes1 = HashSet::new();
        scopes1.insert("read".to_string());

        let state1 = ServerState {
            auth_servers: vec![],
            config: create_test_config(),
            docs: "docs1".to_string(),
            jwks: HashMap::new(),
            scopes: scopes1,
        };

        let mut state2 = state1.clone();
        state2.docs = "docs2".to_string();

        // Ensure cloning creates independent copies
        assert_eq!(state1.docs, "docs1");
        assert_eq!(state2.docs, "docs2");
        assert_eq!(state1.scopes, state2.scopes); // scopes should still be equal
    }

    #[test]
    fn test_discovery_metadata_with_trailing_slash_in_jwks_uri() {
        let metadata = DiscoveryMetadata {
            issuer: Some("https://example.com".to_string()),
            jwks_uri: "https://example.com/.well-known/jwks.json/".to_string(),
        };

        // The jwks_uri should be stored as-is (trailing slash handling is done by HTTP client)
        assert_eq!(
            metadata.jwks_uri,
            "https://example.com/.well-known/jwks.json/"
        );
    }
}
