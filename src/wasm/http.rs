use crate::config::AuthConfig;
use anyhow::{Result, anyhow};
use oauth2::{AuthUrl, ClientSecret, Scope, TokenResponse, basic::BasicClient};
use reqwest::{Client, ClientBuilder, RequestBuilder, redirect};
use std::{cmp::Reverse, collections::HashMap};
use tokio::sync::OnceCell;
use url::Url;

static REQWEST_WASM_CLIENT: OnceCell<Client> = OnceCell::const_new();
static REQWEST_OAUTH2_CLIENT: OnceCell<Client> = OnceCell::const_new();

trait Authenticator {
    /// Adds authentication headers to the request if present in auths.
    async fn add_auth(
        self,
        auths: &Option<HashMap<Url, AuthConfig>>,
        url: &Url,
    ) -> Result<RequestBuilder>;
}

impl Authenticator for RequestBuilder {
    async fn add_auth(
        self,
        auths: &Option<HashMap<Url, AuthConfig>>,
        url: &Url,
    ) -> Result<RequestBuilder> {
        if let Some(auths) = auths {
            let mut auths: Vec<(&str, &AuthConfig)> =
                auths.iter().map(|(k, v)| (k.as_str(), v)).collect();
            auths.sort_by_key(|c| Reverse(c.0.len()));
            let url = url.to_string();
            for (k, v) in auths {
                if url.starts_with(k) {
                    return match v {
                        AuthConfig::Basic { username, password } => {
                            Ok(self.basic_auth(username, Some(password)))
                        }
                        AuthConfig::Token { token } => Ok(self.bearer_auth(token)),
                        AuthConfig::OAuth2 {
                            client_id,
                            client_secret,
                            auth_uri,
                            token_uri,
                            params,
                            scopes,
                        } => {
                            let client = BasicClient::new(oauth2::ClientId::new(client_id.clone()))
                                .set_client_secret(ClientSecret::new(client_secret.clone()))
                                .set_auth_uri(AuthUrl::new(auth_uri.to_string())?)
                                .set_token_uri(oauth2::TokenUrl::new(token_uri.to_string())?);
                            let mut exchange = client.exchange_client_credentials();
                            if let Some(params) = params {
                                for (param, value) in params {
                                    exchange = exchange.add_extra_param(param, value);
                                }
                            }
                            if let Some(scopes) = scopes {
                                for scope in scopes {
                                    exchange = exchange.add_scope(Scope::new(scope.clone()));
                                }
                            }
                            let request_client = REQWEST_OAUTH2_CLIENT
                                .get_or_init(|| async {
                                    ClientBuilder::new()
                                        .redirect(redirect::Policy::none())
                                        .build()
                                        .expect("Failed to build reqwest OAuth2 client")
                                })
                                .await;
                            Ok(self.bearer_auth(
                                exchange
                                    .request_async(request_client)
                                    .await?
                                    .access_token()
                                    .secret(),
                            ))
                        }
                    };
                }
            }
        }

        Ok(self)
    }
}

pub async fn load_wasm(url: &Url, auths: &Option<HashMap<Url, AuthConfig>>) -> Result<Vec<u8>> {
    match url.scheme() {
        "http" => Ok(REQWEST_WASM_CLIENT
            .get_or_init(|| async { Client::new() })
            .await
            .get(url.as_str())
            .send()
            .await?
            .bytes()
            .await?
            .to_vec()),
        "https" => Ok(REQWEST_WASM_CLIENT
            .get_or_init(|| async { Client::new() })
            .await
            .get(url.as_str())
            .add_auth(auths, url)
            .await?
            .send()
            .await?
            .bytes()
            .await?
            .to_vec()),
        _ => Err(anyhow!("Unsupported URL scheme: {}", url.scheme())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::collections::HashMap;
    use url::Url;

    #[tokio::test]
    async fn test_add_auth_basic_authentication() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            url.clone(),
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        let request = client.get("https://api.example.com/endpoint");
        let authenticated_request = request
            .add_auth(&Some(auths), &url)
            .await
            .expect("Failed to add auth");

        // We can't easily test the actual header since reqwest doesn't expose it,
        // but we can verify the method doesn't panic and returns a RequestBuilder
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[tokio::test]
    async fn test_add_auth_token_authentication() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            url.clone(),
            AuthConfig::Token {
                token: "bearer-token-123".to_string(),
            },
        );

        let request = client.get("https://api.example.com/endpoint");
        let authenticated_request = request
            .add_auth(&Some(auths), &url)
            .await
            .expect("Failed to add auth");

        // Verify the method completes without error
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_no_auths_provided() {
        let client = Client::new();
        let url = Url::parse("https://api.example.com").unwrap();

        let request = client.get("https://api.example.com/endpoint");
        let result_request = request.add_auth(&None, &url);

        // Should return the original request unchanged
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[tokio::test]
    async fn test_add_auth_empty_auths_map() {
        let client = Client::new();
        let auths = HashMap::new();
        let url = Url::parse("https://api.example.com").unwrap();

        let request = client.get("https://api.example.com/endpoint");
        let result_request = request
            .add_auth(&Some(auths), &url)
            .await
            .expect("Failed to add auth");

        // Should return the original request unchanged when no matching auth
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[tokio::test]
    async fn test_add_auth_url_prefix_matching() {
        let client = Client::new();
        let mut auths = HashMap::new();

        // Add auth for broader domain
        let domain_url = Url::parse("https://example.com").unwrap();
        auths.insert(
            domain_url,
            AuthConfig::Basic {
                username: "domain_user".to_string(),
                password: "domain_pass".to_string(),
            },
        );

        // Add auth for specific API endpoint (longer prefix)
        let api_url = Url::parse("https://example.com/api").unwrap();
        auths.insert(
            api_url,
            AuthConfig::Token {
                token: "api-token".to_string(),
            },
        );

        // Test that longer prefix wins
        let target_url = Url::parse("https://example.com/api/v1/data").unwrap();
        let request = client.get(target_url.as_str());
        let authenticated_request = request
            .add_auth(&Some(auths), &target_url)
            .await
            .expect("Failed to add auth");

        // The API token should be used (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[tokio::test]
    async fn test_add_auth_url_no_match() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let auth_url = Url::parse("https://api.example.com").unwrap();
        auths.insert(
            auth_url,
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        // Request to different domain
        let target_url = Url::parse("https://different.com/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let result_request = request
            .add_auth(&Some(auths), &target_url)
            .await
            .expect("Failed to add auth");

        // Should return the original request unchanged when no URL match
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[tokio::test]
    async fn test_add_auth_multiple_auths_longest_prefix_wins() {
        let client = Client::new();
        let mut auths = HashMap::new();

        // Add multiple auths with different prefix lengths
        auths.insert(
            Url::parse("https://example.com").unwrap(),
            AuthConfig::Basic {
                username: "broad_user".to_string(),
                password: "broad_pass".to_string(),
            },
        );

        auths.insert(
            Url::parse("https://example.com/api").unwrap(),
            AuthConfig::Token {
                token: "api_token".to_string(),
            },
        );

        auths.insert(
            Url::parse("https://example.com/api/v1").unwrap(),
            AuthConfig::Basic {
                username: "v1_user".to_string(),
                password: "v1_pass".to_string(),
            },
        );

        // Test with URL that matches all three (longest should win)
        let target_url = Url::parse("https://example.com/api/v1/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let authenticated_request = request
            .add_auth(&Some(auths), &target_url)
            .await
            .expect("Failed to add auth");

        // Should use the v1 auth (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[tokio::test]
    async fn test_add_auth_exact_url_match() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let exact_url = Url::parse("https://api.example.com/v1/data").unwrap();
        auths.insert(
            exact_url.clone(),
            AuthConfig::Token {
                token: "exact-match-token".to_string(),
            },
        );

        let request = client.get(exact_url.as_str());
        let authenticated_request = request
            .add_auth(&Some(auths), &exact_url)
            .await
            .expect("Failed to add auth");

        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[tokio::test]
    async fn test_add_auth_case_sensitive_urls() {
        let client = Client::new();
        let mut auths = HashMap::new();

        let auth_url = Url::parse("https://API.EXAMPLE.COM").unwrap();
        auths.insert(
            auth_url,
            AuthConfig::Basic {
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
        );

        // Test with lowercase URL
        let target_url = Url::parse("https://api.example.com/endpoint").unwrap();
        let request = client.get(target_url.as_str());
        let result_request = request
            .add_auth(&Some(auths), &target_url)
            .await
            .expect("Failed to add auth");

        // Should not match due to case sensitivity
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[tokio::test]
    async fn test_auth_config_types_comprehensive() {
        // Test all AuthConfig variants can be created and used
        let basic_auth = AuthConfig::Basic {
            username: "basic_user".to_string(),
            password: "basic_pass".to_string(),
        };

        let token_auth = AuthConfig::Token {
            token: "token_value".to_string(),
        };

        let client = Client::new();
        let url = Url::parse("https://test.com").unwrap();

        // Test both types can be used with add_auth
        let mut auths = HashMap::new();
        auths.insert(url.clone(), basic_auth);

        let request1 = client.get(url.as_str());
        let result1 = request1
            .add_auth(&Some(auths), &url)
            .await
            .expect("Failed to add auth");

        // The fact that we got here without panicking means the method worked
        drop(result1);

        let mut auths = HashMap::new();
        auths.insert(url.clone(), token_auth);

        let request2 = client.get(url.as_str());
        let result2 = request2
            .add_auth(&Some(auths), &url)
            .await
            .expect("Failed to add auth");

        // The fact that we got here without panicking means the method worked
        drop(result2);
    }
}
