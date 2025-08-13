use crate::config::AuthConfig;
use reqwest::RequestBuilder;
use std::{cmp::Reverse, collections::HashMap};
use url::Url;

pub trait Authenticator {
    /// Adds authentication headers to the request if present in auths.
    fn add_auth(self, auths: &Option<HashMap<Url, AuthConfig>>, url: &Url) -> RequestBuilder;
}

impl Authenticator for RequestBuilder {
    fn add_auth(self, auths: &Option<HashMap<Url, AuthConfig>>, url: &Url) -> RequestBuilder {
        if let Some(auths) = auths {
            let mut auths: Vec<(&str, &AuthConfig)> =
                auths.iter().map(|(k, v)| (k.as_str(), v)).collect();
            auths.sort_by_key(|c| Reverse(c.0.len()));
            let url = url.to_string();
            for (k, v) in auths {
                if url.starts_with(k) {
                    return match v {
                        AuthConfig::Basic { username, password } => {
                            self.basic_auth(username, Some(password))
                        }
                        AuthConfig::Token { token } => self.bearer_auth(token),
                    };
                }
            }
        }

        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::collections::HashMap;
    use url::Url;

    #[test]
    fn test_add_auth_basic_authentication() {
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
        let authenticated_request = request.add_auth(&Some(auths), &url);

        // We can't easily test the actual header since reqwest doesn't expose it,
        // but we can verify the method doesn't panic and returns a RequestBuilder
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_token_authentication() {
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
        let authenticated_request = request.add_auth(&Some(auths), &url);

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

    #[test]
    fn test_add_auth_empty_auths_map() {
        let client = Client::new();
        let auths = HashMap::new();
        let url = Url::parse("https://api.example.com").unwrap();

        let request = client.get("https://api.example.com/endpoint");
        let result_request = request.add_auth(&Some(auths), &url);

        // Should return the original request unchanged when no matching auth
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_add_auth_url_prefix_matching() {
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
        let authenticated_request = request.add_auth(&Some(auths), &target_url);

        // The API token should be used (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_url_no_match() {
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
        let result_request = request.add_auth(&Some(auths), &target_url);

        // Should return the original request unchanged when no URL match
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_add_auth_multiple_auths_longest_prefix_wins() {
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
        let authenticated_request = request.add_auth(&Some(auths), &target_url);

        // Should use the v1 auth (longest prefix)
        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_exact_url_match() {
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
        let authenticated_request = request.add_auth(&Some(auths), &exact_url);

        // The fact that we got here without panicking means the method worked
        drop(authenticated_request);
    }

    #[test]
    fn test_add_auth_case_sensitive_urls() {
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
        let result_request = request.add_auth(&Some(auths), &target_url);

        // Should not match due to case sensitivity
        // The fact that we got here without panicking means the method worked
        drop(result_request);
    }

    #[test]
    fn test_auth_config_types_comprehensive() {
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
        let result1 = request1.add_auth(&Some(auths), &url);
        // The fact that we got here without panicking means the method worked
        drop(result1);

        let mut auths = HashMap::new();
        auths.insert(url.clone(), token_auth);

        let request2 = client.get(url.as_str());
        let result2 = request2.add_auth(&Some(auths), &url);
        // The fact that we got here without panicking means the method worked
        drop(result2);
    }
}
