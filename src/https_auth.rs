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
