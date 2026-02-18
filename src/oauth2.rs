use std::{
    collections::HashMap,
    hash::Hash,
    sync::LazyLock,
    time::{Duration, SystemTime},
};

use anyhow::Result;
use extism::{FromBytes, ToBytes};
use extism_convert::Json;
use oauth2::{
    Client, ClientId, ClientSecret, DeviceAuthorizationUrl, EmptyExtraTokenFields,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    reqwest,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AuthType {
    RequestBody,
    BasicAuth,
}

impl From<AuthType> for oauth2::AuthType {
    fn from(value: AuthType) -> Self {
        match value {
            AuthType::RequestBody => oauth2::AuthType::RequestBody,
            AuthType::BasicAuth => oauth2::AuthType::BasicAuth,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromBytes, ToBytes)]
#[encoding(Json)]
pub struct AccessToken {
    pub access_token: oauth2::AccessToken,
    pub expires_at: Option<SystemTime>,
    pub scopes: Option<Vec<Scope>>,
}

impl AccessToken {
    const EXPIRY_SKEW: Duration = Duration::from_secs(30);

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(t) => SystemTime::now() + Self::EXPIRY_SKEW >= t,
            None => false,
        }
    }
}

impl From<&StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> for AccessToken {
    fn from(value: &StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>) -> Self {
        AccessToken {
            access_token: value.access_token().clone(),
            expires_at: value.expires_in().map(|d| SystemTime::now() + d),
            scopes: value.scopes().cloned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthCredentials {
    pub auth_type: Option<AuthType>,
    pub client_id: ClientId,
    pub client_secret: Option<ClientSecret>,
    pub device_authorization_url: Option<DeviceAuthorizationUrl>,
    pub extra_params: Option<HashMap<String, String>>,
    pub scopes: Option<Vec<Scope>>,
    pub token_endpoint_url: TokenUrl,
}

impl Eq for OauthCredentials {}

impl PartialEq for OauthCredentials {
    fn eq(&self, other: &Self) -> bool {
        self.auth_type == other.auth_type
            && self.client_id == other.client_id
            && match (&self.client_secret, &other.client_secret) {
                (Some(s), Some(o)) => s.secret() == o.secret(),
                (None, None) => true,
                _ => false,
            }
            && self.device_authorization_url == other.device_authorization_url
            && self.extra_params == other.extra_params
            && self.scopes == other.scopes
            && self.token_endpoint_url == other.token_endpoint_url
    }
}

impl Hash for OauthCredentials {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.auth_type.hash(state);
        self.client_id.to_string().hash(state);
        self.client_secret
            .as_ref()
            .map(|u| u.secret().to_string())
            .hash(state);
        self.device_authorization_url
            .as_ref()
            .map(|u| u.to_string())
            .hash(state);
        match &self.extra_params {
            None => {
                0u8.hash(state);
            }
            Some(map) => {
                1u8.hash(state);
                let mut kv: Vec<(&String, &String)> = map.iter().collect();
                kv.sort_unstable_by(|(ka, va), (kb, vb)| ka.cmp(kb).then_with(|| va.cmp(vb)));
                kv.len().hash(state);
                for (k, v) in kv {
                    k.hash(state);
                    v.hash(state);
                }
            }
        }
        match &self.scopes {
            None => {
                0u8.hash(state);
            }
            Some(scopes) => {
                1u8.hash(state);
                let mut s: Vec<String> = scopes.iter().map(|sc| sc.to_string()).collect();
                s.sort_unstable();
                s.len().hash(state);
                for scope in s {
                    scope.hash(state);
                }
            }
        }
        self.token_endpoint_url.to_string().hash(state);
    }
}

pub type TokenClient = Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointNotSet,   // auth url
    EndpointMaybeSet, // device auth url (set via *_option)
    EndpointNotSet,   // introspection url
    EndpointNotSet,   // revocation url
    EndpointSet,      // token url
>;

impl From<&OauthCredentials> for TokenClient {
    fn from(value: &OauthCredentials) -> Self {
        let mut client = BasicClient::new(value.client_id.clone())
            .set_token_uri(value.token_endpoint_url.clone())
            .set_device_authorization_url_option(value.device_authorization_url.clone());
        if let Some(client_secret) = &value.client_secret {
            client = client.set_client_secret((*client_secret).clone());
        }
        if let Some(auth_type) = &value.auth_type {
            client = client.set_auth_type((*auth_type).clone().into());
        }
        client
    }
}

pub static HTTP_CLIENT: LazyLock<reqwest::blocking::Client> = LazyLock::new(|| {
    reqwest::blocking::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build OAuth HTTP client")
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{Duration, SystemTime};

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    fn make_creds(
        client_id: &str,
        client_secret: Option<&str>,
        auth_type: Option<AuthType>,
        device_auth_url: Option<&str>,
        extra_params: Option<HashMap<String, String>>,
        scopes: Option<Vec<&str>>,
        token_url: &str,
    ) -> OauthCredentials {
        OauthCredentials {
            auth_type,
            client_id: ClientId::new(client_id.to_string()),
            client_secret: client_secret.map(|s| ClientSecret::new(s.to_string())),
            device_authorization_url: device_auth_url
                .map(|u| DeviceAuthorizationUrl::new(u.to_string()).unwrap()),
            extra_params,
            scopes: scopes.map(|v| v.into_iter().map(|s| Scope::new(s.to_string())).collect()),
            token_endpoint_url: TokenUrl::new(token_url.to_string()).unwrap(),
        }
    }

    // ── AuthType conversion ──────────────────────────────────────────

    #[test]
    fn auth_type_request_body_converts() {
        let converted: oauth2::AuthType = AuthType::RequestBody.into();
        assert!(matches!(converted, oauth2::AuthType::RequestBody));
    }

    #[test]
    fn auth_type_basic_auth_converts() {
        let converted: oauth2::AuthType = AuthType::BasicAuth.into();
        assert!(matches!(converted, oauth2::AuthType::BasicAuth));
    }

    // ── AccessToken::is_expired ──────────────────────────────────────

    #[test]
    fn access_token_not_expired_when_no_expiry() {
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("tok".to_string()),
            expires_at: None,
            scopes: None,
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn access_token_not_expired_when_far_future() {
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("tok".to_string()),
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            scopes: None,
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn access_token_expired_when_in_past() {
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("tok".to_string()),
            expires_at: Some(SystemTime::now() - Duration::from_secs(60)),
            scopes: None,
        };
        assert!(token.is_expired());
    }

    #[test]
    fn access_token_expired_within_skew_window() {
        // Expires in 10 seconds, but EXPIRY_SKEW is 30 seconds, so it
        // should be considered expired.
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("tok".to_string()),
            expires_at: Some(SystemTime::now() + Duration::from_secs(10)),
            scopes: None,
        };
        assert!(token.is_expired());
    }

    #[test]
    fn access_token_not_expired_just_outside_skew() {
        // Expires in 60 seconds – well outside the 30-second skew.
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("tok".to_string()),
            expires_at: Some(SystemTime::now() + Duration::from_secs(60)),
            scopes: None,
        };
        assert!(!token.is_expired());
    }

    // ── AccessToken from StandardTokenResponse ───────────────────────

    #[test]
    fn access_token_from_standard_token_response_without_expiry() {
        let json = serde_json::json!({
            "access_token": "my-access-token",
            "token_type": "bearer"
        });
        let resp: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> =
            serde_json::from_value(json).unwrap();

        let at = AccessToken::from(&resp);
        assert_eq!(at.access_token.secret(), "my-access-token");
        assert!(at.expires_at.is_none());
        assert!(at.scopes.is_none());
    }

    #[test]
    fn access_token_from_standard_token_response_with_expiry_and_scopes() {
        let json = serde_json::json!({
            "access_token": "tok",
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "read write"
        });
        let resp: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType> =
            serde_json::from_value(json).unwrap();

        let before = SystemTime::now();
        let at = AccessToken::from(&resp);
        let after = SystemTime::now();

        assert_eq!(at.access_token.secret(), "tok");

        // expires_at should be approximately now + 3600s
        let expires = at.expires_at.unwrap();
        assert!(expires >= before + Duration::from_secs(3600));
        assert!(expires <= after + Duration::from_secs(3600));

        let scope_strs: Vec<String> = at.scopes.unwrap().iter().map(|s| s.to_string()).collect();
        assert!(scope_strs.contains(&"read".to_string()));
        assert!(scope_strs.contains(&"write".to_string()));
    }

    // ── AccessToken serde roundtrip ──────────────────────────────────

    #[test]
    fn access_token_serde_roundtrip() {
        let token = AccessToken {
            access_token: oauth2::AccessToken::new("secret-tok".to_string()),
            expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            scopes: Some(vec![
                Scope::new("a".to_string()),
                Scope::new("b".to_string()),
            ]),
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: AccessToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_token.secret(), "secret-tok");
        assert_eq!(back.expires_at, token.expires_at);
        assert_eq!(back.scopes.as_ref().unwrap().len(), 2);
    }

    // ── OauthCredentials PartialEq ───────────────────────────────────

    #[test]
    fn credentials_equal_when_identical() {
        let a = make_creds(
            "cid",
            Some("secret"),
            Some(AuthType::BasicAuth),
            Some("https://example.com/device"),
            Some(HashMap::from([("k".into(), "v".into())])),
            Some(vec!["read"]),
            "https://example.com/token",
        );
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_client_id() {
        let a = make_creds(
            "cid1",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid2",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_secret() {
        let a = make_creds(
            "cid",
            Some("s1"),
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            Some("s2"),
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_secret_vs_none() {
        let a = make_creds(
            "cid",
            Some("s"),
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_auth_type() {
        let a = make_creds(
            "cid",
            None,
            Some(AuthType::BasicAuth),
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            Some(AuthType::RequestBody),
            None,
            None,
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_token_url() {
        let a = make_creds("cid", None, None, None, None, None, "https://a.com/token");
        let b = make_creds("cid", None, None, None, None, None, "https://b.com/token");
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_scopes() {
        let a = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            Some(vec!["read"]),
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            Some(vec!["write"]),
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_extra_params() {
        let a = make_creds(
            "cid",
            None,
            None,
            None,
            Some(HashMap::from([("k".into(), "v1".into())])),
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            Some(HashMap::from([("k".into(), "v2".into())])),
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn credentials_not_equal_different_device_auth_url() {
        let a = make_creds(
            "cid",
            None,
            None,
            Some("https://a.com/device"),
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            Some("https://b.com/device"),
            None,
            None,
            "https://example.com/token",
        );
        assert_ne!(a, b);
    }

    // ── OauthCredentials Hash ────────────────────────────────────────

    #[test]
    fn hash_equal_for_equal_credentials() {
        let a = make_creds(
            "cid",
            Some("secret"),
            Some(AuthType::BasicAuth),
            Some("https://example.com/device"),
            Some(HashMap::from([
                ("k1".into(), "v1".into()),
                ("k2".into(), "v2".into()),
            ])),
            Some(vec!["read", "write"]),
            "https://example.com/token",
        );
        let b = a.clone();
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_differs_for_different_credentials() {
        let a = make_creds(
            "cid1",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid2",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        // Hash collisions are theoretically possible but practically
        // should not happen for such trivially different inputs.
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_stable_regardless_of_extra_params_insertion_order() {
        let mut map_a = HashMap::new();
        map_a.insert("z".to_string(), "1".to_string());
        map_a.insert("a".to_string(), "2".to_string());

        let mut map_b = HashMap::new();
        map_b.insert("a".to_string(), "2".to_string());
        map_b.insert("z".to_string(), "1".to_string());

        let a = make_creds(
            "cid",
            None,
            None,
            None,
            Some(map_a),
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            Some(map_b),
            None,
            "https://example.com/token",
        );
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_stable_regardless_of_scope_order() {
        let a = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            Some(vec!["write", "read"]),
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            Some(vec!["read", "write"]),
            "https://example.com/token",
        );
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_none_vs_empty_extra_params_differ() {
        let a = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            Some(HashMap::new()),
            None,
            "https://example.com/token",
        );
        // None hashes discriminant 0; Some(empty) hashes discriminant 1 + len 0.
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn hash_none_vs_empty_scopes_differ() {
        let a = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let b = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            Some(vec![]),
            "https://example.com/token",
        );
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    // ── OauthCredentials can be used as HashMap key ──────────────────

    #[test]
    fn credentials_usable_as_hashmap_key() {
        let mut map = HashMap::new();
        let creds = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        map.insert(creds.clone(), "value");
        assert_eq!(map.get(&creds), Some(&"value"));
    }

    // ── OauthCredentials serde roundtrip ─────────────────────────────

    #[test]
    fn credentials_serde_roundtrip() {
        let creds = make_creds(
            "cid",
            Some("secret"),
            Some(AuthType::RequestBody),
            Some("https://example.com/device"),
            Some(HashMap::from([("audience".into(), "api".into())])),
            Some(vec!["read", "write"]),
            "https://example.com/token",
        );
        let json = serde_json::to_string(&creds).unwrap();
        let back: OauthCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(creds, back);
    }

    // ── TokenClient from OauthCredentials ────────────────────────────

    #[test]
    fn token_client_from_minimal_credentials() {
        let creds = make_creds(
            "cid",
            None,
            None,
            None,
            None,
            None,
            "https://example.com/token",
        );
        let _client: TokenClient = TokenClient::from(&creds);
        // Smoke test – construction should not panic.
    }

    #[test]
    fn token_client_from_full_credentials() {
        let creds = make_creds(
            "cid",
            Some("secret"),
            Some(AuthType::BasicAuth),
            Some("https://example.com/device"),
            Some(HashMap::from([("k".into(), "v".into())])),
            Some(vec!["openid"]),
            "https://example.com/token",
        );
        let _client: TokenClient = TokenClient::from(&creds);
    }

    // ── http_client ──────────────────────────────────────────────────

    #[test]
    fn http_client_builds_successfully() {
        // Verify the lazily-initialized static is accessible and consistent
        let client = &*HTTP_CLIENT;
        let client2 = &*HTTP_CLIENT;
        assert!(std::ptr::eq(client, client2));
    }
}
