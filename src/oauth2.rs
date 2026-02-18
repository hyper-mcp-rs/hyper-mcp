use std::{
    collections::HashMap,
    hash::Hash,
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

pub fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
