use crate::{
    config::ResourceUrl,
    naming::{parse_namespaced_name, parse_namespaced_uri},
    streamable_http::{scopes::ClientScopes, state::ServerState},
};
use anyhow::Result;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header::WWW_AUTHENTICATE},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use rmcp::model::JsonRpcRequest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,
    #[serde(default)]
    pub scope: Option<String>,
}

fn authenticated(
    state: Arc<ServerState>,
    resource_url: &ResourceUrl,
    request: &mut Request<axum::body::Body>,
) -> bool {
    // Extract Bearer token from Authorization header
    let token = match request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        Some(header) => match header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => {
                tracing::debug!("Authorization header found but no Bearer token present");
                return false;
            }
        },
        None => {
            tracing::debug!("No Authorization header found");
            return false;
        }
    };

    // Decode token header to extract key ID
    let token_header = match jsonwebtoken::decode_header(token) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("Failed to decode token header: {}", e);
            return false;
        }
    };

    // Use insecure_decode to extract the issuer claim without validation
    let issuer = match jsonwebtoken::dangerous::insecure_decode::<Claims>(token) {
        Ok(data) => data.claims.iss.clone(),
        Err(e) => {
            tracing::debug!("Failed to get iss: {}", e);
            return false;
        }
    };

    // Get JWKS for the issuer
    match state.jwks.get(&issuer) {
        Some(jwks) => match &token_header.kid {
            Some(kid) => match jwks.find(kid.as_str()) {
                Some(jwk) => match DecodingKey::from_jwk(jwk) {
                    Ok(decoding_key) => {
                        let mut validation = Validation::new(token_header.alg);
                        validation.set_audience(std::slice::from_ref(&resource_url));
                        match decode::<Claims>(token, &decoding_key, &validation) {
                            Ok(token_data) => {
                                // Valid token found, inject claims into request extensions
                                let scopes = ClientScopes::from_scope(
                                    &token_data.claims.scope.unwrap_or("".to_string()),
                                );
                                let extensions = request.extensions_mut();
                                extensions.insert(scopes);
                                true
                            }
                            Err(e) => {
                                tracing::debug!("Token validation failed for kid {}: {}", kid, e);
                                false
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Failed to create decoding key from JWK for kid {}: {}",
                            kid,
                            e
                        );
                        false
                    }
                },
                None => {
                    tracing::debug!("No matching JWK found for kid: {}", kid);
                    false
                }
            },
            None => {
                tracing::debug!("Token has no kid");
                false
            }
        },
        None => false,
    }
}

pub async fn authentication(
    State(state): State<Arc<ServerState>>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // If no auth servers are configured, skip authentication
    if state.auth_servers.is_empty() || state.config.oauth_protected_resource.is_none() {
        return next.run(request).await;
    }

    let resource_url = match state.config.oauth_protected_resource {
        Some(ref resource) => resource.resource.clone(),
        None => {
            tracing::error!("OAuth protected resource configuration missing");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if authenticated(state.clone(), &resource_url, &mut request) {
        next.run(request).await
    } else {
        let mut response = StatusCode::UNAUTHORIZED.into_response();

        // Insert the WWW-Authenticate header
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_str(
                format!(
                    "Bearer resource_metadata=\"{}\"",
                    resource_url.resource_metadata_url()
                )
                .as_str(),
            )
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
        );

        response
    }
}

fn extract_scope_from_json_rpc(json_rpc: &JsonRpcRequest) -> Result<Option<[String; 4]>> {
    match json_rpc.request.method.as_str() {
        "tools/call" => {
            let tool_name = match json_rpc.request.params.get("name") {
                Some(name) => name.to_string(),
                None => return Err(anyhow::anyhow!("Missing tool name parameter")),
            };
            let (plugin_name, tool_name) = parse_namespaced_name(tool_name)?;
            Ok(Some([
                "plugins".to_string(),
                plugin_name.to_string(),
                "tools".to_string(),
                tool_name,
            ]))
        }
        "prompts/get" => {
            let prompt_name = match json_rpc.request.params.get("name") {
                Some(name) => name.to_string(),
                None => return Err(anyhow::anyhow!("Missing prompt name parameter")),
            };
            let (plugin_name, prompt_name) = parse_namespaced_name(prompt_name)?;
            Ok(Some([
                "plugins".to_string(),
                plugin_name.to_string(),
                "prompts".to_string(),
                prompt_name.to_string(),
            ]))
        }
        "resources/read" => {
            let resource_uri = match json_rpc.request.params.get("uri") {
                Some(uri) => uri.to_string(),
                None => return Err(anyhow::anyhow!("Missing resource URI parameter")),
            };
            let (plugin_name, resource_uri) = parse_namespaced_uri(resource_uri)?;
            Ok(Some([
                "plugins".to_string(),
                plugin_name.to_string(),
                "resources".to_string(),
                resource_uri.to_string(),
            ]))
        }
        _ => {
            // Unknown method, pass through
            Ok(None)
        }
    }
}

pub async fn authorization(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If no ClientScopes in extensions, pass through
    let scopes = match request.extensions().get::<ClientScopes>() {
        Some(scopes) => scopes.clone(),
        None => return next.run(request).await,
    };

    // Buffer the request body to read it
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            tracing::error!("Failed to read request body");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Try to parse the JSON-RPC request
    if let Ok(json_rpc) = serde_json::from_slice::<JsonRpcRequest>(&bytes) {
        // Extract scope from the method and parameters
        match extract_scope_from_json_rpc(&json_rpc) {
            Ok(Some(scope)) => {
                // Check if the required scope is contained in the client scopes
                if !scopes.contains_scope(&scope) {
                    // Return 403 with the required scope information
                    let resource_url = match state.config.oauth_protected_resource {
                        Some(ref resource) => resource.resource.clone(),
                        None => {
                            tracing::error!("OAuth protected resource configuration missing");
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };
                    let mut response = StatusCode::FORBIDDEN.into_response();
                    response.headers_mut().insert(
                        WWW_AUTHENTICATE,
                        HeaderValue::from_str(
                            format!(
                                "Bearer error=\"insufficient_scope\", resource_metadata=\"{}\", scope=\"{}.{}.{}.{}\"",
                                resource_url.resource_metadata_url(), scope[0], scope[1], scope[2], scope[3],
                            )
                            .as_str(),
                        )
                        .unwrap_or_else(|_| HeaderValue::from_static("Bearer error=\"insufficient_scope\"")),
                    );
                    return response;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("Failed to extract scope from JSON-RPC request: {}", e);
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
    }

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::Request;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    /// Test-specific Claims struct with required fields for JWT validation
    #[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
    struct TestClaims {
        pub iss: String,
        pub sub: String,
        #[serde(default)]
        pub aud: Option<Vec<String>>,
        #[serde(default)]
        pub exp: Option<u64>,
        #[serde(default)]
        pub scope: Option<String>,
    }

    /// Helper to create a Config with OAuth protected resource from JSON
    /// This mimics how the server loads configuration from JSON files
    fn create_config_with_oauth_from_json(json: &str) -> Config {
        serde_json::from_str(json).expect("Failed to parse config JSON")
    }

    /// Helper to generate an RSA key pair for testing
    /// Returns (private key PEM string, public key modulus, public key exponent)
    fn generate_rsa_key_pair() -> (String, String, String) {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("failed to convert private key to PEM");

        // Get the modulus and exponent as base64url encoded strings
        let n = base64_url::encode(&public_key.n().to_bytes_be());
        let e = base64_url::encode(&public_key.e().to_bytes_be());

        (private_pem.to_string(), n, e)
    }

    /// Helper to get current Unix timestamp + 1 hour for token expiration
    fn get_token_expiration() -> u64 {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        duration.as_secs() + 3600 // 1 hour from now
    }

    /// Helper to create mock JWKS that matches the authorization_servers
    /// in the oauth_protected_resource configuration
    /// This creates a JWKS with RSA keys that can be used for actual signature validation
    fn create_mock_jwks_for_issuer_with_key(n: &str, e: &str) -> jsonwebtoken::jwk::JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-id",
                    "use": "sig",
                    "n": n,
                    "e": e
                }
            ]
        }))
        .unwrap()
    }

    /// Backwards compatibility helper for tests that don't need RSA keys
    fn create_mock_jwks_for_issuer() -> jsonwebtoken::jwk::JwkSet {
        let (_, n, e) = generate_rsa_key_pair();
        create_mock_jwks_for_issuer_with_key(&n, &e)
    }

    /// Helper to generate a valid JWT token signed with RSA private key
    /// Creates tokens with custom issuer, subject, kid, and scope matching oauth_protected_resource requirements
    fn create_valid_jwt(
        issuer: &str,
        subject: &str,
        kid: Option<&str>,
        scope: Option<String>,
    ) -> String {
        create_valid_jwt_with_key(issuer, subject, kid, scope, None)
    }

    /// Helper to generate a valid JWT token signed with RSA private key
    /// If private_key_pem is None, generates a new key pair
    fn create_valid_jwt_with_key(
        issuer: &str,
        subject: &str,
        kid: Option<&str>,
        scope: Option<String>,
        private_key_pem: Option<String>,
    ) -> String {
        create_valid_jwt_with_key_and_aud(issuer, subject, kid, scope, private_key_pem, None)
    }

    /// Helper to generate a valid JWT token with explicit RSA private key and audience
    fn create_valid_jwt_with_key_and_aud(
        issuer: &str,
        subject: &str,
        kid: Option<&str>,
        scope: Option<String>,
        private_key_pem: Option<String>,
        audience: Option<String>,
    ) -> String {
        let claims = TestClaims {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: audience.map(|a| vec![a]),
            exp: Some(get_token_expiration()),
            scope,
        };

        let mut header = Header::default();
        if let Some(key_id) = kid {
            header.kid = Some(key_id.to_string());
        }
        header.alg = jsonwebtoken::Algorithm::RS256;

        let key_pem = private_key_pem.unwrap_or_else(|| {
            let (pem, _, _) = generate_rsa_key_pair();
            pem
        });

        let key = EncodingKey::from_rsa_pem(key_pem.as_bytes())
            .expect("failed to create encoding key from RSA PEM");
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    /// Helper to generate an invalid JWT token (with bad signature)
    fn create_invalid_jwt(issuer: &str, subject: &str, kid: Option<&str>) -> String {
        let claims = TestClaims {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: None,
            exp: Some(get_token_expiration()),
            scope: None,
        };

        let mut header = Header::default();
        if let Some(key_id) = kid {
            header.kid = Some(key_id.to_string());
        }

        let key = EncodingKey::from_secret(b"wrong-secret-key");
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    /// Helper to create ServerState from config with JWKS populated
    fn create_server_state_from_config(config: Config, issuer: &str) -> ServerState {
        create_server_state_from_config_with_jwks(config, issuer, None)
    }

    /// Helper to create ServerState from config with JWKS populated, optionally with specific RSA key
    fn create_server_state_from_config_with_jwks(
        config: Config,
        issuer: &str,
        jwks: Option<jsonwebtoken::jwk::JwkSet>,
    ) -> ServerState {
        let mut jwks_map = std::collections::HashMap::new();
        let jwks_for_issuer = jwks.unwrap_or_else(create_mock_jwks_for_issuer);
        jwks_map.insert(issuer.to_string(), jwks_for_issuer);

        ServerState {
            auth_servers: vec![],
            config,
            docs: "test documentation".to_string(),
            jwks: jwks_map,
            scopes: std::collections::HashSet::new(),
        }
    }

    #[test]
    fn test_authenticated_rejects_missing_authorization_header() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_non_bearer_authorization() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_empty_bearer_token() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_malformed_jwt() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", "Bearer not.a.valid.jwt")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_jwt_without_kid() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let token = create_valid_jwt(issuer, "user", None, None);

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_jwt_with_unknown_kid() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let token = create_valid_jwt(issuer, "user", Some("unknown-key-id"), None);

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_jwt_with_unknown_issuer() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let state = create_server_state_from_config(config.clone(), "https://example.com");
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let token = create_valid_jwt("https://other.com", "user", Some("test-key-id"), None);

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_rejects_invalid_jwt_signature() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let token = create_invalid_jwt(issuer, "user", Some("test-key-id"));

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_with_valid_jwt_and_scope() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com",
                "resource_name": "Test API"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let scope = Some("plugins.test.tools.read".to_string());
        let token = create_valid_jwt(issuer, "user@example.com", Some("test-key-id"), scope);

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result); // Fails due to signature validation with test key
    }

    #[test]
    fn test_authenticated_with_multiple_scopes() {
        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        let scope = Some("plugins.test.tools.read plugins.test.tools.write".to_string());
        let token = create_valid_jwt(issuer, "user", Some("test-key-id"), scope);

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);
        assert!(!result);
    }

    #[test]
    fn test_authenticated_injects_client_scopes_on_success() {
        // This test verifies the behavior of ClientScopes injection into request.extensions
        // when calling authenticated() with a properly signed RSA JWT.
        //
        // The authenticated function injects ClientScopes ONLY after successful JWT
        // signature validation. We use an RSA key pair for signing to ensure the
        // signature validation passes.

        let json = r#"{
                "plugins": {},
                "oauth_protected_resource": {
                    "authorization_servers": ["https://example.com"],
                    "resource": "https://api.example.com"
                }
            }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";

        // Generate RSA key pair for this test
        let (private_pem, n, e) = generate_rsa_key_pair();

        // Create JWKS with the public key components
        let jwks = create_mock_jwks_for_issuer_with_key(&n, &e);

        // Create ServerState with the matching JWKS
        let state = create_server_state_from_config_with_jwks(config.clone(), issuer, Some(jwks));
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        // Create a JWT with scope, signed with the RSA private key
        let scope = Some("plugins.test.tools.read plugins.test.tools.write".to_string());
        let token = create_valid_jwt_with_key_and_aud(
            issuer,
            "user@example.com",
            Some("test-key-id"),
            scope.clone(),
            Some(private_pem),
            Some(resource_url.to_string()),
        );

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);

        // Authentication should succeed with properly signed RSA JWT
        assert!(
            result,
            "Authentication should succeed with valid RSA-signed JWT"
        );

        // Verify ClientScopes IS in extensions since authentication succeeded
        let client_scopes = request
            .extensions()
            .get::<ClientScopes>()
            .expect("ClientScopes should be injected on successful authentication");

        // Verify the scopes were parsed correctly
        assert!(
            client_scopes.contains_scope(&[
                "plugins".to_string(),
                "test".to_string(),
                "tools".to_string(),
                "read".to_string()
            ]),
            "Should contain plugins.test.tools.read scope"
        );
        assert!(
            client_scopes.contains_scope(&[
                "plugins".to_string(),
                "test".to_string(),
                "tools".to_string(),
                "write".to_string()
            ]),
            "Should contain plugins.test.tools.write scope"
        );
    }

    #[test]
    fn test_authenticated_does_not_inject_scopes_on_failure() {
        // This test verifies that ClientScopes is NOT added to request.extensions
        // when authentication fails (e.g., missing header, invalid token, etc.)

        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        // Create request with no Authorization header - authentication will fail
        let mut request = Request::builder()
            .uri("http://example.com/test")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);

        // Verify authentication failed
        assert!(!result);

        // Verify no ClientScopes were added to extensions
        let extensions = request.extensions();
        let scopes = extensions.get::<ClientScopes>();
        assert!(
            scopes.is_none(),
            "ClientScopes should not be in extensions on authentication failure"
        );
    }

    #[test]
    fn test_authenticated_does_not_inject_scopes_on_malformed_jwt() {
        // This test verifies that ClientScopes is NOT injected when JWT is malformed

        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        // Create request with malformed JWT
        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", "Bearer not.a.valid.jwt")
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);

        // Verify authentication failed
        assert!(!result);

        // Verify no ClientScopes were added to extensions
        let extensions = request.extensions();
        let scopes = extensions.get::<ClientScopes>();
        assert!(
            scopes.is_none(),
            "ClientScopes should not be in extensions on malformed JWT"
        );
    }

    #[test]
    fn test_authenticated_does_not_inject_scopes_on_unknown_issuer() {
        // This test verifies that ClientScopes is NOT injected when issuer is unknown

        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        // Create JWT with unknown issuer
        let token = create_valid_jwt(
            "https://unknown.com",
            "user",
            Some("test-key-id"),
            Some("plugins.test.tools.read".to_string()),
        );

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);

        // Verify authentication failed
        assert!(!result);

        // Verify no ClientScopes were added to extensions
        let extensions = request.extensions();
        let scopes = extensions.get::<ClientScopes>();
        assert!(
            scopes.is_none(),
            "ClientScopes should not be in extensions when issuer is unknown"
        );
    }

    #[test]
    fn test_authenticated_does_not_inject_scopes_on_missing_kid() {
        // This test verifies that ClientScopes is NOT injected when JWT has no kid

        let json = r#"{
            "plugins": {},
            "oauth_protected_resource": {
                "authorization_servers": ["https://example.com"],
                "resource": "https://api.example.com"
            }
        }"#;

        let config = create_config_with_oauth_from_json(json);
        let issuer = "https://example.com";
        let state = create_server_state_from_config(config.clone(), issuer);
        let resource_url = config.oauth_protected_resource.unwrap().resource;

        // Create JWT without kid in header
        let token = create_valid_jwt(
            issuer,
            "user",
            None,
            Some("plugins.test.tools.read".to_string()),
        );

        let mut request = Request::builder()
            .uri("http://example.com/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let result = authenticated(Arc::new(state), &resource_url, &mut request);

        // Verify authentication failed
        assert!(!result);

        // Verify no ClientScopes were added to extensions
        let extensions = request.extensions();
        let scopes = extensions.get::<ClientScopes>();
        assert!(
            scopes.is_none(),
            "ClientScopes should not be in extensions when JWT has no kid"
        );
    }
}
