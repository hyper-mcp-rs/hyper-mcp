use crate::{
    naming::{parse_namespaced_name, parse_namespaced_uri},
    streamable_http::{scopes::ClientScopes, state::ServerState},
};
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
use std::{fmt, sync::Arc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientToken(String);

impl fmt::Display for ClientToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

    let unauthorized_response = || {
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
    };

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
                return unauthorized_response();
            }
        },
        None => {
            tracing::debug!("No Authorization header found");
            return unauthorized_response();
        }
    };

    // Decode token header to extract key ID
    let token_header = match jsonwebtoken::decode_header(token) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("Failed to decode token header: {}", e);
            return unauthorized_response();
        }
    };

    // Use insecure_decode to extract the issuer claim without validation
    let issuer = match jsonwebtoken::dangerous::insecure_decode::<Claims>(token) {
        Ok(data) => data.claims.iss.clone(),
        Err(e) => {
            tracing::debug!("Failed to get iss: {}", e);
            return unauthorized_response();
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
                                let token = ClientToken(token.to_string());
                                let scopes = ClientScopes::from_scope(
                                    &token_data.claims.scope.unwrap_or("".to_string()),
                                );
                                let extensions = request.extensions_mut();
                                extensions.insert(scopes);
                                extensions.insert(token);
                                next.run(request).await
                            }
                            Err(e) => {
                                tracing::debug!("Token validation failed for kid {}: {}", kid, e);
                                unauthorized_response()
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Failed to create decoding key from JWK for kid {}: {}",
                            kid,
                            e
                        );
                        unauthorized_response()
                    }
                },
                None => {
                    tracing::debug!("No matching JWK found for kid: {}", kid);
                    unauthorized_response()
                }
            },
            None => {
                tracing::debug!("Token has no kid");
                unauthorized_response()
            }
        },
        None => unauthorized_response(),
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
    let json_rpc: JsonRpcRequest = match serde_json::from_slice(&bytes) {
        Ok(req) => req,
        Err(_) => {
            // If it's not valid JSON-RPC, pass through
            return next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
        }
    };

    let extract_scope_from_json_rpc = || {
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
    };

    // Extract scope from the method and parameters
    match extract_scope_from_json_rpc() {
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

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}
