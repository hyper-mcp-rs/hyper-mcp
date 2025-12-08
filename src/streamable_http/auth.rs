use crate::{config::ResourceUrl, streamable_http::state::ServerState};
use axum::{
    extract::State,
    http::{HeaderValue, Request, StatusCode, header::WWW_AUTHENTICATE},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token(String);

fn mcp_error_response(resource_url: &ResourceUrl) -> Response {
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
                return mcp_error_response(&resource_url);
            }
        },
        None => {
            tracing::debug!("No Authorization header found");
            return mcp_error_response(&resource_url);
        }
    };

    // Decode token header to extract key ID
    let token_header = match jsonwebtoken::decode_header(token) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("Failed to decode token header: {}", e);
            return mcp_error_response(&resource_url);
        }
    };

    // Use insecure_decode to extract the issuer claim without validation
    let issuer = match jsonwebtoken::dangerous::insecure_decode::<Claims>(token) {
        Ok(data) => data.claims.iss.clone(),
        Err(e) => {
            tracing::debug!("Failed to get iss: {}", e);
            return mcp_error_response(&resource_url);
        }
    };

    // Get JWKS for the issuer
    match state.jwks.get(&issuer) {
        Some(jwks) => match &token_header.kid {
            Some(kid) => match jwks.find(kid.as_str()) {
                Some(jwk) => match DecodingKey::from_jwk(jwk) {
                    Ok(decoding_key) => {
                        let mut validation = Validation::new(token_header.alg);
                        validation.set_audience(&[resource_url.clone()]);
                        match decode::<Claims>(token, &decoding_key, &validation) {
                            Ok(token_data) => {
                                // Valid token found, inject claims into request extensions
                                let token = Token(token.to_string());
                                let extensions = request.extensions_mut();
                                extensions.insert(token_data.claims);
                                extensions.insert(token);
                                next.run(request).await
                            }
                            Err(e) => {
                                tracing::debug!("Token validation failed for kid {}: {}", kid, e);
                                mcp_error_response(&resource_url)
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Failed to create decoding key from JWK for kid {}: {}",
                            kid,
                            e
                        );
                        mcp_error_response(&resource_url)
                    }
                },
                None => {
                    tracing::debug!("No matching JWK found for kid: {}", kid);
                    mcp_error_response(&resource_url)
                }
            },
            None => {
                tracing::debug!("Token has no kid");
                mcp_error_response(&resource_url)
            }
        },
        None => mcp_error_response(&resource_url),
    }
}
