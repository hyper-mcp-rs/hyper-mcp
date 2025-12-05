use crate::streamable_http::state::ServerState;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header::LOCATION},
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

pub async fn docs(State(state): State<Arc<ServerState>>) -> Response {
    Html(state.documentation.clone()).into_response()
}

pub async fn oauth_protected_resource(State(state): State<Arc<ServerState>>) -> Response {
    match state.config.clone().oauth_protected_resource {
        Some(oath_protected_resource) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "authorization_servers": oath_protected_resource.authorization_servers,
                "bearer_methods_supported": vec!["header"],
                "resource": oath_protected_resource.resource,
                "resource_documentation": format!("{}/docs", oath_protected_resource.resource),
                "resource_name": oath_protected_resource.resource_name,
                "resource_policy_uri": if oath_protected_resource.resource_policy_uri.is_some() {
                    Some(format!("{}/policy", oath_protected_resource.resource))
                } else {
                    None
                },
                "resource_tos_uri": if oath_protected_resource.resource_tos_uri.is_some() {
                    Some(format!("{}/tos", oath_protected_resource.resource))
                } else {
                    None
                },
            })),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn policy(State(state): State<Arc<ServerState>>) -> Response {
    match state.config.clone().oauth_protected_resource {
        Some(oath_protected_resource) => match oath_protected_resource.resource_policy_uri {
            Some(policy_uri) => (
                StatusCode::TEMPORARY_REDIRECT,
                [(LOCATION, policy_uri.to_string())],
            )
                .into_response(),
            None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
        },
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn tos(State(state): State<Arc<ServerState>>) -> Response {
    match state.config.clone().oauth_protected_resource {
        Some(oath_protected_resource) => match oath_protected_resource.resource_tos_uri {
            Some(tos_uri) => (
                StatusCode::TEMPORARY_REDIRECT,
                [(LOCATION, tos_uri.to_string())],
            )
                .into_response(),
            None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
        },
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}
