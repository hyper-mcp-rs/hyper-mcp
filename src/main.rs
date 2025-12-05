mod cli;
mod config;
mod https_auth;
mod logging;
mod naming;
mod plugin;
mod service;
mod wasm;

use crate::config::Config;
use anyhow::Result;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header::LOCATION},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use rmcp::transport::sse_server::SseServer;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{
    ServiceExt,
    model::ClientInfo,
    service::{RoleClient, RoleServer, RunningService, Service, serve_client, serve_server},
    transport::stdio,
};
use std::sync::Arc;
use tokio::{io::duplex, runtime::Handle, task::block_in_place};

#[derive(Clone)]
struct ServerState {
    config: Config,
    documentation: String,
}

impl ServerState {
    async fn create_documentation(config: &Config) -> Result<String> {
        async fn documentation_pair<S, C>(
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

        let (server, client) = documentation_pair(
            service::PluginService::new(&config).await?,
            ClientInfo::default(),
        )
        .await;

        let docs = server.service().generate_docs().await?;

        server.cancel().await?;
        client.cancel().await?;

        Ok(docs)
    }

    pub async fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            documentation: Self::create_documentation(config).await?,
        })
    }
}

async fn docs(State(state): State<Arc<ServerState>>) -> Response {
    Html(state.documentation.clone()).into_response()
}

async fn oauth_protected_resource(State(state): State<Arc<ServerState>>) -> Response {
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

async fn policy(State(state): State<Arc<ServerState>>) -> Response {
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

async fn tos(State(state): State<Arc<ServerState>>) -> Response {
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let config = config::load_config(&cli).await?;
    tracing::info!("Starting hyper-mcp server");

    match cli.transport.as_str() {
        "stdio" => {
            tracing::info!("Starting hyper-mcp with stdio transport");
            let service = service::PluginService::new(&config)
                .await?
                .serve(stdio())
                .await
                .inspect_err(|e| {
                    tracing::error!("Serving error: {:?}", e);
                })?;
            service.waiting().await?;
        }
        "sse" => {
            tracing::info!(
                "Starting hyper-mcp with SSE transport at {}",
                cli.bind_address
            );

            // Pre-create the service to catch any initialization errors early
            service::PluginService::new(&config).await?;

            let ct = SseServer::serve(cli.bind_address.parse()?)
                .await?
                .with_service({
                    move || {
                        block_in_place(|| {
                            Handle::current()
                                .block_on(async { service::PluginService::new(&config).await })
                        })
                        .expect("Failed to create plugin service")
                    }
                });

            tokio::signal::ctrl_c().await?;
            ct.cancel();
        }
        "streamable-http" => {
            let bind_address = cli.bind_address.clone();
            tracing::info!(
                "Starting hyper-mcp with streamable-http transport at {}/mcp",
                bind_address
            );

            let server_state = Arc::new(ServerState::new(&config).await?);

            let service = StreamableHttpService::new(
                {
                    move || {
                        block_in_place(|| {
                            Handle::current()
                                .block_on(async { service::PluginService::new(&config).await })
                        })
                        .map_err(std::io::Error::other)
                    }
                },
                LocalSessionManager::default().into(),
                Default::default(),
            );

            let router = axum::Router::new()
                .route("/docs", get(docs))
                .route("/policy", get(policy))
                .route("/tos", get(tos))
                .route(
                    "/.well-known/oauth-protected-resource",
                    get(oauth_protected_resource),
                )
                .nest_service("/mcp", service)
                .with_state(server_state);

            let listener = tokio::net::TcpListener::bind(bind_address.clone()).await?;

            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.unwrap();
                    tracing::info!("Received Ctrl+C, shutting down hyper-mcp server...");
                    // Give the log a moment to flush
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    std::process::exit(0);
                })
                .await;
        }
        _ => unreachable!(),
    }

    Ok(())
}
