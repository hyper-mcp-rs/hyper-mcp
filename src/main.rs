mod cli;
mod config;
mod logging;
mod models;
mod naming;
mod plugin;
mod service;
mod streamable_http;
mod wasm;

use crate::streamable_http::{
    auth::{authentication, authorization},
    routes,
    state::ServerState,
};
use anyhow::Result;
use axum::middleware;
use axum::routing::get;
use clap::Parser;
use rmcp::transport::sse_server::SseServer;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ServiceExt, transport::stdio};
use std::sync::Arc;
use tokio::{runtime::Handle, task::block_in_place};

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
            tracing::warn!(
                "THE SSE TRANSPORT IS DEPRICATED AND WILL BE REMOVED IN A FUTURE RELEASE. Please migrate to the streamable-http transport. Starting hyper-mcp with SSE transport at {}.",
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
                .route("/docs", get(routes::docs))
                .route("/policy", get(routes::policy))
                .route("/tos", get(routes::tos))
                .route(
                    "/.well-known/oauth-protected-resource",
                    get(routes::oauth_protected_resource),
                )
                .nest_service("/mcp", service)
                .layer(middleware::from_fn_with_state(
                    server_state.clone(),
                    authorization,
                ))
                .layer(middleware::from_fn_with_state(
                    server_state.clone(),
                    authentication,
                ))
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
