mod cli;
mod config;
mod logging;
mod naming;
mod plugin;
mod service;
mod wasm;

use anyhow::Result;
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ServiceExt, transport::stdio};
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
        "streamable-http" => {
            let bind_address = cli.bind_address.clone();
            tracing::info!(
                "Starting hyper-mcp with streamable-http transport at {}/mcp",
                bind_address
            );

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

            let router = axum::Router::new().nest_service("/mcp", service);

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
