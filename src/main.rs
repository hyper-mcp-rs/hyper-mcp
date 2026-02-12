mod cli;
mod config;
mod logging;
mod naming;
mod plugin;
mod service;
mod wasm;

use anyhow::Result;
use clap::Parser;
use rmcp::{RoleServer, service::serve_directly_with_ct, transport::stdio};
use tokio::signal;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    tracing::debug!("Loading config from {:?}", cli);
    let config = config::load_config(&cli).await?;
    tracing::info!("Starting hyper-mcp");
    let service = service::PluginService::new(&config).await?;
    let ct = CancellationToken::new();
    let running =
        serve_directly_with_ct::<RoleServer, _, _, _, _>(service, stdio(), None, ct.clone());
    tokio::select! {
        res = running.waiting() => {
            tracing::warn!("Shutting down, {:?}", res?);
        }
        _ = signal::ctrl_c() => {
            tracing::warn!("SIGTERM received, shutting down");
            ct.cancel();
        }
    }
    Ok(())
}
