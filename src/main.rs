mod cli;
mod config;
mod expand_env;
mod logging;
mod naming;
mod oauth2;
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
    async fn run() -> Result<()> {
        let span = tracing::info_span!("process", pid = std::process::id());
        let _span = span.enter();
        let cli = cli::Cli::parse();
        tracing::debug!("Loading config from {:?}", cli);

        // The platform-native keyring store is initialized lazily the first time a
        // `keyring::Entry` is created. Probe it here so an unavailable store is reported
        // at startup rather than only when a keyring-backed secret is first accessed.
        if let Err(e) = keyring::Entry::new("hyper-mcp", "startup-probe") {
            tracing::warn!(error = ?e, "Failed to initialize native keyring store; keyring secrets will be unavailable");
        }

        let config = config::Config::load(&cli).await?;
        tracing::info!("Starting hyper-mcp");
        let service = service::PluginService::new(&config).await?;
        let ct = CancellationToken::new();
        let running =
            serve_directly_with_ct::<RoleServer, _, _, _, _>(service, stdio(), None, ct.clone());
        tokio::select! {
            res = running.waiting() => {
                tracing::warn!(reason = ?res?, "Shutting down");
            }
            _ = signal::ctrl_c() => {
                tracing::warn!(reason = "SIGTERM", "Shutting down");
                ct.cancel();
            }
        }
        Ok(())
    }

    let result = run().await;
    if let Err(ref e) = result {
        tracing::error!(error = ?e, "Error starting hyper-mcp");
    }
    result
}
