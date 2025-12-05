use crate::config::Config;
use anyhow::Result;
use rmcp::model::ClientInfo;
use rmcp::service::{RoleClient, RoleServer, RunningService, Service, serve_client, serve_server};
use tokio::io::duplex;

#[derive(Clone)]
pub struct ServerState {
    pub config: Config,
    pub documentation: String,
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
            crate::service::PluginService::new(&config).await?,
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
