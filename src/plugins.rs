use crate::{
    Cli,
    config::{Config, PluginName, PluginNameParseError, load_config},
    oci::pull_and_extract_oci_image,
};
use anyhow::Result;
use aws_sdk_s3::Client as S3Client;
use bytesize::ByteSize;
use extism::{Manifest, Plugin, Wasm};
use oci_client::Client as OciClient;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::*,
    service::{NotificationContext, RequestContext, RoleServer},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tokio::sync::{OnceCell, RwLock};

#[derive(Debug, Clone)]
pub struct ToolNameParseError;

impl fmt::Display for ToolNameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse tool name")
    }
}

impl std::error::Error for ToolNameParseError {}

impl From<PluginNameParseError> for ToolNameParseError {
    fn from(_: PluginNameParseError) -> Self {
        ToolNameParseError
    }
}

fn create_namespaced_tool_name(
    plugin_name: &PluginName,
    tool_name: &str,
) -> Result<String, ToolNameParseError> {
    if tool_name.contains("::") {
        // If the tool name already contains '::', return it as is to avoid ambiguity
        return Err(ToolNameParseError);
    }
    Ok(format!("{plugin_name}::{tool_name}"))
}

fn parse_namespaced_tool_name(
    tool_name: std::borrow::Cow<'static, str>,
) -> Result<(PluginName, String), ToolNameParseError> {
    let parts: Vec<&str> = tool_name.split("::").collect();
    if parts.len() != 2 {
        return Err(ToolNameParseError);
    }
    Ok((PluginName::from_str(parts[0])?, parts[1].to_string()))
}

#[derive(Clone)]
pub struct PluginService {
    config: Config,
    plugins: Arc<RwLock<HashMap<PluginName, Arc<Mutex<Plugin>>>>>,
}

impl PluginService {
    pub async fn new(cli: &Cli) -> Result<Self> {
        // Get default config path in the user's config directory
        let default_config_path = dirs::config_dir()
            .map(|mut path| {
                path.push("hyper-mcp");
                path.push("config.json");
                path
            })
            .unwrap();

        let config_path = cli.config_file.as_ref().unwrap_or(&default_config_path);
        tracing::info!("Using config file at {}", config_path.display());

        let service = Self {
            config: load_config(config_path).await?,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        service.load_plugins(cli).await?;
        Ok(service)
    }

    async fn load_plugins(&self, cli: &Cli) -> Result<()> {
        let oci_client: OnceCell<OciClient> = OnceCell::new();
        let s3_client: OnceCell<S3Client> = OnceCell::new();

        for (plugin_name, plugin_cfg) in &self.config.plugins {
            let wasm_content = match plugin_cfg.url.scheme() {
                "file" => tokio::fs::read(plugin_cfg.url.path()).await?,
                "http" | "https" => reqwest::get(plugin_cfg.url.as_str())
                    .await?
                    .bytes()
                    .await?
                    .to_vec(),
                "oci" => {
                    let image_reference = plugin_cfg.url.as_str().strip_prefix("oci://").unwrap();
                    let target_file_path = "/plugin.wasm";
                    let mut hasher = Sha256::new();
                    hasher.update(image_reference);
                    let hash = hasher.finalize();
                    let short_hash = &hex::encode(hash)[..7];
                    let cache_dir = dirs::cache_dir()
                        .map(|mut path| {
                            path.push("hyper-mcp");
                            path
                        })
                        .unwrap();
                    std::fs::create_dir_all(&cache_dir)?;

                    let local_output_path =
                        cache_dir.join(format!("{plugin_name}-{short_hash}.wasm"));
                    let local_output_path = local_output_path.to_str().unwrap();

                    if let Err(e) = pull_and_extract_oci_image(
                        cli,
                        oci_client
                            .get_or_init(|| async {
                                OciClient::new(oci_client::client::ClientConfig::default())
                            })
                            .await,
                        image_reference,
                        target_file_path,
                        local_output_path,
                    )
                    .await
                    {
                        log::error!("Error pulling oci plugin: {e}");
                        return Err(anyhow::anyhow!("Failed to pull OCI plugin: {}", e));
                    }
                    log::info!("cache plugin `{plugin_name}` to : {local_output_path}");
                    tokio::fs::read(local_output_path).await?
                }
                "s3" => {
                    let bucket = plugin_cfg.url.host_str().ok_or_else(|| {
                        anyhow::anyhow!("S3 URL must have a valid bucket name in the host")
                    })?;
                    let key = plugin_cfg.url.path().trim_start_matches('/');
                    match s3_client
                        .get_or_init(|| async { S3Client::new(&aws_config::load_from_env().await) })
                        .await
                        .get_object()
                        .bucket(bucket)
                        .key(key)
                        .send()
                        .await
                    {
                        Ok(response) => match response.body.collect().await {
                            Ok(body) => body.to_vec(),
                            Err(e) => {
                                log::error!("Failed to collect S3 object body: {e}");
                                return Err(anyhow::anyhow!(
                                    "Failed to collect S3 object body: {}",
                                    e
                                ));
                            }
                        },
                        Err(e) => {
                            log::error!("Failed to get object from S3: {e}");
                            return Err(anyhow::anyhow!("Failed to get object from S3: {}", e));
                        }
                    }
                }
                unsupported => {
                    log::error!("Unsupported plugin URL scheme: {unsupported}");
                    return Err(anyhow::anyhow!(
                        "Unsupported plugin URL scheme: {}",
                        unsupported
                    ));
                }
            };

            let mut manifest = Manifest::new([Wasm::data(wasm_content)]);
            if let Some(runtime_cfg) = &plugin_cfg.runtime_config {
                log::info!("runtime_cfg: {runtime_cfg:?}");
                if let Some(hosts) = &runtime_cfg.allowed_hosts {
                    for host in hosts {
                        manifest = manifest.with_allowed_host(host);
                    }
                }
                if let Some(paths) = &runtime_cfg.allowed_paths {
                    for path in paths {
                        // path will be available in the plugin with exact same path
                        manifest = manifest.with_allowed_path(path.clone(), path.clone());
                    }
                }

                // Add plugin configurations if present
                if let Some(env_vars) = &runtime_cfg.env_vars {
                    for (key, value) in env_vars {
                        manifest = manifest.with_config_key(key, value);
                    }
                }

                if let Some(memory_limit) = &runtime_cfg.memory_limit {
                    match ByteSize::from_str(memory_limit) {
                        Ok(b) => {
                            // Wasm page size 64KiB, convert to number of pages
                            let num_pages = b.as_u64() / (64 * 1024);
                            manifest = manifest.with_memory_max(num_pages as u32);
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to parse memory_limit '{memory_limit}': {e}. Using default memory limit."
                            );
                        }
                    }
                }
            }
            let plugin = Arc::new(Mutex::new(Plugin::new(&manifest, [], true).unwrap()));

            self.plugins
                .write()
                .await
                .insert(plugin_name.clone(), plugin);
            log::info!("Loaded plugin {plugin_name}");
        }
        Ok(())
    }
}

impl ServerHandler for PluginService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            server_info: Implementation {
                name: "hyper-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            capabilities: ServerCapabilities::builder().enable_tools().build(),

            ..Default::default()
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (plugin_name, tool_name) = match parse_namespaced_tool_name(request.name) {
            Ok((plugin_name, tool_name)) => (plugin_name, tool_name),
            Err(e) => {
                return Err(McpError::invalid_request(
                    format!("Failed to parse tool name: {e}"),
                    None,
                ));
            }
        };
        let plugin_config = match self.config.plugins.get(&plugin_name) {
            Some(config) => config,
            None => {
                return Err(McpError::method_not_found::<CallToolRequestMethod>());
            }
        };
        if let Some(skip_tools) = &plugin_config
            .runtime_config
            .as_ref()
            .and_then(|rc| rc.skip_tools.clone())
        {
            if skip_tools.iter().any(|s| s == &tool_name) {
                log::info!("Tool {tool_name} in skip_tools");
                return Err(McpError::method_not_found::<CallToolRequestMethod>());
            }
        }

        let call_payload = json!({
            "params": CallToolRequestParam {
                name: std::borrow::Cow::Owned(tool_name),
                arguments: request.arguments,
            },
        });
        let json_string =
            serde_json::to_string(&call_payload).expect("Failed to serialize request");

        let plugins = self.plugins.read().await;

        if let Some(plugin_arc) = plugins.get(&plugin_name) {
            let plugin_clone = Arc::clone(plugin_arc);

            return match tokio::task::spawn_blocking(move || {
                let mut plugin = plugin_clone.lock().unwrap();
                plugin.call::<&str, String>("call", &json_string)
            })
            .await
            {
                Ok(Ok(result)) => match serde_json::from_str::<CallToolResult>(&result) {
                    Ok(parsed) => Ok(parsed),
                    Err(e) => Err(McpError::internal_error(
                        format!("Failed to deserialize data: {e}"),
                        None,
                    )),
                },
                Ok(Err(e)) => Err(McpError::internal_error(
                    format!("Failed to execute plugin {plugin_name}: {e}"),
                    None,
                )),
                Err(e) => Err(McpError::internal_error(
                    format!("Failed to spawn blocking task for plugin {plugin_name}: {e}"),
                    None,
                )),
            };
        }

        Err(McpError::method_not_found::<CallToolRequestMethod>())
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        tracing::info!("got tools/list request {:?}", request);
        let plugins = self.plugins.read().await;

        let mut payload = ListToolsResult::default();

        for (plugin_name, plugin) in plugins.iter() {
            let plugin_name = plugin_name.clone();
            let plugin = Arc::clone(plugin);
            let plugin_cfg = self.config.plugins.get(&plugin_name).ok_or_else(|| {
                McpError::internal_error(
                    format!("Plugin configuration not found for {plugin_name}"),
                    None,
                )
            })?;
            let skip_tools = plugin_cfg
                .runtime_config
                .as_ref()
                .and_then(|rc| rc.skip_tools.clone())
                .unwrap_or_default();

            match tokio::task::spawn_blocking(move || {
                let mut plugin = plugin.lock().unwrap();
                plugin.call::<&str, String>("describe", "")
            })
            .await
            {
                Ok(Ok(result)) => {
                    if let Ok(parsed) = serde_json::from_str::<ListToolsResult>(&result) {
                        for mut tool in parsed.tools {
                            let tool_name = tool.name.as_ref() as &str;
                            if skip_tools.iter().any(|s| s == tool_name) {
                                log::info!(
                                    "Skipping tool {} as requested in skip_tools",
                                    tool.name
                                );
                                continue;
                            }
                            tool.name = std::borrow::Cow::Owned(match create_namespaced_tool_name(
                                &plugin_name,
                                tool_name,
                            ) {
                                Ok(namespaced) => namespaced,
                                Err(_) => {
                                    log::error!(
                                        "Tool name {tool_name} in plugin {plugin_name} contains '::', which is not allowed. Skipping this tool to avoid ambiguity.",
                                    );
                                    continue;
                                }
                            });
                            payload.tools.push(tool);
                        }
                    }
                }
                Ok(Err(e)) => {
                    log::error!("{plugin_name} describe() error: {e}");
                }
                Err(e) => {
                    log::error!("{plugin_name} spawn_blocking error: {e}");
                }
            }
        }

        Ok(payload)
    }

    fn initialize(
        &self,
        request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        tracing::info!("got initialize request {:?}", request);
        std::future::ready(Ok(self.get_info()))
    }

    fn ping(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = std::result::Result<(), McpError>> + Send + '_ {
        tracing::info!("got ping request");
        std::future::ready(Ok(()))
    }

    fn on_initialized(
        &self,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        tracing::info!("got initialized notification");
        std::future::ready(())
    }

    fn on_cancelled(
        &self,
        _notification: CancelledNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        std::future::ready(())
    }

    fn on_progress(
        &self,
        _notification: ProgressNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        std::future::ready(())
    }

    fn complete(
        &self,
        request: CompleteRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = std::result::Result<CompleteResult, McpError>> + Send + '_ {
        tracing::info!("got complete request {:?}", request);
        std::future::ready(Err(McpError::method_not_found::<CompleteRequestMethod>()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_tool_name() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "example_tool";
        let expected = "example_plugin::example_tool";
        assert_eq!(
            create_namespaced_tool_name(&plugin_name, tool_name).unwrap(),
            expected
        );
    }

    #[test]
    fn test_parse_tool_name() {
        let tool_name = "example_plugin::example_tool".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        assert!(result.is_ok());
        let (plugin_name, tool) = result.unwrap();
        assert_eq!(plugin_name.as_str(), "example_plugin");
        assert_eq!(tool, "example_tool");
    }

    #[test]
    fn test_create_tool_name_invalid() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "invalid::tool";
        assert!(create_namespaced_tool_name(&plugin_name, tool_name).is_err());
    }
}
