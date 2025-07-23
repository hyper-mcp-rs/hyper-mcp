use crate::Cli;
use crate::config::{Config, load_config};
use crate::oci::pull_and_extract_oci_image;
use anyhow::Result;
use bytesize::ByteSize;
use extism::{Manifest, Plugin, Wasm};
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler, model::*};
use std::str::FromStr;

use aws_sdk_s3::Client as S3Client;
use oci_client::Client as OciClient;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{OnceCell, RwLock};

#[derive(Clone)]
pub struct PluginService {
    config: Config,
    plugins: Arc<RwLock<HashMap<String, Arc<Mutex<Plugin>>>>>,
    tool_plugin_map: Arc<RwLock<HashMap<String, String>>>,
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
            tool_plugin_map: Arc::new(RwLock::new(HashMap::new())),
        };

        service.load_plugins(cli).await?;
        Ok(service)
    }

    async fn load_plugins(&self, cli: &Cli) -> Result<()> {
        let oci_client: OnceCell<OciClient> = OnceCell::new();
        let s3_client: OnceCell<S3Client> = OnceCell::new();

        for plugin_cfg in &self.config.plugins {
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
                        cache_dir.join(format!("{}-{}.wasm", plugin_cfg.name, short_hash));
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
                    log::info!(
                        "cache plugin `{}` to : {}",
                        plugin_cfg.name,
                        local_output_path
                    );
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
            let plugin_clone = Arc::clone(&plugin);

            // Try to get tool information from the plugin and populate the cache
            let describe_result = tokio::task::spawn_blocking(move || {
                let mut plugin = plugin_clone.lock().unwrap();
                plugin.call::<&str, String>("describe", "")
            })
            .await;

            if let Ok(Ok(result)) = describe_result {
                if let Ok(parsed) = serde_json::from_str::<ListToolsResult>(&result) {
                    let mut cache = self.tool_plugin_map.write().await;
                    let skip_tools = plugin_cfg
                        .runtime_config
                        .as_ref()
                        .and_then(|rc| rc.skip_tools.clone())
                        .unwrap_or_default();
                    for tool in parsed.tools {
                        if skip_tools.iter().any(|s| s == tool.name.as_ref() as &str) {
                            log::info!("Skipping tool {} as requested in skip_tools", tool.name);
                            continue;
                        }
                        log::info!("Saving tool {}/{} to cache", plugin_cfg.name, tool.name);
                        // Check if the tool name already exists in another plugin
                        if let Some(existing_plugin) = cache.get(&tool.name.to_string()) {
                            if existing_plugin != &plugin_cfg.name {
                                log::error!(
                                    "Tool name collision detected: {} is provided by both {} and {} plugins",
                                    tool.name,
                                    existing_plugin,
                                    plugin_cfg.name
                                );
                                panic!(
                                    "Tool name collision detected: {} is provided by both {} and {} plugins",
                                    tool.name, existing_plugin, plugin_cfg.name
                                );
                            }
                        }
                        cache.insert(tool.name.to_string(), plugin_cfg.name.clone());
                    }
                }
            }

            let plugin_name = plugin_cfg.name.clone();
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
        let plugins = self.plugins.read().await;
        let tool_cache = self.tool_plugin_map.read().await;

        let tool_name = request.name.clone();
        let tool_name_str = tool_name.to_string();

        // Find the plugin name and strip the prefix if needed
        let mut original_name = tool_name_str.clone();
        let mut plugin_name_for_tool = None;

        // First try to find the tool directly in the cache
        if let Some(plugin_name) = tool_cache.get(&tool_name_str) {
            plugin_name_for_tool = Some(plugin_name.clone());

            // Check if this tool has a prefix that needs to be stripped
            for plugin_cfg in &self.config.plugins {
                if let Some(rt_config) = &plugin_cfg.runtime_config {
                    if let Some(tool_name_prefix) = &rt_config.tool_name_prefix {
                        if tool_name_str.starts_with(tool_name_prefix) {
                            // Strip the prefix to get the original tool name
                            original_name = tool_name_str[tool_name_prefix.len()..].to_string();
                            log::info!(
                                "Found tool with prefix, stripping for internal call: {tool_name_str} -> {original_name}"
                            );
                            break;
                        }
                    }
                }
            }
        } else {
            // If not found directly, check if it has a prefix that needs to be stripped
            for plugin_cfg in &self.config.plugins {
                if let Some(rt_config) = &plugin_cfg.runtime_config {
                    if let Some(tool_name_prefix) = &rt_config.tool_name_prefix {
                        if tool_name_str.starts_with(tool_name_prefix) {
                            // Strip the prefix to get the original tool name
                            original_name = tool_name_str[tool_name_prefix.len()..].to_string();
                            log::info!(
                                "Stripping prefix from tool: {tool_name_str} -> {original_name}"
                            );

                            // Check if the original tool name is in the cache
                            if let Some(plugin_name) = tool_cache.get(&original_name) {
                                plugin_name_for_tool = Some(plugin_name.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Create a modified request with the original tool name
        let mut modified_request = request.clone();
        // Convert the String to Cow<'static, str> using into()
        modified_request.name = std::borrow::Cow::Owned(original_name);

        let call_payload = json!({
            "params": modified_request,
        });
        let json_string =
            serde_json::to_string(&call_payload).expect("Failed to serialize request");

        // Check if the tool exists in the cache
        if let Some(plugin_name) = plugin_name_for_tool {
            if let Some(plugin_arc) = plugins.get(&plugin_name) {
                let plugin_clone = Arc::clone(plugin_arc);
                let plugin_name_clone = plugin_name.clone();

                let result = tokio::task::spawn_blocking(move || {
                    let mut plugin = plugin_clone.lock().unwrap();
                    plugin.call::<&str, String>("call", &json_string)
                })
                .await;

                return match result {
                    Ok(Ok(result)) => match serde_json::from_str::<CallToolResult>(&result) {
                        Ok(parsed) => Ok(parsed),
                        Err(e) => Err(McpError::internal_error(
                            format!("Failed to deserialize data: {e}"),
                            None,
                        )),
                    },
                    Ok(Err(e)) => Err(McpError::internal_error(
                        format!("Failed to execute plugin {plugin_name_clone}: {e}"),
                        None,
                    )),
                    Err(e) => Err(McpError::internal_error(
                        format!(
                            "Failed to spawn blocking task for plugin {plugin_name_clone}: {e}"
                        ),
                        None,
                    )),
                };
            }
        }

        Err(McpError::method_not_found::<CallToolRequestMethod>())
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        tracing::info!("got tools/list request {:?}", request);
        let plugins = self.plugins.write().await;
        let mut tool_cache = self.tool_plugin_map.write().await;

        let mut payload = ListToolsResult::default();

        // Clear the existing cache when listing tools
        tool_cache.clear();

        for plugin_cfg in &self.config.plugins {
            if let Some(plugin_arc) = plugins.get(&plugin_cfg.name) {
                let plugin_clone = Arc::clone(plugin_arc);
                let plugin_name = plugin_cfg.name.clone();

                let result = tokio::task::spawn_blocking(move || {
                    let mut plugin = plugin_clone.lock().unwrap();
                    plugin.call::<&str, String>("describe", "")
                })
                .await;

                match result {
                    Ok(Ok(result)) => {
                        if let Ok(parsed) = serde_json::from_str::<ListToolsResult>(&result) {
                            let skip_tools = plugin_cfg
                                .runtime_config
                                .as_ref()
                                .and_then(|rc| rc.skip_tools.clone())
                                .unwrap_or_default();
                            for mut tool in parsed.tools {
                                if skip_tools.iter().any(|s| s == tool.name.as_ref() as &str) {
                                    log::info!(
                                        "Skipping tool {} as requested in skip_tools",
                                        tool.name
                                    );
                                    continue;
                                }
                                // If tool_name_prefix is set, append it to the tool name
                                let original_name = tool.name.to_string();
                                if let Some(runtime_cfg) = &plugin_cfg.runtime_config {
                                    if let Some(tool_name_prefix) = &runtime_cfg.tool_name_prefix {
                                        let prefixed_name =
                                            format!("{tool_name_prefix}{original_name}");
                                        log::info!(
                                            "Adding prefix to tool: {original_name} -> {prefixed_name}"
                                        );

                                        // Store both the original and prefixed tool names in the cache
                                        // This ensures we can find the tool by either name
                                        tool_cache
                                            .insert(original_name.clone(), plugin_cfg.name.clone());

                                        // Update the tool name with the prefix
                                        tool.name = std::borrow::Cow::Owned(prefixed_name);
                                    }
                                }

                                // Store the tool name (which might be prefixed now) -> plugin mapping
                                tool_cache.insert(tool.name.to_string(), plugin_cfg.name.clone());
                                payload.tools.push(tool);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        log::error!("tool {plugin_name} describe() error: {e}");
                    }
                    Err(e) => {
                        log::error!("tool {plugin_name} spawn_blocking error: {e}");
                    }
                }
            }
        }

        Ok(payload)
    }

    // fn list_tools(
    //     &self,
    //     _request: Option<PaginatedRequestParam>,
    //     _context: RequestContext<RoleServer>,
    // ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
    //     tracing::info!("got tools/list request {:?}", _request);
    //     std::future::ready(Ok(ListToolsResult::default()))
    // }

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
