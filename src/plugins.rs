use crate::{
    Cli,
    config::{Config, PluginName, PluginNameParseError, load_config},
    https_auth::Authenticator,
    oci::pull_and_extract_oci_image,
};
use anyhow::Result;
use bytesize::ByteSize;
use extism::{Manifest, Plugin, Wasm};
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
    Ok(format!("{plugin_name}-{tool_name}"))
}

fn parse_namespaced_tool_name(
    tool_name: std::borrow::Cow<'static, str>,
) -> Result<(PluginName, String), ToolNameParseError> {
    if let Some((plugin_name, tool_name)) = tool_name.split_once("-") {
        return Ok((PluginName::from_str(plugin_name)?, tool_name.to_string()));
    }
    Err(ToolNameParseError)
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

    async fn call_tool(&self, request: CallToolRequestParam) -> Result<CallToolResult, McpError> {
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

    async fn list_tools(&self) -> std::result::Result<ListToolsResult, McpError> {
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

    async fn load_plugins(&self, cli: &Cli) -> Result<()> {
        let reqwest_client: OnceCell<reqwest::Client> = OnceCell::new();
        let oci_client: OnceCell<oci_client::Client> = OnceCell::new();
        let s3_client: OnceCell<aws_sdk_s3::Client> = OnceCell::new();

        for (plugin_name, plugin_cfg) in &self.config.plugins {
            let wasm_content = match plugin_cfg.url.scheme() {
                "file" => tokio::fs::read(plugin_cfg.url.path()).await?,
                "http" => reqwest_client
                    .get_or_init(|| async { reqwest::Client::new() })
                    .await
                    .get(plugin_cfg.url.as_str())
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec(),
                "https" => reqwest_client
                    .get_or_init(|| async { reqwest::Client::new() })
                    .await
                    .get(plugin_cfg.url.as_str())
                    .add_auth(&self.config.auths, &plugin_cfg.url)
                    .send()
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
                                oci_client::Client::new(oci_client::client::ClientConfig::default())
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
                        .get_or_init(|| async {
                            aws_sdk_s3::Client::new(&aws_config::load_from_env().await)
                        })
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
        tracing::info!("got tools/call request {:?}", request);
        self.call_tool(request).await
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        tracing::info!("got tools/list request {:?}", request);
        self.list_tools().await
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
    use crate::config::Config;
    use rmcp::{ServerHandler, model::ProtocolVersion};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    #[test]
    fn test_create_tool_name() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "example_tool";
        let expected = "example_plugin-example_tool";
        assert_eq!(
            create_namespaced_tool_name(&plugin_name, tool_name).unwrap(),
            expected
        );
    }

    #[test]
    fn test_parse_tool_name() {
        let tool_name = "example_plugin-example_tool".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        assert!(result.is_ok());
        let (plugin_name, tool) = result.unwrap();
        assert_eq!(plugin_name.as_str(), "example_plugin");
        assert_eq!(tool, "example_tool");
    }

    #[test]
    fn test_create_tool_name_invalid() {
        let plugin_name = PluginName::from_str("example_plugin").unwrap();
        let tool_name = "invalid-tool";
        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "example_plugin-invalid-tool");
    }

    #[test]
    fn test_create_namespaced_tool_name_with_special_chars() {
        let plugin_name = PluginName::from_str("test_plugin_123").unwrap();
        let tool_name = "tool_name_with_underscores";
        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "test_plugin_123-tool_name_with_underscores");
    }

    #[test]
    fn test_create_namespaced_tool_name_empty_tool_name() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "";
        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "test_plugin-");
    }

    #[test]
    fn test_create_namespaced_tool_name_multiple_hyphens() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "invalid-tool-name";
        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "test_plugin-invalid-tool-name");
    }

    #[test]
    fn test_parse_namespaced_tool_name_with_special_chars() {
        let tool_name = "plugin_name_123-tool_name_456".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name)).unwrap();
        assert_eq!(result.0.as_str(), "plugin_name_123");
        assert_eq!(result.1, "tool_name_456");
    }

    #[test]
    fn test_parse_namespaced_tool_name_no_separator() {
        let tool_name = "invalid_tool_name".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ToolNameParseError));
    }

    #[test]
    fn test_parse_namespaced_tool_name_multiple_separators() {
        let tool_name = "plugin-tool-extra".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name)).unwrap();
        assert_eq!(result.0.as_str(), "plugin");
        assert_eq!(result.1, "tool-extra");
    }

    #[test]
    fn test_parse_namespaced_tool_name_empty_parts() {
        let tool_name = "-tool".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        // This should still work but with empty plugin name
        if result.is_ok() {
            let (plugin, _) = result.unwrap();
            assert!(plugin.as_str().is_empty());
        }
    }

    #[test]
    fn test_parse_namespaced_tool_name_only_separator() {
        let tool_name = "-".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        // Should result in empty plugin and tool names
        if let Ok((plugin, tool)) = result {
            assert!(plugin.as_str().is_empty());
            assert!(tool.is_empty());
        }
    }

    #[test]
    fn test_parse_namespaced_tool_name_empty_string() {
        let tool_name = "".to_string();
        let result = parse_namespaced_tool_name(std::borrow::Cow::Owned(tool_name));
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_name_parse_error_display() {
        let error = ToolNameParseError;
        assert_eq!(format!("{}", error), "Failed to parse tool name");
    }

    #[test]
    fn test_tool_name_parse_error_from_plugin_name_error() {
        let plugin_error = PluginNameParseError;
        let tool_error: ToolNameParseError = plugin_error.into();
        assert_eq!(format!("{}", tool_error), "Failed to parse tool name");
    }

    #[test]
    fn test_round_trip_tool_name_operations() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let original_tool = "my_tool";

        let namespaced = create_namespaced_tool_name(&plugin_name, original_tool).unwrap();
        let (parsed_plugin, parsed_tool) =
            parse_namespaced_tool_name(std::borrow::Cow::Owned(namespaced)).unwrap();

        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_tool, "my_tool");
    }

    #[test]
    fn test_tool_name_with_unicode() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "тест_工具"; // Cyrillic and Chinese characters

        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "test_plugin-тест_工具");
    }

    #[test]
    fn test_very_long_tool_names() {
        let plugin_name = PluginName::from_str("plugin").unwrap();
        let very_long_tool = "a".repeat(1000);

        let result = create_namespaced_tool_name(&plugin_name, &very_long_tool);
        assert!(result.is_ok());

        let namespaced = result.unwrap();
        let (parsed_plugin, parsed_tool) =
            parse_namespaced_tool_name(std::borrow::Cow::Owned(namespaced)).unwrap();

        assert_eq!(parsed_plugin.as_str(), "plugin");
        assert_eq!(parsed_tool.len(), 1000);
    }

    #[test]
    fn test_plugin_name_error_conversion() {
        let plugin_error = PluginNameParseError;
        let tool_error: ToolNameParseError = plugin_error.into();

        // Test that the error implements standard error traits
        assert!(std::error::Error::source(&tool_error).is_none());
        assert!(!format!("{}", tool_error).is_empty());
    }

    #[test]
    fn test_tool_name_with_numbers_and_special_chars() {
        let plugin_name = PluginName::from_str("plugin_123").unwrap();
        let tool_name = "tool_456_test";

        let result = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();
        assert_eq!(result, "plugin_123-tool_456_test");

        let (parsed_plugin, parsed_tool) =
            parse_namespaced_tool_name(std::borrow::Cow::Owned(result)).unwrap();
        assert_eq!(parsed_plugin.as_str(), "plugin_123");
        assert_eq!(parsed_tool, "tool_456_test");
    }

    #[test]
    fn test_borrowed_vs_owned_cow_strings() {
        // Test with borrowed string
        let borrowed_result = parse_namespaced_tool_name(std::borrow::Cow::Borrowed("plugin-tool"));
        assert!(borrowed_result.is_ok());

        // Test with owned string
        let owned_result =
            parse_namespaced_tool_name(std::borrow::Cow::Owned("plugin-tool".to_string()));
        assert!(owned_result.is_ok());

        let (plugin1, tool1) = borrowed_result.unwrap();
        let (plugin2, tool2) = owned_result.unwrap();

        assert_eq!(plugin1.as_str(), plugin2.as_str());
        assert_eq!(tool1, tool2);
    }

    #[test]
    fn test_tool_name_edge_cases() {
        let plugin = PluginName::from_str("test").unwrap();

        let edge_cases = vec![
            ("a", true, "single character tool"),
            ("tool_123", true, "tool with numbers"),
            ("TOOL_NAME", true, "uppercase tool name"),
            ("tool-invalid", true, "tool with hyphen"),
            ("-tool", true, "tool starting with hyphen"),
            ("tool-", true, "tool ending with hyphen"),
        ];

        for (tool_name, should_succeed, description) in edge_cases {
            let result = create_namespaced_tool_name(&plugin, tool_name);

            if should_succeed {
                assert!(result.is_ok(), "{}: {}", description, tool_name);

                if let Ok(namespaced) = result {
                    let parse_result =
                        parse_namespaced_tool_name(std::borrow::Cow::Owned(namespaced));
                    assert!(
                        parse_result.is_ok(),
                        "Should parse back {}: {}",
                        description,
                        tool_name
                    );
                }
            } else {
                assert!(result.is_err(), "{}: {}", description, tool_name);
            }
        }
    }

    #[test]
    fn test_namespaced_tool_format_invariants() {
        let plugin_name = PluginName::from_str("test_plugin").unwrap();
        let tool_name = "test_tool";

        let namespaced = create_namespaced_tool_name(&plugin_name, tool_name).unwrap();

        // Should contain at least one "-" (the separator)
        let hyphen_count = namespaced.matches("-").count();
        assert!(hyphen_count >= 1, "Should contain at least one '-'");

        // Should start with plugin name
        assert!(
            namespaced.starts_with("test_plugin"),
            "Should start with plugin name"
        );

        // Should end with tool name
        assert!(
            namespaced.ends_with("test_tool"),
            "Should end with tool name"
        );

        // Should be in the format "plugin-tool"
        assert_eq!(namespaced, "test_plugin-test_tool");

        // Test parsing works correctly with the first hyphen as separator
        let (parsed_plugin, parsed_tool) =
            parse_namespaced_tool_name(std::borrow::Cow::Owned(namespaced.clone())).unwrap();
        assert_eq!(parsed_plugin.as_str(), "test_plugin");
        assert_eq!(parsed_tool, "test_tool");
    }

    // Helper functions for PluginService tests

    fn create_test_cli() -> crate::Cli {
        crate::Cli {
            config_file: None,
            log_level: Some("info".to_string()),
            transport: "stdio".to_string(),
            bind_address: "127.0.0.1:3001".to_string(),
            insecure_skip_signature: false,
            use_sigstore_tuf_data: true,
            rekor_pub_keys: None,
            fulcio_certs: None,
            cert_issuer: None,
            cert_email: None,
            cert_url: None,
        }
    }

    async fn create_temp_config_file(content: &str) -> anyhow::Result<(TempDir, PathBuf)> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test_config.yaml");
        tokio::fs::write(&config_path, content).await?;
        Ok((temp_dir, config_path))
    }

    fn get_test_wasm_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("plugins");
        path.push("time");
        path.push("time.wasm");
        path
    }

    fn test_wasm_exists() -> bool {
        get_test_wasm_path().exists()
    }

    // Helper function to create a dummy request context for compilation
    // These tests will be skipped at runtime since we can't easily mock contexts
    // PluginService creation tests

    #[tokio::test]
    async fn test_plugin_service_creation_empty_config() {
        let config_content = r#"
plugins: {}
"#;
        let (_temp_dir, config_path) = create_temp_config_file(config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let result = PluginService::new(&cli).await;
        assert!(
            result.is_ok(),
            "Should create service with empty plugin config"
        );

        let service = result.unwrap();
        let plugins = service.plugins.read().await;
        assert!(plugins.is_empty(), "Should have no plugins loaded");
    }

    #[tokio::test]
    async fn test_plugin_service_creation_with_file_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      memory_limit: "1MB"
      env_vars:
        TEST_MODE: "true"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let result = PluginService::new(&cli).await;
        assert!(
            result.is_ok(),
            "Should create service with valid WASM plugin"
        );

        let service = result.unwrap();
        let plugins = service.plugins.read().await;
        assert_eq!(plugins.len(), 1, "Should have one plugin loaded");
        assert!(plugins.contains_key(&PluginName::from_str("time_plugin").unwrap()));
    }

    #[tokio::test]
    async fn test_plugin_service_creation_with_nonexistent_file() {
        let config_content = r#"
plugins:
  missing_plugin:
    url: "file:///nonexistent/path/plugin.wasm"
"#;

        let (_temp_dir, config_path) = create_temp_config_file(config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let result = PluginService::new(&cli).await;
        assert!(result.is_err(), "Should fail with nonexistent plugin file");
    }

    #[tokio::test]
    async fn test_plugin_service_creation_with_invalid_memory_limit() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      memory_limit: "invalid_size"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let result = PluginService::new(&cli).await;
        // Should still succeed but log an error about invalid memory limit
        assert!(
            result.is_ok(),
            "Should handle invalid memory limit gracefully"
        );
    }

    // ServerHandler tests

    #[test]
    fn test_plugin_service_get_info() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        let info = service.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert_eq!(info.server_info.name, "hyper-mcp");
        assert!(!info.server_info.version.is_empty());
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_plugin_service_list_tools_with_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let service = PluginService::new(&cli).await.unwrap();

        // Verify the service was created successfully
        assert!(
            service.plugins.read().await.len() > 0,
            "Should have loaded plugin"
        );

        // Test the list_tools function
        let result = service.list_tools().await;
        assert!(result.is_ok(), "list_tools should succeed");

        let list_tools_result = result.unwrap();
        assert!(
            !list_tools_result.tools.is_empty(),
            "Should have tools from the loaded plugin"
        );

        // Verify we get the expected tools from time.wasm plugin
        let expected_tools = vec!["time_plugin-time"];

        let actual_tool_names: Vec<String> = list_tools_result
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();

        for expected_tool in &expected_tools {
            assert!(
                actual_tool_names.contains(&expected_tool.to_string()),
                "Expected tool '{}' not found in actual tools: {:?}",
                expected_tool,
                actual_tool_names
            );
        }

        assert_eq!(
            list_tools_result.tools.len(),
            expected_tools.len(),
            "Expected {} tools but got {}: {:?}",
            expected_tools.len(),
            list_tools_result.tools.len(),
            actual_tool_names
        );

        // Verify the time tool has the expected operations in its schema
        let time_tool = list_tools_result
            .tools
            .iter()
            .find(|tool| tool.name == "time_plugin-time")
            .expect("time_plugin-time tool should exist");

        // Check that the tool description mentions the expected operations
        let description = time_tool
            .description
            .as_ref()
            .expect("Tool should have description");
        let expected_operations = vec!["get_time_utc", "parse_time", "time_offset"];
        for operation in &expected_operations {
            assert!(
                description.contains(operation),
                "Tool description should mention operation '{}': {}",
                operation,
                description
            );
        }

        // Check that the input schema includes the expected operations in the enum
        let schema_value = &time_tool.input_schema;
        if let Some(properties) = schema_value.get("properties") {
            if let Some(name_property) = properties.get("name") {
                if let Some(enum_values) = name_property.get("enum") {
                    if let Some(enum_array) = enum_values.as_array() {
                        let schema_operations: Vec<String> = enum_array
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();

                        for operation in &expected_operations {
                            assert!(
                                schema_operations.contains(&operation.to_string()),
                                "Input schema should include operation '{}' in enum: {:?}",
                                operation,
                                schema_operations
                            );
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_plugin_service_list_tools_with_skip_tools() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      skip_tools:
        - "time"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let service = PluginService::new(&cli).await.unwrap();

        // Verify the service was created successfully
        assert!(
            service.plugins.read().await.len() > 0,
            "Should have loaded plugin"
        );

        // Test the list_tools function with skip_tools configuration
        let result = service.list_tools().await;
        assert!(result.is_ok(), "list_tools should succeed");

        let list_tools_result = result.unwrap();

        // Since we're skipping the "time" tool, the tools list should be empty
        assert!(
            list_tools_result.tools.is_empty(),
            "Should have no tools since 'time' tool is skipped. Found tools: {:?}",
            list_tools_result
                .tools
                .iter()
                .map(|t| t.name.as_ref() as &str)
                .collect::<Vec<&str>>()
        );

        // Verify specifically that the time-plugin::time tool is not present
        let tool_names: Vec<String> = list_tools_result
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();

        assert!(
            !tool_names.contains(&"time_plugin-time".to_string()),
            "time_plugin-time should be skipped but was found in tools: {:?}",
            tool_names
        );

        // Verify that the plugin itself was loaded (skip_tools should not prevent plugin loading)
        let plugins = service.plugins.read().await;
        let plugin_name: PluginName = "time_plugin".parse().unwrap();
        assert!(
            plugins.contains_key(&plugin_name),
            "Plugin 'time_plugin' should still be loaded even with skip_tools configuration"
        );

        // Verify the plugin configuration includes skip_tools
        let plugin_config = service.config.plugins.get(&plugin_name).unwrap();
        let skip_tools = plugin_config
            .runtime_config
            .as_ref()
            .and_then(|rc| rc.skip_tools.as_ref())
            .unwrap();

        assert!(
            skip_tools.contains(&"time".to_string()),
            "Configuration should include 'time' in skip_tools list: {:?}",
            skip_tools
        );

        assert_eq!(
            skip_tools.len(),
            1,
            "Should have exactly one tool in skip_tools list: {:?}",
            skip_tools
        );
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_invalid_format() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        // Test calling tool with invalid format (missing plugin name separator)
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("invalid_tool_name"),
            arguments: None,
        };

        let result = service.call_tool(request).await;
        assert!(result.is_err(), "Should fail with invalid tool name format");

        if let Err(error) = result {
            // Should be an invalid_request error
            assert!(
                error.to_string().contains("Failed to parse tool name"),
                "Error should mention parsing failure: {}",
                error
            );
        }

        // Test with empty tool name
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed(""),
            arguments: None,
        };

        let result = service.call_tool(request).await;
        assert!(result.is_err(), "Should fail with empty tool name");
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_nonexistent_plugin() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        // Test calling tool on nonexistent plugin
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("nonexistent_plugin-some_tool"),
            arguments: None,
        };

        let result = service.call_tool(request).await;
        assert!(result.is_err(), "Should fail with nonexistent plugin");

        if let Err(error) = result {
            // Should be a method_not_found error since plugin doesn't exist
            let error_str = error.to_string();
            assert!(
                error_str.contains("-32601") || error_str.contains("tools/call"),
                "Error should indicate method not found: {}",
                error
            );
        }
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_with_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let service = PluginService::new(&cli).await.unwrap();

        // Verify the service was created successfully
        assert!(
            service.plugins.read().await.len() > 0,
            "Should have loaded plugin"
        );

        // Test calling the time tool with get_time_utc operation
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("time_plugin-time"),
            arguments: Some({
                let mut map = serde_json::Map::new();
                map.insert(
                    "name".to_string(),
                    serde_json::Value::String("get_time_utc".to_string()),
                );
                map
            }),
        };

        let result = service.call_tool(request).await;
        assert!(
            result.is_ok(),
            "Should successfully call time tool: {:?}",
            result
        );

        let call_result = result.unwrap();

        assert!(
            !call_result.content.is_empty(),
            "call_result.content should not be empty"
        );

        // Test calling with parse_time operation
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("time_plugin-time"),
            arguments: Some({
                let mut map = serde_json::Map::new();
                map.insert(
                    "name".to_string(),
                    serde_json::Value::String("parse_time".to_string()),
                );
                map.insert(
                    "time_rfc2822".to_string(),
                    serde_json::Value::String("Wed, 18 Feb 2015 23:16:09 GMT".to_string()),
                );
                map
            }),
        };

        let result = service.call_tool(request).await;
        assert!(
            result.is_ok(),
            "Should successfully call parse_time operation: {:?}",
            result
        );

        let call_result = result.unwrap();
        // Verify the parse_time operation returns content

        assert!(
            !call_result.content.is_empty(),
            "Parse time operation should return non-empty content"
        );
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_with_skipped_tool() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      skip_tools:
        - "time"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let service = PluginService::new(&cli).await.unwrap();

        // Verify the service was created successfully
        assert!(
            service.plugins.read().await.len() > 0,
            "Should have loaded plugin"
        );

        // Test calling the skipped time tool
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("time_plugin-time"),
            arguments: Some({
                let mut map = serde_json::Map::new();
                map.insert(
                    "name".to_string(),
                    serde_json::Value::String("get_time_utc".to_string()),
                );
                map
            }),
        };

        let result = service.call_tool(request).await;
        assert!(result.is_err(), "Should fail when calling skipped tool");

        if let Err(error) = result {
            // Should be a method_not_found error since tool is skipped
            let error_str = error.to_string();
            assert!(
                error_str.contains("-32601") || error_str.contains("tools/call"),
                "Error should indicate method not found for skipped tool: {}",
                error
            );
        }
    }

    #[test]
    fn test_plugin_service_ping() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        // Test that the service implements ServerHandler
        assert_eq!(service.get_info().server_info.name, "hyper-mcp");
    }

    #[test]
    fn test_plugin_service_initialize() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        // Test server info
        let info = service.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert_eq!(info.server_info.name, "hyper-mcp");
    }

    #[test]
    fn test_plugin_service_methods_exist() {
        let config = Config {
            plugins: HashMap::new(),
            auths: Some(HashMap::new()),
        };
        let service = PluginService {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
        };

        // Test that ServerHandler methods exist by calling get_info
        let info = service.get_info();
        assert_eq!(info.server_info.name, "hyper-mcp");
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_plugin_service_multiple_plugins() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {:?}", wasm_path);
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin_1:
    url: "file://{}"
    runtime_config:
      memory_limit: "1MB"
  time_plugin_2:
    url: "file://{}"
    runtime_config:
      memory_limit: "2MB"
"#,
            wasm_path.display(),
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);

        let service = PluginService::new(&cli).await.unwrap();
        let plugins = service.plugins.read().await;

        assert_eq!(plugins.len(), 2, "Should have loaded two plugins");
        assert!(plugins.contains_key(&PluginName::from_str("time_plugin_1").unwrap()));
        assert!(plugins.contains_key(&PluginName::from_str("time_plugin_2").unwrap()));
    }
}
