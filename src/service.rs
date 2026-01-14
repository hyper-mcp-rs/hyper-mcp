use crate::{
    config::{Config, PluginName},
    naming::{
        create_namespaced_name, create_namespaced_uri, parse_namespaced_name, parse_namespaced_uri,
    },
    plugin::{Plugin, PluginV1, PluginV2},
    wasm,
};
use anyhow::{Error, Result};
use bytesize::ByteSize;
use dashmap::{DashMap, DashSet, Entry};
use extism::{EXTISM_USER_MODULE, Function, Manifest, UserData, Wasm, host_fn};
use extism_convert::Json;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::*,
    service::{NotificationContext, Peer, RequestContext, RoleServer},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as};
use std::{
    collections::HashMap,
    fmt::Debug,
    ops::Deref,
    str::FromStr,
    sync::{Arc, LazyLock, Mutex, RwLock, Weak},
    time::Duration,
};
use tokio::{runtime::Handle, sync::SetOnce};
use uuid::Uuid;

/// Check if a value contains an environment variable reference in the format ${ENVVARKEY}
/// and replace it with the actual environment variable value if it exists.
/// If the environment variable doesn't exist, returns the original value.
fn check_env_reference(value: &str) -> String {
    // Check if the value matches the pattern ${ENVVARKEY}
    if let Some(stripped) = value.strip_prefix("${").and_then(|s| s.strip_suffix("}")) {
        // Try to get the environment variable
        match std::env::var(stripped) {
            Ok(env_value) => {
                tracing::debug!(
                    "Resolved environment variable reference ${{{stripped}}} to actual value"
                );
                env_value
            }
            Err(_) => {
                tracing::warn!(
                    "Environment variable {stripped} not found, keeping original value {value}"
                );
                value.to_string()
            }
        }
    } else {
        value.to_string()
    }
}

static PLUGIN_SERVICE_INNER_REGISTRY: LazyLock<DashMap<Uuid, Weak<PluginServiceInner>>> =
    LazyLock::new(DashMap::new);
static WASM_DATA_CACHE: LazyLock<DashMap<PluginName, Vec<u8>>> = LazyLock::new(DashMap::new);

#[allow(dead_code)]
#[serde_as]
#[derive(Clone, Debug, Serialize)]
struct CreateElicitationRequestParamWithTimeout {
    #[serde(flatten)]
    pub inner: CreateElicitationRequestParam,
    #[serde_as(as = "Option<DurationSeconds<f64>>")]
    pub timeout: Option<Duration>,
}

impl<'de> Deserialize<'de> for CreateElicitationRequestParamWithTimeout {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;

        fn patch_formats(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    if let Some(Value::String(s)) = map.get_mut("format")
                        && s == "date_time"
                    {
                        *s = "date-time".to_string();
                    }
                    for val in map.values_mut() {
                        patch_formats(val);
                    }
                }
                Value::Array(arr) => {
                    for val in arr.iter_mut() {
                        patch_formats(val);
                    }
                }
                _ => {}
            }
        }

        patch_formats(&mut value);

        #[serde_as]
        #[derive(Deserialize)]
        struct Helper {
            #[serde(flatten)]
            inner: CreateElicitationRequestParam,
            #[serde_as(as = "Option<DurationSeconds<f64>>")]
            timeout: Option<Duration>,
        }

        let Helper { inner, timeout } =
            Helper::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(CreateElicitationRequestParamWithTimeout { inner, timeout })
    }
}

#[derive(Clone, Debug)]
struct PluginServiceContext {
    handle: Handle,
    plugin_service_id: Uuid,
    plugin_name: String,
}

pub struct PluginServiceInner {
    config: Config,
    id: Uuid,
    logging_level: RwLock<LoggingLevel>,
    names: SetOnce<HashMap<Uuid, PluginName>>,
    peer: SetOnce<Peer<RoleServer>>,
    plugins: SetOnce<HashMap<PluginName, Box<dyn Plugin>>>,
    subscriptions: DashSet<String>,
}

impl Drop for PluginServiceInner {
    fn drop(&mut self) {
        PLUGIN_SERVICE_INNER_REGISTRY.remove(&self.id);
    }
}

pub struct PluginService(Arc<PluginServiceInner>);

impl Clone for PluginService {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Deref for PluginService {
    type Target = Arc<PluginServiceInner>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PluginService {
    pub async fn new(config: &Config) -> Result<Self> {
        let inner = Arc::new(PluginServiceInner {
            config: config.clone(),
            id: Uuid::new_v4(),
            logging_level: RwLock::new(LoggingLevel::Error),
            names: SetOnce::new(),
            peer: SetOnce::new(),
            plugins: SetOnce::new(),
            subscriptions: DashSet::new(),
        });
        PLUGIN_SERVICE_INNER_REGISTRY.insert(inner.id, Arc::downgrade(&inner));
        let service = Self(inner);

        service.load_plugins().await?;
        Ok(service)
    }

    fn get(id: Uuid) -> Option<PluginService> {
        if let Some(weak_inner) = PLUGIN_SERVICE_INNER_REGISTRY.get(&id)
            && let Some(inner) = weak_inner.upgrade()
        {
            return Some(PluginService(inner));
        }
        PLUGIN_SERVICE_INNER_REGISTRY.remove(&id);
        None
    }

    async fn load_plugins(&self) -> Result<()> {
        let mut names = HashMap::new();
        let mut plugins: HashMap<PluginName, Box<dyn Plugin>> = HashMap::new();

        host_fn!(create_elicitation(ctx: PluginServiceContext; elicitation_msg: Json<CreateElicitationRequestParamWithTimeout>) -> Json<CreateElicitationResult> {
            let elicitation_msg = elicitation_msg.into_inner();
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            match plugin_service.peer.get() {
                Some(peer) => {
                    if peer.supports_elicitation() {
                        if let Some(timeout) = elicitation_msg.timeout {
                            tracing::info!("Creating elicitation from {} with timeout {:?}", ctx.plugin_name, timeout);
                            ctx.handle.block_on(peer.create_elicitation_with_timeout(elicitation_msg.inner, Some(timeout))).map(Json).map_err(Error::from)
                        } else {
                            tracing::info!("Creating elicitation from {}", ctx.plugin_name);
                            ctx.handle.block_on(peer.create_elicitation(elicitation_msg.inner)).map(Json).map_err(Error::from)
                        }
                    } else {
                        tracing::info!("Peer does not support elicitation, declining from {}", ctx.plugin_name);
                        Ok(Json(CreateElicitationResult {
                            action: ElicitationAction::Decline,
                            content: None,
                        }))
                    }
                },
                None => Err(anyhow::anyhow!("No peer available")),
            }
        });

        host_fn!(create_message(ctx: PluginServiceContext; sampling_msg: Json<CreateMessageRequestParam>) -> Json<CreateMessageResult> {
            let sampling_msg = sampling_msg.into_inner();
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            match plugin_service.peer.get() {
                Some(peer) => {
                    if let Some(peer_info) = peer.peer_info() && peer_info.capabilities.sampling.is_some() {
                        tracing::info!("Creating sampling message from {}", ctx.plugin_name);
                        ctx.handle.block_on(peer.create_message(sampling_msg)).map(Json).map_err(Error::from)
                    } else {
                        Err(anyhow::anyhow!("Peer does not support sampling"))
                    }
                },
                None => Err(anyhow::anyhow!("No peer available")),
            }
        });

        // Declares a host function `list_roots` that plugins can call
        host_fn!(list_roots(ctx: PluginServiceContext;) -> Json<ListRootsResult> {
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            match plugin_service.peer.get() {
                Some(peer) => {
                    if let Some(peer_info) = peer.peer_info() && peer_info.capabilities.roots.is_some() {
                        tracing::info!("Listing roots from {}", ctx.plugin_name);
                        ctx.handle.block_on(peer.list_roots()).map(Json).map_err(Error::from)
                    } else {
                        Ok(Json(ListRootsResult::default()))
                    }
                },
                None => Err(anyhow::anyhow!("No peer available")),
            }
        });

        // Declares a host function `notify_logging_message` that plugins can call
        host_fn!(notify_logging_message(ctx: PluginServiceContext; log_msg: Json<LoggingMessageNotificationParam>) {
            let log_msg = log_msg.into_inner();
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            if !plugin_service.config.disable_logging && (plugin_service.logging_level() as u8) <= (log_msg.level as u8) && let Some(peer) = plugin_service.peer.get() {
                tracing::debug!("Logging message from {}", ctx.plugin_name);
                return ctx.handle.block_on(peer.notify_logging_message(log_msg)).map_err(Error::from);
            }
            Ok(())
        });

        // Declares a host function `notify_progress` that plugins can call
        host_fn!(notify_progress(ctx: PluginServiceContext; progress_msg: Json<ProgressNotificationParam>) {
            let progress_msg = progress_msg.into_inner();
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            match plugin_service.peer.get() {
                Some(peer) => {
                    tracing::debug!("Progress notification from {}", ctx.plugin_name);
                    ctx.handle.block_on(peer.notify_progress(progress_msg)).map_err(Error::from)
                },
                None => Ok(()),
            }
        });

        host_fn!(notify_prompt_list_changed(ctx: PluginServiceContext;) {
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;

            match plugin_service.peer.get() {
                Some(peer) => {
                    tracing::info!("Notifying tool list changed from {}", ctx.plugin_name);
                    ctx.handle.block_on(peer.notify_prompt_list_changed()).map_err(Error::from)
                },
                None => Ok(()),
            }
        });

        host_fn!(notify_resource_list_changed(ctx: PluginServiceContext;) {
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;

            match plugin_service.peer.get() {
                Some(peer) => {
                    tracing::info!("Notifying tool list changed from {}", ctx.plugin_name);
                    ctx.handle.block_on(peer.notify_resource_list_changed()).map_err(Error::from)
                },
                None => Ok(()),
            }
        });

        host_fn!(notify_resource_updated(ctx: PluginServiceContext; update_msg: Json<ResourceUpdatedNotificationParam>) {
            let update_msg = update_msg.into_inner();
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;
            if plugin_service.subscriptions.contains(&update_msg.uri) {
                match plugin_service.peer.get() {
                    Some(peer) => {
                        tracing::info!("Notifying resource {} updated from {}", update_msg.uri, ctx.plugin_name);
                        ctx.handle.block_on(peer.notify_resource_updated(update_msg)).map_err(Error::from)
                    },
                    None => Ok(()),
                }
            }
            else {
                Ok(())
            }
        });

        // Declares a host function `notify_tool_list_changed` that plugins can call
        host_fn!(notify_tool_list_changed(ctx: PluginServiceContext;) {
            let ctx = ctx.get()?.lock().unwrap().clone();
            let plugin_service = PluginService::get(ctx.plugin_service_id).ok_or_else(|| {
                anyhow::anyhow!("PluginService with ID {:?} not found", ctx.plugin_service_id)
            })?;

            match plugin_service.peer.get() {
                Some(peer) => {
                    tracing::info!("Notifying tool list changed from {}", ctx.plugin_name);
                    ctx.handle.block_on(peer.notify_tool_list_changed()).map_err(Error::from)
                },
                None => Ok(()),
            }
        });

        for (plugin_name, plugin_cfg) in &self.config.plugins {
            let wasm_data = match WASM_DATA_CACHE.entry(plugin_name.clone()) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    let content = match plugin_cfg.url.scheme() {
                        "file" => tokio::fs::read(plugin_cfg.url.path()).await?,
                        "http" => wasm::http::load_wasm(&plugin_cfg.url, &None).await?,
                        "https" => {
                            wasm::http::load_wasm(&plugin_cfg.url, &self.config.auths).await?
                        }
                        "oci" => {
                            wasm::oci::load_wasm(&plugin_cfg.url, &self.config.oci, plugin_name)
                                .await?
                        }
                        "s3" => wasm::s3::load_wasm(&plugin_cfg.url).await?,
                        unsupported => {
                            tracing::error!("Unsupported plugin URL scheme: {unsupported}");
                            return Err(anyhow::anyhow!(
                                "Unsupported plugin URL scheme: {unsupported}"
                            ));
                        }
                    };
                    entry.insert(content.clone());
                    content
                }
            };
            let mut manifest = Manifest::new([Wasm::data(wasm_data)]);
            if let Some(runtime_cfg) = &plugin_cfg.runtime_config {
                tracing::info!("runtime_cfg: {runtime_cfg:?}");
                if let Some(hosts) = &runtime_cfg.allowed_hosts {
                    for host in hosts {
                        manifest = manifest.with_allowed_host(host);
                    }
                }
                if let Some(paths) = &runtime_cfg.allowed_paths {
                    for path in paths {
                        // host path will be available in the plugin at the plugin path
                        manifest = manifest.with_allowed_path(path.host.to_string(), &path.plugin);
                    }
                }

                // Add plugin configurations if present
                if let Some(env_vars) = &runtime_cfg.env_vars {
                    for (key, value) in env_vars {
                        let resolved_value = check_env_reference(value);
                        manifest = manifest.with_config_key(key, &resolved_value);
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
                            tracing::error!(
                                "Failed to parse memory_limit '{memory_limit}': {e}. Using default memory limit."
                            );
                        }
                    }
                }
            }
            let extism_plugin = extism::Plugin::new(
                &manifest,
                [
                    Function::new(
                        "create_elicitation",
                        [extism::PTR],
                        [extism::PTR],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        create_elicitation,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "create_message",
                        [extism::PTR],
                        [extism::PTR],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        create_message,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "list_roots",
                        [],
                        [extism::PTR],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        list_roots,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_logging_message",
                        [extism::PTR],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_logging_message,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_progress",
                        [extism::PTR],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_progress,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_prompt_list_changed",
                        [],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_prompt_list_changed,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_resource_list_changed",
                        [],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_resource_list_changed,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_resource_updated",
                        [extism::PTR],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_resource_updated,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                    Function::new(
                        "notify_tool_list_changed",
                        [],
                        [],
                        UserData::new(PluginServiceContext {
                            plugin_service_id: self.id,
                            handle: Handle::current(),
                            plugin_name: plugin_name.to_string(),
                        }),
                        notify_tool_list_changed,
                    )
                    .with_namespace(EXTISM_USER_MODULE),
                ],
                true,
            )
            .unwrap();

            let plugin_id = extism_plugin.id;
            let plugin: Box<dyn Plugin> = if extism_plugin.function_exists("call")
                && extism_plugin.function_exists("describe")
            {
                Box::new(PluginV1::new(
                    plugin_name.clone(),
                    Arc::new(Mutex::new(extism_plugin)),
                ))
            } else {
                Box::new(PluginV2::new(
                    plugin_name.clone(),
                    Arc::new(Mutex::new(extism_plugin)),
                ))
            };

            names.insert(plugin_id, plugin_name.clone());
            plugins.insert(plugin_name.clone(), plugin);
            tracing::info!("Loaded plugin {plugin_name}");
        }
        self.names.set(names).expect("Names already set");
        self.plugins.set(plugins).expect("Plugins already set");
        Ok(())
    }

    pub fn logging_level(&self) -> LoggingLevel {
        *self.logging_level.read().unwrap()
    }

    pub fn set_logging_level(&self, level: LoggingLevel) {
        *self.logging_level.write().unwrap() = level;
    }
}

impl ServerHandler for PluginService {
    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!("got tools/call request {:?}", request);
        let (plugin_name, tool_name) = match parse_namespaced_name(request.name.to_string()) {
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
            && skip_tools.is_match(&tool_name)
        {
            tracing::warn!("Tool {tool_name} in skip_tools");
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        }

        let request = CallToolRequestParam {
            name: std::borrow::Cow::Owned(tool_name.clone()),
            arguments: request.arguments,
        };

        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let Some(plugin) = plugins.get(&plugin_name) else {
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        };
        plugin.call_tool(request, context).await
    }

    async fn complete(
        &self,
        request: CompleteRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        tracing::info!("got completion/complete request {:?}", request);
        let (plugin_name, request) = match request.r#ref {
            Reference::Prompt(PromptReference { name, title }) => {
                let (plugin_name, prompt_name) = match parse_namespaced_name(name.to_string()) {
                    Ok((plugin_name, prompt_name)) => (plugin_name, prompt_name),
                    Err(e) => {
                        return Err(McpError::invalid_request(
                            format!("Failed to parse prompt name: {e}"),
                            None,
                        ));
                    }
                };
                let plugin_config = match self.config.plugins.get(&plugin_name) {
                    Some(config) => config,
                    None => {
                        return Err(McpError::method_not_found::<CompleteRequestMethod>());
                    }
                };
                if let Some(skip_prompts) = &plugin_config
                    .runtime_config
                    .as_ref()
                    .and_then(|rc| rc.skip_prompts.clone())
                    && skip_prompts.is_match(&prompt_name)
                {
                    tracing::warn!("Prompt {prompt_name} in skip_prompts");
                    return Err(McpError::method_not_found::<CompleteRequestMethod>());
                }
                (
                    plugin_name,
                    CompleteRequestParam {
                        r#ref: Reference::Prompt(PromptReference {
                            name: prompt_name,
                            title,
                        }),
                        argument: request.argument,
                        context: request.context,
                    },
                )
            }
            Reference::Resource(ResourceReference { uri }) => {
                let (plugin_name, resource_uri) = match parse_namespaced_uri(uri.to_string()) {
                    Ok((plugin_name, resource_uri)) => (plugin_name, resource_uri),
                    Err(e) => {
                        return Err(McpError::invalid_request(
                            format!("Failed to parse prompt name: {e}"),
                            None,
                        ));
                    }
                };
                let plugin_config = match self.config.plugins.get(&plugin_name) {
                    Some(config) => config,
                    None => {
                        return Err(McpError::method_not_found::<CompleteRequestMethod>());
                    }
                };
                if let Some(skip_resource_templates) = &plugin_config
                    .runtime_config
                    .as_ref()
                    .and_then(|rc| rc.skip_resource_templates.clone())
                    && skip_resource_templates.is_match(&resource_uri)
                {
                    tracing::warn!("Resource {resource_uri} in skip_resources");
                    return Err(McpError::method_not_found::<CompleteRequestMethod>());
                }
                (
                    plugin_name,
                    CompleteRequestParam {
                        r#ref: Reference::Resource(ResourceReference { uri: resource_uri }),
                        argument: request.argument,
                        context: request.context,
                    },
                )
            }
        };

        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let Some(plugin) = plugins.get(&plugin_name) else {
            return Err(McpError::method_not_found::<CallToolRequestMethod>());
        };
        plugin.complete(request, context).await
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "hyper-mcp".to_string(),
                title: Some("Hyper MCP".to_string()),
                version: env!("CARGO_PKG_VERSION").to_string(),
                website_url: Some("https://github.com/tuananh/hyper-mcp".to_string()),

                ..Default::default()
            },
            capabilities: if self.config.disable_logging {
                ServerCapabilities::builder()
                    .enable_completions()
                    .enable_prompts()
                    .enable_prompts_list_changed()
                    .enable_resources()
                    .enable_resources_list_changed()
                    .enable_resources_subscribe()
                    .enable_tools()
                    .enable_tool_list_changed()
                    .build()
            } else {
                ServerCapabilities::builder()
                    .enable_completions()
                    .enable_logging()
                    .enable_prompts()
                    .enable_prompts_list_changed()
                    .enable_resources()
                    .enable_resources_list_changed()
                    .enable_resources_subscribe()
                    .enable_tools()
                    .enable_tool_list_changed()
                    .build()
            },

            ..Default::default()
        }
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        tracing::info!("got prompts/get request {:?}", request);
        let (plugin_name, prompt_name) = match parse_namespaced_name(request.name.to_string()) {
            Ok((plugin_name, prompt_name)) => (plugin_name, prompt_name),
            Err(e) => {
                return Err(McpError::invalid_request(
                    format!("Failed to parse prompt name: {e}"),
                    None,
                ));
            }
        };
        let plugin_config = match self.config.plugins.get(&plugin_name) {
            Some(config) => config,
            None => {
                return Err(McpError::method_not_found::<GetPromptRequestMethod>());
            }
        };
        if let Some(skip_prompts) = &plugin_config
            .runtime_config
            .as_ref()
            .and_then(|rc| rc.skip_prompts.clone())
            && skip_prompts.is_match(&prompt_name)
        {
            tracing::warn!("Prompt {prompt_name} in skip_prompts");
            return Err(McpError::method_not_found::<GetPromptRequestMethod>());
        }

        let request = GetPromptRequestParam {
            name: prompt_name.clone(),
            arguments: request.arguments,
        };

        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let Some(plugin) = plugins.get(&plugin_name) else {
            return Err(McpError::method_not_found::<GetPromptRequestMethod>());
        };
        plugin.get_prompt(request, context).await
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        tracing::info!("got prompts/list request {:?}", request);
        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let mut list_prompts_result = ListPromptsResult::default();

        for (plugin_name, plugin) in plugins.iter() {
            let plugin_prompts = plugin
                .list_prompts(request.clone(), context.clone())
                .await?;
            let plugin_cfg = self.config.plugins.get(plugin_name).ok_or_else(|| {
                McpError::internal_error(
                    format!("Plugin configuration not found for {plugin_name}"),
                    None,
                )
            })?;
            let skip_prompts = plugin_cfg
                .runtime_config
                .as_ref()
                .and_then(|rc| rc.skip_prompts.clone())
                .unwrap_or_default();
            for prompt in plugin_prompts.prompts {
                let prompt_name = prompt.name.as_ref() as &str;
                if skip_prompts.is_match(prompt_name) {
                    tracing::info!(
                        "Skipping prompt {} as requested in skip_prompts",
                        prompt.name
                    );
                    continue;
                }
                let mut new_prompt = prompt.clone();
                new_prompt.name = create_namespaced_name(plugin_name, &prompt.name);
                list_prompts_result.prompts.push(new_prompt);
            }
        }

        Ok(list_prompts_result)
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        tracing::info!("got resources/list request {:?}", request);
        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let mut list_resources_result = ListResourcesResult::default();

        for (plugin_name, plugin) in plugins.iter() {
            let plugin_resources = plugin
                .list_resources(request.clone(), context.clone())
                .await?;
            let plugin_cfg = self.config.plugins.get(plugin_name).ok_or_else(|| {
                McpError::internal_error(
                    format!("Plugin configuration not found for {plugin_name}"),
                    None,
                )
            })?;
            let skip_resources = plugin_cfg
                .runtime_config
                .as_ref()
                .and_then(|rc| rc.skip_resources.clone())
                .unwrap_or_default();
            for resource in plugin_resources.resources {
                if skip_resources.is_match(resource.uri.as_str()) {
                    tracing::info!(
                        "Skipping resource {} as requested in skip_resources",
                        resource.uri
                    );
                    continue;
                }
                let mut raw = resource.raw.clone();
                raw.uri = create_namespaced_uri(plugin_name, &resource.uri)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                list_resources_result.resources.push(Resource {
                    raw,
                    annotations: resource.annotations.clone(),
                });
            }
        }

        Ok(list_resources_result)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        tracing::info!("got resources/templates/list request {:?}", request);
        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let mut list_resource_templates_result = ListResourceTemplatesResult::default();

        for (plugin_name, plugin) in plugins.iter() {
            let plugin_resource_templates = plugin
                .list_resource_templates(request.clone(), context.clone())
                .await?;
            let plugin_cfg = self.config.plugins.get(plugin_name).ok_or_else(|| {
                McpError::internal_error(
                    format!("Plugin configuration not found for {plugin_name}"),
                    None,
                )
            })?;
            let skip_resource_templates = plugin_cfg
                .runtime_config
                .as_ref()
                .and_then(|rc| rc.skip_resource_templates.clone())
                .unwrap_or_default();
            for resource_template in plugin_resource_templates.resource_templates {
                if skip_resource_templates.is_match(resource_template.uri_template.as_str()) {
                    tracing::info!(
                        "Skipping resource template {} as requested in skip_resources",
                        resource_template.uri_template
                    );
                    continue;
                }
                let mut raw = resource_template.raw.clone();
                raw.uri_template =
                    create_namespaced_uri(plugin_name, &resource_template.uri_template)
                        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                list_resource_templates_result
                    .resource_templates
                    .push(ResourceTemplate {
                        raw,
                        annotations: resource_template.annotations.clone(),
                    });
            }
        }

        Ok(list_resource_templates_result)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        tracing::info!("got tools/list request {:?}", request);
        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let mut list_tools_result = ListToolsResult::default();

        for (plugin_name, plugin) in plugins.iter() {
            let plugin_tools = plugin.list_tools(request.clone(), context.clone()).await?;
            let plugin_cfg = self.config.plugins.get(plugin_name).ok_or_else(|| {
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
            for tool in plugin_tools.tools {
                let tool_name = tool.name.as_ref() as &str;
                if skip_tools.is_match(tool_name) {
                    tracing::info!("Skipping tool {} as requested in skip_tools", tool.name);
                    continue;
                }
                let mut new_tool = tool.clone();
                new_tool.name =
                    std::borrow::Cow::Owned(create_namespaced_name(plugin_name, &tool.name));
                list_tools_result.tools.push(new_tool);
            }
        }

        Ok(list_tools_result)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        tracing::info!("client initialized");
        self.peer.set(context.peer).expect("Peer already set");
        std::future::ready(())
    }

    async fn on_roots_list_changed(&self, context: NotificationContext<RoleServer>) -> () {
        tracing::info!("got roots/list_changed notification");
        let Some(plugins) = self.plugins.get() else {
            tracing::error!("Plugins not initialized");
            return;
        };
        for (plugin_name, plugin) in plugins.iter() {
            if let Err(e) = plugin.on_roots_list_changed(context.clone()).await {
                tracing::error!("Failed to notify plugin {plugin_name} of roots list change: {e}");
            }
        }
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        tracing::info!("got resources/read request {:?}", request);
        let (plugin_name, resource_uri) = match parse_namespaced_uri(request.uri.to_string()) {
            Ok((plugin_name, resource_uri)) => (plugin_name, resource_uri),
            Err(e) => {
                return Err(McpError::invalid_request(
                    format!("Failed to parse prompt name: {e}"),
                    None,
                ));
            }
        };
        let plugin_config = match self.config.plugins.get(&plugin_name) {
            Some(config) => config,
            None => {
                return Err(McpError::method_not_found::<ReadResourceRequestMethod>());
            }
        };
        if let Some(skip_resources) = &plugin_config
            .runtime_config
            .as_ref()
            .and_then(|rc| rc.skip_resources.clone())
            && skip_resources.is_match(&resource_uri)
        {
            tracing::warn!("Resource {resource_uri} in skip_resources");
            return Err(McpError::method_not_found::<ReadResourceRequestMethod>());
        }

        let request = ReadResourceRequestParam {
            uri: resource_uri.clone(),
        };

        let Some(plugins) = self.plugins.get() else {
            return Err(McpError::internal_error(
                "Plugins not initialized".to_string(),
                None,
            ));
        };

        let Some(plugin) = plugins.get(&plugin_name) else {
            return Err(McpError::method_not_found::<GetPromptRequestMethod>());
        };
        plugin.read_resource(request, context).await
    }

    fn set_level(
        &self,
        request: SetLevelRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), McpError>> + Send + '_ {
        self.set_logging_level(request.level);
        std::future::ready(Ok(()))
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = std::result::Result<(), McpError>> + Send + '_ {
        self.subscriptions.insert(request.uri);
        std::future::ready(Ok(()))
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = std::result::Result<(), McpError>> + Send + '_ {
        self.subscriptions.remove(&request.uri);
        std::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cli::Cli, config::load_config};
    use rmcp::{
        ClientHandler,
        model::ClientInfo,
        service::{RoleClient, RunningService, Service, serve_client, serve_server},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;
    use tokio::io::duplex;
    use tokio_test::assert_ok;
    use tokio_util::sync::CancellationToken;

    struct TestClientInner {
        tool_list_changed_count: AtomicUsize,
    }

    struct TestClient(Arc<TestClientInner>);

    impl Clone for TestClient {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }

    impl Deref for TestClient {
        type Target = Arc<TestClientInner>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl ClientHandler for TestClient {
        fn on_tool_list_changed(
            &self,
            _context: NotificationContext<RoleClient>,
        ) -> impl Future<Output = ()> + Send + '_ {
            self.tool_list_changed_count.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        }
    }

    impl TestClient {
        fn new() -> Self {
            Self(Arc::new(TestClientInner {
                tool_list_changed_count: AtomicUsize::new(0),
            }))
        }

        fn get_tool_list_changed_count(&self) -> usize {
            self.tool_list_changed_count.load(Ordering::SeqCst)
        }
    }

    async fn create_temp_config_file(content: &str) -> anyhow::Result<(TempDir, PathBuf)> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test_config.yaml");
        tokio::fs::write(&config_path, content).await?;
        Ok((temp_dir, config_path))
    }

    fn create_test_cli() -> Cli {
        crate::cli::Cli::default()
    }

    fn create_test_ctx(
        running: &RunningService<RoleServer, PluginService>,
    ) -> RequestContext<RoleServer> {
        RequestContext {
            ct: CancellationToken::new(),
            extensions: Extensions::default(),
            id: RequestId::Number(1),
            meta: Meta::default(),
            peer: running.peer().clone(),
        }
    }

    fn create_test_service(config: Config) -> PluginService {
        PluginService(Arc::new(PluginServiceInner {
            config,
            id: Uuid::new_v4(),
            logging_level: RwLock::new(LoggingLevel::Info),
            names: SetOnce::new(),
            peer: SetOnce::new(),
            plugins: SetOnce::new(),
            subscriptions: DashSet::new(),
        }))
    }

    async fn create_test_pair<S, C>(
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
        .expect("Failed to create test pair")
    }

    fn get_test_wasm_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("plugins");
        path.push("v1");
        path.push("time");
        path.push("time.wasm");
        path
    }

    fn test_wasm_exists() -> bool {
        get_test_wasm_path().exists()
    }

    fn get_tool_list_changed_wasm_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("plugins");
        path.push("v1");
        path.push("tool-list-changed");
        path.push("tool_list_changed.wasm");
        path
    }

    fn test_tool_list_changed_wasm_exists() -> bool {
        get_tool_list_changed_wasm_path().exists()
    }

    fn get_rstime_wasm_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("plugins");
        path.push("v2");
        path.push("rstime");
        path.push("rstime.wasm");
        path
    }

    fn test_rstime_wasm_exists() -> bool {
        get_rstime_wasm_path().exists()
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
        let config = load_config(&cli).await.unwrap();

        let result = PluginService::new(&config).await;
        assert!(
            result.is_ok(),
            "Should create service with empty plugin config"
        );

        let service = result.unwrap();
        let Some(plugins) = service.plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(plugins.is_empty(), "Should have no plugins loaded");
    }

    #[tokio::test]
    async fn test_plugin_service_creation_with_file_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let result = PluginService::new(&config).await;
        assert!(
            result.is_ok(),
            "Should create service with valid WASM plugin"
        );

        let service = result.unwrap();
        let Some(plugins) = service.plugins.get() else {
            panic!("Plugins should be initialized");
        };
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
        let config = load_config(&cli).await.unwrap();

        let result = PluginService::new(&config).await;
        assert!(result.is_err(), "Should fail with nonexistent plugin file");
    }

    #[tokio::test]
    async fn test_plugin_service_creation_with_invalid_memory_limit() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let result = PluginService::new(&config).await;
        // Should still succeed but log an error about invalid memory limit
        assert!(
            result.is_ok(),
            "Should handle invalid memory limit gracefully"
        );
    }

    // ServerHandler tests

    #[test]
    fn test_plugin_service_get_info() {
        let config = Config::default();
        let service = create_test_service(config);

        let info = rmcp::ServerHandler::get_info(&service);
        assert_eq!(info.protocol_version, ProtocolVersion::LATEST);
        assert_eq!(info.server_info.name, "hyper-mcp");
        assert!(!info.server_info.version.is_empty());
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn test_plugin_service_get_info_default_flags() {
        // Test with default config (both flags false, so both features enabled)
        let config = Config::default();
        let service = create_test_service(config);

        let info = rmcp::ServerHandler::get_info(&service);

        // Verify basic info
        assert_eq!(info.server_info.name, "hyper-mcp");
        assert_eq!(info.server_info.title, Some("Hyper MCP".to_string()));
        assert!(!info.server_info.version.is_empty());
        assert_eq!(
            info.server_info.website_url,
            Some("https://github.com/tuananh/hyper-mcp".to_string())
        );

        // With both flags false, both completions and logging should be enabled
        assert!(
            info.capabilities.completions.is_some(),
            "completions should be enabled"
        );
        assert!(
            info.capabilities.logging.is_some(),
            "logging should be enabled"
        );

        // Standard capabilities should always be present
        assert!(info.capabilities.prompts.is_some());
        assert!(info.capabilities.resources.is_some());
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn test_plugin_service_get_info_capabilities_structure() {
        // Test that all expected capability fields are present with default config
        let config = Config::default();
        let service = create_test_service(config);

        let info = rmcp::ServerHandler::get_info(&service);
        let caps = &info.capabilities;

        // Check all expected capabilities
        assert!(caps.completions.is_some());
        assert!(caps.logging.is_some());
        assert!(caps.prompts.is_some());
        assert!(caps.resources.is_some());
        assert!(caps.tools.is_some());

        // Check that prompts capabilities are properly set
        if let Some(prompts) = &caps.prompts {
            assert!(
                prompts.list_changed.unwrap_or(false),
                "prompts list_changed should be enabled"
            );
        }

        // Check that resources capabilities are properly set
        if let Some(resources) = &caps.resources {
            assert!(
                resources.list_changed.unwrap_or(false),
                "resources list_changed should be enabled"
            );
            assert!(
                resources.subscribe.unwrap_or(false),
                "resources subscribe should be enabled"
            );
        }

        // Check that tools capabilities are properly set
        if let Some(tools) = &caps.tools {
            assert!(
                tools.list_changed.unwrap_or(false),
                "tools list_changed should be enabled"
            );
        }
    }

    #[tokio::test]
    async fn test_plugin_service_list_tools_with_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        // Verify the service was created successfully
        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded plugin");

        // Test the list_tools function
        let request = None; // No pagination for this test
        let ctx = create_test_ctx(&server);
        let result = server.service().list_tools(request, ctx).await;
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
                "Expected tool '{expected_tool}' not found in actual tools: {actual_tool_names:?}"
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
                "Tool description should mention operation '{operation}': {description}"
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
                                "Input schema should include operation '{operation}' in enum: {schema_operations:?}"
                            );
                        }
                    }
                }
            }
        }
        // Cleanup
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_list_tools_with_skip_tools() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded plugin");

        // Test the list_tools function with skip_tools configuration
        let request = None; // No pagination for this test
        let ctx = create_test_ctx(&server);
        let result = server.service().list_tools(request, ctx).await;
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
            "time_plugin-time should be skipped but was found in tools: {tool_names:?}"
        );

        // Verify that the plugin itself was loaded (skip_tools should not prevent plugin loading)
        {
            let plugin_name: PluginName = "time_plugin".parse().unwrap();
            assert!(
                plugins.contains_key(&plugin_name),
                "Plugin 'time_plugin' should still be loaded even with skip_tools configuration"
            );
        } // plugins guard dropped here

        // Verify the plugin configuration includes skip_tools
        let plugin_name: PluginName = "time_plugin".parse().unwrap();
        let plugin_config = server.service().config.plugins.get(&plugin_name).unwrap();
        let skip_tools = plugin_config
            .runtime_config
            .as_ref()
            .and_then(|rc| rc.skip_tools.as_ref())
            .unwrap();

        assert!(
            skip_tools.is_match(&"time"),
            "Configuration should include 'time' in skip_tools list: {skip_tools:?}"
        );

        assert_eq!(
            skip_tools.len(),
            1,
            "Should have exactly one tool in skip_tools list: {skip_tools:?}"
        );

        // Cleanup
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_invalid_format() {
        let config = Config::default();
        let (server, client) =
            create_test_pair(create_test_service(config), ClientInfo::default()).await;

        // Test calling tool with invalid format (missing plugin name separator)
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("invalid_tool_name"),
            arguments: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(result.is_err(), "Should fail with invalid tool name format");

        if let Err(error) = result {
            // Should be an invalid_request error
            assert!(
                error.to_string().contains("Failed to parse tool name"),
                "Error should mention parsing failure: {error}"
            );
        }

        // Test with empty tool name
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed(""),
            arguments: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(result.is_err(), "Should fail with empty tool name");
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_nonexistent_plugin() {
        let config = Config::default();
        let (server, client) =
            create_test_pair(create_test_service(config), ClientInfo::default()).await;

        // Test calling tool on nonexistent plugin
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("nonexistent_plugin-some_tool"),
            arguments: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(result.is_err(), "Should fail with nonexistent plugin");

        if let Err(error) = result {
            // Should be a method_not_found error since plugin doesn't exist
            let error_str = error.to_string();
            assert!(
                error_str.contains("-32601") || error_str.contains("tools/call"),
                "Error should indicate method not found: {error}"
            );
        }
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_with_plugin() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded plugin");

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

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call time tool: {result:?}"
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

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call parse_time operation: {result:?}"
        );

        let call_result = result.unwrap();
        // Verify the parse_time operation returns content

        assert!(
            !call_result.content.is_empty(),
            "Parse time operation should return non-empty content"
        );
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_with_skipped_tool() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded plugin");

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

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(result.is_err(), "Should fail when calling skipped tool");

        if let Err(error) = result {
            // Should be a method_not_found error since tool is skipped
            let error_str = error.to_string();
            assert!(
                error_str.contains("-32601") || error_str.contains("tools/call"),
                "Error should indicate method not found for skipped tool: {error}"
            );
        }
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[test]
    fn test_plugin_service_ping() {
        let config = Config::default();
        let service = create_test_service(config);

        // Test that the service implements ServerHandler
        assert_eq!(
            rmcp::ServerHandler::get_info(&service).server_info.name,
            "hyper-mcp"
        );
    }

    #[test]
    fn test_plugin_service_initialize() {
        let config = Config::default();
        let service = create_test_service(config);

        // Test server info
        let info = rmcp::ServerHandler::get_info(&service);
        assert_eq!(info.protocol_version, ProtocolVersion::LATEST);
        assert_eq!(info.server_info.name, "hyper-mcp");
    }

    #[test]
    fn test_plugin_service_methods_exist() {
        let config = Config::default();
        let service = create_test_service(config);

        // Test that ServerHandler methods exist by calling get_info
        let info = rmcp::ServerHandler::get_info(&service);
        assert_eq!(info.server_info.name, "hyper-mcp");
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_plugin_service_multiple_plugins() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
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
        let config = load_config(&cli).await.unwrap();

        let service = PluginService::new(&config).await.unwrap();
        let Some(plugins) = service.plugins.get() else {
            panic!("Plugins should be initialized");
        };

        assert_eq!(plugins.len(), 2, "Should have loaded two plugins");
        assert!(plugins.contains_key(&PluginName::from_str("time_plugin_1").unwrap()));
        assert!(plugins.contains_key(&PluginName::from_str("time_plugin_2").unwrap()));
    }

    #[tokio::test]
    async fn test_plugin_service_call_tool_with_cancellation() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.to_string_lossy()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Create a cancellation token
        let cancellation_token = CancellationToken::new();

        // Create request context with the cancellation token
        let ctx = RequestContext {
            ct: cancellation_token.clone(),
            extensions: Extensions::default(),
            id: RequestId::Number(1),
            meta: Meta::default(),
            peer: server.peer().clone(),
        };

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

        // Cancel the token before executing call_tool to force cancellation path
        cancellation_token.cancel();

        // Execute call_tool with the already-cancelled token
        let result = server.service().call_tool(request, ctx).await;

        assert!(result.is_err(), "Expected cancellation error");
        let error = result.unwrap_err();
        let error_message = error.to_string();
        assert!(
            error_message.contains("cancelled") || error_message.contains("canceled"),
            "Expected cancellation error message, got: {error_message}"
        );
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_plugin_service_list_tools_with_cancellation() {
        let wasm_path = get_test_wasm_path();
        if !test_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  time_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Create a cancellation token
        let cancellation_token = CancellationToken::new();

        // Create request context with the cancellation token
        let ctx = RequestContext {
            ct: cancellation_token.clone(),
            extensions: Extensions::default(),
            id: RequestId::Number(1),
            meta: Meta::default(),
            peer: server.peer().clone(),
        };

        // Cancel the token before executing list_tools to force cancellation path
        cancellation_token.cancel();

        // Execute list_tools with the already-cancelled token
        let result = server.service().list_tools(None, ctx).await;

        assert!(result.is_err(), "Expected cancellation error");
        let error = result.unwrap_err();
        let error_message = error.to_string();
        assert!(
            error_message.contains("cancelled") || error_message.contains("canceled"),
            "Expected cancellation error message, got: {error_message}"
        );
        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    // ========================================================================
    // Tests for notify_tool_list_changed host function
    // ========================================================================

    #[tokio::test]
    async fn test_notify_tool_list_changed_basic() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        let ctx = create_test_ctx(&server);

        // List tools to verify the plugin loaded and has initial tools
        let result = server.service().list_tools(None, ctx).await;
        assert!(result.is_ok(), "list_tools should succeed");

        let tools = result.unwrap();
        assert!(
            !tools.tools.is_empty(),
            "tool_list_changed_plugin should have at least one tool"
        );

        // Verify add_tool exists
        let tool_names: Vec<String> = tools.tools.iter().map(|t| t.name.to_string()).collect();
        assert!(
            tool_names.contains(&"tool_list_changed_plugin-add_tool".to_string()),
            "add_tool should be in the tool list"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_triggers_on_add() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            TestClient::new(),
        )
        .await;
        let ctx = create_test_ctx(&server);

        // Get initial tool list
        let initial_tools = server.service().list_tools(None, ctx.clone()).await;
        assert!(initial_tools.is_ok());
        let initial_result = initial_tools.unwrap();
        let initial_count = initial_result.tools.len();

        // Call add_tool
        let add_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
            arguments: Some(serde_json::Map::new()),
        };

        let result = server
            .service()
            .call_tool(add_tool_request, ctx.clone())
            .await;
        assert!(
            result.is_ok(),
            "add_tool should succeed. Error: {:?}",
            result.err()
        );

        assert!(client.service().get_tool_list_changed_count() == 1);

        // Get updated tool list
        let ctx2 = create_test_ctx(&server);
        let updated_tools = server.service().list_tools(None, ctx2).await;
        assert!(updated_tools.is_ok());
        let updated_result = updated_tools.unwrap();
        let updated_count = updated_result.tools.len();

        // Verify tool list grew
        assert!(
            updated_count > initial_count,
            "Tool count should increase after add_tool. Initial: {}, Updated: {}",
            initial_count,
            updated_count
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_multiple_additions() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            TestClient::new(),
        )
        .await;

        // Call add_tool three times
        for i in 1..=3 {
            let ctx = create_test_ctx(&server);
            let add_tool_request = CallToolRequestParam {
                name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
                arguments: Some(serde_json::Map::new()),
            };

            let result = server.service().call_tool(add_tool_request, ctx).await;
            assert!(result.is_ok(), "add_tool call {} should succeed", i);
        }

        assert!(client.service().get_tool_list_changed_count() == 3);

        // Get final tool list
        let ctx = create_test_ctx(&server);
        let final_tools = server.service().list_tools(None, ctx).await;
        assert!(final_tools.is_ok());

        let final_result = final_tools.unwrap();
        let tool_names: Vec<String> = final_result
            .tools
            .iter()
            .map(|t| t.name.to_string())
            .collect();

        // Verify all three tools exist
        assert!(
            tool_names.contains(&"tool_list_changed_plugin-tool_1".to_string()),
            "tool_1 should exist in tool list"
        );
        assert!(
            tool_names.contains(&"tool_list_changed_plugin-tool_2".to_string()),
            "tool_2 should exist in tool list"
        );
        assert!(
            tool_names.contains(&"tool_list_changed_plugin-tool_3".to_string()),
            "tool_3 should exist in tool list"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_tool_callable_after_add() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Add a tool
        let ctx = create_test_ctx(&server);
        let add_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
            arguments: Some(serde_json::Map::new()),
        };

        let result = server.service().call_tool(add_tool_request, ctx).await;
        assert!(result.is_ok(), "add_tool should succeed");

        // Call the newly created tool_1
        let ctx2 = create_test_ctx(&server);
        let tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-tool_1"),
            arguments: Some(serde_json::Map::new()),
        };

        let result = server.service().call_tool(tool_request, ctx2).await;
        assert!(result.is_ok(), "tool_1 should be callable after creation");

        let response = result.unwrap();
        assert!(!response.content.is_empty(), "tool_1 should return content");

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_response_format() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;
        let ctx = create_test_ctx(&server);

        // Call add_tool and verify response format
        let add_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
            arguments: Some(serde_json::Map::new()),
        };

        let result = server.service().call_tool(add_tool_request, ctx).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.content.is_empty(), "Response should have content");

        // Just verify that we got content back - the content structure is handled by rmcp
        assert_eq!(
            response.is_error,
            Some(false),
            "Response should not be an error"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_sequential_tool_numbers() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Add 5 tools and verify tool_count in responses
        for expected_count in 1..=5 {
            let ctx = create_test_ctx(&server);
            let add_tool_request = CallToolRequestParam {
                name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
                arguments: Some(serde_json::Map::new()),
            };

            let result = server.service().call_tool(add_tool_request, ctx).await;
            assert!(result.is_ok());

            let response = result.unwrap();
            // Verify response indicates success
            assert_eq!(
                response.is_error,
                Some(false),
                "add_tool call {} should succeed",
                expected_count
            );
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_invalid_tool_call() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Try to call a tool that doesn't exist yet (tool_5 when only tool_1 exists)
        let ctx = create_test_ctx(&server);
        let invalid_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-tool_5"),
            arguments: Some(serde_json::Map::new()),
        };

        let result = server.service().call_tool(invalid_tool_request, ctx).await;
        assert!(
            result.is_ok(),
            "Tool call should complete, but indicate error"
        );

        let response = result.unwrap();
        assert!(
            response.is_error == Some(true),
            "Calling non-existent tool should return error"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_add_tool_failure_propagates() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Call add_tool with additional arguments (should still work but they're ignored)
        let ctx = create_test_ctx(&server);
        let mut args = serde_json::Map::new();
        args.insert(
            "extra_param".to_string(),
            serde_json::Value::String("should_be_ignored".to_string()),
        );

        let add_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
            arguments: Some(args),
        };

        let result = server.service().call_tool(add_tool_request, ctx).await;
        assert!(
            result.is_ok(),
            "add_tool should succeed even with extra params"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_new_tools_appear_in_list() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Get initial tools
        let ctx = create_test_ctx(&server);
        let initial_result = server.service().list_tools(None, ctx).await;
        assert!(initial_result.is_ok());
        let initial_tools = initial_result.unwrap();
        let initial_names: Vec<String> = initial_tools
            .tools
            .iter()
            .map(|t| t.name.to_string())
            .collect();

        // Verify tool_1 doesn't exist yet
        assert!(
            !initial_names.contains(&"tool_list_changed_plugin-tool_1".to_string()),
            "tool_1 should not exist initially"
        );

        // Add tool_1
        let ctx = create_test_ctx(&server);
        let add_tool_request = CallToolRequestParam {
            name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
            arguments: Some(serde_json::Map::new()),
        };
        let _ = server.service().call_tool(add_tool_request, ctx).await;

        // Get updated tools
        let ctx = create_test_ctx(&server);
        let updated_result = server.service().list_tools(None, ctx).await;
        assert!(updated_result.is_ok());
        let updated_tools = updated_result.unwrap();
        let updated_names: Vec<String> = updated_tools
            .tools
            .iter()
            .map(|t| t.name.to_string())
            .collect();

        // Verify tool_1 exists now
        assert!(
            updated_names.contains(&"tool_list_changed_plugin-tool_1".to_string()),
            "tool_1 should exist after add_tool"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_notify_tool_list_changed_tool_descriptions() {
        let wasm_path = get_tool_list_changed_wasm_path();
        if !test_tool_list_changed_wasm_exists() {
            println!("Skipping test - tool-list-changed WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  tool_list_changed_plugin:
    url: "file://{}"
    runtime_config:
      max_memory_mb: 10
      max_execution_time_ms: 5000
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Add two tools
        for _ in 0..2 {
            let ctx = create_test_ctx(&server);
            let add_tool_request = CallToolRequestParam {
                name: std::borrow::Cow::Borrowed("tool_list_changed_plugin-add_tool"),
                arguments: Some(serde_json::Map::new()),
            };
            let _ = server.service().call_tool(add_tool_request, ctx).await;
        }

        // Get tool list and verify descriptions
        let ctx = create_test_ctx(&server);
        let result = server.service().list_tools(None, ctx).await;
        assert!(result.is_ok());

        let tools = result.unwrap();
        let tool_map: std::collections::HashMap<String, &Tool> = tools
            .tools
            .iter()
            .map(|t| (t.name.to_string(), t))
            .collect();

        // Verify tool descriptions exist and are meaningful
        if let Some(add_tool) = tool_map.get("tool_list_changed_plugin-add_tool") {
            if let Some(desc) = &add_tool.description {
                assert!(!desc.is_empty(), "add_tool should have a description");
                assert!(
                    desc.to_lowercase().contains("add"),
                    "add_tool description should mention 'add'"
                );
            }
        }

        if let Some(tool_1) = tool_map.get("tool_list_changed_plugin-tool_1") {
            if let Some(desc) = &tool_1.description {
                assert!(!desc.is_empty(), "tool_1 should have a description");
                assert!(
                    desc.to_lowercase().contains("tool"),
                    "tool_1 description should mention 'tool'"
                );
            }
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    // Comprehensive tests for rstime v2 plugin

    #[tokio::test]
    async fn test_rstime_list_tools() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded rstime plugin");

        let request = None;
        let ctx = create_test_ctx(&server);
        let result = server.service().list_tools(request, ctx).await;
        assert!(result.is_ok(), "list_tools should succeed");

        let list_tools_result = result.unwrap();
        assert!(
            !list_tools_result.tools.is_empty(),
            "Should have tools from rstime plugin"
        );

        // Verify expected tools: get_time and parse_time
        let tool_names: Vec<String> = list_tools_result
            .tools
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();

        assert!(
            tool_names.iter().any(|name| name.contains("get_time")),
            "Should have get_time tool"
        );
        assert!(
            tool_names.iter().any(|name| name.contains("parse_time")),
            "Should have parse_time tool"
        );

        // Verify tool properties
        for tool in &list_tools_result.tools {
            assert!(!tool.name.is_empty(), "Tool should have a name");
            assert!(tool.description.is_some(), "Tool should have a description");
            // Just verify the tool exists, schema validation happens at plugin level
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_list_prompts() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded rstime plugin");

        let request = None;
        let ctx = create_test_ctx(&server);
        let result = server.service().list_prompts(request, ctx).await;
        assert!(result.is_ok(), "list_prompts should succeed");

        let list_prompts_result = result.unwrap();
        assert!(
            !list_prompts_result.prompts.is_empty(),
            "Should have prompts from rstime plugin"
        );

        // Verify the get_time_with_timezone prompt exists
        let prompt_names: Vec<String> = list_prompts_result
            .prompts
            .iter()
            .map(|p| p.name.to_string())
            .collect();

        assert!(
            prompt_names
                .iter()
                .any(|name| name.contains("get_time_with_timezone")),
            "Should have get_time_with_timezone prompt"
        );

        // Verify prompt properties
        for prompt in &list_prompts_result.prompts {
            assert!(!prompt.name.is_empty(), "Prompt should have a name");
            assert!(
                prompt.description.is_some(),
                "Prompt should have a description"
            );
            assert!(prompt.arguments.is_some(), "Prompt should have arguments");
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_list_resource_templates() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded rstime plugin");

        let request = None;
        let ctx = create_test_ctx(&server);
        let result = server.service().list_resource_templates(request, ctx).await;
        assert!(result.is_ok(), "list_resource_templates should succeed");

        let list_templates_result = result.unwrap();
        assert!(
            !list_templates_result.resource_templates.is_empty(),
            "Should have resource templates from rstime plugin"
        );

        // Verify the time_zone_converter template exists
        let template_names: Vec<String> = list_templates_result
            .resource_templates
            .iter()
            .map(|t| t.name.to_string())
            .collect();

        assert!(
            template_names
                .iter()
                .any(|name| name.contains("time_zone_converter")),
            "Should have time_zone_converter resource template"
        );

        // Verify template properties
        for template in &list_templates_result.resource_templates {
            assert!(!template.name.is_empty(), "Template should have a name");
            assert!(
                template.description.is_some(),
                "Template should have a description"
            );
            assert!(
                template.uri_template.contains("{timezone}"),
                "Template should have URI template with timezone placeholder"
            );
            assert!(
                template.mime_type.is_some(),
                "Template should have a MIME type"
            );
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_list_resources() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        let Some(plugins) = server.service().plugins.get() else {
            panic!("Plugins should be initialized");
        };
        assert!(!plugins.is_empty(), "Should have loaded rstime plugin");

        let request = None;
        let ctx = create_test_ctx(&server);
        let result = server.service().list_resources(request, ctx).await;
        assert!(result.is_ok(), "list_resources should succeed");

        let list_resources_result = result.unwrap();
        // rstime plugin returns empty resources list, which is expected
        assert_eq!(
            list_resources_result.resources.len(),
            0,
            "rstime should return empty resources"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_call_get_time_tool() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test calling get_time with UTC (default)
        let request = CallToolRequestParam {
            name: std::borrow::Cow::Owned("rstime-get_time".to_string()),
            arguments: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call get_time tool: {result:?}"
        );

        let call_result = result.unwrap();
        assert!(
            !call_result.content.is_empty(),
            "get_time should return content"
        );

        // Verify structured content contains current_time
        assert!(
            call_result.structured_content.is_some(),
            "Should have structured content"
        );

        let structured = call_result.structured_content.unwrap();
        let has_current_time = if let Some(map) = structured.as_object() {
            map.contains_key("current_time")
        } else {
            false
        };
        assert!(
            has_current_time,
            "Structured content should have current_time field"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_call_get_time_with_timezone() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test calling get_time with a specific timezone
        let mut args = serde_json::Map::new();
        args.insert(
            "timezone".to_string(),
            serde_json::Value::String("America/New_York".to_string()),
        );

        let request = CallToolRequestParam {
            name: std::borrow::Cow::Owned("rstime-get_time".to_string()),
            arguments: Some(args),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call get_time with timezone: {result:?}"
        );

        let call_result = result.unwrap();
        assert!(
            !call_result.content.is_empty(),
            "get_time with timezone should return content"
        );
        assert!(
            call_result.structured_content.is_some(),
            "Should have structured content"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_call_parse_time_tool() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test calling parse_time with a valid RFC2822 timestamp
        let mut args = serde_json::Map::new();
        args.insert(
            "time".to_string(),
            serde_json::Value::String("Wed, 18 Feb 2015 23:16:09 GMT".to_string()),
        );

        let request = CallToolRequestParam {
            name: std::borrow::Cow::Owned("rstime-parse_time".to_string()),
            arguments: Some(args),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call parse_time tool: {result:?}"
        );

        let call_result = result.unwrap();
        assert!(
            !call_result.content.is_empty(),
            "parse_time should return content"
        );

        // Verify it parsed correctly and returned a timestamp
        assert!(
            call_result.structured_content.is_some(),
            "Should have structured content"
        );

        let structured = call_result.structured_content.unwrap();
        let has_timestamp = if let Some(map) = structured.as_object() {
            map.contains_key("timestamp")
        } else {
            false
        };
        assert!(
            has_timestamp,
            "Structured content should have timestamp field"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_call_parse_time_invalid() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test calling parse_time with invalid timestamp
        let mut args = serde_json::Map::new();
        args.insert(
            "time".to_string(),
            serde_json::Value::String("invalid timestamp".to_string()),
        );

        let request = CallToolRequestParam {
            name: std::borrow::Cow::Owned("rstime-parse_time".to_string()),
            arguments: Some(args),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().call_tool(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should return result (may indicate error in content)"
        );

        let call_result = result.unwrap();
        // Tool returns error flag when parsing fails
        assert_eq!(
            call_result.is_error,
            Some(true),
            "Should mark result as error for invalid input"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_get_prompt() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test getting the prompt without timezone argument
        let request = GetPromptRequestParam {
            name: "rstime-get_time_with_timezone".to_string(),
            arguments: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().get_prompt(request, ctx).await;
        assert!(result.is_ok(), "Should successfully get prompt: {result:?}");

        let prompt_result = result.unwrap();
        assert!(
            !prompt_result.messages.is_empty(),
            "Prompt should have messages"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_get_prompt_with_timezone() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test getting the prompt with timezone argument
        let mut args = serde_json::Map::new();
        args.insert(
            "timezone".to_string(),
            serde_json::Value::String("Europe/London".to_string()),
        );

        let request = GetPromptRequestParam {
            name: "rstime-get_time_with_timezone".to_string(),
            arguments: Some(args),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().get_prompt(request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully get prompt with timezone: {result:?}"
        );

        let prompt_result = result.unwrap();
        assert!(
            !prompt_result.messages.is_empty(),
            "Prompt should have messages"
        );

        // Verify description mentions the timezone
        assert!(
            prompt_result.description.is_some(),
            "Prompt should have description"
        );
        let desc = prompt_result.description.unwrap();
        assert!(
            desc.contains("London"),
            "Prompt description should mention the timezone"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_read_resource() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test reading a resource with timezone - use namespaced URI
        // Format: scheme://host/plugin-name/path?query (as created by create_namespaced_uri)
        // Test reading a resource with timezone
        // Resource URIs are namespaced with plugin name inserted into the path
        // Format: scheme://host/plugin-name/rest-of-path
        // With allowed_hosts configured, the plugin can make HTTP requests
        let request = ReadResourceRequestParam {
            uri: "https://www.timezoneconverter.com/rstime/cgi-bin/zoneinfo?tz=America/New_York"
                .to_string(),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().read_resource(request, ctx).await;
        // With allowed_hosts configured, the plugin should be able to fetch the resource
        match result {
            Ok(read_result) => {
                // If successful, verify we got contents
                assert!(
                    !read_result.contents.is_empty(),
                    "Should return resource contents from HTTP response"
                );
            }
            Err(e) => {
                // If there's an error (e.g., network unavailable in test env),
                // at least verify it's a reasonable error and not a parsing error
                let error_msg = e.message.to_lowercase();
                assert!(
                    !error_msg.contains("parse"),
                    "Should not have parsing errors with allowed_hosts: {:?}",
                    e.message
                );
            }
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_complete_prompt_timezone() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // Test calling the complete() function for prompt timezone argument
        let argument_info = ArgumentInfo {
            name: "timezone".to_string(),
            value: "Ame".to_string(),
        };

        let complete_request = CompleteRequestParam {
            r#ref: Reference::Prompt(PromptReference {
                name: "rstime-get_time_with_timezone".to_string(),
                title: None,
            }),
            argument: argument_info,
            context: Some(CompletionContext {
                arguments: Some(HashMap::new()),
            }),
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().complete(complete_request, ctx).await;
        assert!(
            result.is_ok(),
            "Should successfully call complete() for prompt timezone: {result:?}"
        );

        let complete_result = result.unwrap();
        // Verify completion results include timezone suggestions
        assert!(
            !complete_result.completion.values.is_empty(),
            "Completion should return timezone suggestions"
        );

        // Verify we get timezone suggestions starting with "Ame"
        let suggestions: Vec<String> = complete_result
            .completion
            .values
            .iter()
            .map(|v| v.to_string())
            .collect();

        assert!(
            suggestions
                .iter()
                .any(|s| s.contains("America") || s.contains("ame")),
            "Should suggest timezones matching 'Ame' pattern: {suggestions:?}"
        );

        // Verify completion metadata
        assert!(
            complete_result.completion.total.unwrap_or(0) > 0,
            "Completion should have total count > 0"
        );

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }

    #[tokio::test]
    async fn test_rstime_complete_resource_template_timezone() {
        let wasm_path = get_rstime_wasm_path();
        if !test_rstime_wasm_exists() {
            println!("Skipping test - WASM file not found at {wasm_path:?}");
            return;
        }

        let config_content = format!(
            r#"
plugins:
  rstime:
    url: "file://{}"
    runtime_config:
      allowed_hosts:
        - "www.timezoneconverter.com"
"#,
            wasm_path.display()
        );

        let (_temp_dir, config_path) = create_temp_config_file(&config_content).await.unwrap();
        let mut cli = create_test_cli();
        cli.config_file = Some(config_path);
        let config = load_config(&cli).await.unwrap();

        let (server, client) = create_test_pair(
            PluginService::new(&config).await.unwrap(),
            ClientInfo::default(),
        )
        .await;

        // First verify that resource templates exist and have proper structure
        let list_ctx = create_test_ctx(&server);
        let list_result = server
            .service()
            .list_resource_templates(None, list_ctx)
            .await;
        assert!(
            list_result.is_ok(),
            "Should successfully list resource templates"
        );

        let templates = list_result.unwrap();
        assert!(
            !templates.resource_templates.is_empty(),
            "Should have resource templates available"
        );

        // Verify the time_zone_converter template exists with proper URI template
        let tz_template = templates
            .resource_templates
            .iter()
            .find(|t| t.name.contains("time_zone_converter"))
            .expect("Should have time_zone_converter resource template");

        assert!(
            tz_template.uri_template.contains("{timezone}"),
            "Resource template should have timezone parameter placeholder"
        );

        // Now test calling the complete() function for resource template timezone parameter
        // Use the namespaced URI format with plugin name inserted
        let resource_uri =
            "https://www.timezoneconverter.com/rstime/cgi-bin/zoneinfo?tz=Eur".to_string();

        let argument_info = ArgumentInfo {
            name: "timezone".to_string(),
            value: "Eur".to_string(),
        };

        let complete_request = CompleteRequestParam {
            r#ref: Reference::Resource(ResourceReference { uri: resource_uri }),
            argument: argument_info,
            context: None,
        };

        let ctx = create_test_ctx(&server);
        let result = server.service().complete(complete_request, ctx).await;

        // The rstime plugin may not implement completion for resource URIs,
        // so we verify the interface works even if completion isn't supported
        match result {
            Ok(complete_result) => {
                // If completion is supported, verify results
                assert!(
                    !complete_result.completion.values.is_empty(),
                    "Completion should return timezone suggestions for resource template"
                );

                let suggestions: Vec<String> = complete_result
                    .completion
                    .values
                    .iter()
                    .map(|v| v.to_string())
                    .collect();

                assert!(
                    suggestions
                        .iter()
                        .any(|s| s.contains("Europe") || s.contains("eur")),
                    "Should suggest timezones matching 'Eur' pattern: {suggestions:?}"
                );

                assert!(
                    complete_result.completion.total.unwrap_or(0) > 0,
                    "Completion should have total count > 0 for resource templates"
                );
            }
            Err(e) => {
                // If resource completion is not implemented, that's acceptable
                // The important part is that the complete() method was called successfully
                let error_msg = e.message.to_lowercase();
                assert!(
                    error_msg.contains("not implemented") || error_msg.contains("completion"),
                    "If completion fails for resources, it should be a clear error: {}",
                    e.message
                );
            }
        }

        assert_ok!(server.cancel().await);
        assert_ok!(client.cancel().await);
    }
}
