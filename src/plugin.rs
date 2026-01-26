use crate::naming::PluginName;
use async_trait::async_trait;
use rmcp::{
    ErrorData as McpError,
    model::*,
    service::{NotificationContext, RequestContext, RoleServer},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fmt::Debug,
    ops::Deref,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

type PluginHandle = Arc<Mutex<extism::Plugin>>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PluginRequestContext {
    pub id: NumberOrString,
    #[serde(rename = "_meta")]
    pub meta: Meta,
}

impl<'a> From<&'a RequestContext<RoleServer>> for PluginRequestContext {
    fn from(context: &'a RequestContext<RoleServer>) -> Self {
        PluginRequestContext {
            id: context.id.clone(),
            meta: context.meta.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PluginNotificationContext {
    #[serde(rename = "_meta")]
    pub meta: Meta,
}

impl<'a> From<&'a NotificationContext<RoleServer>> for PluginNotificationContext {
    fn from(context: &'a NotificationContext<RoleServer>) -> Self {
        PluginNotificationContext {
            meta: context.meta.clone(),
        }
    }
}

#[async_trait]
#[allow(unused_variables)]
pub trait Plugin: Send + Sync + Debug {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError>;

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        Ok(CompleteResult::default())
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        Err(McpError::method_not_found::<GetPromptRequestMethod>())
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult::default())
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::default())
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult::default())
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError>;

    fn name(&self) -> &PluginName;

    async fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), McpError> {
        Ok(())
    }

    fn plugin(&self) -> &PluginHandle;

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        Err(McpError::method_not_found::<ReadResourceRequestMethod>())
    }
}

async fn call_plugin<R>(
    plugin: &dyn Plugin,
    name: &str,
    payload: String,
    ct: CancellationToken,
) -> Result<R, McpError>
where
    R: DeserializeOwned + Send + 'static,
{
    let plugin_name = plugin.name().to_string();
    if !function_exists_plugin(plugin, name) {
        return Err(McpError::invalid_request(
            format!("Method {name} not found for plugin {plugin_name}"),
            None,
        ));
    }
    let plugin = Arc::clone(plugin.plugin());
    let cancel_handle = {
        let guard = plugin.lock().unwrap();
        guard.cancel_handle()
    };

    let name = name.to_string();
    let mut join = tokio::task::spawn_blocking(move || {
        let mut plugin = plugin.lock().unwrap();
        let result: Result<String, extism::Error> = plugin.call(&name, payload);
        match result {
            Ok(res) => match serde_json::from_str::<R>(&res) {
                Ok(parsed) => Ok(parsed),
                Err(e) => Err(McpError::internal_error(
                    format!("Failed to deserialize data: {e}"),
                    None,
                )),
            },
            Err(e) => Err(McpError::internal_error(
                format!("Failed to call plugin: {e}"),
                None,
            )),
        }
    });

    tokio::select! {
        // Finished normally
        res = &mut join => {
            match res {
                Ok(Ok(result)) => Ok(result),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(McpError::internal_error(
                    format!("Failed to spawn blocking task for plugin {plugin_name}: {e}"),
                    None,
                )),
            }
        }

        //Cancellation requested
        _ = ct.cancelled() => {
            if let Err(e) = cancel_handle.cancel() {
                tracing::error!("Failed to cancel plugin {plugin_name}: {e}");
                return Err(McpError::internal_error(
                    format!("Failed to cancel plugin {plugin_name}: {e}"),
                    None,
                ));
            }
            match tokio::time::timeout(std::time::Duration::from_millis(250), join).await {
                Ok(Ok(Ok(_))) => Err(McpError::internal_error(
                    format!("Plugin {plugin_name} was cancelled"),
                    None,
                )),
                Ok(Ok(Err(e))) => Err(McpError::internal_error(
                    format!("Failed to execute plugin {plugin_name}: {e}"),
                    None,
                )),
                Ok(Err(e)) => Err(McpError::internal_error(
                    format!("Join error for plugin {plugin_name}: {e}"),
                    None,
                )),
                Err(_) => Err(McpError::internal_error(
                    format!("Timeout waiting for plugin {plugin_name} to cancel"),
                    None,
                )),
            }
        }
    }
}

fn function_exists_plugin(plugin: &dyn Plugin, name: &str) -> bool {
    let plugin = Arc::clone(plugin.plugin());
    plugin.lock().unwrap().function_exists(name)
}

async fn notify_plugin(plugin: &dyn Plugin, name: &str, payload: String) -> Result<(), McpError> {
    let plugin_name = plugin.name().to_string();
    if !function_exists_plugin(plugin, name) {
        return Err(McpError::invalid_request(
            format!("Method {name} not found for plugin {plugin_name}"),
            None,
        ));
    }
    let plugin = Arc::clone(plugin.plugin());
    let name = name.to_string();
    tokio::task::spawn_blocking(move || {
        let mut plugin = plugin.lock().unwrap();
        let result: Result<String, extism::Error> = plugin.call(&name, payload);
        if let Err(e) = result {
            tracing::error!("Failed to notify plugin {plugin_name}: {e}");
        }
    });
    Ok(())
}

#[derive(Debug)]
pub struct PluginBase {
    pub name: PluginName,
    pub plugin: PluginHandle,
}

#[derive(Debug)]
pub struct PluginV1(pub PluginBase);

impl Deref for PluginV1 {
    type Target = PluginBase;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl Plugin for PluginV1 {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        call_plugin::<CallToolResult>(
            self,
            "call",
            serde_json::to_string(&json!({
                "params": request,
            }))
            .expect("Failed to serialize request"),
            context.ct,
        )
        .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        call_plugin::<ListToolsResult>(self, "describe", "".to_string(), context.ct).await
    }

    fn name(&self) -> &PluginName {
        &self.name
    }

    fn plugin(&self) -> &PluginHandle {
        &self.plugin
    }
}

impl PluginV1 {
    pub fn new(name: PluginName, plugin: PluginHandle) -> Self {
        Self(PluginBase { name, plugin })
    }
}

#[derive(Debug)]
pub struct PluginV2(pub PluginBase);

impl Deref for PluginV2 {
    type Target = PluginBase;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl Plugin for PluginV2 {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        call_plugin::<CallToolResult>(
            self,
            "call_tool",
            serde_json::to_string(&json!({
                "request": request,
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize request"),
            context.ct,
        )
        .await
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        #[derive(Debug, Clone)]
        struct Helper(CompleteRequestParams);

        impl Serialize for Helper {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut value = serde_json::to_value(&self.0).map_err(serde::ser::Error::custom)?;

                if let Value::Object(root) = &mut value
                    && let Some(Value::Object(ref_obj)) = root.get_mut("ref")
                    && let Some(Value::String(t)) = ref_obj.get_mut("type")
                    && let Some(stripped) = t.strip_prefix("ref/")
                {
                    *t = stripped.to_string();
                }

                value.serialize(serializer)
            }
        }

        call_plugin::<CompleteResult>(
            self,
            "complete",
            serde_json::to_string(&json!({
                "request": Helper(request),
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize request"),
            context.ct,
        )
        .await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        call_plugin::<GetPromptResult>(
            self,
            "get_prompt",
            serde_json::to_string(&json!({
                "request": request,
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize request"),
            context.ct,
        )
        .await
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        if !function_exists_plugin(self, "list_prompts") {
            return Ok(ListPromptsResult::default());
        }
        call_plugin::<ListPromptsResult>(
            self,
            "list_prompts",
            serde_json::to_string(&json!({
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize context"),
            context.ct,
        )
        .await
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        if !function_exists_plugin(self, "list_resources") {
            return Ok(ListResourcesResult::default());
        }
        call_plugin::<ListResourcesResult>(
            self,
            "list_resources",
            serde_json::to_string(&json!({
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize context"),
            context.ct,
        )
        .await
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        if !function_exists_plugin(self, "list_resource_templates") {
            return Ok(ListResourceTemplatesResult::default());
        }
        call_plugin::<ListResourceTemplatesResult>(
            self,
            "list_resource_templates",
            serde_json::to_string(&json!({
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize context"),
            context.ct,
        )
        .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        if !function_exists_plugin(self, "list_tools") {
            return Ok(ListToolsResult::default());
        }
        call_plugin::<ListToolsResult>(
            self,
            "list_tools",
            serde_json::to_string(&json!({
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize context"),
            context.ct,
        )
        .await
    }

    fn name(&self) -> &PluginName {
        &self.name
    }

    async fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), McpError> {
        if function_exists_plugin(self, "on_roots_list_changed") {
            return Ok(());
        }
        notify_plugin(
            self,
            "on_roots_list_changed",
            serde_json::to_string(&json!({
                "context": PluginNotificationContext::from(&context),
            }))
            .expect("Failed to serialize context"),
        )
        .await
    }

    fn plugin(&self) -> &PluginHandle {
        &self.plugin
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        call_plugin::<ReadResourceResult>(
            self,
            "read_resource",
            serde_json::to_string(&json!({
                "request": request,
                "context": PluginRequestContext::from(&context),
            }))
            .expect("Failed to serialize request"),
            context.ct,
        )
        .await
    }
}

impl PluginV2 {
    pub fn new(name: PluginName, plugin: PluginHandle) -> Self {
        Self(PluginBase { name, plugin })
    }
}
