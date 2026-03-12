# Built-in Tools

hyper-mcp exposes a set of built-in tools under the `hyper_mcp` namespace. These tools are managed by hyper-mcp itself and are not provided by any plugin.

## `hyper_mcp-list_plugins`

Lists all plugins currently loaded in the MCP session.

**Always available** — this tool is registered regardless of configuration.

### Arguments

This tool takes no arguments.

### Response

Returns a JSON object with a `plugins` array. Each entry contains:

| Field         | Type              | Description                                          |
|---------------|-------------------|------------------------------------------------------|
| `name`        | `string`          | The registered name of the plugin.                   |
| `url`         | `string`          | The URL the plugin was loaded from.                  |
| `description` | `string` or null  | The human-readable description from the plugin config, if provided. |

#### Example response

```json
{
  "plugins": [
    {
      "name": "time",
      "url": "oci://ghcr.io/hyper-mcp-rs/time-plugin:latest",
      "description": "Get current time and do time calculations"
    },
    {
      "name": "fetch",
      "url": "oci://ghcr.io/hyper-mcp-rs/fetch-plugin:latest"
    }
  ]
}
```

---

## `hyper_mcp-load_plugin`

Dynamically loads a new plugin into the current MCP session.

**Requires `dynamic_loading` to be enabled.** If dynamic loading is disabled the tool will return an error.

### Arguments

| Field    | Type           | Required | Description                                                                                      |
|----------|----------------|----------|--------------------------------------------------------------------------------------------------|
| `name`   | `string`       | Yes      | The name to register the plugin under. Letters, numbers, and underscores only.                   |
| `config` | `PluginConfig` | Yes      | The plugin configuration object (see [Plugin Configuration](#plugin-configuration) below).       |

#### Example call

```json
{
  "name": "my_plugin",
  "config": {
    "url": "oci://ghcr.io/example/my-plugin:latest",
    "description": "An example plugin loaded at runtime",
    "runtime_config": {
      "allowed_hosts": ["api.example.com"],
      "memory_limit": "256Mi"
    }
  }
}
```

### Behavior

1. If a plugin with the given name already exists, the tool returns an error advising you to unload it first.
2. The plugin binary is fetched from the URL (supporting `oci://`, `file://`, `http://`, `https://`, and `s3://` schemes).
3. A sandboxed WebAssembly instance is created with the provided `runtime_config`.
4. On success the MCP client is notified that the tool, prompt, and resource lists have changed.

---

## `hyper_mcp-unload_plugin`

Dynamically unloads an existing plugin from the current MCP session.

**Requires `dynamic_loading` to be enabled.** If dynamic loading is disabled the tool will return an error.

### Arguments

| Field  | Type     | Required | Description                          |
|--------|----------|----------|--------------------------------------|
| `name` | `string` | Yes      | The name of the plugin to unload.    |

#### Example call

```json
{
  "name": "my_plugin"
}
```

### Behavior

1. The plugin is removed from both the active plugin set and the running configuration.
2. If no plugin with the given name exists the call is a no-op (no error is returned).
3. On completion the MCP client is notified that the tool, prompt, and resource lists have changed.

---

## Plugin Configuration

The `config` object accepted by `hyper_mcp-load_plugin` has the following shape:

| Field            | Type              | Required | Description                                                                 |
|------------------|-------------------|----------|-----------------------------------------------------------------------------|
| `url`            | `string` (URI)    | Yes      | The URL or path of the plugin (`oci://`, `file://`, `http://`, `https://`, or `s3://`). |
| `description`    | `string`          | No       | A human-readable description of what the plugin does.                       |
| `runtime_config` | `RuntimeConfig`   | No       | Plugin-specific runtime configuration. See [RUNTIME_CONFIG.md](./RUNTIME_CONFIG.md) for all available options. |

---

## Enabling Dynamic Loading

The `hyper_mcp-load_plugin` and `hyper_mcp-unload_plugin` tools are only registered when dynamic loading is enabled. It can be turned on or off in three ways (listed by precedence, highest first):

1. **CLI flag:** `--dynamic-loading true`
2. **Environment variable:** `HYPER_MCP_DYNAMIC_LOADING=true`
3. **Config file:**

```json
{
  "dynamic_loading": true,
  "plugins": {}
}
```

> **Security note:** Dynamic loading is disabled by default. When enabled, any connected MCP client can load arbitrary plugins or unload existing ones. Only enable it in trusted environments. See [RUNTIME_CONFIG.md — Security Considerations](./RUNTIME_CONFIG.md#security-considerations) for more details.

## Tool Name Prefix

All built-in tool names are prefixed with `hyper_mcp-` to avoid collisions with plugin-provided tools. The name `hyper_mcp` is reserved and cannot be used as a plugin name.
