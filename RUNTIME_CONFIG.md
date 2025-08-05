# Runtime Configuration

## Structure

The configuration is structured as follows:

- **plugins**: An array of plugin configuration objects.
  - **name** (`string`): Name of the plugin.
  - **path** (`string`): OCI path or HTTP URL or local path for the plugin.
  - **runtime_config** (`object`, optional): Plugin-specific runtime configuration. The available fields are:
    - **skip_tools** (`array[string]`, optional): List of tool names to skip loading at runtime.
    - **allowed_hosts** (`array[string]`, optional): List of allowed hosts for the plugin (e.g., `["1.1.1.1"]` or `["*"]`).
    - **allowed_paths** (`array[string]`, optional): List of allowed file system paths.
    - **env_vars** (`object`, optional): Key-value pairs of environment variables for the plugin.
    - **memory_limit** (`string`, optional): Memory limit for the plugin (e.g., `"512Mi"`).

## Example (YAML)

```yaml
plugins:
  - time:
    path: oci://ghcr.io/tuananh/time-plugin:latest
  - myip:
    path: oci://ghcr.io/tuananh/myip-plugin:latest
    runtime_config:
      allowed_hosts:
        - "1.1.1.1"
      skip_tools:
        - "debug"
      env_vars:
        FOO: "bar"
      memory_limit: "512Mi"
```

## Example (JSON)

```json
{
  "plugins": {
    "time": {
      "path": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "myip": {
      "path": "oci://ghcr.io/tuananh/myip-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["1.1.1.1"],
        "skip_tools": ["debug"],
        "env_vars": {"FOO": "bar"},
        "memory_limit": "512Mi",
      }
    }
  }
}
```

## Loading Configuration

Configuration is loaded at runtime from a file with `.json`, `.yaml`, `.yml`, or `.toml` extension. The loader will parse the file according to its extension. If the file does not exist or the format is unsupported, an error will be raised.

## Notes

- Fields marked as `optional` can be omitted.
- Plugin authors may extend `runtime_config` with additional fields, but only the above are officially recognized.
