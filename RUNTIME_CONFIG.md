# Runtime Configuration

## Structure

The configuration is structured as follows:

- **disable_completions** (`boolean`, optional, default: `false`): When set to `true`, disables the completions capability in the MCP server. This means the server will not provide completion suggestions to clients.
- **disable_logging** (`boolean`, optional, default: `false`): When set to `true`, disables the logging capability in the MCP server. This prevents the server from accepting and processing log messages from clients.
- **auths** (`object`, optional): Authentication configurations for HTTPS requests, keyed by URL.
- **plugins**: A map of plugin names to  plugin configuration objects.
  - **path** (`string`): OCI path or HTTP URL or local path for the plugin.
  - **runtime_config** (`object`, optional): Plugin-specific runtime configuration. The available fields are:
    - **skip_tools** (`array[string]`, optional): List of regex patterns for tool names to skip loading at runtime. Each pattern is automatically anchored to match the entire tool name (equivalent to wrapping with `^` and `$`). Supports full regex syntax for powerful pattern matching.
    - **allowed_hosts** (`array[string]`, optional): List of allowed hosts for the plugin (e.g., `["1.1.1.1"]` or `["*"]`).
    - **allowed_paths** (`array[string]`, optional): List of allowed file system paths. Supports both simple paths and host-to-plugin path mapping. See [Allowed Paths Configuration](#allowed-paths-configuration) for detailed documentation.
    - **env_vars** (`object`, optional): Key-value pairs of environment variables for the plugin.
    - **memory_limit** (`string`, optional): Memory limit for the plugin (e.g., `"512Mi"`).

## Plugin Names

Plugin names must follow strict naming conventions to ensure consistency and avoid conflicts:

### Allowed Characters
- **Letters**: A-Z, a-z (case-sensitive)
- **Numbers**: 0-9
- **Underscores**: _ (as separators only)

### Naming Rules
- Must start with a letter or number (not underscore)
- Must end with a letter or number (not underscore)
- Cannot contain consecutive underscores
- Cannot contain hyphens or other special characters
- Cannot contain spaces or whitespace

### Valid Examples
```
✅ plugin
✅ myPlugin
✅ plugin_name
✅ plugin123
✅ my_awesome_plugin_v2
✅ Plugin_Name_123
```

### Invalid Examples
```
❌ plugin-name        (hyphens not allowed)
❌ plugin_            (cannot end with underscore)
❌ _plugin            (cannot start with underscore)
❌ plugin__name       (consecutive underscores)
❌ plugin name        (spaces not allowed)
❌ plugin@name        (special characters not allowed)
```

### Best Practices
- Use descriptive, meaningful names
- Follow consistent naming conventions within your organization
- Consider using prefixes for related plugins (e.g., `company_auth`, `company_logging`)
- Use underscores to separate logical components (e.g., `api_client`, `data_processor`)

## Server Capabilities

The top-level configuration includes flags to control which MCP server capabilities are enabled:

### disable_logging

When set to `true`, the MCP server will not advertise or provide the logging capability. This is useful if you want to:
- Disable log message output when 
    - not needed
    - the client cannot accept them or calls setLevel before initialization is complete (e.g. - VS Code/Copilot)
- Reduce server overhead by disabling unused features

**Default**: `false` (logging is enabled by default)

## Authentication Configuration

The `auths` field allows you to configure authentication for HTTPS requests made by plugins. Authentication is matched by URL prefix, with longer prefixes taking precedence.

### Supported Authentication Types

#### Basic Authentication
```yaml
auths:
  "https://api.example.com":
    type: basic
    username: "your-username"
    password: "your-password"
```

#### Bearer Token Authentication
```yaml
auths:
  "https://api.example.com":
    type: token
    token: "your-bearer-token"
```

#### Keyring Authentication
```yaml
auths:
  "https://private.registry.io":
    type: keyring
    service: "my-app"
    user: "registry-user"
```

### Keyring Setup Examples

For keyring authentication, you need to store the actual auth configuration JSON in your system keyring. This provides secure credential storage without exposing sensitive data in config files.

#### macOS (using Keychain Access or security command)

**Using the `security` command:**
```bash
# Store basic auth credentials
security add-generic-password -a "registry-user" -s "my-app" -w '{"type":"basic","username":"actual-user","password":"actual-pass"}'

# Store token auth credentials
security add-generic-password -a "api-user" -s "my-service" -w '{"type":"token","token":"actual-bearer-token"}'

# Verify the entry was created
security find-generic-password -a "registry-user" -s "my-app"
```

**Using Keychain Access GUI:**
1. Open Keychain Access (Applications → Utilities → Keychain Access)
2. Click "File" → "New Password Item"
3. Set "Keychain Item Name" to your service name (e.g., "my-app")
4. Set "Account Name" to your user name (e.g., "registry-user")
5. Set "Password" to the JSON auth config: `{"type":"basic","username":"actual-user","password":"actual-pass"}`
6. Click "Add"

#### Linux (using libsecret/gnome-keyring)

**Install required tools:**
```bash
# Ubuntu/Debian
sudo apt-get install libsecret-tools

# RHEL/CentOS/Fedora
sudo yum install libsecret-devel
```

**Using `secret-tool`:**
```bash
# Store basic auth credentials
echo '{"type":"basic","username":"actual-user","password":"actual-pass"}' | secret-tool store --label="my-app credentials" service "my-app" username "registry-user"

# Store token auth credentials
echo '{"type":"token","token":"actual-bearer-token"}' | secret-tool store --label="my-service token" service "my-service" username "api-user"

# Verify the entry was created
secret-tool lookup service "my-app" username "registry-user"
```

#### Windows (using Windows Credential Manager)

**Using `cmdkey` (Command Prompt as Administrator):**
```cmd
REM Store basic auth credentials (escape quotes for JSON)
cmdkey /generic:"my-app" /user:"registry-user" /pass:"{\"type\":\"basic\",\"username\":\"actual-user\",\"password\":\"actual-pass\"}"

REM Store token auth credentials
cmdkey /generic:"my-service" /user:"api-user" /pass:"{\"type\":\"token\",\"token\":\"actual-bearer-token\"}"

REM Verify the entry was created
cmdkey /list:"my-app"
```

**Using Credential Manager GUI:**
1. Open "Credential Manager" from Control Panel → User Accounts → Credential Manager
2. Click "Add a generic credential"
3. Set "Internet or network address" to your service name (e.g., "my-app")
4. Set "User name" to your user name (e.g., "registry-user")
5. Set "Password" to the JSON auth config: `{"type":"basic","username":"actual-user","password":"actual-pass"}`
6. Click "OK"

**Using PowerShell:**
```powershell
# Store basic auth credentials
$cred = New-Object System.Management.Automation.PSCredential("registry-user", (ConvertTo-SecureString '{"type":"basic","username":"actual-user","password":"actual-pass"}' -AsPlainText -Force))
New-StoredCredential -Target "my-app" -Credential $cred -Type Generic
```

### URL Matching Behavior

Authentication is applied based on URL prefix matching:
- Longer prefixes take precedence over shorter ones
- Exact matches take highest precedence
- URLs are matched case-sensitively

**Example:**
```yaml
auths:
  "https://example.com":
    type: basic
    username: "broad-user"
    password: "broad-pass"
  "https://example.com/api":
    type: token
    token: "api-token"
  "https://example.com/api/v1":
    type: basic
    username: "v1-user"
    password: "v1-pass"
```

- Request to `https://example.com/api/v1/users` → uses v1 basic auth (longest match)
- Request to `https://example.com/api/data` → uses api token auth
- Request to `https://example.com/public` → uses broad basic auth

### Keyring Authentication Example

**Configuration file:**
```yaml
auths:
  "https://private.registry.io":
    type: keyring
    service: "private-registry"
    user: "registry-user"
  "https://internal.company.com":
    type: keyring
    service: "company-api"
    user: "api-user"

plugins:
  secure-plugin:
    url: "https://private.registry.io/secure-plugin"
    runtime_config:
      allowed_hosts:
        - "private.registry.io"
```

**Corresponding keyring entries (stored separately):**
- Service: `private-registry`, User: `registry-user`, Password: `{"type":"basic","username":"real-user","password":"real-pass"}`
- Service: `company-api`, User: `api-user`, Password: `{"type":"token","token":"company-jwt-token"}`

### Real-World Keyring Scenarios

#### Scenario 1: Corporate Environment
```yaml
auths:
  "https://artifactory.company.com":
    type: keyring
    service: "company-artifactory"
    user: "build-service"
  "https://nexus.company.com":
    type: keyring
    service: "company-nexus"
    user: "deployment-bot"
```

Setup corporate credentials once:
```bash
# macOS
security add-generic-password -a "build-service" -s "company-artifactory" -w '{"type":"basic","username":"corp_user","password":"corp_secret"}'

# Linux
echo '{"type":"basic","username":"corp_user","password":"corp_secret"}' | secret-tool store --label="Company Artifactory" service "company-artifactory" username "build-service"

# Windows
cmdkey /generic:"company-artifactory" /user:"build-service" /pass:"{\"type\":\"basic\",\"username\":\"corp_user\",\"password\":\"corp_secret\"}"
```

#### Scenario 2: Multi-Environment Setup
```yaml
auths:
  "https://staging-api.example.com":
    type: keyring
    service: "example-staging"
    user: "staging-user"
  "https://prod-api.example.com":
    type: keyring
    service: "example-prod"
    user: "prod-user"
```

Store different credentials for each environment:
```bash
# Staging credentials
security add-generic-password -a "staging-user" -s "example-staging" -w '{"type":"token","token":"staging-jwt-token"}'

# Production credentials
security add-generic-password -a "prod-user" -s "example-prod" -w '{"type":"token","token":"prod-jwt-token"}'
```

#### Scenario 3: Team Shared Configuration
```yaml
# Team members can share this config file safely
auths:
  "https://shared-registry.team.com":
    type: keyring
    service: "team-registry"
    user: "developer"
```

Each team member stores their own credentials:
```bash
# Developer A
security add-generic-password -a "developer" -s "team-registry" -w '{"type":"basic","username":"alice","password":"alice_key"}'

# Developer B
security add-generic-password -a "developer" -s "team-registry" -w '{"type":"basic","username":"bob","password":"bob_key"}'
```

### Keyring Best Practices

1. **Service Naming Convention**: Use descriptive, consistent service names (e.g., `company-artifactory`, `project-registry`)
2. **User Identification**: Use role-based usernames (e.g., `build-service`, `deployment-bot`) rather than personal names
3. **Credential Rotation**: Update keyring entries when rotating credentials - no config file changes needed
4. **Environment Separation**: Use different service names for different environments
5. **Team Coordination**: Document your service/user naming conventions for team members
6. **Backup Strategy**: Consider backing up keyring entries for critical services
7. **Testing**: Use non-production credentials in keyring for testing

## Example (YAML)

```yaml
# Optional: Disable specific server capabilities
disable_logging: false       # Set to true to disable logging capability

auths:
  "https://private.registry.io":
    type: basic
    username: "registry-user"
    password: "registry-pass"
  "https://api.github.com":
    type: token
    token: "ghp_1234567890abcdef"
  "https://enterprise.api.com":
    type: basic
    username: "enterprise-user"
    password: "enterprise-pass"

plugins:
  time:
    url: oci://ghcr.io/tuananh/time-plugin:latest
  myip:
    url: oci://ghcr.io/tuananh/myip-plugin:latest
    runtime_config:
      allowed_hosts:
        - "1.1.1.1"
      allowed_paths:
        - "/tmp"                      # Single path (same for host and plugin)
        - "/var/log:/plugin/logs"     # Mapped path (host:plugin)
        - "/home/user/data"           # Another single path
      skip_tools:
        - "debug_tool"           # Skip exact tool name
        - "temp_.*"              # Skip tools starting with "temp_"
        - ".*_backup"            # Skip tools ending with "_backup"
        - "test_[0-9]+"          # Skip tools like "test_1", "test_42"
      env_vars:
        FOO: "bar"
      memory_limit: "512Mi"
  private_plugin:
    url: "https://private.registry.io/my-plugin"
    runtime_config:
      allowed_hosts:
        - "private.registry.io"
```

## Example (JSON)

```json
{
  "disable_logging": false,
  "auths": {
    "https://private.registry.io": {
      "type": "basic",
      "username": "registry-user",
      "password": "registry-pass"
    },
    "https://api.github.com": {
      "type": "token",
      "token": "ghp_1234567890abcdef"
    },
    "https://enterprise.api.com": {
      "type": "basic",
      "username": "enterprise-user",
      "password": "enterprise-pass"
    }
  },
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "myip": {
      "url": "oci://ghcr.io/tuananh/myip-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["1.1.1.1"],
        "allowed_paths": [
          "/tmp",
          "/var/log:/plugin/logs",
          "/home/user/data"
        ],
        "skip_tools": [
          "debug_tool",
          "temp_.*",
          ".*_backup",
          "test_[0-9]+"
        ],
        "env_vars": {"FOO": "bar"},
        "memory_limit": "512Mi"
      }
    },
    "private_plugin": {
      "url": "https://private.registry.io/my-plugin",
      "runtime_config": {
        "allowed_hosts": ["private.registry.io"]
      }
    }
  }
}
```

## Loading Configuration

Configuration is loaded at runtime from a file with `.json`, `.yaml`, `.yml`, or `.toml` extension. The loader will parse the file according to its extension. If the file does not exist or the format is unsupported, an error will be raised.

## Security Considerations

### Credential Storage
- **Basic/Token auth**: Credentials are stored directly in the config file. Ensure proper file permissions (e.g., `chmod 600`).
- **Keyring auth**: Credentials are stored securely in the system keyring. The config file only contains service/user identifiers.

### Best Practices
- Use keyring authentication for production environments
- Rotate credentials regularly
- Use environment-specific config files
- Never commit credentials to version control
- Consider using short-lived tokens when possible

## Troubleshooting Keyring Authentication

### Common Issues

#### "No matching entry found in secure storage"
This error occurs when the keyring entry doesn't exist or can't be accessed.

**Solutions:**
1. Verify the service and user names match exactly between config and keyring
2. Check that the keyring entry exists:
   ```bash
   # macOS
   security find-generic-password -a "your-user" -s "your-service"

   # Linux
   secret-tool lookup service "your-service" username "your-user"

   # Windows
   cmdkey /list:"your-service"
   ```
3. Ensure the current user has permission to access the keyring entry

#### "Failed to parse JSON from keyring"
This error occurs when the stored password isn't valid JSON or doesn't match the expected AuthConfig format.

**Solutions:**
1. Verify the stored password is valid JSON:
   ```bash
   # macOS - retrieve and validate
   security find-generic-password -a "your-user" -s "your-service" -w | jq .
   ```
2. Ensure the JSON matches one of these formats:
   - `{"type":"basic","username":"real-user","password":"real-pass"}`
   - `{"type":"token","token":"real-token"}`

#### Platform-Specific Issues

**macOS:**
- Keychain may be locked - unlock it manually or use `security unlock-keychain`
- Application may not have keychain access permissions

**Linux:**
- GNOME Keyring service may not be running: `systemctl --user status gnome-keyring`
- D-Bus session may not be available in non-graphical environments

**Windows:**
- Credential Manager may require administrator privileges for certain operations
- Windows Credential Manager has size limits for stored passwords

### Debugging Tips

1. **Test keyring access independently:**
   ```bash
   # Create a test entry
   security add-generic-password -a "test-user" -s "test-service" -w '{"type":"token","token":"test"}'

   # Retrieve it
   security find-generic-password -a "test-user" -s "test-service" -w

   # Clean up
   security delete-generic-password -a "test-user" -s "test-service"
   ```

2. **Validate JSON format:**
   ```bash
   echo '{"type":"basic","username":"user","password":"pass"}' | jq .
   ```

3. **Check permissions:**
   ```bash
   # Ensure config file is readable
   ls -la config.yaml

   # Set appropriate permissions
   chmod 600 config.yaml
   ```

## Skip Tools Pattern Matching

The `skip_tools` field supports powerful regex pattern matching for filtering out unwanted tools at runtime.

> 📖 **For comprehensive examples, advanced patterns, and detailed use cases, see [SKIP_TOOLS_GUIDE.md](./SKIP_TOOLS_GUIDE.md)**

### Pattern Behavior
- **Automatic Anchoring**: Patterns are automatically anchored to match the entire tool name (wrapped with `^` and `$`)
- **Regex Support**: Full regex syntax is supported, including wildcards, character classes, and quantifiers
- **Case Sensitive**: Pattern matching is case-sensitive
- **Compilation**: All patterns are compiled into a single optimized regex set for efficient matching

### Pattern Examples

#### Exact Matches
```yaml
skip_tools:
  - "debug_tool"      # Matches only "debug_tool"
  - "test_runner"     # Matches only "test_runner"
```

#### Wildcard Patterns
```yaml
skip_tools:
  - "temp_.*"         # Matches "temp_file", "temp_data", etc.
  - ".*_backup"       # Matches "data_backup", "file_backup", etc.
  - "debug.*"         # Matches "debug", "debugger", "debug_info", etc.
```

#### Advanced Regex Patterns
```yaml
skip_tools:
  - "tool_[0-9]+"                    # Matches "tool_1", "tool_42", etc.
  - "test_(unit|integration)"        # Matches "test_unit" and "test_integration"
  - "[a-z]+_helper"                  # Matches lowercase word + "_helper"
  - "system_(admin|user)_.*"         # Matches tools starting with "system_admin_" or "system_user_"
```

#### Explicit Anchoring
```yaml
skip_tools:
  - "^prefix_.*"      # Explicit start anchor (same as "prefix_.*" due to auto-anchoring)
  - ".*_suffix$"      # Explicit end anchor (same as ".*_suffix" due to auto-anchoring)
  - "^exact_only$"    # Fully explicit anchoring (same as "exact_only")
```

#### Special Characters
```yaml
skip_tools:
  - "file\\.exe"      # Matches "file.exe" literally (escaped dot)
  - "script\\?"       # Matches "script?" literally (escaped question mark)
  - "temp\\*data"     # Matches "temp*data" literally (escaped asterisk)
```

#### Common Use Cases
```yaml
skip_tools:
  - ".*_test"         # Skip all test tools
  - "dev_.*"          # Skip all development tools
  - "mock_.*"         # Skip all mock tools
  - ".*_deprecated"   # Skip all deprecated tools
  - "admin_.*"        # Skip all admin tools
  - "debug.*"         # Skip all debug-related tools
```

### Error Handling
- Invalid regex patterns will cause configuration loading to fail with a descriptive error
- Empty pattern arrays are allowed and will skip no tools
- The `skip_tools` field can be omitted entirely to skip no tools

### Performance Notes
- All patterns are compiled into a single optimized `RegexSet` for O(1) tool name checking
- Pattern compilation happens once at startup, not per tool evaluation
- Large numbers of patterns have minimal runtime performance impact

## Allowed Paths Configuration

The `allowed_paths` field provides fine-grained control over filesystem access for plugins. It supports both simple paths and sophisticated host-to-plugin path mapping, enabling secure isolation while maintaining flexibility.

### Path Format

Paths can be specified in two formats:

#### 1. Simple Path Format
When the same path should be accessible to both the host and plugin:

```yaml
allowed_paths:
  - "/tmp"
  - "/home/user/data"
  - "./relative/path"
```

#### 2. Mapped Path Format
When you want to map a host filesystem path to a different path as seen by the plugin:

**Unix/Linux/macOS** (using `:` as separator):
```yaml
allowed_paths:
  - "/host/path:/plugin/path"
  - "/var/log:/plugin/logs"
  - "/home/user/data:/plugin/user/data"
```

**Windows** (using `;` as separator):
```yaml
allowed_paths:
  - "C:\\host\\path;C:\\plugin\\path"
  - "C:\\logs;C:\\plugin\\logs"
```

### Platform-Specific Separators

The separator used for path mapping is platform-dependent:
- **Unix/Linux/macOS**: Colon (`:`) - e.g., `"/host/path:/plugin/path"`
- **Windows**: Semicolon (`;`) - e.g., `"C:\\host\\path;C:\\plugin\\path"`

This ensures compatibility with Windows drive letters (which contain colons) and Unix absolute paths.

### Path Mapping Examples

#### Basic Mapping
```yaml
allowed_paths:
  - "/tmp"                           # Plugin sees /tmp at /tmp
  - "/var/log:/plugin/logs"          # Host /var/log appears as /plugin/logs to plugin
  - "/home/user/data"                # Plugin sees /home/user/data at /home/user/data
```

#### Relative Paths
```yaml
allowed_paths:
  - "./local/data"                   # Relative to current directory
  - "../shared/files"                # Parent directory reference
  - "./host/config:./plugin/config"  # Mapped relative paths
```

#### Windows Paths
```yaml
allowed_paths:
  - "C:\\Users\\Public"              # Simple Windows path
  - "C:\\app\\data;C:\\plugin\\data" # Mapped Windows path
  - "\\\\server\\share"              # UNC network path
  - "C:\\logs;D:\\plugin\\logs"      # Map between different drives
```

#### Home Directory Expansion
```yaml
allowed_paths:
  - "~/Documents"                    # User home directory
  - "~/host/config:~/plugin/config"  # Mapped home directories
```

#### Complex Scenarios
```yaml
allowed_paths:
  # Root and system paths
  - "/"                              # Root directory (use with caution!)
  - "/usr/local/share:/plugin/share"
  
  # Application-specific paths
  - "/opt/myapp/data:/plugin/data"
  - "/etc/myapp/config:/plugin/config"
  
  # Paths with special characters
  - "/path/with spaces"
  - "/path-with-dashes"
  - "/path_with_underscores"
  - "/path.with.dots"
  
  # Deeply nested structures
  - "/very/deeply/nested/path/structure"
```

### Whitespace Handling

Whitespace around paths is automatically trimmed:

```yaml
allowed_paths:
  - "  /tmp  "                       # Treated as "/tmp"
  - "  /var/log  :  /plugin/logs  "  # Treated as "/var/log:/plugin/logs"
```

### Empty Plugin Path Behavior

If the plugin path is empty or contains only whitespace after the separator, the host path is used for both:

```yaml
allowed_paths:
  - "/tmp:"          # Equivalent to "/tmp" (plugin path defaults to host path)
  - "/var/log:  "    # Equivalent to "/var/log" (whitespace-only plugin path)
```

### Multiple Colons/Semicolons

Only the first separator is used to split the mapping. This allows paths to contain additional colons or semicolons:

**Unix:**
```yaml
allowed_paths:
  - "/host/path:/plugin/path:with:colons"  # Host: "/host/path", Plugin: "/plugin/path:with:colons"
```

**Windows:**
```yaml
allowed_paths:
  - "C:\\host;C:\\plugin;data"  # Host: "C:\host", Plugin: "C:\plugin;data"
```

### Use Cases

#### 1. Read-Only Configuration Access
```yaml
runtime_config:
  allowed_paths:
    - "/etc/myapp/config:/plugin/config"
```
Host configuration at `/etc/myapp/config` appears to the plugin at `/plugin/config`.

#### 2. Isolated Data Directories
```yaml
runtime_config:
  allowed_paths:
    - "/var/lib/myapp/plugin1:/plugin/data"
```
Each plugin gets its own isolated data directory mapped to a standard location.

#### 3. Multi-Environment Setup
```yaml
runtime_config:
  allowed_paths:
    - "/opt/production/data:/plugin/data"    # Production
    # - "/opt/staging/data:/plugin/data"     # Staging (commented out)
    # - "/opt/dev/data:/plugin/data"         # Development (commented out)
```

#### 4. Shared Resources
```yaml
runtime_config:
  allowed_paths:
    - "/tmp"                                  # Shared temp directory
    - "/usr/local/share:/plugin/shared"       # Shared libraries/resources
    - "/var/cache/myapp:/plugin/cache"        # Shared cache
```

#### 5. Cross-Platform Compatibility
```yaml
# Unix/Linux/macOS
allowed_paths:
  - "~/config:/plugin/config"
  - "/var/log:/plugin/logs"

# Windows equivalent
allowed_paths:
  - "C:\\Users\\username\\config;C:\\plugin\\config"
  - "C:\\logs;C:\\plugin\\logs"
```

### Complete Example

```yaml
plugins:
  file_processor:
    url: "oci://ghcr.io/myorg/file-processor:latest"
    runtime_config:
      allowed_hosts:
        - "api.example.com"
      allowed_paths:
        # Temporary workspace
        - "/tmp"
        
        # Configuration (read-only in practice)
        - "/etc/myapp/config:/plugin/config"
        
        # Input data (host path) -> Plugin working directory
        - "/var/lib/myapp/input:/plugin/input"
        
        # Output directory
        - "/var/lib/myapp/output:/plugin/output"
        
        # Logs (isolated per plugin)
        - "/var/log/myapp/file-processor:/plugin/logs"
        
        # Shared cache directory
        - "/var/cache/myapp:/plugin/cache"
      env_vars:
        PLUGIN_ENV: "production"
        LOG_LEVEL: "info"
      memory_limit: "1GB"
```

### Security Considerations

1. **Principle of Least Privilege**: Only grant access to paths that the plugin absolutely needs.
2. **Path Isolation**: Use path mapping to isolate plugins from each other's data.
3. **Avoid Root Access**: Avoid granting access to `/` unless absolutely necessary.
4. **Validate Paths**: Ensure paths exist and have appropriate permissions before configuring them.
5. **Use Mapping for Isolation**: Map host paths to plugin-specific locations to prevent plugins from knowing the actual host filesystem structure.

### Error Handling

- **Invalid Format**: Paths are parsed at configuration load time; invalid formats will cause startup errors.
- **Missing Separators**: If no separator is found, the entire string is treated as a simple path.
- **Empty Paths**: Empty path strings are not allowed and will cause configuration errors.

### Performance Notes

- Path configuration is parsed once at startup, not during runtime operations.
- Path mapping has minimal overhead during filesystem operations.
- Large numbers of allowed paths have negligible performance impact.

### Best Practices

1. **Use Descriptive Mappings**: Map host paths to clear, consistent plugin paths (e.g., `/plugin/config`, `/plugin/data`).
2. **Document Path Purpose**: Comment your path configurations to explain their purpose.
3. **Group Related Paths**: Organize paths by function (config, data, logs, cache).
4. **Version-Aware Paths**: Consider including version information in paths for easier upgrades.
5. **Environment-Specific Paths**: Use different path configurations for different environments (dev, staging, prod).
6. **Test Path Access**: Verify that plugins can actually access configured paths before deploying to production.

## Notes

- Fields marked as `optional` can be omitted.
- Plugin authors may extend `runtime_config` with additional fields, but only the above are officially recognized.
- Authentication applies to all HTTPS requests made by plugins, including plugin downloads and runtime API calls.
- URL matching is case-sensitive and based on string prefix matching.
- Keyring authentication requires platform-specific keyring services to be available and accessible.
- Skip tools patterns use full regex syntax with automatic anchoring for precise tool filtering.
