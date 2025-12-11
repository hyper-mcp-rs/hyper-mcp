# Runtime Configuration

## Structure

The configuration is structured as follows:

- **auths** (`object`, optional): Authentication configurations for HTTPS requests, keyed by URL.
- **oci** (`object`, optional): OCI image verification and signature configuration. Applies globally to all OCI plugins. CLI arguments will override these values. The available fields are:
  - **insecure_skip_signature** (`boolean`, optional, default: `false`): Skip signature verification for OCI images.
  - **use_sigstore_tuf_data** (`boolean`, optional, default: `true`): Use Sigstore TUF data for OCI verification.
  - **rekor_pub_keys** (`string`, optional): Path to Rekor public keys for OCI verification.
  - **fulcio_certs** (`string`, optional): Path to Fulcio certificates for OCI verification.
  - **cert_issuer** (`string`, optional): Certificate issuer to verify OCI images against (e.g., `"https://github.com/login/oauth"`).
  - **cert_email** (`string`, optional): Certificate email to verify OCI images against.
  - **cert_url** (`string`, optional): Certificate URL to verify OCI images against.
- **oauth_protected_resource** (`object`, optional): OAuth 2.0 protected resource configuration for securing the streamable-http transport. **CRITICAL:** Populate `authorization_servers` to enable authorization enforcement. The available fields are:
  - **resource** (`string`, required): The canonical URI of your MCP server (e.g., `"https://mcp.example.com"`).
  - **authorization_servers** (`array[string]`, **REQUIRED to secure the server**): Authorization server URIs where clients obtain tokens. If empty or not provided, authorization is disabled.
  - **resource_name** (`string`, optional): Human-readable name for the resource.
  - **resource_policy_uri** (`string`, optional): URI to resource policy document.
  - **resource_tos_uri** (`string`, optional): URI to resource terms of service.
- **plugins**: A map of plugin names to  plugin configuration objects.
  - **path** (`string`): OCI path or HTTP URL or local path for the plugin.
  - **runtime_config** (`object`, optional): Plugin-specific runtime configuration. The available fields are:
    - **skip_tools** (`array[string]`, optional): List of regex patterns for tool names to skip loading at runtime. Each pattern is automatically anchored to match the entire tool name (equivalent to wrapping with `^` and `$`). Supports full regex syntax for powerful pattern matching.
    - **allowed_hosts** (`array[string]`, optional): List of allowed hosts for the plugin (e.g., `["1.1.1.1"]` or `["*"]`).
    - **allowed_paths** (`array[string]`, optional): List of allowed file system paths.
    - **env_vars** (`object`, optional): Key-value pairs of environment variables for the plugin.
    - **memory_limit** (`string`, optional): Memory limit for the plugin (e.g., `"512Mi"`).

## OCI Configuration

The `oci` configuration section allows you to control how OCI (Open Container Initiative) images are loaded and verified. This is particularly important for plugins distributed as OCI images (using the `oci://` scheme).

### CLI Override Behavior

All OCI configuration fields can be overridden via command-line arguments and environment variables. When a CLI argument or environment variable is provided, it takes precedence over the corresponding value in the configuration file.

**Example of CLI override:**

If your config file has:
```yaml
oci:
  insecure_skip_signature: false
  cert_issuer: "https://github.com/login/oauth"
```

And you run hyper-mcp with:
```bash
hyper-mcp --insecure-skip-signature true --cert-email "user@example.com"
```

The final effective configuration will be:
- `insecure_skip_signature`: `true` (overridden by CLI)
- `cert_issuer`: `"https://github.com/login/oauth"` (from config file)
- `cert_email`: `"user@example.com"` (set by CLI)

### Available CLI Arguments and Environment Variables

| Config Field | CLI Argument | Environment Variable |
|---|---|---|
| `insecure_skip_signature` | `--insecure-skip-signature` | `HYPER_MCP_INSECURE_SKIP_SIGNATURE` |
| `use_sigstore_tuf_data` | `--use-sigstore-tuf-data` | `HYPER_MCP_USE_SIGSTORE_TUF_DATA` |
| `rekor_pub_keys` | `--rekor-pub-keys` | `HYPER_MCP_REKOR_PUB_KEYS` |
| `fulcio_certs` | `--fulcio-certs` | `HYPER_MCP_FULCIO_CERTS` |
| `cert_issuer` | `--cert-issuer` | `HYPER_MCP_CERT_ISSUER` |
| `cert_email` | `--cert-email` | `HYPER_MCP_CERT_EMAIL` |
| `cert_url` | `--cert-url` | `HYPER_MCP_CERT_URL` |

### Usage Examples

**Configuration file only (YAML):**
```yaml
oci:
  cert_issuer: "https://github.com/login/oauth"
  cert_email: "user@github.com"
  use_sigstore_tuf_data: true
```

**CLI override (environment variable):**
```bash
HYPER_MCP_INSECURE_SKIP_SIGNATURE=true hyper-mcp
```

**CLI override (argument):**
```bash
hyper-mcp --cert-issuer "https://example.com" --cert-email "admin@example.com"
```

**Combined approach (config file + CLI override):**
```bash
# Config file has default cert_issuer, but this run uses a different one
hyper-mcp --config config.yaml --cert-issuer "https://production.example.com"
```

### Signature Verification Behavior

When loading OCI plugins:
1. The system first loads values from the config file
2. Any CLI arguments or environment variables override the config file values
3. The final merged configuration is used for signature verification
4. If `insecure_skip_signature` is `true`, all signature verification is disabled regardless of other settings
5. Otherwise, the configured certificates and keys (from config or CLI) are used for verification

## OAuth Protected Resource Configuration

The `oauth_protected_resource` configuration section enables OAuth 2.0-based authorization for the hyper-mcp server when using the streamable-http transport. This allows you to secure your MCP server with industry-standard OAuth mechanisms, following the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

### Overview

When configured, `oauth_protected_resource` defines:
- **The protected resource**: Your MCP server endpoint that requires authorization
- **Authorization servers**: Where clients should obtain access tokens
- **Supported scopes**: What permissions are available for your resource

### Configuration Fields

```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com"
  authorization_servers:
    - "https://auth.example.com"
  resource_name: "Example MCP Server"
  resource_policy_uri: "https://example.com/policy"
  resource_tos_uri: "https://example.com/tos"
```

**Note:** The `scopes_supported` field is automatically calculated at runtime from your configured plugins and is served via the Protected Resource Metadata endpoint. See [Dynamic Scope Calculation](#dynamic-scope-calculation) below for details.

- **resource** (`string`, required): The canonical URI of your MCP server as defined in RFC 8707. This is the identifier that clients will request tokens for. Use the most specific URI that identifies your MCP server (e.g., `https://mcp.example.com` or `https://mcp.example.com/mcp`).

- **authorization_servers** (`array[string]`, optional but **REQUIRED** to secure streamable-http): An array of authorization server URIs that clients should use to obtain access tokens for this protected resource. **This field MUST be populated for the streamable-http transport to enforce authorization.** If this array is empty or not provided, the server will not require authorization, even if other oauth_protected_resource fields are configured.

- **resource_name** (`string`, optional): A human-readable name for your protected resource. Displayed to end-users during the authorization flow.

- **resource_policy_uri** (`string`, optional): A URL pointing to your resource's policy document or terms of service related to data handling.

- **resource_tos_uri** (`string`, optional): A URL pointing to your resource's terms of service.

### Critical Security Requirement: Securing streamable-http Transport

**To enforce authorization on the streamable-http transport, you MUST populate the `authorization_servers` array.**

Without populating `authorization_servers`:
- ❌ The MCP server will NOT enforce authorization
- ❌ All requests will be accepted without OAuth tokens
- ❌ Your server is exposed to unauthorized access

With `authorization_servers` populated:
- ✅ The MCP server will require valid OAuth tokens from specified authorization servers
- ✅ Invalid or missing tokens will be rejected with HTTP 401 Unauthorized
- ✅ Token audience validation ensures tokens are issued for your specific server

**Example of INSECURE configuration (authorization disabled):**
```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com"
  # ❌ MISSING authorization_servers - server will NOT enforce authorization!
```

**Example of SECURE configuration (authorization enabled):**
```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com"
  # ✅ authorization_servers populated - server WILL enforce authorization
  authorization_servers:
    - "https://auth.example.com"
```

### MCP Authorization Flow

The `oauth_protected_resource` configuration plays a crucial role in the MCP OAuth 2.0 authorization flow, as defined in the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization):

#### 1. **Protected Resource Metadata Discovery**

When a client attempts to access your MCP server and receives a `401 Unauthorized` response, the server provides the Protected Resource Metadata URL via the `WWW-Authenticate` header:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The client uses this URL to fetch metadata about your protected resource, which includes:
- Your authorization server(s) from the `authorization_servers` field
- Available scopes from `scopes_supported`
- Your resource URI from the `resource` field

#### 2. **Authorization Server Discovery**

Using the authorization server URI(s) from your configuration, the client discovers the authorization server's metadata endpoint by checking:

For issuer `https://auth.example.com`:
- `https://auth.example.com/.well-known/oauth-authorization-server`
- `https://auth.example.com/.well-known/openid-configuration`

This metadata tells the client:
- The authorization endpoint for user authentication
- The token endpoint for obtaining access tokens
- Supported capabilities (PKCE, scopes, grant types, etc.)

Your server's `scopes_supported` is automatically calculated from your plugins and advertised through this discovery process (see [Dynamic Scope Calculation](#dynamic-scope-calculation) below).

#### 3. **Authorization Request**

The client initiates an OAuth 2.0 authorization code flow with the authorization server, including:
- Your `resource` URI as the `resource` parameter (RFC 8707)
- Requested scopes (from your server's dynamically-calculated `scopes_supported` or from the WWW-Authenticate `scope` challenge)
- PKCE parameters for code interception prevention

#### 4. **Token Issuance**

The authorization server issues an access token bound to:
- Your MCP server as the intended audience (resource)
- The scopes requested by the client
- The authorization server that issued it

#### 5. **Token Validation**

Your hyper-mcp server receives requests with the OAuth access token in the `Authorization: Bearer` header and validates:
- The token is cryptographically valid
- The token's audience matches your server's `resource` URI
- The token was issued by one of your configured `authorization_servers`
- The token has not expired
- The token has appropriate scopes for the requested operation

#### 6. **Scope Challenge (Optional)**

If a client needs additional scopes at runtime (e.g., to perform a protected operation), the server responds with:

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                         scope="mcp:read mcp:write",
                         resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The client then initiates a step-up authorization flow to request the additional scopes.

### Real-World Configuration Examples

#### Example 1: Simple OAuth-Protected Server

Minimal configuration for securing your MCP server with a single authorization server:

```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com"
  authorization_servers:
    - "https://auth.example.com"
```

Available scopes will be automatically calculated from your configured plugins at runtime.

#### Example 2: Multi-Authorization Server Setup

For enterprise environments with multiple identity providers:

```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com/production"
  authorization_servers:
    - "https://primary-auth.company.com"
    - "https://backup-auth.company.com"
  resource_name: "Company MCP Production Server"
  resource_policy_uri: "https://company.com/mcp-policy"
  resource_tos_uri: "https://company.com/tos"
```

Scopes are dynamically calculated from your plugins. Clients will receive the full list at the Protected Resource Metadata endpoint.

#### Example 3: Development vs Production

Development environment (authorization disabled):
```yaml
# .env.development.yaml
oauth_protected_resource:
  resource: "https://localhost:3001"
  # No authorization_servers - authorization disabled for local testing
```

Production environment (authorization enabled):
```yaml
# .env.production.yaml
oauth_protected_resource:
  resource: "https://mcp.production.company.com"
  authorization_servers:
    - "https://auth.company.com"  # ✅ MUST be present for security
  resource_name: "Production MCP Server"
  resource_policy_uri: "https://company.com/policy"
  resource_tos_uri: "https://company.com/tos"
```

Scopes are automatically calculated from your configured plugins in both environments.

### Important Notes

- **Transport Type**: OAuth Protected Resource configuration is specifically designed for the `streamable-http` transport. The `stdio` transport does not support OAuth-based authorization.

- **Metadata Endpoint**: hyper-mcp automatically serves your `oauth_protected_resource` configuration at the well-known endpoints specified in RFC 9728:
  - `https://mcp.example.com/.well-known/oauth-protected-resource`
  - At your MCP endpoint path: `https://mcp.example.com/mcp/.well-known/oauth-protected-resource`

- **Token Validation**: Your server validates tokens using standard OAuth 2.0 practices, including audience validation as defined in RFC 8707 and RFC 9068.

- **Backward Compatibility**: If `oauth_protected_resource` is not configured, the server operates without OAuth authorization, allowing any client to access your MCP server. This is suitable for development environments but NOT recommended for production.

- **Scope Challenge Handling**: When clients encounter insufficient scopes at runtime, they initiate a step-up authorization flow to request additional permissions, as detailed in the [MCP Authorization Specification - Scope Challenge Handling](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#runtime-insufficient-scope-errors).

### Dynamic Scope Calculation

Your hyper-mcp server automatically calculates available scopes based on your configured plugins and their capabilities. You do not need to manually specify scopes in your configuration.

#### How Scopes Are Calculated

When the server starts, it:
1. Loads all configured plugins
2. Introspects each plugin to discover available tools, prompts, and resources
3. Generates a scope for each capability in the format: `plugins.{plugin_name}.{resource_type}.{resource_name}`

#### Scope Format

Scopes follow a hierarchical dot-notation format:

- **Global scopes**: `plugins`, `plugins.tools`, `plugins.prompts`, `plugins.resources`
- **Plugin-level scopes**: `plugins.{plugin_name}`, `plugins.{plugin_name}.tools`, `plugins.{plugin_name}.prompts`, `plugins.{plugin_name}.resources`
- **Resource-specific scopes**: `plugins.{plugin_name}.tools.{tool_name}`, `plugins.{plugin_name}.prompts.{prompt_name}`, `plugins.{plugin_name}.resources.{resource_uri}`

**Example scopes generated from plugins:**
- `plugins.search_plugin.tools.web_search` - Access to the web_search tool in search_plugin
- `plugins.file_manager.resources.file://*` - Access to file resources in file_manager. Note that resources support wildcards for pattern matching.
- `plugins.weather.prompts.forecast` - Access to the forecast prompt in weather plugin

#### Scope Authorization

Your server validates that client tokens include the required scopes for each operation:

- A client requesting a tool must have the corresponding `plugins.{plugin_name}.tools.{tool_name}` scope (or a parent scope like `plugins.{plugin_name}.tools`, `plugins.{plugin_name}`, `plugins.tools` or `plugins`)
- A client requesting a prompt must have the corresponding `plugins.{plugin_name}.prompts.{prompt_name}` scope (or a parent scope like `plugins.{plugin_name}.prompts`, `plugins.{plugin_name}`, `plugins.prompts` or `plugins`)
- A client requesting a resource must have the corresponding `plugins.{plugin_name}.resources.{resource_uri}` scope (supporting wildcards for pattern matching) (or a parent scope like `plugins.{plugin_name}.resources`, `plugins.{plugin_name}`, `plugins.resources` or `plugins`)

#### Scope Discovery by Clients

When clients access your server, they discover available scopes through:

1. **Protected Resource Metadata Endpoint**: The server serves dynamically-calculated scopes at:
   ```
   GET https://mcp.example.com/.well-known/oauth-protected-resource
   ```

   Response includes `scopes_supported`:
   ```json
   {
     "resource": "https://mcp.example.com",
     "authorization_servers": ["https://auth.example.com"],
     "scopes_supported": [
       "plugins",
       "plugins.tools",
       "plugins.search_plugin.tools.web_search",
       "plugins.file_manager.resources.file://*",
       ...
     ]
   }
   ```

2. **WWW-Authenticate Challenge**: When a client lacks sufficient scopes, the server responds with a 403 Forbidden and includes required scope.
   ```
   HTTP/1.1 403 Forbidden
   WWW-Authenticate: Bearer error="insufficient_scope",
                            scope="plugins.database.tools.query"
   ```

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

### Reserved Names
The following plugin names are reserved and cannot be used:

- `hyper_mcp` - Reserved for the core hyper-mcp framework

Attempting to use a reserved plugin name will result in a deserialization error when loading the configuration. If you encounter an error stating that a plugin name is reserved, choose a different name for your plugin.

**Example of Invalid Configuration:**
```yaml
plugins:
  hyper_mcp:  # ❌ This will cause an error - reserved name
    url: "oci://ghcr.io/example/plugin:latest"
```

**Corrected Configuration:**
```yaml
plugins:
  my_hyper_plugin:  # ✅ Use a different name instead
    url: "oci://ghcr.io/example/plugin:latest"
```

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

## Notes

- Fields marked as `optional` can be omitted.
- Plugin authors may extend `runtime_config` with additional fields, but only the above are officially recognized.
- Authentication applies to all HTTPS requests made by plugins, including plugin downloads and runtime API calls.
- URL matching is case-sensitive and based on string prefix matching.
- Keyring authentication requires platform-specific keyring services to be available and accessible.
- Skip tools patterns use full regex syntax with automatic anchoring for precise tool filtering.
