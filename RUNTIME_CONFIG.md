# Runtime Configuration

## Structure

The configuration is structured as follows:

- **auths** (`object`, optional): Authentication configurations for HTTPS requests, keyed by URL.
- **plugins**: A map of plugin names to  plugin configuration objects.
  - **path** (`string`): OCI path or HTTP URL or local path for the plugin.
  - **runtime_config** (`object`, optional): Plugin-specific runtime configuration. The available fields are:
    - **skip_tools** (`array[string]`, optional): List of tool names to skip loading at runtime.
    - **allowed_hosts** (`array[string]`, optional): List of allowed hosts for the plugin (e.g., `["1.1.1.1"]` or `["*"]`).
    - **allowed_paths** (`array[string]`, optional): List of allowed file system paths.
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
        - "debug"
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
        "skip_tools": ["debug"],
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

## Notes

- Fields marked as `optional` can be omitted.
- Plugin authors may extend `runtime_config` with additional fields, but only the above are officially recognized.
- Authentication applies to all HTTPS requests made by plugins, including plugin downloads and runtime API calls.
- URL matching is case-sensitive and based on string prefix matching.
- Keyring authentication requires platform-specific keyring services to be available and accessible.
