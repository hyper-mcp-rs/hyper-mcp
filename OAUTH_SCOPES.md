# OAuth Scopes for hyper-mcp Streamable-HTTP Transport

This document describes the OAuth scopes supported by hyper-mcp when using the `streamable-http` transport with OAuth 2.0 authorization enabled.

## Overview

hyper-mcp supports fine-grained OAuth 2.0 scopes that allow clients to request specific permissions for accessing plugins, tools, prompts, and resources. Scopes follow a hierarchical naming convention that enables both broad and granular access control.

## Scope Hierarchy

Scopes in hyper-mcp are organized in a dot-separated hierarchy with up to four components:

```
plugins[.plugin_name][.resource_type][.resource_identifier]
```

### Scope Components

1. **Base Scope**: `plugins`
   - The root scope that grants access to the plugin system
   - Can be combined with more specific components for finer control

2. **Plugin Name**: (Optional)
   - Specific plugin identifier (e.g., `myapp`, `github`, `fetch`)
   - If omitted at this level, the scope applies globally to that resource type

3. **Resource Type**: (Optional)
   - Type of resource within the plugin:
     - `tools` - Callable functions and commands
     - `prompts` - Predefined prompts and templates
     - `resources` - Data resources like files or API endpoints

4. **Resource Identifier**: (Optional)
   - Specific resource reference, supports wildcards
   - For resources, often uses protocols (e.g., `file://`, `http://`)

## Common Scopes

### Global Scopes

These are the broadest scopes that grant access across all plugins:

#### `plugins`
- Grants full access to all plugins, tools, prompts, and resources
- Most permissive scope
- Use with caution in production environments

**Example use case**: Administrative or internal tools that need unrestricted access

#### `plugins.tools`
- Grants access to all tools across all plugins
- Does not grant access to prompts or resources
- Useful for clients that only need to execute tools

**Example use case**: Automation workflows that call plugin functions

#### `plugins.prompts`
- Grants access to all prompts across all plugins
- Does not grant access to tools or resources

**Example use case**: Prompt engineering and template management

#### `plugins.resources`
- Grants access to all resources across all plugins
- Does not grant access to tools or prompts

**Example use case**: Data integration and file access systems

### Plugin-Specific Scopes

Access controls scoped to individual plugins:

#### `plugins.{plugin_name}`
- Grants full access to a specific plugin (all tools, prompts, and resources)

**Example**: `plugins.github`
- Grants access to all GitHub plugin functionality

#### `plugins.{plugin_name}.tools`
- Grants access to all tools within a specific plugin
- Does not grant access to that plugin's prompts or resources

**Example**: `plugins.fetch.tools`
- Allows calling all tools from the fetch plugin
- Cannot access fetch plugin resources

#### `plugins.{plugin_name}.prompts`
- Grants access to all prompts within a specific plugin
- Does not grant access to that plugin's tools or resources

**Example**: `plugins.memory.prompts`
- Can access all prompts from the memory plugin

#### `plugins.{plugin_name}.resources`
- Grants access to all resources within a specific plugin
- Does not grant access to that plugin's tools or prompts

**Example**: `plugins.qdrant.resources`
- Can access all resources from the Qdrant plugin

### Resource-Specific Scopes

Fine-grained access to individual or patterned resources:

#### `plugins.{plugin_name}.resources.{resource_identifier}`
- Grants access to a specific resource
- Resource identifier often uses URI schemes for clarity

**Examples**:
- `plugins.fs.resources.file:///home/user/documents`
- `plugins.fetch.resources.http://api.example.com`
- `plugins.database.resources.postgresql://db.example.com/mydb`

#### Wildcard Resource Scopes

Resource scopes support wildcard patterns for flexible access control:

##### Protocol-Level Wildcards

Grant access to all resources using a specific protocol:

**Example**: `plugins.fs.resources.file://*`
- Grants access to all files in the file system
- Matches: `file:///home/user/data.txt`, `file:///var/log/app.log`, etc.
- Does not match: `http://example.com` (different protocol)

**Example**: `plugins.fetch.resources.http://*`
- Grants access to all HTTP endpoints
- Matches: `http://api.example.com/v1/users`, `http://example.com/page`, etc.
- Does not match: `https://secure.example.com` (different protocol, HTTPS)

##### Path-Based Wildcards

Grant access to specific directory trees or URL paths:

**Example**: `plugins.fs.resources.file:///home/user/documents/*`
- Grants access to all files under the documents directory
- Matches: `file:///home/user/documents/readme.md`, `file:///home/user/documents/reports/q1.pdf`, etc.
- Does not match: `file:///home/user/downloads/file.zip` (outside documents tree)

**Example**: `plugins.fetch.resources.http://api.example.com/public/*`
- Grants access to all public API endpoints
- Matches: `http://api.example.com/public/users`, `http://api.example.com/public/data/export`, etc.
- Does not match: `http://api.example.com/admin/settings` (outside public path)

##### Universal Wildcard

Grant access to all resources within a plugin:

**Example**: `plugins.fs.resources.*`
- Grants access to all resources from the fs plugin
- Matches any resource: `file://`, `http://`, custom protocols, etc.

#### Tool-Specific Scopes (Exact Match)

Some plugins may support tool-specific scopes:

**Example**: `plugins.github.tools.list_repos`
- Grants access only to the `list_repos` tool
- Does not grant access to other GitHub tools

## Practical Examples

### Example 1: Read-Only File Access

Scope: `plugins.fs.resources.file:///home/user/documents/*`

Allows:
- ✅ Reading files from `/home/user/documents/` and subdirectories
- ✅ Accessing `file:///home/user/documents/report.pdf`
- ✅ Accessing `file:///home/user/documents/archive/backup.zip`

Denies:
- ❌ Accessing files outside documents directory
- ❌ Accessing `/home/user/downloads/`
- ❌ Network resources like `http://example.com`

### Example 2: GitHub Integration

Scopes: `plugins.github.tools plugins.github.resources.http://api.github.com/*`

Allows:
- ✅ Calling all GitHub tools
- ✅ Accessing GitHub API resources
- ✅ Creating issues, listing repositories, etc.

Denies:
- ❌ Accessing GitHub prompts
- ❌ Accessing other HTTP endpoints

### Example 3: Analytics Dashboard

Scopes: `plugins.database.tools plugins.fetch.resources.http://analytics.example.com/*`

Allows:
- ✅ Calling database tools to query data
- ✅ Fetching analytics data from the company endpoint
- ✅ Executing aggregation functions

Denies:
- ❌ Accessing other HTTP endpoints
- ❌ Modifying database directly (if tool-level restrictions apply)
- ❌ Accessing files or other resources

### Example 4: Content Creator with Limited Access

Scopes: `plugins.memory.tools plugins.memory.prompts plugins.fetch.resources.http://public-api.example.com/*`

Allows:
- ✅ Using all memory plugin tools and prompts
- ✅ Fetching content from public API
- ✅ Retrieving stored memories

Denies:
- ❌ Accessing other plugins
- ❌ Accessing private APIs
- ❌ File system access

## Scope Authorization Behavior

### Scope Matching Rules

1. **Exact Match**: A requested scope must match exactly or be covered by a granted scope
2. **Hierarchical Inheritance**: Broader scopes grant access to narrower scopes
   - `plugins.github` grants access to `plugins.github.tools` and `plugins.github.resources.*`
   - `plugins.tools` grants access to `plugins.{any_plugin}.tools`
3. **Wildcard Expansion**: Wildcards in granted scopes match requested resources
   - `plugins.fs.resources.file://*` matches `plugins.fs.resources.file:///home/user/data.txt`
   - `plugins.fetch.resources.http://api.*` matches `http://api.example.com` and `http://api.other.com`

### Scope Combination

Multiple scopes can be combined in the OAuth access token to build comprehensive permissions:

**Example**: Multiple scopes in token request
```
scope=plugins.github.tools plugins.fs.resources.file:///home/user/data/* plugins.memory.prompts
```

This grants:
- ✅ All GitHub tools
- ✅ File access under `/home/user/data/`
- ✅ All memory prompts

### Default Scopes

When no scopes are requested by the client, the authorization server may:
1. Deny the request (no default)
2. Grant minimal scopes (e.g., `plugins.prompts` only)
3. Require explicit scope requests

This is configured in your authorization server, not in hyper-mcp.

## Configuration and Enforcement

### Enabling OAuth Scopes

OAuth scopes are only enforced when:
1. Using the `streamable-http` transport
2. `oauth_protected_resource.authorization_servers` is configured with at least one server
3. Clients provide valid OAuth 2.0 access tokens

### Server Metadata

When OAuth is configured, hyper-mcp automatically serves scope information at:
```
https://your-mcp-server/.well-known/oauth-protected-resource
```

This endpoint includes:
- Supported scopes (calculated from your plugins)
- Authorization server URLs
- Resource metadata

### Configuration Example

```yaml
oauth_protected_resource:
  resource: "https://mcp.example.com"
  authorization_servers:
    - "https://auth.example.com"
    - "https://backup-auth.example.com"
  resource_name: "Example MCP Server"
  resource_policy_uri: "https://example.com/privacy"
  resource_tos_uri: "https://example.com/tos"
```

## Best Practices

### For Server Operators

1. **Principle of Least Privilege**: Request scopes narrowly from your authorization server
2. **Plugin-Scoped Access**: Use plugin-specific scopes rather than global `plugins` scope
3. **Resource Wildcards**: Use path prefixes for resources instead of universal wildcards
4. **Regular Audits**: Review which scopes are requested by clients
5. **Update Frequently**: Rotate authorization servers and policies regularly

### For Client Applications

1. **Request Specific Scopes**: Only request scopes needed for your use case
2. **Cache Tokens**: Store valid tokens to avoid repeated authorization
3. **Handle Denials**: Gracefully handle `403 Forbidden` responses when scopes are insufficient
4. **Scope Discovery**: Fetch server metadata to discover available scopes
5. **User Transparency**: Inform users about the permissions being requested

### For Authorization Server Configuration

1. **Whitelist Scopes**: Only allow specific scopes to be requested
2. **Default Scopes**: Set reasonable defaults if no scopes are specified
3. **User Consent**: Require user approval for sensitive scopes
4. **Token Expiration**: Use short-lived tokens with refresh token rotation
5. **Scope Mapping**: Map client applications to pre-approved scope sets

## Troubleshooting

### "Insufficient Scope" Errors

**Symptom**: Requests fail with 403 Forbidden or "insufficient_scope" error

**Solutions**:
1. Check the error details to see which scope is missing
2. Request a new token with the required scopes
3. Verify your authorization server grants those scopes
4. Check that scopes are correctly formatted (no typos or spaces)

### Unexpected Scope Denials

**Symptom**: A wildcard scope doesn't match expected resources

**Solutions**:
1. Verify protocol matches exactly (e.g., `http://` vs `https://`)
2. Check for trailing slashes or path differences
3. Test scope patterns against the resource identifier
4. Review scope matching rules above

### Missing Scopes in Metadata

**Symptom**: Expected scopes don't appear in `/.well-known/oauth-protected-resource`

**Solutions**:
1. Restart the server after changing plugin configuration
2. Verify plugins are loaded correctly
3. Check server logs for configuration errors
4. Manually add scopes to your authorization server if needed

## Related Documentation

- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Runtime Configuration Guide](./CONFIG.md)
- [Creating Plugins Guide](./CREATING_PLUGINS.md)
- [Streamable HTTP Transport](./README.md#getting-started)
```

Now I'll update the README.md to add a link to this new documentation:
