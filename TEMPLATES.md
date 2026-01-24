# Plugin Templates

The `templates/plugins/` directory contains templates for creating plugins for hyper-mcp in various programming languages. Plugins extend hyper-mcp's functionality by providing tools, resources, prompts, and other MCP capabilities through WebAssembly modules.

## Available Templates

### 🦀 Rust

The recommended language for building hyper-mcp plugins. Rust provides excellent performance, safety, and tooling for WebAssembly development.

- **Location**: `templates/plugins/rust/`
- **Getting Started**: See [templates/plugins/rust/README.md](./templates/plugins/rust/README.md)
- **Use When**: You want the best performance, safety, and ecosystem support
- **Compile Target**: WebAssembly (`wasm32-wasip1`)

**Key Features:**
- Excellent WASM performance and code size
- Strong type system catches errors at compile time
- Rich ecosystem of crates for common tasks
- Memory-safe execution model
- Direct support for Extism PDK

### 🐹 Go

A modern, approachable language for building hyper-mcp plugins. Go offers simplicity, fast compilation, and a clean standard library for WebAssembly development.

- **Location**: `templates/plugins/go/`
- **Getting Started**: See [templates/plugins/go/README.md](./templates/plugins/go/README.md)
- **Use When**: You prefer simplicity, fast development cycles, and Go's syntax
- **Compile Target**: WebAssembly (`wasip1`)

**Key Features:**
- Simple, readable syntax with fast learning curve
- Fast compilation times
- Excellent standard library
- Strong concurrency primitives (though limited in WASM)
- Growing WASM ecosystem with Extism Go PDK support

## Quick Start

1. **Choose a template language** (Rust or Go)
2. **Read the template README** for language-specific setup instructions
3. **Implement your plugin** by adding tools, resources, prompts, etc.
4. **Build and test locally** using the provided build instructions
5. **Publish to a registry** following the distribution guide

## Plugin Capabilities

Plugins can provide any combination of:

- **Tools** - Functions that clients can call with structured inputs
- **Resources** - URI-based references to files, data, or services
- **Resource Templates** - URI patterns for dynamic resource discovery
- **Prompts** - Pre-defined prompts for specific use cases
- **Completions** - Auto-completion suggestions for user input

## Plugin Development Workflow

```
1. Create project from template
   ↓
2. Implement plugin handlers
   ↓
3. Build to WebAssembly
   ↓
4. Test locally with hyper-mcp
   ↓
5. Build Docker image
   ↓
6. Push to registry (Docker Hub, GHCR, etc.)
   ↓
7. Configure in hyper-mcp's config.json
   ↓
8. Use in Claude Desktop, Cursor IDE, or other MCP clients
```

## Common Tasks

### Set Up Development Environment

Follow the language-specific template README (e.g., [templates/plugins/rust/README.md](./templates/plugins/rust/README.md) or [templates/plugins/go/README.md](./templates/plugins/go/README.md)) for:
- Required tools and dependencies
- Target/runtime setup
- Local build instructions

### Implement Plugin Handlers

**Only implement what you need** - for example:
- Tools-only plugin: `list_tools()` + `call_tool()`
- Resources-only plugin: `list_resources()` + `read_resource()`
- Prompts-only plugin: `list_prompts()` + `get_prompt()`

See the template README for a complete handler reference table.

### Call Host Functions

Your plugin can call host functions to interact with the MCP client:
- Request user input with `create_elicitation()`
- Generate messages with `create_message()`
- Report progress with `notify_progress()`
- Send logs with `notify_logging_message()`
- Query available roots with `list_roots()`
- Notify about changes to tools, resources, or prompts

See the template README for complete host function documentation.

### Build for Production

Each template includes a `Dockerfile` for reproducible, multi-stage builds:

```bash
docker build -t your-registry/your-plugin-name .
docker push your-registry/your-plugin-name:latest
```

### Configure in hyper-mcp

Add your plugin to hyper-mcp's config file:

```json
{
  "plugins": {
    "my_plugin": {
      "url": "oci://your-registry/your-plugin-name:latest"
    }
  }
}
```

For local development, use a file:// URL:

```json
{
  "plugins": {
    "my_plugin": {
      "url": "file:///path/to/plugin.wasm"
    }
  }
}
```

## Language Comparison

| Feature | Rust | Go |
|---------|------|-----|
| Performance | Excellent | Very Good |
| Code Size | Small | Medium |
| Learning Curve | Steep | Gentle |
| Compilation Speed | Moderate | Fast |
| Type Safety | Very Strong | Good |
| Standard Library | Moderate | Excellent |
| WASM Support | Native | Excellent (1.22+) |
| Extism Support | Full | Full |

## Resources

- [hyper-mcp Main README](https://github.com/hyper-mcp-rs/hyper-mcp#readme)
- [hyper-mcp Plugin Creation Guide](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/CREATING_PLUGINS.md)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Extism Documentation](https://docs.extism.org/)
- [Extism Go PDK](https://github.com/extism/go-pdk)
- [Example Plugins](https://github.com/hyper-mcp-rs/hyper-mcp/tree/main/examples/plugins)

## Adding More Templates

To add a template for another language:

1. Create a new directory: `templates/plugins/your-language/`
2. Set up the build system for compiling to WebAssembly
3. Create a `Dockerfile` for building OCI container images
4. Add a comprehensive `README.md` following the pattern from existing templates
5. Include example implementations of key handlers
6. Convert all MCP protocol types from the Rust `types.rs` to your language
7. Submit as a contribution to hyper-mcp

## Support

- Check the template README for language-specific questions
- See [CREATING_PLUGINS.md](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/CREATING_PLUGINS.md) for general plugin development
- Review [example plugins](https://github.com/search?q=topic%3Aplugins+org%3Ahyper-mcp-rs&type=repositories) for working implementations
- Open an issue on [GitHub](https://github.com/hyper-mcp-rs/hyper-mcp) for bugs or feature requests

Happy plugin building! 🚀
