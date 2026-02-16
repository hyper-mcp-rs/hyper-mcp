<div align="center">
  <picture>
    <img alt="hyper-mcp logo" src="./assets/logo.png" width="50%">
  </picture>
</div>

<div align="center">

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://crates.io/crates/hyper-mcp)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue)](#license)
[![Issues - hyper-mcp](https://img.shields.io/github/issues/hyper-mcp-rs/hyper-mcp)](https://github.com/hyper-mcp-rs/hyper-mcp/issues)
![GitHub Release](https://img.shields.io/github/v/release/hyper-mcp-rs/hyper-mcp)

<a href="https://trendshift.io/repositories/13451" target="_blank"><img src="https://trendshift.io/api/badge/repositories/13451" alt="hyper-mcp-rs%2Fhyper-mcp | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>

</div>

# hyper-mcp

A fast, secure MCP server that extends its capabilities through WebAssembly plugins.

## What is it?

hyper-mcp makes it easy to add AI capabilities to your applications. It works with Claude Desktop, Cursor IDE, and other MCP-compatible apps. Write plugins in your favorite language, distribute them through container registries, and run them anywhere - from cloud to edge.

## Features

- Write plugins in any language that compiles to WebAssembly
- Distribute plugins via standard OCI registries (like Docker Hub)
- Built on [Extism](https://github.com/extism/extism) for rock-solid plugin support
- Sanboxing with WASM: ability to limit network, filesystem, memory access
- Lightweight enough for resource-constrained environments
- Support `stdio` transport protocol
- Deploy anywhere: serverless, edge, mobile, IoT devices
- Cross-platform compatibility out of the box
- Support tool name prefix to prevent tool names collision

## Security

Built with security-first mindset:

- Sandboxed plugins that can't access your system without permission
- Memory-safe execution with resource limits
- Secure plugin distribution through container registries
- Fine-grained access control for host functions
- OCI plugin images are signed at publish time and verified at load time with [sigstore](https://www.sigstore.dev/).

## Getting Started

1. Create your config file:
   - Linux: `$HOME/.config/hyper-mcp/config.json`
   - Windows: `{FOLDERID_RoamingAppData}\hyper-mcp\config.json`. Eg: `C:\Users\Alice\AppData\Roaming\hyper-mcp\config.json`
   - macOS: `$HOME/Library/Application Support/hyper-mcp/config.json`

```json
{
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/hyper-mcp-rs/time-plugin:latest"
    },
    "qr_code": {
      "url": "oci://ghcr.io/hyper-mcp-rs/qrcode-plugin:latest"
    },
    "hash": {
      "url": "oci://ghcr.io/hyper-mcp-rs/hash-plugin:latest"
    },
    "myip": {
      "url": "oci://ghcr.io/hyper-mcp-rs/myip-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["1.1.1.1"]
      }
    },
    "fetch": {
      "url": "oci://ghcr.io/hyper-mcp-rs/fetch-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["*"],
        "memory_limit": "100 MB",
      }
    }
  }
}
```

> 📖 **For detailed configuration options including authentication setup, runtime configuration, and advanced features, see [RUNTIME_CONFIG.md](./RUNTIME_CONFIG.md)**

Supported URL schemes:
- `oci://` - for OCI-compliant registries (like Docker Hub, GitHub Container Registry, etc.) **REQUIRES COSIGN**
- `file://` - for local files
- `http://` or `https://` - for remote files
- `s3://` - for Amazon S3 objects (requires that you have your AWS credentials set up in the environment)

2. Start the server:

```sh
$ hyper-mcp
```

- Uses `stdio` transport protocol.
- If you want to debug, use `RUST_LOG=debug`.
- If you're loading unsigned OCI plugin, you need to set `insecure_skip_signature` flag or env var `HYPER_MCP_INSECURE_SKIP_SIGNATURE` to `true`

> **Running in SSE/streamable-http**: To do this, wrap `hyper-mcp` in one of the many proxies that supports the network transports **AND** that creates an instance of `hyper-mcp` per client connection.

## Output Logging

hyper-mcp automatically logs all output to daily rolling log files for debugging and monitoring purposes.

**Log Location:**
- Linux: `$HOME/.config/hyper-mcp/logs/mcp-server.log`
- Windows: `{FOLDERID_RoamingAppData}\hyper-mcp\logs\mcp-server.log`
- macOS: `$HOME/Library/Application Support/hyper-mcp/logs/mcp-server.log`

**Custom Log Path:**

You can override the default log directory by setting the `HYPER_MCP_LOG_PATH` environment variable:

```sh
export HYPER_MCP_LOG_PATH=/path/to/your/logs
hyper-mcp
```

**Log Levels:**

Control the verbosity of logs using the `RUST_LOG` environment variable:

```sh
# Info level (default)
RUST_LOG=info hyper-mcp

# Debug level (verbose, useful for troubleshooting)
RUST_LOG=debug hyper-mcp

# Warn level (only warnings and errors)
RUST_LOG=warn hyper-mcp
```

**Features:**
- Daily log rotation (new file created each day)
- Non-blocking writes to prevent performance impact
- Includes timestamps, line numbers, and target information
- Safe for use with stdio transport (logs don't interfere with MCP communication)

## Using with Cursor IDE

You can configure hyper-mcp either globally for all projects or specifically for individual projects.

1. For project-scope configuration, create `.cursor/mcp.json` in your project root:
```json
{
  "mcpServers": {
    "hyper-mcp": {
      "command": "/path/to/hyper-mcp"
    }
  }
}
```

2. Set up hyper-mcp in Cursor's settings:
   ![cursor mcp](./assets/cursor-mcp.png)

3. Start using tools through chat:
   ![cursor mcp chat](./assets/cursor-mcp-1.png)

## Available Plugins

We maintain several example plugins to get you started:

### V1 Plugins

These plugins use the v1 plugin interface. While still supported, new plugins should use the v2 interface.

- [time](https://github.com/hyper-mcp-rs/time-plugin): Get current time and do time calculations (Rust)
- [qr_code](https://github.com/hyper-mcp-rs/qr-code-plugin): Generate QR codes (Rust)
- [hash](https://github.com/hyper-mcp-rs/hash-plugin): Generate various types of hashes (Rust)
- [myip](https://github.com/hyper-mcp-rs/myip-plugin): Get your current IP (Rust)
- [fetch](https://github.com/hyper-mcp-rs/fetch-plugin): Basic webpage fetching (Rust)
- [crypto_price](https://github.com/hyper-mcp-rs/crypto-price-plugin): Get cryptocurrency prices (Go)
- [fs](https://github.com/hyper-mcp-rs/fs-plugin): File system operations (Rust)
- [github](https://github.com/hyper-mcp-rs/github-plugin): GitHub plugin (Go)
- [eval_py](https://github.com/hyper-mcp-rs/eval-py-plugin): Evaluate Python code with RustPython (Rust)
- [arxiv](https://github.com/hyper-mcp-rs/arxiv-plugin): Search & download arXiv papers (Rust)
- [memory](https://github.com/hyper-mcp-rs/memory-plugin): Let you store & retrieve memory, powered by SQLite (Rust)
- [sqlite](https://github.com/hyper-mcp-rs/sqlite-plugin): Interact with SQLite (Rust)
- [crates-io](https://github.com/hyper-mcp-rs/crates-io-plugin): Get crate general information, check crate latest version (Rust)
- [gomodule](https://github.com/hyper-mcp-rs/gomodule-plugin): Get Go modules info, version (Rust)
- [qdrant](https://github.com/hyper-mcp-rs/qdrant-plugin): keeping & retrieving memories to Qdrant vector search engine (Rust)
- [gitlab](https://github.com/hyper-mcp-rs/gitlab-plugin): GitLab plugin (Rust)
- [meme_generator](https://github.com/hyper-mcp-rs/meme-generator-plugin): Meme generator (Rust)
- [think](https://github.com/hyper-mcp-rs/think-plugin): Think tool(Rust)
- [maven](https://github.com/hyper-mcp-rs/maven-plugin): Maven plugin (Rust)
- [serper](https://github.com/hyper-mcp-rs/serper-plugin): Serper web search plugin (Rust)

### V2 Plugins
These plugins use the v2 plugin interface. New plugins should use this interface.

- [rstime](https://github.com/hyper-mcp-rs/rstime-plugin): Get current time and do time calculations (Rust)
- [context7](https://github.com/hyper-mcp-rs/context7-plugin): Lookup library documentation (Rust)


### Community-built plugins

- [hackernews](https://github.com/hungran/hyper-mcp-hackernews-tool): This plugin connects to the Hacker News API to fetch the current top stories and display them with their titles, scores, authors, and URLs.
- [release-monitor-id](https://github.com/ntheanh201/hyper-mcp-release-monitor-id-tool): This plugin retrieves project ID from release-monitoring.org, which helps track versions of released software.
- [yahoo-finance](https://github.com/phamngocquy/hyper-mcp-yfinance): This plugin connects to the Yahoo Finance API to provide stock prices (OHLCV) based on a company name or ticker symbol.
- [rand16](https://github.com/dabevlohn/rand16): This plugen generates random 16 bytes buffer and provides it in base64uri format - very usable for symmetric cryptography online.

## Documentation

- **[Runtime Configuration Guide](./RUNTIME_CONFIG.md)** - Comprehensive guide to configuration options including:
  - Authentication setup (Basic, Token, and Keyring)
  - Plugin runtime configuration
  - Security considerations and best practices
  - Platform-specific keyring setup for macOS, Linux, and Windows
  - Troubleshooting authentication issues
- **[Skip Tools Pattern Guide](./SKIP_TOOLS_GUIDE.md)** - Comprehensive guide to filtering tools using regex patterns:
  - Pattern syntax and examples
  - Common use cases and best practices
  - Environment-specific filtering strategies
  - Advanced regex techniques
  - Migration and troubleshooting

## Creating Plugins

For comprehensive instructions on creating plugins, see [CREATING_PLUGINS.md](./CREATING_PLUGINS.md).

For ready-to-use plugin templates in Rust and Go, see [TEMPLATES.md](./TEMPLATES.md).

## License

[Apache 2.0](./LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=hyper-mcp-rs/hyper-mcp&type=Date)](https://www.star-history.com/#hyper-mcp-rs/hyper-mcp&Date)
