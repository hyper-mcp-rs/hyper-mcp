<div align="center">
  <picture>
    <img alt="hyper-mcp logo" src="./assets/logo.png" width="50%">
  </picture>
</div>

<div align="center">

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://crates.io/crates/hyper-mcp)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue)](#license)
[![Issues - hyper-mcp](https://img.shields.io/github/issues/tuananh/hyper-mcp)](https://github.com/tuananh/hyper-mcp/issues)
![GitHub Release](https://img.shields.io/github/v/release/tuananh/hyper-mcp)

<a href="https://trendshift.io/repositories/13451" target="_blank"><img src="https://trendshift.io/api/badge/repositories/13451" alt="tuananh%2Fhyper-mcp | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>

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
- Support all 3 protocols in the spec: `stdio`, `sse` and `streamble-http`.
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
   - Windows: `{FOLDERID_RoamingAppData}`. Eg: `C:\Users\Alice\AppData\Roaming`
   - macOS: `$HOME/Library/Application Support/hyper-mcp/config.json`

```json
{
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "qr_code": {
      "url": "oci://ghcr.io/tuananh/qrcode-plugin:latest"
    },
    "hash": {
      "url": "oci://ghcr.io/tuananh/hash-plugin:latest"
    },
    "myip": {
      "url": "oci://ghcr.io/tuananh/myip-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["1.1.1.1"]
      }
    },
    "fetch": {
      "url": "oci://ghcr.io/tuananh/fetch-plugin:latest",
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
- `oci://` - for OCI-compliant registries (like Docker Hub, GitHub Container Registry, etc.)
- `file://` - for local files
- `http://` or `https://` - for remote files
- `s3://` - for Amazon S3 objects (requires that you have your AWS credentials set up in the environment)

2. Start the server:

```sh
$ hyper-mcp
```

- By default, it will use `stdio` transport. If you want to use SSE, use flag `--transport sse` or streamable HTTP with `--transport streamable-http`.
- If you want to debug, use `RUST_LOG=info`.
- If you're loading unsigned OCI plugin, you need to set `insecure_skip_signature` flag or env var `HYPER_MCP_INSECURE_SKIP_SIGNATURE` to `true`

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

- [time](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/time): Get current time and do time calculations (Rust)
- [qr_code](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/qr-code): Generate QR codes (Rust)
- [hash](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/hash): Generate various types of hashes (Rust)
- [myip](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/myip): Get your current IP (Rust)
- [fetch](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/fetch): Basic webpage fetching (Rust)
- [crypto_price](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/crypto-price): Get cryptocurrency prices (Go)
- [fs](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/fs): File system operations (Rust)
- [github](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/github): GitHub plugin (Go)
- [eval_py](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/eval-py): Evaluate Python code with RustPython (Rust)
- [arxiv](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/arxiv): Search & download arXiv papers (Rust)
- [memory](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/memory): Let you store & retrieve memory, powered by SQLite (Rust)
- [sqlite](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/sqlite): Interact with SQLite (Rust)
- [crates-io](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/crates-io): Get crate general information, check crate latest version (Rust)
- [gomodule](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/gomodule): Get Go modules info, version (Rust)
- [qdrant](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/qdrant): keeping & retrieving memories to Qdrant vector search engine (Rust)
- [gitlab](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/gitlab): GitLab plugin (Rust)
- [meme_generator](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/meme-generator): Meme generator (Rust)
- [context7](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/context7): Lookup library documentation (Rust)
- [think](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/think): Think tool(Rust)
- [maven](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/maven): Maven plugin (Rust)
- [serper](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins/serper): Serper web search plugin (Rust)


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

## Creating Plugins

1. Install the [XTP CLI](https://docs.xtp.dylibso.com/docs/cli):
    ```sh
    curl https://static.dylibso.com/cli/install.sh -s | bash
    ```

2. Create a new plugin project:
    ```sh
    xtp plugin init --schema-file plugin-schema.yaml
    ```
    Follow the prompts to set up your plugin. This will create the necessary files and structure.

    For example, if you chose Rust as the language, it will create a `Cargo.toml`, `src/lib.rs` and a `src/pdk.rs` file.

3. Implement your plugin logic in the language appropriate files(s) created (e.g. - `Cargo.toml` and `src/lib.rs` for Rust)
    For example, if you chose Rust as the language you will need to update the `Cargo.toml` and `src/lib.rs` files.

    Be sure to modify the `.gitignore` that is created for you to allow committing your `Cargo.lock` file.

Check out our [example plugins](https://github.com/tuananh/hyper-mcp/tree/main/examples/plugins) for insight.

To publish a plugin:

```dockerfile
# example how to build with rust
FROM rust:1.88-slim AS builder

RUN rustup target add wasm32-wasip1 && \
    rustup component add rust-std --target wasm32-wasip1 && \
    cargo install cargo-auditable

WORKDIR /workspace
COPY . .
RUN cargo fetch
RUN cargo auditable build --release --target wasm32-wasip1

FROM scratch
WORKDIR /
COPY --from=builder /workspace/target/wasm32-wasip1/release/plugin.wasm /plugin.wasm

```

Then build and push:
```sh
docker build -t your-registry/plugin-name .
docker push your-registry/plugin-name
```

## License

[Apache 2.0](./LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=tuananh/hyper-mcp&type=Date)](https://www.star-history.com/#tuananh/hyper-mcp&Date)
