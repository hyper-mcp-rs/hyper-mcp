# hyper-mcp (Claude Code plugin)

This plugin wires the [`hyper-mcp`](https://github.com/hyper-mcp-rs/hyper-mcp)
WebAssembly-plugin MCP server into Claude Code.

## Prerequisites

This plugin distributes configuration only — **not** the `hyper-mcp` binary.
You must have `hyper-mcp` installed and available on your `PATH` first:

```sh
# Homebrew (macOS / Linux)
brew install hyper-mcp

# or from crates.io
cargo install hyper-mcp
```

Alternatively, download a pre-built binary from
[GitHub Releases](https://github.com/hyper-mcp-rs/hyper-mcp/releases):

| Platform | Architecture | Download |
|---|---|---|
| macOS | Apple Silicon (ARM64) | `hyper-mcp-aarch64-apple-darwin.tar.gz` |
| Linux | x86_64 | `hyper-mcp-x86_64-unknown-linux-gnu.tar.gz` |
| Linux | ARM64 | `hyper-mcp-aarch64-unknown-linux-gnu.tar.gz` |
| Windows | x86_64 | `hyper-mcp-x86_64-pc-windows-msvc.zip` |

- **macOS / Linux:** extract the `.tar.gz` and place `hyper-mcp` in `/usr/local/bin`.
- **Windows:** extract the `.zip` and place `hyper-mcp.exe` somewhere on your `PATH`.

If `hyper-mcp` is not on your `PATH`, the plugin will install but the MCP server
will fail to start (you'll see `Executable not found in $PATH` in the `/plugin`
**Errors** tab).

Loading `oci://` plugins also requires the
[`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) CLI on
your `PATH` for signature verification. If you only use `file://`, `http(s)://`,
or `s3://` plugins, cosign is not needed.

## Install

```text
/plugin marketplace add hyper-mcp-rs/hyper-mcp
/plugin install hyper-mcp@hyper-mcp-rs
/reload-plugins
```

## Configuration

The bundled [`config.json`](./config.json) loads a small set of signed
first-party plugins (`time`, `qr-code`, `hash`). To load your own plugins, edit
that file or point `--config-file` at your own config. See the
[main README](https://github.com/hyper-mcp-rs/hyper-mcp#getting-started) and
[`config.example.json`](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/config.example.json)
for the full set of options.
