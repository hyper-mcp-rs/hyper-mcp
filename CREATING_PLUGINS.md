# Creating Plugins

> **📌 Recommended: Use Plugin Templates**
>
> The fastest and easiest way to create a plugin is to use the provided templates. Templates include all necessary boilerplate, build configuration, and documentation out of the box.
>
> **[👉 Start with the Plugin Templates](./TEMPLATES.md)**

Check out our [example plugins](https://github.com/hyper-mcp-rs/hyper-mcp/tree/main/examples/plugins/v2) for insight.

> Note: Prior versions of hyper-mcp used a different plugin interface (v1). While this plugin interface is still supported, new plugins should use the v2 interface.

## Quick Start with Templates (Recommended Method)

The recommended way to create a new plugin:

1. **Browse available templates** in [`templates/plugins/`](./TEMPLATES.md)

2. **Copy the template** for your language:
   ```sh
   cp -r templates/plugins/rust/ ../my-plugin/
   cd ../my-plugin/
   ```

3. **Follow the template README** - each template includes comprehensive setup instructions, examples, and best practices

4. **Customize and implement** your plugin logic

5. **Build and publish** using the provided `Dockerfile`

See [Plugin Templates Documentation](./TEMPLATES.md) for complete details and language options.

## Using XTP (Alternative Method)

If you prefer to use the XTP CLI tool:

1. Install the [XTP CLI](https://docs.xtp.dylibso.com/docs/cli):
    ```sh
    curl https://static.dylibso.com/cli/install.sh -s | bash
    ```

2. Create a new plugin project:
    ```sh
    xtp plugin init --schema-file xtp-plugin-schema.yaml
    ```
    Follow the prompts to set up your plugin. This will create the necessary files and structure.

    For example, if you chose Rust as the language, it will create a `Cargo.toml`, `src/lib.rs` and a `src/pdk.rs` file.

3. Implement your plugin logic in the language appropriate files(s) created (e.g. - `Cargo.toml` and `src/lib.rs` for Rust)
    For example, if you chose Rust as the language you will need to update the `Cargo.toml` and `src/lib.rs` files.

    Be sure to modify the `.gitignore` that is created for you to allow committing your `Cargo.lock` file.

## Publishing Plugins

### Rust

To publish a Rust plugin:

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

**Note:** The Rust template includes this Dockerfile and all necessary build configuration - no additional setup needed if you're using the template.

## Next Steps

- **[📖 Plugin Templates Documentation](./TEMPLATES.md)** - Comprehensive guide to using templates
- **[🚀 Rust Plugin Template](./templates/plugins/rust/README.md)** - Complete Rust plugin setup and development guide
- **[📚 Example Plugins](https://github.com/hyper-mcp-rs/hyper-mcp/tree/main/examples/plugins)** - Working examples to learn from
- **[🔗 MCP Protocol Specification](https://spec.modelcontextprotocol.io/)** - Protocol details and specifications
- **[⚙️ Extism Documentation](https://docs.extism.org/)** - Plugin runtime and PDK documentation
