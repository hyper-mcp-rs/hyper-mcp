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

The OCI loader accepts two types of artifacts:

1. **ORAS artifacts** (preferred method) - using `application/vnd.hyper-mcp.plugin.v2` artifact type
2. **Docker images** - must be `linux/amd64` architecture

Both methods **must be signed using cosign** for supply chain security.

### Method 1: ORAS Artifacts (Recommended)

ORAS artifacts are the preferred method as they are more efficient and purpose-built for distributing WebAssembly plugins.

Build the WebAssembly binary separately, then package it as an ORAS artifact 

**Example workflow** (see [rstime-plugin](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/rstime-plugin/.github/workflows/release.yml)):

```yaml
- name: Install ORAS
  uses: oras-project/setup-oras@v1

- name: Install cosign
  uses: sigstore/cosign-installer@faadad0cce49287aee09b3a48701e75088a2c6ad

- name: ORAS login to GHCR
  shell: bash
  run: |
    echo "${{ secrets.GITHUB_TOKEN }}" | oras login ghcr.io -u "${{ github.actor }}" --password-stdin

- name: Push ORAS artifact (plugin.wasm)
  shell: bash
  run: |
    oras push "ghcr.io/your-org/your-plugin:$TAG" \
      --artifact-type application/vnd.hyper-mcp.plugin.v2 \
      ./plugin.wasm:application/wasm

- name: Resolve digest
  id: digest
  shell: bash
  run: |
    DIGEST="$(
      oras manifest fetch "ghcr.io/your-org/your-plugin:$TAG" --descriptor \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
    )"
    echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"

- name: Sign ORAS artifact by digest
  shell: bash
  run: |
    cosign sign --yes "ghcr.io/your-org/your-plugin@${{ steps.digest.outputs.digest }}"
```

### Method 2: Docker Images

Docker images must target `linux/amd64` architecture. Build the WebAssembly binary separately, then package it in a minimal container.

**Efficient Dockerfile** (see [time-plugin](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/time-plugin/Dockerfile)):

```dockerfile
FROM scratch
WORKDIR /
# plugin.wasm must be present in the Docker build context
COPY plugin.wasm /plugin.wasm
```

**Example workflow** (see [time-plugin release workflow](https://github.com/hyper-mcp-rs/hyper-mcp/blob/main/time-plugin/.github/workflows/release.yml)):

```yaml
- name: Install cosign
  uses: sigstore/cosign-installer@faadad0cce49287aee09b3a48701e75088a2c6ad

- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@v3

- name: Log in to GitHub Container Registry
  uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}

- name: Build and push image (linux/amd64)
  uses: docker/build-push-action@v6
  with:
    context: .
    file: ./Dockerfile
    push: true
    platforms: linux/amd64
    provenance: false
    tags: ghcr.io/your-org/your-plugin:$TAG

- name: Resolve digest
  id: digest
  shell: bash
  run: |
    DIGEST="$(
      docker buildx imagetools inspect "ghcr.io/your-org/your-plugin:$TAG" \
        --format '{{json .Manifest}}' \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
    )"
    echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"

- name: Sign by digest
  shell: bash
  run: |
    cosign sign --yes "ghcr.io/your-org/your-plugin@${{ steps.digest.outputs.digest }}"
```

### Building the WebAssembly Binary

For all plugins, build the WebAssembly binary before packaging.

#### Rust

```sh
# Install wasm32-wasip1 target
rustup target add wasm32-wasip1

# Install cargo-auditable for supply chain security
cargo install cargo-auditable

# Build the plugin
cargo fetch
cargo auditable build --release --target wasm32-wasip1

# Copy to build context
cp target/wasm32-wasip1/release/plugin.wasm ./plugin.wasm
```

### Supply Chain Security

**All plugins must be signed with cosign.** This ensures:
- Authenticity: Verify the plugin came from the claimed source
- Integrity: Detect tampering or corruption
- Transparency: Audit trail via Sigstore's transparency log

**Always reference artifacts by digest** (not tags) for immutable, verifiable deployments:
```
ghcr.io/your-org/your-plugin@sha256:abc123...
```

Users can verify the signature:
```sh
cosign verify \
  --certificate-identity-regexp "https://github.com/your-org/your-plugin/.github/workflows/release.yml@refs/tags/v*" \
  --certificate-oidc-issuer-regexp "https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/your-plugin@sha256:...
```

## Next Steps

- **[📖 Plugin Templates Documentation](./TEMPLATES.md)** - Comprehensive guide to using templates
- **[🚀 Rust Plugin Template](./templates/plugins/rust/README.md)** - Complete Rust plugin setup and development guide
- **[📚 Example Plugins](https://github.com/hyper-mcp-rs/hyper-mcp/tree/main/examples/plugins)** - Working examples to learn from
- **[🔗 MCP Protocol Specification](https://spec.modelcontextprotocol.io/)** - Protocol details and specifications
- **[⚙️ Extism Documentation](https://docs.extism.org/)** - Plugin runtime and PDK documentation
