# ------ Builder Stage --------------
FROM rust:1.99@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign

# ------- Production Stage -----------
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

LABEL org.opencontainers.image.authors="joseph.wortmann@gmail.com" \
    org.opencontainers.image.url="https://github.com/hyper-mcp-rs/hyper-mcp" \
    org.opencontainers.image.source="https://github.com/hyper-mcp-rs/hyper-mcp" \
    org.opencontainers.image.vendor="github.com/hyper-mcp-rs/hyper-mcp" \
    io.modelcontextprotocol.server.name="io.github.hyper-mcp-rs/hyper-mcp"

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

WORKDIR /app
COPY --from=builder /app/target/release/hyper-mcp /usr/local/bin/hyper-mcp
ENTRYPOINT ["/usr/local/bin/hyper-mcp"]
