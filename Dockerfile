# ------ Builder Stage --------------
FROM rust:1.92 AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
RUN cargo fetch
COPY src ./src
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v2.6.2 AS cosign

# ------- Production Stage -----------
FROM debian:13-slim

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
