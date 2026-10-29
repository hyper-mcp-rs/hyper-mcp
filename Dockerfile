# ------ Builder Stage --------------
FROM rust:1.99@sha256:09027f873d45b8ecd1dc86f1fa13b7a62b875c961f017a0e331267b350430137 AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign

# ------- Production Stage -----------
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

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
