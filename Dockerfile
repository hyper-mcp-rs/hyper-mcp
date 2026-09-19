# ------ Builder Stage --------------
FROM rust:1.98@sha256:c92b3414e418f5b250f13c5bd393f90192f0b4bb4767e64f29c9e583197b27cb AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

# ------- Production Stage -----------
FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

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
