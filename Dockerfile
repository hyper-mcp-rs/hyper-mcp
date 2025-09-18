FROM --platform=$BUILDPLATFORM rust:1.90 AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
RUN cargo fetch
COPY src ./src
RUN cargo auditable build --release --locked

FROM gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.authors="me@tuananh.org" \
      org.opencontainers.image.url="https://github.com/tuananh/hyper-mcp" \
      org.opencontainers.image.source="https://github.com/tuananh/hyper-mcp" \
      org.opencontainers.image.vendor="github.com/tuananh/hyper-mcp" \
      io.modelcontextprotocol.server.name="io.github.tuananh/hyper-mcp"

WORKDIR /app
COPY --from=builder /app/target/release/hyper-mcp /usr/local/bin/hyper-mcp
ENTRYPOINT ["/usr/local/bin/hyper-mcp"]
