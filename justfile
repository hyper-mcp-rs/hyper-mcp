hyper_mcp_bin := `realpath ./target/debug/hyper-mcp`

_default:
  @just --list --unsorted

all *args:
    just fmt {{args}}
    just clippy {{args}}

debug:
    npx @modelcontextprotocol/inspector {{hyper_mcp_bin}} --config-file ~/.config/hyper-mcp/config.json

run:
    cargo run

fmt *args:
    cargo fmt --all {{args}}

clippy *args:
    cargo clippy --all -- -D warnings {{args}}

renovate:
    docker run --rm \
        -e RENOVATE_TOKEN=$(gh auth token) \
        -e LOG_LEVEL=info \
        -v "$(pwd)/.github/renovate.json5:/usr/src/app/config.json" \
        renovate/renovate hyper-mcp-rs/hyper-mcp

install:
    sudo install -Dm755 target/debug/hyper-mcp /usr/local/bin/hyper-mcp
