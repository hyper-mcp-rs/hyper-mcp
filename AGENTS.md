# AGENTS.md

## Project Overview

hyper-mcp is a Rust-based Model Context Protocol server that loads and manages plugins (WASM binaries) at runtime.

## Tooling

- **defuddle** — Fetches web pages and converts them to clean Markdown. Use when you need content from a URL.
- **context7** — Queries documentation for any library or framework. Always resolve the library ID first via `resolve_library_id`, then query via `query_docs`.
- **sentrux** — Enforces architectural constraints defined in `.sentrux/rules.toml`. Run `check_rules` before submitting changes to ensure compliance.

## Commits

Always sign commits with `-s` (`git commit -s`). Resolve any lefthook errors from pre-commit or pre-push hooks before finishing.

## Testing

**Unit tests are mandatory for new functionality.** Every new feature, module, or non-trivial change must be accompanied by tests. Do not add code without tests.

**Rust code must pass `cargo fmt` and `cargo clippy`.** Run both before submitting changes.
