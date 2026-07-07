# AGENTS.md

## Project Overview

hyper-mcp is a Rust-based Model Context Protocol server that loads and manages plugins (WASM binaries) at runtime.

## Tooling

- **defuddle** — Fetches web pages and converts them to clean Markdown. Use when you need content from a URL.
- **context7** — Queries documentation for any library or framework. Always resolve the library ID first via `resolve_library_id`, then query via `query_docs`.
- **sentrux** — Enforces architectural constraints defined in `.sentrux/rules.toml`. Run `check_rules` before submitting changes to ensure compliance.

## Commits

Always sign commits with `-s` (`git commit -s`). Never bypass git hooks. Resolve any lefthook errors from pre-commit or pre-push hooks before finishing.

## Testing

**Unit tests are mandatory for new functionality.** Every new feature, module, or non-trivial change must be accompanied by tests. Do not add code without tests.

**Rust code must pass `cargo fmt` and `cargo clippy`.** Run both before submitting changes.

## Session Constraints

**Sentrux session checks are mandatory.** Always call `session_start` at the beginning of every session to establish a quality baseline. At the end of a session, call `session_end` to compare the final state against the baseline.

**Quality drops must be called out.** If `session_end` reports any degradation (modularity, acyclicity, depth, equality, or redundancy), document the specific violations and explain why they occurred. Do not ignore or silently accept quality declines.

**Rescan boundaries.** Call `rescan` whenever you make edits that may affect the quality signals (file creation, deletion, or structural changes). The scan picks up file changes since the last scan and re-evaluates the quality baseline. Always rescan after meaningful changes before running `session_end` to ensure the final comparison reflects the actual state of the codebase.
