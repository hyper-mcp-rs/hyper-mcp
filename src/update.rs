//! Self-update support for the `--auto-update` flag.
//!
//! This module is a thin wrapper around the `auto-update` crate, configuring
//! it with hyper-mcp-specific values (repo, binary name, guard env, throttle
//! file). See the `auto-update` crate documentation for details on the update
//! flow.

use anyhow::Result;

/// Entry point for `--auto-update`.
///
/// On success with no update available, returns `Ok(())` and the caller
/// proceeds to start the server. If an update is applied, this function does
/// not return: it replaces the process image and re-executes with Unix
/// `exec()`, preserving stdio file descriptors. Any failure is returned as
/// an error; the caller is expected to log it and continue running the
/// current version.
pub async fn run() -> Result<()> {
    auto_update::Updater::new()
        .repo_owner("hyper-mcp-rs")
        .repo_name("hyper-mcp")
        .binary_name("hyper-mcp")
        .guard_env("HYPER_MCP_AUTO_UPDATED")
        .throttle_file("hyper-mcp-update-check")
        .windows_policy(auto_update::WindowsPolicy::Disabled)
        .run()
        .await
}
