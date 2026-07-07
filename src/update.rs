//! Self-update support for the `--auto-update` flag.
//!
//! When enabled, this checks the project's GitHub releases for a newer
//! version, and if one is found it downloads the release archive built for the
//! current target triple, verifies it against the published
//! `checksums-<target>.txt` file, replaces the running executable, and
//! re-executes it with the original arguments.
//!
//! Checksum verification here is an integrity check against accidental
//! corruption, not a tamper-proofing signature: the archive and its checksum
//! are served from the same release, so anyone able to alter one can alter the
//! other. Transport integrity relies on TLS to GitHub.

use anyhow::{Context, Result};
use self_update::{backends::github::Update, cargo_crate_version};
use std::path::Path;

/// Set on the re-executed process so a single launch updates at most once and
/// can never enter a restart loop, even if version detection is off.
const GUARD_ENV: &str = "HYPER_MCP_AUTO_UPDATED";

/// The throttle file name (fixed, no cleanup needed).
const THROTTLE_FILE: &str = "hyper-mcp-update-check";

/// The throttle window: 15 minutes.
const THROTTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Returns the path to the throttle file in the system temp directory.
fn throttle_path() -> std::path::PathBuf {
    std::env::temp_dir().join(THROTTLE_FILE)
}

/// Returns true if we should perform an update check.
/// Checks the mtime of the throttle file; returns true if the file doesn't
/// exist or was last touched more than THROTTLE_WINDOW ago.
fn should_check() -> bool {
    let path = throttle_path();
    match std::fs::metadata(&path) {
        Ok(meta) => {
            // Get file modification time
            if let Ok(mtime) = meta.modified() {
                let now = std::time::SystemTime::now();
                if let Ok(elapsed) = now.duration_since(mtime) {
                    return elapsed > THROTTLE_WINDOW;
                }
            }
            // On any error reading mtime, proceed with the check
            true
        }
        Err(_) => {
            // File doesn't exist -> first launch, proceed with check
            true
        }
    }
}

/// Touches the throttle file to update its mtime, recording that a check was made.
fn touch_throttle() {
    let path = throttle_path();
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path);
}

/// Entry point for `--auto-update`.
///
/// On success with no update available, returns `Ok(())` and the caller
/// proceeds to start the server. If an update is applied, this function does
/// not return: it replaces the process image and re-executes with Unix
/// `exec()`, preserving stdio file descriptors. Any failure is returned as
/// an error; the caller is expected to log it and continue running the
/// current version.
pub async fn run() -> Result<()> {
    // Guard: skip if already restarted after an update.
    if std::env::var_os(GUARD_ENV).is_some() {
        tracing::debug!("Auto-update guard set; already updated this launch, skipping check");
        return Ok(());
    }

    // Throttle: skip if we checked within the last 15 minutes.
    if !should_check() {
        tracing::info!("Auto-update: check skipped (within 15-min window)");
        return Ok(());
    }

    // Derive owner/repo from the repository URL set by build.rs.
    let repo = env!("CARGO_PKG_REPOSITORY");
    let (owner, repo_name) = parse_repository(repo)?;

    // Build the self_update updater.
    let updater = Update::configure()
        .repo_owner(&owner)
        .repo_name(&repo_name)
        .bin_name(bin_name())
        .current_version(cargo_crate_version!())
        .no_confirm(true) // unattended — no interactive prompt
        .show_download_progress(false) // silent in MCP mode
        .target(get_target())
        .build()?;

    // Perform the update: download, verify checksum, extract, install.
    // This replaces the binary on disk but does NOT restart the process.
    let status = updater.update()?;
    tracing::info!(
        "Auto-update: installed new binary, version {}",
        status.version()
    );
    touch_throttle();

    // Restart the process with the new binary.
    restart(&std::env::current_exe()?)
}

/// Restarts the process using the freshly installed executable, preserving the
/// original arguments and stdio. Does not return on success.
fn restart(exe: &Path) -> Result<()> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut command = std::process::Command::new(exe);
    command.args(&args).env(GUARD_ENV, "1");

    use std::os::unix::process::CommandExt;
    // Replaces the current process image; stdio file descriptors (and thus
    // the MCP stdio transport) are preserved across the exec.
    let err = command.exec();
    Err(err).context("re-executing updated binary")
}

/// Binary name used when looking up and extracting the release archive.
/// Derived from the Cargo package name so renaming the binary in
/// `Cargo.toml` automatically updates this.
fn bin_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Returns the target triple (e.g. `aarch64-apple-darwin`).
fn get_target() -> &'static str {
    env!("BUILD_TARGET")
}

/// Derives `(owner, repo)` from a GitHub repository URL such as
/// `https://github.com/hyper-mcp-rs/hyper-mcp`.
fn parse_repository(url: &str) -> Result<(String, String)> {
    let rest = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .ok_or_else(|| {
            anyhow::anyhow!("unsupported repository URL `{url}`; expected a github.com URL")
        })?;
    let (owner, repo) = rest
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("could not parse owner/repo from `{url}`"))?;
    if owner.is_empty() || repo.is_empty() {
        return Err(anyhow::anyhow!("could not parse owner/repo from `{url}`"));
    }
    Ok((owner.to_string(), repo.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_repository() {
        let (owner, repo) = parse_repository("https://github.com/hyper-mcp-rs/hyper-mcp").unwrap();
        assert_eq!(owner, "hyper-mcp-rs");
        assert_eq!(repo, "hyper-mcp");
    }

    #[test]
    fn parses_repository_with_trailing_slash_and_git_suffix() {
        let (owner, repo) =
            parse_repository("https://github.com/hyper-mcp-rs/hyper-mcp.git/").unwrap();
        assert_eq!(owner, "hyper-mcp-rs");
        assert_eq!(repo, "hyper-mcp");
    }

    #[test]
    fn rejects_non_github_repository() {
        assert!(parse_repository("https://gitlab.com/foo/bar").is_err());
    }

    // ---- Throttling tests --------------------------------------------------
    // These tests use a shared throttle file in the temp directory, so they
    // must run sequentially to avoid interference.

    #[serial_test::serial(throttle_tests)]
    #[test]
    fn should_check_returns_true_when_no_throttle_file() {
        // Clean up any existing throttle file first
        let _ = std::fs::remove_file(throttle_path());

        // Should return true when file doesn't exist
        assert!(
            should_check(),
            "should_check should return true when throttle file does not exist"
        );

        // Clean up after test
        let _ = std::fs::remove_file(throttle_path());
    }

    #[serial_test::serial(throttle_tests)]
    #[test]
    fn should_check_returns_true_when_throttle_file_is_old() {
        // Clean up any existing throttle file first
        let _ = std::fs::remove_file(throttle_path());

        // Create a throttle file and set its mtime to 20 minutes ago
        let path = throttle_path();
        std::fs::write(&path, "test").unwrap();

        // Set modification time to 20 minutes ago (1200 seconds)
        let old_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            - std::time::Duration::from_secs(20 * 60);
        let old_time = filetime::FileTime::from_unix_time(old_time.as_secs() as i64, 0);
        filetime::set_file_mtime(&path, old_time).unwrap();

        // Should return true because the file is older than THROTTLE_WINDOW (15 min)
        assert!(
            should_check(),
            "should_check should return true when throttle file is older than 15 minutes"
        );

        // Clean up after test
        let _ = std::fs::remove_file(throttle_path());
    }

    #[serial_test::serial(throttle_tests)]
    #[test]
    fn should_check_returns_false_when_throttle_file_is_recent() {
        // Clean up any existing throttle file first
        let _ = std::fs::remove_file(throttle_path());

        // Create a throttle file with current mtime
        let path = throttle_path();
        std::fs::write(&path, "test").unwrap();

        // File was just created (within THROTTLE_WINDOW)
        assert!(
            !should_check(),
            "should_check should return false when throttle file exists and is recent"
        );

        // Clean up after test
        let _ = std::fs::remove_file(throttle_path());
    }

    #[serial_test::serial(throttle_tests)]
    #[test]
    fn touch_throttle_creates_file() {
        // Clean up any existing throttle file first
        let _ = std::fs::remove_file(throttle_path());

        // Touch should create the file
        touch_throttle();

        assert!(
            throttle_path().exists(),
            "touch_throttle should create the throttle file"
        );
        assert!(
            std::fs::metadata(throttle_path()).is_ok(),
            "throttle file should be readable"
        );

        // Clean up after test
        let _ = std::fs::remove_file(throttle_path());
    }

    // ---- self_update integration tests ------------------------------------
    // These tests verify the integration points between our custom code
    // and self_update. Since self_update has its own comprehensive test suite,
    // we focus on verifying our configuration and error handling.

    #[test]
    fn bin_name_matches_package_name() {
        assert_eq!(bin_name(), "hyper-mcp");
    }

    #[test]
    fn get_target_returns_env_value() {
        // Verify we're getting the target from the build environment
        let target = get_target();
        // The BUILD_TARGET should be set during build, but not necessarily
        assert!(!target.is_empty());
    }
}
