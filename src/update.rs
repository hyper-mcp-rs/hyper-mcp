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

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

/// The version this binary was compiled as (clean semver, e.g. `0.8.1`).
///
/// This intentionally uses the crate version rather than the git-describe
/// string shown by `--version`: releases are tagged from this value, and it is
/// always clean semver, which is what the release-tag comparison below needs.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The exact target triple, captured by `build.rs` (e.g. `aarch64-apple-darwin`).
const TARGET: &str = env!("BUILD_TARGET");
/// The repository URL from `Cargo.toml`, used to derive the GitHub owner/repo.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
/// Set on the re-executed process so a single launch updates at most once and
/// can never enter a restart loop, even if version detection is off.
const GUARD_ENV: &str = "HYPER_MCP_AUTO_UPDATED";

/// The throttle file name (fixed, no cleanup needed).
const THROTTLE_FILE: &str = "hyper-mcp-update-check";

/// The throttle window: 15 minutes.
const THROTTLE_WINDOW: Duration = Duration::from_secs(15 * 60);

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

#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(serde::Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Entry point for `--auto-update`.
///
/// On success with no update available, returns `Ok(())` and the caller
/// proceeds to start the server. If an update is applied, this function does
/// not return: it replaces the process image (Unix) or exits after the child
/// finishes (Windows). Any failure is returned as an error; the caller is
/// expected to log it and continue running the current version.
pub async fn run() -> Result<()> {
    if std::env::var_os(GUARD_ENV).is_some() {
        tracing::debug!("Auto-update guard set; already updated this launch, skipping check");
        return Ok(());
    }

    // Throttle: skip if we checked within the last 15 minutes.
    if !should_check() {
        tracing::info!("Auto-update: check skipped (within 15-min window)");
        return Ok(());
    }

    // Best-effort cleanup of a leftover backup from a previous Windows update.
    #[cfg(windows)]
    if let Ok(current) = std::env::current_exe() {
        let _ = std::fs::remove_file(current.with_extension("old"));
    }

    let (owner, repo) = parse_repository(REPOSITORY)?;
    let install_path = std::env::current_exe()
        .context("locating current executable")?
        .canonicalize()
        .context("canonicalizing current executable path")?;

    let plan = Plan {
        releases_url: format!("https://api.github.com/repos/{owner}/{repo}/releases/latest"),
        user_agent: format!("hyper-mcp/{CURRENT_VERSION}"),
        current_version: semver::Version::parse(CURRENT_VERSION)
            .with_context(|| format!("parsing current version `{CURRENT_VERSION}`"))?,
        archive_name: format!("hyper-mcp-{TARGET}.{ARCHIVE_EXT}"),
        checksum_name: format!("checksums-{TARGET}.txt"),
        bin_name: BIN_NAME.to_string(),
        install_path,
    };

    tracing::info!(
        "Auto-update: checking for newer release at {}",
        plan.releases_url
    );
    match execute(&plan).await {
        Ok(Outcome::UpToDate) => {
            touch_throttle();
            tracing::info!(
                "Auto-update: already on the latest version ({})",
                plan.current_version
            );
            Ok(())
        }
        Ok(Outcome::Installed) => {
            touch_throttle();
            tracing::info!("Auto-update: installed new binary, restarting");
            restart(&plan.install_path)
        }
        Err(e) => {
            touch_throttle();
            Err(e)
        }
    }
}

/// Everything the updater needs to check for, download, verify, and install a
/// release. Kept as an explicit input so the whole flow can be driven against a
/// local server and a throwaway install path in tests, without touching the
/// network or the running executable.
struct Plan {
    /// Full URL of the "latest release" API endpoint.
    releases_url: String,
    /// `User-Agent` to send (GitHub requires one).
    user_agent: String,
    /// The version we are currently running.
    current_version: semver::Version,
    /// Expected name of the archive asset for this target.
    archive_name: String,
    /// Expected name of the checksum asset for this target.
    checksum_name: String,
    /// Name of the binary inside the archive.
    bin_name: String,
    /// File to replace with the downloaded binary.
    install_path: std::path::PathBuf,
}

/// Result of a successful update check.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The installed version is already the latest; nothing was changed.
    UpToDate,
    /// A newer binary was verified and written to `Plan::install_path`.
    Installed,
}

/// Checks for an update and, if one is available, downloads it, verifies its
/// checksum, and installs it to `plan.install_path`. Does not restart the
/// process; that is the caller's responsibility (see `run`). This contains the
/// full network + filesystem flow and is exercised end-to-end by the tests.
async fn execute(plan: &Plan) -> Result<Outcome> {
    // Bound the network work so a slow or unreachable GitHub can never hang
    // startup: `connect_timeout` catches a stalled connect, and `read_timeout`
    // is an idle timeout between reads, so a slow-but-steady archive download
    // is not penalized the way a fixed total timeout would be.
    let client = reqwest::Client::builder()
        .user_agent(&plan.user_agent)
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let release: Release = client
        .get(&plan.releases_url)
        .send()
        .await
        .context("requesting latest release")?
        .error_for_status()
        .context("latest release request returned an error status")?
        .json()
        .await
        .context("parsing latest release response")?;

    let latest_str = release.tag_name.trim_start_matches('v');
    let latest = semver::Version::parse(latest_str)
        .with_context(|| format!("parsing latest tag `{}`", release.tag_name))?;

    if latest <= plan.current_version {
        return Ok(Outcome::UpToDate);
    }
    tracing::info!(
        "Auto-update: upgrading from {} to {latest}",
        plan.current_version
    );

    let archive_url = asset_url(&release, &plan.archive_name)?;
    let checksum_url = asset_url(&release, &plan.checksum_name)?;

    let archive = client
        .get(archive_url)
        .send()
        .await
        .with_context(|| format!("downloading {}", plan.archive_name))?
        .error_for_status()
        .with_context(|| format!("download of {} returned an error status", plan.archive_name))?
        .bytes()
        .await
        .with_context(|| format!("reading body of {}", plan.archive_name))?;

    let checksum_text = client
        .get(checksum_url)
        .send()
        .await
        .with_context(|| format!("downloading {}", plan.checksum_name))?
        .error_for_status()
        .with_context(|| {
            format!(
                "download of {} returned an error status",
                plan.checksum_name
            )
        })?
        .text()
        .await
        .with_context(|| format!("reading body of {}", plan.checksum_name))?;

    verify_checksum(&archive, &checksum_text, &plan.archive_name)?;
    tracing::info!("Auto-update: checksum verified for {}", plan.archive_name);

    let new_binary = extract_binary(&archive, &plan.bin_name)?;
    install_binary(&plan.install_path, &new_binary)?;
    Ok(Outcome::Installed)
}

/// Derives `(owner, repo)` from a GitHub repository URL such as
/// `https://github.com/hyper-mcp-rs/hyper-mcp`.
fn parse_repository(url: &str) -> Result<(String, String)> {
    let rest = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .ok_or_else(|| anyhow!("unsupported repository URL `{url}`; expected a github.com URL"))?;
    let (owner, repo) = rest
        .split_once('/')
        .ok_or_else(|| anyhow!("could not parse owner/repo from `{url}`"))?;
    if owner.is_empty() || repo.is_empty() {
        bail!("could not parse owner/repo from `{url}`");
    }
    Ok((owner.to_string(), repo.to_string()))
}

/// Finds the download URL for the named asset in a release.
fn asset_url<'a>(release: &'a Release, name: &str) -> Result<&'a str> {
    release
        .assets
        .iter()
        .find(|a| a.name == name)
        .map(|a| a.browser_download_url.as_str())
        .ok_or_else(|| {
            anyhow!(
                "release does not contain expected asset `{name}` \
                 (target `{TARGET}` may not be a supported release platform)"
            )
        })
}

/// Verifies that `archive` hashes to the SHA-256 recorded for `archive_name` in
/// a `sha256sum`-style checksum file (the format produced by the release
/// workflow).
///
/// The published checksum file lists more than one asset (the archive and the
/// `.mcpb` bundle share a single `checksums-<target>.txt`), so the correct line
/// is matched by filename rather than by position.
fn verify_checksum(archive: &[u8], checksum_text: &str, archive_name: &str) -> Result<()> {
    let expected = checksum_text
        .lines()
        .filter_map(|line| {
            // Each line is `<hex-digest> <mode><path>`; `<mode>` is ` ` (text)
            // or `*` (binary), and `<path>` may carry a `dist/` prefix.
            let (digest, path) = line.split_once(char::is_whitespace)?;
            let file = path.trim().trim_start_matches('*').rsplit('/').next()?;
            (file == archive_name).then_some(digest)
        })
        .next()
        .map(str::to_ascii_lowercase)
        .filter(|tok| tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            anyhow!("checksum file did not contain a valid SHA-256 digest for `{archive_name}`")
        })?;

    let mut hasher = Sha256::new();
    hasher.update(archive);
    let actual = hex::encode(hasher.finalize());

    if actual != expected {
        bail!("checksum mismatch: expected {expected}, computed {actual}");
    }
    Ok(())
}

#[cfg(not(windows))]
const ARCHIVE_EXT: &str = "tar.gz";
#[cfg(windows)]
const ARCHIVE_EXT: &str = "zip";

#[cfg(not(windows))]
const BIN_NAME: &str = "hyper-mcp";
#[cfg(windows)]
const BIN_NAME: &str = "hyper-mcp.exe";

/// Extracts the named binary from the downloaded `.tar.gz` release archive.
#[cfg(not(windows))]
fn extract_binary(archive: &[u8], bin_name: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar = tar::Archive::new(decoder);
    for entry in tar.entries().context("reading tar archive")? {
        let mut entry = entry.context("reading tar entry")?;
        let is_bin = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_os_string()))
            .is_some_and(|n| n == *bin_name);
        if is_bin {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("reading binary from tar")?;
            return Ok(buf);
        }
    }
    bail!("`{bin_name}` not found in downloaded archive");
}

/// Extracts the named binary from the downloaded `.zip` release archive.
#[cfg(windows)]
fn extract_binary(archive: &[u8], bin_name: &str) -> Result<Vec<u8>> {
    use std::io::Read;

    let cursor = std::io::Cursor::new(archive);
    let mut zip = zip::ZipArchive::new(cursor).context("reading zip archive")?;
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).context("reading zip entry")?;
        let matches = file
            .enclosed_name()
            .and_then(|p| p.file_name().map(|n| n.to_os_string()))
            .is_some_and(|n| n == *bin_name);
        if matches {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .context("reading binary from zip")?;
            return Ok(buf);
        }
    }
    bail!("`{bin_name}` not found in downloaded archive");
}

/// Writes `new_binary` over `install_path`, replacing it atomically.
///
/// The new binary is first written next to the destination (same filesystem,
/// so the swap is an atomic rename) and then moved into place. On Windows,
/// where a running executable cannot be overwritten, the existing file is
/// renamed aside first; it is cleaned up on the next launch.
fn install_binary(install_path: &Path, new_binary: &[u8]) -> Result<()> {
    let dir = install_path
        .parent()
        .context("install path has no parent directory")?;

    let staged = dir.join(format!(".hyper-mcp-update-{}", std::process::id()));
    std::fs::write(&staged, new_binary)
        .with_context(|| format!("writing new binary to {}", staged.display()))?;

    // Install the staged binary, cleaning it up on any failure so a partial
    // update never leaves a stray temp file next to the executable.
    let result = install_staged(install_path, &staged);
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Moves the already-written `staged` binary into `install_path`. Split out from
/// `install_binary` so the caller can clean up `staged` on any error path.
fn install_staged(install_path: &Path, staged: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o755))
            .context("setting permissions on new binary")?;
        // Atomically replace the on-disk file. A running process keeps its open
        // inode, so this is safe even when replacing the current executable.
        std::fs::rename(staged, install_path).context("replacing executable")?;
    }

    #[cfg(windows)]
    {
        // Windows cannot overwrite a running executable, but it can rename it.
        let backup = install_path.with_extension("old");
        let _ = std::fs::remove_file(&backup);
        if install_path.exists() {
            std::fs::rename(install_path, &backup).context("moving executable aside")?;
        }
        if let Err(e) = std::fs::rename(staged, install_path) {
            // Try to restore the original so we don't leave a broken install.
            let _ = std::fs::rename(&backup, install_path);
            return Err(e).context("installing new executable");
        }
    }

    Ok(())
}

/// Restarts the process using the freshly installed executable, preserving the
/// original arguments and stdio. Does not return on success.
fn restart(exe: &Path) -> Result<()> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut command = std::process::Command::new(exe);
    command.args(&args).env(GUARD_ENV, "1");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Replaces the current process image; stdio file descriptors (and thus
        // the MCP stdio transport) are preserved across the exec.
        let err = command.exec();
        Err(err).context("re-executing updated binary")
    }

    #[cfg(windows)]
    {
        // No exec() on Windows: run the new binary as a child inheriting our
        // stdio, then exit with its status so the parent process goes away.
        let status = command.status().context("spawning updated binary")?;
        std::process::exit(status.code().unwrap_or(0));
    }
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

    #[test]
    fn verify_checksum_accepts_matching_digest() {
        let data = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hex::encode(hasher.finalize());
        let line = format!("{digest}  dist/hyper-mcp-x86_64-unknown-linux-gnu.tar.gz\n");
        assert!(verify_checksum(data, &line, "hyper-mcp-x86_64-unknown-linux-gnu.tar.gz").is_ok());
    }

    #[test]
    fn verify_checksum_matches_by_filename_regardless_of_order() {
        // A real `checksums-<target>.txt` lists both the `.mcpb` bundle and the
        // archive; the archive's digest must be selected by name, not position.
        let data = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hex::encode(hasher.finalize());
        let text = format!(
            "{}  dist/hyper-mcp-x86_64-unknown-linux-gnu.mcpb\n\
             {digest}  dist/hyper-mcp-x86_64-unknown-linux-gnu.tar.gz\n",
            "0".repeat(64)
        );
        assert!(verify_checksum(data, &text, "hyper-mcp-x86_64-unknown-linux-gnu.tar.gz").is_ok());
    }

    #[test]
    fn verify_checksum_rejects_mismatch() {
        let line = format!("{}  whatever\n", "a".repeat(64));
        assert!(verify_checksum(b"hello world", &line, "whatever").is_err());
    }

    #[test]
    fn verify_checksum_rejects_missing_filename() {
        // Digest present, but not for the asset we are installing.
        let line = format!("{}  some-other-file.tar.gz\n", "a".repeat(64));
        assert!(verify_checksum(b"hello world", &line, "wanted.tar.gz").is_err());
    }

    #[test]
    fn verify_checksum_rejects_garbage() {
        assert!(verify_checksum(b"data", "not-a-checksum\n", "any.tar.gz").is_err());
    }

    #[test]
    fn finds_named_asset() {
        let release = Release {
            tag_name: "v1.2.3".to_string(),
            assets: vec![Asset {
                name: "checksums-foo.txt".to_string(),
                browser_download_url: "https://example.com/checksums-foo.txt".to_string(),
            }],
        };
        assert_eq!(
            asset_url(&release, "checksums-foo.txt").unwrap(),
            "https://example.com/checksums-foo.txt"
        );
        assert!(asset_url(&release, "missing").is_err());
    }

    // ---- End-to-end tests -------------------------------------------------
    //
    // These drive the full `execute` flow (HTTP fetch -> checksum verify ->
    // archive extract -> on-disk install) against a local mock release server
    // and a throwaway install path, so the updater is validated before it
    // ever ships. The process-replacing `restart` step is intentionally not
    // invoked here; `execute` stops once the new binary is on disk.

    use axum::{Router, extract::State, routing::get};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockRelease {
        release_json: String,
        archive: Vec<u8>,
        checksum: String,
    }

    async fn latest(State(s): State<Arc<MockRelease>>) -> String {
        s.release_json.clone()
    }
    async fn serve_archive(State(s): State<Arc<MockRelease>>) -> Vec<u8> {
        s.archive.clone()
    }
    async fn serve_checksum(State(s): State<Arc<MockRelease>>) -> String {
        s.checksum.clone()
    }

    /// Builds a release archive containing `contents` under `bin_name`, in the
    /// same format the release workflow produces for this platform.
    #[cfg(not(windows))]
    fn make_archive(bin_name: &str, contents: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::GzEncoder};
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut builder = tar::Builder::new(&mut enc);
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, bin_name, contents)
                .unwrap();
            builder.finish().unwrap();
        }
        enc.finish().unwrap()
    }

    #[cfg(windows)]
    fn make_archive(bin_name: &str, contents: &[u8]) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            zw.start_file(bin_name, SimpleFileOptions::default())
                .unwrap();
            zw.write_all(contents).unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    /// `sha256sum`-style checksum file for `data`, matching the release workflow
    /// format: a `.mcpb` entry followed by the archive entry, both `dist/`
    /// prefixed. The leading unrelated entry ensures the updater selects the
    /// archive's digest by filename rather than by position.
    fn checksum_file(data: &[u8], archive_name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!(
            "{}  dist/hyper-mcp-bundle.mcpb\n{}  dist/{archive_name}\n",
            "0".repeat(64),
            hex::encode(hasher.finalize()),
        )
    }

    /// Starts a local server that mimics the GitHub "latest release" endpoint
    /// plus the archive/checksum downloads, and returns its base URL.
    async fn spawn_release(
        tag: &str,
        archive: Vec<u8>,
        checksum: String,
        archive_name: &str,
        checksum_name: &str,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let release_json = serde_json::json!({
            "tag_name": tag,
            "assets": [
                { "name": archive_name, "browser_download_url": format!("{base}/archive") },
                { "name": checksum_name, "browser_download_url": format!("{base}/checksum") },
            ]
        })
        .to_string();
        let state = Arc::new(MockRelease {
            release_json,
            archive,
            checksum,
        });
        let app = Router::new()
            .route("/releases/latest", get(latest))
            .route("/archive", get(serve_archive))
            .route("/checksum", get(serve_checksum))
            .with_state(state);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    fn plan_for(base: &str, current: &str, install_path: std::path::PathBuf) -> Plan {
        Plan {
            releases_url: format!("{base}/releases/latest"),
            user_agent: "hyper-mcp-test".to_string(),
            current_version: semver::Version::parse(current).unwrap(),
            archive_name: format!("hyper-mcp-{TARGET}.{ARCHIVE_EXT}"),
            checksum_name: format!("checksums-{TARGET}.txt"),
            bin_name: BIN_NAME.to_string(),
            install_path,
        }
    }

    #[tokio::test]
    async fn e2e_downloads_verifies_and_installs_newer_version() {
        let new_contents = b"BRAND-NEW-HYPER-MCP-BINARY";
        let archive = make_archive(BIN_NAME, new_contents);
        let archive_name = format!("hyper-mcp-{TARGET}.{ARCHIVE_EXT}");
        let checksum_name = format!("checksums-{TARGET}.txt");
        let checksum = checksum_file(&archive, &archive_name);
        let base = spawn_release(
            "v9999.0.0",
            archive,
            checksum,
            &archive_name,
            &checksum_name,
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let install_path = dir.path().join(BIN_NAME);
        std::fs::write(&install_path, b"OLD-BINARY").unwrap();

        let plan = plan_for(&base, "0.0.1", install_path.clone());
        let outcome = execute(&plan).await.unwrap();

        assert_eq!(outcome, Outcome::Installed);
        assert_eq!(std::fs::read(&install_path).unwrap(), new_contents);
    }

    #[tokio::test]
    async fn e2e_skips_install_when_up_to_date() {
        let archive = make_archive(BIN_NAME, b"irrelevant");
        let archive_name = format!("hyper-mcp-{TARGET}.{ARCHIVE_EXT}");
        let checksum_name = format!("checksums-{TARGET}.txt");
        let checksum = checksum_file(&archive, &archive_name);
        let base = spawn_release("v1.0.0", archive, checksum, &archive_name, &checksum_name).await;

        let dir = tempfile::tempdir().unwrap();
        let install_path = dir.path().join(BIN_NAME);
        std::fs::write(&install_path, b"ORIGINAL").unwrap();

        let plan = plan_for(&base, "2.0.0", install_path.clone());
        let outcome = execute(&plan).await.unwrap();

        assert_eq!(outcome, Outcome::UpToDate);
        assert_eq!(std::fs::read(&install_path).unwrap(), b"ORIGINAL");
    }

    #[tokio::test]
    async fn e2e_rejects_bad_checksum_without_touching_binary() {
        let archive = make_archive(BIN_NAME, b"BRAND-NEW-HYPER-MCP-BINARY");
        let archive_name = format!("hyper-mcp-{TARGET}.{ARCHIVE_EXT}");
        let checksum_name = format!("checksums-{TARGET}.txt");
        let bad_checksum = format!("{}  dist/{archive_name}\n", "0".repeat(64));
        let base = spawn_release(
            "v9999.0.0",
            archive,
            bad_checksum,
            &archive_name,
            &checksum_name,
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let install_path = dir.path().join(BIN_NAME);
        std::fs::write(&install_path, b"ORIGINAL").unwrap();

        let plan = plan_for(&base, "0.0.1", install_path.clone());
        let err = execute(&plan).await.unwrap_err();

        assert!(
            err.to_string().contains("checksum"),
            "expected a checksum error, got: {err}"
        );
        assert_eq!(std::fs::read(&install_path).unwrap(), b"ORIGINAL");
    }
}
