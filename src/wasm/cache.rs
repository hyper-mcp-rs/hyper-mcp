use std::{env::temp_dir, path::PathBuf, sync::LazyLock};

static CACHE_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let mut path = match dirs::cache_dir() {
        Some(path) => path,
        None => temp_dir(),
    };
    path.push("hyper-mcp");
    path
});

pub fn cache_dir() -> PathBuf {
    CACHE_DIR.clone()
}
