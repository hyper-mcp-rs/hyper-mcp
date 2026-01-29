use dashmap::DashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::{Mutex, OwnedMutexGuard};
use url::Url;

pub static DOWNLOAD_LOCKS: LazyLock<Locks> = LazyLock::new(|| Locks(DashMap::new()));

pub struct Locks(DashMap<Url, Arc<Mutex<()>>>);

impl Locks {
    pub async fn lock(&self, url: &Url) -> OwnedMutexGuard<()> {
        let arc = self
            .0
            .entry(url.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();

        arc.lock_owned().await
    }
}
