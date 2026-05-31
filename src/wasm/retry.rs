//! Shared retry policy for plugin downloads.
//!
//! Every download path - HTTP, OCI manifest, OCI blob - wants the same shape:
//! exponential backoff, 5s cap between attempts, give up after ~30s of total
//! accumulated sleep. Defining the policy once here keeps tuning in a single
//! place instead of three copies of the same struct literal.

use backon::ExponentialBuilder;
use std::time::Duration;

/// Exponential backoff policy used by every plugin download path.
///
/// Schedule: start at 500ms, multiply by 1.5 each attempt, cap individual
/// sleeps at 5s, give up once total sleep exceeds 30s. Jitter is on so
/// concurrent retriers don't synchronise their wakeups.
///
/// `with_max_times(usize::MAX)` disables the retry-count cap so the total
/// elapsed delay is the only stop condition - matching the behaviour we had
/// under `backoff::ExponentialBackoff { max_elapsed_time: Some(30s), .. }`.
pub fn download_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(5))
        .with_factor(1.5)
        .with_total_delay(Some(Duration::from_secs(30)))
        .with_max_times(usize::MAX)
        .with_jitter()
}
