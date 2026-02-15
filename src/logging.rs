use std::sync::OnceLock;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[cfg(not(test))]
static LOGGING: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

#[cfg(test)]
static LOGGING: OnceLock<()> = OnceLock::new();

#[ctor::ctor]
fn _install_global_tracing() {
    LOGGING.get_or_init(|| {
        let fmt = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false)
            .with_span_events(FmtSpan::CLOSE);

        #[cfg(test)]
        {
            // Captured by the test harness (doesn't risk corrupting stdio MCP)
            fmt.with_test_writer().init();
            ()
        }

        #[cfg(not(test))]
        {
            // Cross-platform log directory
            let log_dir = std::env::var("HYPER_MCP_LOG_PATH")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::config_dir()
                        .map(|mut path| {
                            path.push("hyper-mcp");
                            path.push("logs");
                            path
                        })
                        .expect("Unable to determine log directory")
                });

            std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");

            // Rolling daily log file
            let file_appender = tracing_appender::rolling::daily(&log_dir, "mcp-server.log");

            // Non-blocking writer (important for stdio MCP)
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            fmt.with_writer(non_blocking).init();

            // Keep guard alive for flushing
            guard
        }
    });
}
