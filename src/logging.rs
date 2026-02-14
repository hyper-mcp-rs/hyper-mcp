use once_cell::sync::OnceCell;
use tracing_subscriber::EnvFilter;

static LOGGING: OnceCell<()> = OnceCell::new();

#[ctor::ctor]
fn _install_global_tracing() {
    LOGGING.get_or_init(|| {
        let fmt = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false);

        #[cfg(test)]
        let fmt = fmt.with_test_writer();

        #[cfg(not(test))]
        let fmt = fmt.with_writer(std::io::stderr);

        fmt.init();
    });
}
