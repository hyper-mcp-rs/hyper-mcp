fn main() {
    // Expose the exact target triple the binary was built for so the
    // auto-updater can pick the matching release asset (e.g.
    // `hyper-mcp-aarch64-apple-darwin.tar.gz`). Cargo sets `TARGET` for
    // build scripts but does not otherwise expose it to the crate.
    let target = std::env::var("TARGET").expect("cargo always sets TARGET for build scripts");
    println!("cargo:rustc-env=BUILD_TARGET={target}");
}
