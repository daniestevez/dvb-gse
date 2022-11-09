#[cfg(feature = "cli")]
fn main() -> anyhow::Result<()> {
    dvb_gse::cli::main()
}

#[cfg(not(feature = "cli"))]
fn main() -> Result<(), &'static str> {
    Err("The CLI application needs to be built with the 'cli' flag enabled")
}
