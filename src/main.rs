fn main() -> anyhow::Result<()> {
    let app: dvb_gse::cli::App = dvb_gse::cli::App::with_default_metrics()?;
    app.run()
}
