use clap::Parser;
use dvb_gse::metrics::Metrics;

#[derive(Parser, Debug)]
struct Args {
    #[command(flatten)]
    args: dvb_gse::cli::Args,
    /// Custom argument included in the example
    #[arg(long)]
    custom_argument: String,
}

impl AsRef<dvb_gse::cli::Args> for Args {
    fn as_ref(&self) -> &dvb_gse::cli::Args {
        &self.args
    }
}

#[derive(Debug, Clone)]
struct CustomMetrics {
    bbframe_count: u64,
    gse_count: u64,
    custom_argument: String,
}

impl CustomMetrics {
    fn new(custom_argument: String) -> CustomMetrics {
        CustomMetrics {
            bbframe_count: 0,
            gse_count: 0,
            custom_argument,
        }
    }
}

impl Metrics for CustomMetrics {
    fn bbframe_received(&mut self, _bbframe: &bytes::Bytes) {
        self.bbframe_count += 1;
        log::info!(
            "[{}] BBFRAME received (total {})",
            self.custom_argument,
            self.bbframe_count
        );
    }

    fn bbframe_error(&mut self, error: &std::io::Error) {
        log::info!("[{}] BBFRAME error: {error}", self.custom_argument);
    }

    fn gse_pdu_received(&mut self, _pdu: &dvb_gse::gsepacket::PDU) {
        self.gse_count += 1;
        log::info!(
            "[{}] GSE PDU received (total {})",
            self.custom_argument,
            self.gse_count
        );
    }

    fn gse_pdu_dropped_label_filtering(&mut self, _pdu: &dvb_gse::gsepacket::PDU) {
        log::info!(
            "[{}] GSE PDU dropped by label filtering",
            self.custom_argument
        );
    }

    fn tcp_client_connected(&mut self, _stream: &std::net::TcpStream) {
        log::info!("[{}] TCP client connected", self.custom_argument);
    }

    fn tcp_client_finished(&mut self) {
        log::info!("[{}] TCP client finished", self.custom_argument);
    }

    fn tun_error(&mut self, error: &std::io::Error, _pdu: &dvb_gse::gsepacket::PDU) {
        log::info!("[{}] TUN write error: {error}", self.custom_argument);
    }
}

fn main() -> anyhow::Result<()> {
    let app: dvb_gse::cli::App<Args, CustomMetrics> =
        dvb_gse::cli::App::new(|args: &Args| Ok(CustomMetrics::new(args.custom_argument.clone())))?;
    app.run()
}
