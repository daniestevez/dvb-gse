use clap::Parser;
use dvb_gse::metrics::Metrics;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering::Relaxed},
};

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
    // These are Arc's containing an atomic because the CustomMetrics object is
    // cloned and shared among multiple threads (for instance TCP workers for
    // each connection).
    bbframe_count: Arc<AtomicU64>,
    gse_count: Arc<AtomicU64>,
    custom_argument: String,
}

impl CustomMetrics {
    fn new(custom_argument: String) -> CustomMetrics {
        CustomMetrics {
            bbframe_count: Arc::new(AtomicU64::new(0)),
            gse_count: Arc::new(AtomicU64::new(0)),
            custom_argument,
        }
    }
}

impl Metrics for CustomMetrics {
    fn bbframe_received(&mut self, _bbframe: &bytes::Bytes) {
        let count = self.bbframe_count.fetch_add(1, Relaxed);
        log::info!(
            "[{}] BBFRAME received (total {})",
            self.custom_argument,
            count + 1
        );
    }

    fn bbframe_error(&mut self, error: &std::io::Error) {
        log::info!("[{}] BBFRAME error: {error}", self.custom_argument);
    }

    fn gse_pdu_received(&mut self, _pdu: &dvb_gse::gsepacket::PDU) {
        let count = self.gse_count.fetch_add(1, Relaxed);
        log::info!(
            "[{}] GSE PDU received (total {})",
            self.custom_argument,
            count + 1
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
