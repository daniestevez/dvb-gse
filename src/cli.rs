//! CLI application.
//!
//! This module implements a CLI application that receives UDP or TCP packets
//! containing BBFRAMEs from an external DVB-S2 receiver such as
//! [`Longmynd`](https://github.com/BritishAmateurTelevisionClub/longmynd). It
//! obtains IP packets from a continous-mode GSE stream, and sends the IP
//! packets to a TUN device.

use crate::{
    bbframe::{BBFrameDefrag, BBFrameReceiver, BBFrameRecv, BBFrameStream},
    gseheader::Label,
    gsepacket::{GSEPacketDefrag, PDU},
    metrics::Metrics as MetricsTrait,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use std::{
    net::{SocketAddr, TcpListener, UdpSocket},
    os::unix::io::AsRawFd,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

/// dvb-gse CLI application.
///
/// This struct contains everything that is needed by the dvb-gse application.
///
/// The `AppArgs` type argument defines the type of the CLI arguments of the
/// application. It can either be [`Args`] if no custom CLI arguments are
/// needed, or a custom type that extends [`Args`] by implementing
/// [`clap::Parser`] and `AsRef<Args>`.
///
/// The `Metrics` type argument defines the type of the custom metrics. The
/// default type `()` is used for no metrics. It is possible to provide a type
/// here that implements the [`Metrics`](MetricsTrait) trait to add custom
/// metrics to the application.
pub struct App<AppArgs = Args, Metrics = ()> {
    args: AppArgs,
    metrics: AppMetrics<Metrics>,
}

/// Receive DVB-GSE and send PDUs into a TUN device.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// IP address and port to listen on to receive DVB-S2 BBFRAMEs.
    #[arg(long)]
    pub listen: SocketAddr,
    /// TUN interface name.
    #[arg(long)]
    pub tun: String,
    /// Input format: "UDP fragments", "UDP complete", or "TCP".
    #[arg(long, default_value_t)]
    pub input: InputFormat,
    /// Input header length (the header is discarded).
    #[arg(long, default_value_t = 0)]
    pub header_length: usize,
    /// ISI to process in MIS mode (if this option is not specified, run in SIS mode).
    #[arg(long)]
    pub isi: Option<u8>,
    /// Time interval used to log statistics (in seconds).
    #[arg(long, default_value_t = 100.0)]
    pub stats_interval: f64,
    /// Skip checking the GSE total length field.
    #[arg(long)]
    pub skip_total_length: bool,
    /// Allow GSE packets addressed to the broadcast label (no label).
    ///
    /// If this argument is used, all the GSE packets not explicitly allowed via
    /// CLI arguments are dropped.
    #[arg(long)]
    pub allow_broadcast: bool,
    /// Allow GSE packets addressed to this 3-byte or 6-byte label.
    ///
    /// If this argument is used, all the GSE packets not explicitly allowed via
    /// CLI arguments are dropped. This argument can be used multiple times to
    /// allow multiple labels.
    #[arg(long, value_parser = Label::from_hex)]
    pub allow_label: Vec<Label>,
}

impl AsRef<Args> for Args {
    fn as_ref(&self) -> &Args {
        self
    }
}

#[derive(Debug, Clone)]
struct AppMetrics<Metrics> {
    stats: Arc<Mutex<Stats>>,
    metrics: Metrics,
}

impl<Metrics: MetricsTrait> MetricsTrait for AppMetrics<Metrics> {
    fn bbframe_received(&mut self, bbframe: &Bytes) {
        self.stats.lock().unwrap().bbframes += 1;
        self.metrics.bbframe_received(bbframe);
    }

    fn bbframe_error(&mut self, error: &std::io::Error) {
        self.stats.lock().unwrap().bbframe_errors += 1;
        self.metrics.bbframe_error(error);
    }

    fn gse_pdu_received(&mut self, pdu: &PDU) {
        self.stats.lock().unwrap().gse_pdus += 1;
        self.metrics.gse_pdu_received(pdu);
    }

    fn gse_pdu_dropped_label_filtering(&mut self, pdu: &PDU) {
        self.stats.lock().unwrap().gse_pdus_dropped_by_label += 1;
        self.metrics.gse_pdu_dropped_label_filtering(pdu);
    }

    fn tcp_client_connected(&mut self, stream: &std::net::TcpStream) {
        self.metrics.tcp_client_connected(stream);
    }

    fn tcp_client_finished(&mut self) {
        self.metrics.tcp_client_finished();
    }

    fn tun_error(&mut self, error: &std::io::Error, pdu: &PDU) {
        self.stats.lock().unwrap().tun_errors += 1;
        self.metrics.tun_error(error, pdu);
    }
}

impl<AppArgs: Parser, Metrics> App<AppArgs, Metrics> {
    /// Creates a dvb-gse application by parsing arguments and doing some
    /// initialization.
    ///
    /// The [`App::run`] method needs to be called to run the application.
    ///
    /// The `build_metrics` closure is used to build a `Metrics` object from the
    /// parsed CLI arguments.
    pub fn new<F: FnOnce(&AppArgs) -> Result<Metrics>>(build_metrics: F) -> Result<Self> {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
        let args = AppArgs::parse();
        let metrics = build_metrics(&args)?;
        let stats = Arc::new(Mutex::new(Stats::default()));
        let metrics = AppMetrics { stats, metrics };
        Ok(App { args, metrics })
    }
}

impl<AppArgs: Parser, Metrics: Default> App<AppArgs, Metrics> {
    /// Creates a dvb-gse application with default metrics by parsing arguments
    /// and doing some initialization.
    ///
    /// The [`App::run`] method needs to be called to run the application.
    ///
    /// The `Metrics` object is constructed by calling its [`Default`]
    /// implementation.
    pub fn with_default_metrics() -> Result<Self> {
        Self::new(|_| Ok(Metrics::default()))
    }
}

impl<AppArgs: AsRef<Args>, Metrics: MetricsTrait + Clone + Send + 'static> App<AppArgs, Metrics> {
    /// Runs the dvb-gse application.
    ///
    /// This function only returns if there is a fatal error.
    pub fn run(self) -> Result<()> {
        let tun = tun_tap::Iface::without_packet_info(&self.args.as_ref().tun, tun_tap::Mode::Tun)
            .context("failed to open TUN device")?;
        log::info!("dvb-gse v{} started", env!("CARGO_PKG_VERSION"));
        let stats_interval = self.args.as_ref().stats_interval;
        if stats_interval != 0.0 {
            std::thread::spawn({
                let stats = Arc::clone(&self.metrics.stats);
                move || {
                    report_stats(&stats, Duration::from_secs_f64(stats_interval));
                }
            });
        }
        match self.args.as_ref().input {
            InputFormat::UdpFragments | InputFormat::UdpComplete => self.run_udp_input(tun),
            InputFormat::Tcp => self.run_tcp_input(tun),
        }
    }

    fn run_udp_input(self, tun: tun_tap::Iface) -> Result<()> {
        let gsepacket_defrag = gsepacket_defragmenter(self.args.as_ref());
        let socket =
            UdpSocket::bind(self.args.as_ref().listen).context("failed to bind to UDP socket")?;
        setup_multicast(&socket, &self.args.as_ref().listen)?;
        let allow_settings = AllowSettings::from(self.args.as_ref());
        match self.args.as_ref().input {
            InputFormat::UdpFragments => {
                let mut bbframe_recv = BBFrameDefrag::new(socket);
                bbframe_recv.set_isi(self.args.as_ref().isi);
                bbframe_recv.set_header_bytes(self.args.as_ref().header_length)?;
                let mut app = AppLoop {
                    bbframe_recv,
                    gsepacket_defrag,
                    tun,
                    bbframe_recv_errors_fatal: true,
                    metrics: self.metrics,
                    allow_settings,
                };
                app.app_loop()?;
            }
            InputFormat::UdpComplete => {
                let mut bbframe_recv = BBFrameRecv::new(socket);
                bbframe_recv.set_isi(self.args.as_ref().isi);
                bbframe_recv.set_header_bytes(self.args.as_ref().header_length)?;
                let mut app = AppLoop {
                    bbframe_recv,
                    gsepacket_defrag,
                    tun,
                    bbframe_recv_errors_fatal: false,
                    metrics: self.metrics,
                    allow_settings,
                };
                app.app_loop()?;
            }
            // This function is only called for UDP input types
            InputFormat::Tcp => unreachable!(),
        }
        Ok(())
    }

    fn run_tcp_input(mut self, mut tun: tun_tap::Iface) -> Result<()> {
        let listener =
            TcpListener::bind(self.args.as_ref().listen).context("failed to bind to TCP socket")?;
        // For TCP, the application runs each TCP connection in a dedicated
        // thread. There is another thread that owns the TUN. The TCP
        // connection threads are connected to the TUN thread by an mpsc
        // channel.
        let channel_capacity = 64;
        let (tun_tx, tun_rx) = mpsc::sync_channel(channel_capacity);
        let allow_settings = AllowSettings::from(self.args.as_ref());
        thread::spawn({
            let mut metrics = self.metrics.clone();
            move || {
                for pdu in tun_rx.iter() {
                    write_pdu_tun(&pdu, &mut tun, &mut metrics, &allow_settings);
                }
            }
        });
        // use thread scope to pass args by reference
        thread::scope(|s| {
            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("connection error {e}");
                        continue;
                    }
                };
                match stream.peer_addr() {
                    Ok(addr) => log::info!("TCP client connected from {addr}"),
                    Err(err) => log::error!(
                        "TCP client connected (but could not retrieve peer address): {err}"
                    ),
                }
                self.metrics.tcp_client_connected(&stream);
                s.spawn({
                    let args = self.args.as_ref();
                    let tun_tx = tun_tx.clone();
                    let mut metrics = self.metrics.clone();
                    move || {
                        let mut gsepacket_defrag = gsepacket_defragmenter(args);
                        let mut bbframe_recv = BBFrameStream::new(stream);
                        bbframe_recv.set_isi(args.isi);
                        if let Err(err) = bbframe_recv.set_header_bytes(args.header_length) {
                            eprintln!("could not set header length: {err}");
                            std::process::exit(1);
                        }
                        loop {
                            let bbframe = bbframe_recv.get_bbframe();
                            let bbframe = {
                                match bbframe {
                                    Ok(b) => {
                                        metrics.bbframe_received(&b);
                                        b
                                    }
                                    Err(err) => {
                                        log::error!("failed to receive BBFRAME; terminating connection: {err}");
                                        metrics.bbframe_error(&err);
                                        metrics.tcp_client_finished();
                                        return;
                                    }
                                }
                            };
                            // the BBFRAME was validated by bbframe_recv, so we can unwrap here
                            for pdu in gsepacket_defrag.defragment(&bbframe).unwrap() {
                                tun_tx.send(pdu).unwrap();
                            }
                        }
                    }
                });
            }
        });
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AllowSettings {
    allow_broadcast: bool,
    allow_label: Vec<Label>,
}

impl AllowSettings {
    fn is_label_allowed(&self, label: &Label) -> bool {
        if !self.allow_broadcast && self.allow_label.is_empty() {
            // no 'allow' arguments used; allow everything
            return true;
        }
        if label.is_broadcast() {
            return self.allow_broadcast;
        }
        self.allow_label.iter().any(|allowed| label == allowed)
    }
}

impl From<&Args> for AllowSettings {
    fn from(args: &Args) -> AllowSettings {
        AllowSettings {
            allow_broadcast: args.allow_broadcast,
            allow_label: args.allow_label.clone(),
        }
    }
}

/// Input format for the dvb-gse CLI application.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum InputFormat {
    /// BBFRAME fragments in UDP datagrams.
    #[default]
    UdpFragments,
    /// Complete BBFRAMEs in UDP datagrams.
    UdpComplete,
    /// BBFRAMEs in a TCP stream.
    Tcp,
}

impl std::str::FromStr for InputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "UDP" | "UDP fragments" => InputFormat::UdpFragments,
            "UDP complete" => InputFormat::UdpComplete,
            "TCP" => InputFormat::Tcp,
            _ => return Err(format!("invalid input format {s}")),
        })
    }
}

impl std::fmt::Display for InputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                InputFormat::UdpFragments => "UDP fragments",
                InputFormat::UdpComplete => "UDP complete",
                InputFormat::Tcp => "TCP",
            }
        )
    }
}

fn setup_multicast(socket: &UdpSocket, addr: &SocketAddr) -> Result<()> {
    match addr.ip() {
        std::net::IpAddr::V4(addr) if addr.is_multicast() => {
            set_reuseaddr(socket)?;
            log::info!("joining multicast address {}", addr);
            socket.join_multicast_v4(&addr, &std::net::Ipv4Addr::UNSPECIFIED)?;
        }
        std::net::IpAddr::V6(addr) if addr.is_multicast() => {
            set_reuseaddr(socket)?;
            log::info!("joining multicast address {}", addr);
            socket.join_multicast_v6(&addr, 0)?;
        }
        _ => (),
    }
    Ok(())
}

fn set_reuseaddr(socket: &UdpSocket) -> Result<()> {
    let optval: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap(),
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("could not set SO_REUSEADDR: {err}")
    }
    Ok(())
}

#[derive(Debug)]
struct AppLoop<D, Metrics> {
    bbframe_recv: D,
    gsepacket_defrag: GSEPacketDefrag,
    tun: tun_tap::Iface,
    bbframe_recv_errors_fatal: bool,
    metrics: AppMetrics<Metrics>,
    allow_settings: AllowSettings,
}

fn write_pdu_tun<Metrics: MetricsTrait>(
    pdu: &PDU,
    tun: &mut tun_tap::Iface,
    metrics: &mut AppMetrics<Metrics>,
    allow_settings: &AllowSettings,
) {
    metrics.gse_pdu_received(pdu);
    if !allow_settings.is_label_allowed(pdu.label()) {
        metrics.gse_pdu_dropped_label_filtering(pdu);
        return;
    }
    if let Err(err) = tun.send(pdu.data()) {
        log::error!("could not write packet to TUN device: {err}");
        metrics.tun_error(&err, pdu);
    }
}

impl<D: BBFrameReceiver, Metrics: MetricsTrait> AppLoop<D, Metrics> {
    fn app_loop(&mut self) -> Result<()> {
        loop {
            let bbframe = self.bbframe_recv.get_bbframe();
            let bbframe = match bbframe {
                Ok(b) => {
                    self.metrics.bbframe_received(&b);
                    b
                }
                Err(err) => {
                    self.metrics.bbframe_error(&err);
                    if self.bbframe_recv_errors_fatal {
                        return Err(err).context("failed to receive BBFRAME");
                    } else {
                        continue;
                    }
                }
            };
            // the BBFRAME was validated by bbframe_recv, so we can unwrap here
            for pdu in self.gsepacket_defrag.defragment(&bbframe).unwrap() {
                write_pdu_tun(&pdu, &mut self.tun, &mut self.metrics, &self.allow_settings);
            }
        }
    }
}

fn gsepacket_defragmenter(args: &Args) -> GSEPacketDefrag {
    let mut defrag = GSEPacketDefrag::new();
    defrag.set_skip_total_length_check(args.skip_total_length);
    defrag
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
struct Stats {
    bbframes: u64,
    bbframe_errors: u64,
    gse_pdus: u64,
    gse_pdus_dropped_by_label: u64,
    tun_errors: u64,
}

fn report_stats(stats: &Mutex<Stats>, interval: Duration) {
    loop {
        {
            let stats = stats.lock().unwrap();
            log::info!(
                "BBFRAMES: {}, BBFRAME errors: {}, GSE PDUs: {}, GSE PDUs dropped by label: {}, TUN errors: {}",
                stats.bbframes,
                stats.bbframe_errors,
                stats.gse_pdus,
                stats.gse_pdus_dropped_by_label,
                stats.tun_errors
            );
        }
        std::thread::sleep(interval);
    }
}
