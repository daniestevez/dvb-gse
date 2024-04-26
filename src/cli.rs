//! CLI application.
//!
//! This module implements a CLI application that receives UDP or TCP packets
//! containing BBFRAMEs from an external DVB-S2 receiver such as
//! [`Longmynd`](https://github.com/BritishAmateurTelevisionClub/longmynd). It
//! obtains IP packets from a continous-mode GSE stream, and sends the IP
//! packets to a TUN device.

use crate::{
    bbframe::{BBFrameDefrag, BBFrameReceiver, BBFrameRecv, BBFrameStream},
    gsepacket::{GSEPacketDefrag, PDU},
};
use anyhow::{Context, Result};
use clap::Parser;
use std::{
    net::{SocketAddr, TcpListener, UdpSocket},
    os::unix::io::AsRawFd,
    sync::mpsc,
    thread,
};

/// Receive DVB-GSE and send PDUs into a TUN device
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address and port to listen on to receive DVB-S2 BBFRAMEs
    #[arg(long)]
    listen: SocketAddr,
    /// TUN interface name
    #[arg(long)]
    tun: String,
    /// Input format: "UDP fragments", "UDP complete", or "TCP"
    #[arg(long, default_value_t)]
    input: InputFormat,
    /// Input header length (the header is discarded)
    #[arg(long, default_value_t = 0)]
    header_length: usize,
    /// ISI to process in MIS mode (if this option is not specified, run in SIS mode)
    #[arg(long)]
    isi: Option<u8>,
    /// Skip checking the GSE total length field
    #[arg(long)]
    skip_total_length: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
enum InputFormat {
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
struct AppLoop<D> {
    bbframe_recv: D,
    gsepacket_defrag: GSEPacketDefrag,
    tun: tun_tap::Iface,
    bbframe_recv_errors_fatal: bool,
}

fn write_pdu_tun(pdu: &PDU, tun: &mut tun_tap::Iface) {
    if let Err(err) = tun.send(pdu.data()) {
        log::error!("could not write packet to TUN device: {err}");
    }
}

impl<D: BBFrameReceiver> AppLoop<D> {
    fn app_loop(&mut self) -> Result<()> {
        loop {
            let bbframe = match self.bbframe_recv.get_bbframe() {
                Ok(b) => b,
                Err(err) => {
                    if self.bbframe_recv_errors_fatal {
                        return Err(err).context("failed to receive BBFRAME");
                    } else {
                        continue;
                    }
                }
            };
            // the BBFRAME was validated by bbframe_recv, so we can unwrap here
            for pdu in self.gsepacket_defrag.defragment(&bbframe).unwrap() {
                write_pdu_tun(&pdu, &mut self.tun);
            }
        }
    }
}

fn gsepacket_defragmenter(args: &Args) -> GSEPacketDefrag {
    let mut defrag = GSEPacketDefrag::new();
    defrag.set_skip_total_length_check(args.skip_total_length);
    defrag
}

/// Main function of the CLI application.
pub fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let mut tun = tun_tap::Iface::without_packet_info(&args.tun, tun_tap::Mode::Tun)
        .context("failed to open TUN device")?;
    match args.input {
        InputFormat::UdpFragments | InputFormat::UdpComplete => {
            let gsepacket_defrag = gsepacket_defragmenter(&args);
            let socket = UdpSocket::bind(args.listen).context("failed to bind to UDP socket")?;
            setup_multicast(&socket, &args.listen)?;
            match args.input {
                InputFormat::UdpFragments => {
                    let mut bbframe_recv = BBFrameDefrag::new(socket);
                    bbframe_recv.set_isi(args.isi);
                    bbframe_recv.set_header_bytes(args.header_length)?;
                    let mut app = AppLoop {
                        bbframe_recv,
                        gsepacket_defrag,
                        tun,
                        bbframe_recv_errors_fatal: true,
                    };
                    app.app_loop()?;
                }
                InputFormat::UdpComplete => {
                    let mut bbframe_recv = BBFrameRecv::new(socket);
                    bbframe_recv.set_isi(args.isi);
                    bbframe_recv.set_header_bytes(args.header_length)?;
                    let mut app = AppLoop {
                        bbframe_recv,
                        gsepacket_defrag,
                        tun,
                        bbframe_recv_errors_fatal: false,
                    };
                    app.app_loop()?;
                }
                _ => unreachable!(),
            }
        }
        InputFormat::Tcp => {
            let listener =
                TcpListener::bind(args.listen).context("failed to bind to TCP socket")?;
            // For TCP, the application runs each TCP connection in a dedicated
            // thread. There is another thread that owns the TUN. The TCP
            // connection threads are connected to the TUN thread by an mpsc
            // channel.
            let channel_capacity = 64;
            let (tun_tx, tun_rx) = mpsc::sync_channel(channel_capacity);
            thread::spawn(move || {
                for pdu in tun_rx.iter() {
                    write_pdu_tun(&pdu, &mut tun);
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
                    s.spawn({
                        let args = &args;
                        let tun_tx = tun_tx.clone();
                        move || {
                            let mut gsepacket_defrag = gsepacket_defragmenter(args);
                            let mut bbframe_recv = BBFrameStream::new(stream);
                            bbframe_recv.set_isi(args.isi);
                            if let Err(err) = bbframe_recv.set_header_bytes(args.header_length) {
                                eprintln!("could not set header length: {err}");
                                std::process::exit(1);
                            }
                            loop {
                                let bbframe = match bbframe_recv.get_bbframe() {
                                    Ok(b) => b,
                                    Err(err) => {
                                        log::error!("failed to receive BBFRAME; terminating connection: {err}");
                                        return;
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
        }
    }
    Ok(())
}
