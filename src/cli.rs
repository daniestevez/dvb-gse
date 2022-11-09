//! CLI application.
//!
//! This module implements a CLI applicaton that receives UDP
//! packets from
//! [`Longmynd`](https://github.com/BritishAmateurTelevisionClub/longmynd)
//! containing fragments of BBFRAMES, obtains IP packets from a continous-mode
//! GSE stream, and sends the IP packets to a TUN device.

use crate::{bbframe::BBFrameDefrag, gsepacket::GSEPacketDefrag};
use anyhow::{Context, Result};
use clap::Parser;
use std::net::{SocketAddr, UdpSocket};

/// Receive DVB-GSE and send PDUs into a TUN device
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP and UDP port to listen to DVB-GSE packets from Longmynd
    #[arg(long)]
    listen: SocketAddr,
    /// TUN interface name
    #[arg(long)]
    tun: String,
}

/// Main function of the CLI application.
pub fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let tap = tun_tap::Iface::without_packet_info(&args.tun, tun_tap::Mode::Tun)
        .context("failed to open TUN device")?;
    let socket = UdpSocket::bind(args.listen).context("failed to bind to UDP socket")?;
    let mut bbframe_defrag = BBFrameDefrag::new(socket);
    let mut gsepacket_defrag = GSEPacketDefrag::new();
    loop {
        let bbframe = bbframe_defrag
            .get_bbframe()
            .context("failed to receive BBFRAME")?;
        for pdu in gsepacket_defrag.defragment(&bbframe) {
            tap.send(pdu.data())
                .context("failed to send PDU to TUN device")?;
        }
    }
}
