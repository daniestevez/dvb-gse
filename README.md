# dvb-gse

[![Crates.io][crates-badge]][crates-url]
[![Rust](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml/badge.svg)](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml)

[crates-badge]: https://img.shields.io/crates/v/dvb-gse.svg
[crates-url]: https://crates.io/crates/dvb-gse

dvg-gse is a Rust implementation of the DVB GSE (Generic Stream Encapsulation)
protocol and related protocols.

It is mainly intended to be used as a CLI application that receives BBFRAMEs by
UDP or TCP packets from a DVB-S2 receiver (such as
[Longmynd](https://github.com/BritishAmateurTelevisionClub/longmynd)), obtains
IP packets from a continous-mode GSE stream, and sends the IP packets to a TUN
device.

The crate can also be used as a library to process GSE Packets and
DVB-S2/DVB-S2X BBFRAMES.

## Quickstart

Install `dvb-gse` with [`cargo`](https://doc.rust-lang.org/cargo/):

```
cargo install dvb-gse
```

Create a TUN device to receive the IP packets:

```
sudo ip tuntap add dev tun0 mode tun
sudo ip link set tun0 up
```

Run `dvb-gse`:

```
dvb-gse --listen 0.0.0.0:2000 --tun tun0
```

It is possible to use the environment variable `RUST_LOG=debug` or
`RUST_LOG=trace` to see more detailed logging information.

Now send BBFRAMEs to UDP port 2000 (how to do this will depend on the DVB-S2
receiver being used). `dvb-gse` will obtain the IP packets from the GSE stream
and write them into the `tun0` interface. These packets can be inspected by
running Wireshark or `tcpdump` in `tun0`.

## Input formats

The CLI application supports the following input formats for the BBFRAMEs. The
input format is selected with the `--input` argument:

### UDP fragments (`--input UDP` or `--input "UDP fragments"`)

This corresponds to BBFRAMEs fragmented into multiple UDP packets (since usually
DVB-S2 BBFRAMEs are larger than a 1500 byte MTU). The following rules need to be
followed.

* The beginning of each BBFRAME should be aligned with the beginning of the
  payload of a UDP packet.

* The BBFRAME padding can either be removed or be present. If possible, it is
  recommended to remove the BBFRAME padding, in order to reduce the network
  traffic and to simplify the operation of the defragmenter.

* BBFRAMEs can be fragmented into multiple UDP packets in any way.
  
The CLI application tries to recover from dropped UDP packets.

### UDP packets with complete BBFRAMES (`--input "UDP complete"`)

This corresponds to BBFRAMEs carried in a single UDP packet (it will typically
be a jumbo packet). The following rules need to be followed.

* Each BBFRAME should be completely contained at the start of a single UDP
  packet.

* There can be padding or any other data following the BBFRAME in the same UDP
  packet.

UDP packets can be dropped. The CLI application will handle this gracefully.

### TCP stream (`--input TCP`)

This corresponds to receiving BBFRAMEs in a TCP stream. The CLI application acts
as server. The following rules need to be followed.

* BBFRAMEs need to be present back to back in the TCP stream.

* BBFRAMEs padding must be remoted. The length of the BBFRAMEs in the stream
  must equal 10 bytes for the BBHEADER plus the value of their DFL dividided by 8.

* No other data can be present in the TCP stream.

If an error occurrs or the client closes the connection, the CLI application
will continue listen for new clients.

## API documentation

The documentation for dvb-gse Rust crate is hosted in [docs.rs](https://docs.rs/dvb-gse/).

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
