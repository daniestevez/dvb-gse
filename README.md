# dvb-gse

[![Crates.io][crates-badge]][crates-url]
[![Rust](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml/badge.svg)](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml)

[crates-badge]: https://img.shields.io/crates/v/dvb-gse.svg
[crates-url]: https://crates.io/crates/dvb-gse

dvg-gse is a Rust implementation of the DVB GSE (Generic Stream Encapsulation)
protocol and related protocols.

It is mainly intended to be used as a CLI application that receives UDP
packets from
[Longmynd](https://github.com/BritishAmateurTelevisionClub/longmynd)
containing fragments of BBFRAMES, obtains IP packets from a continous-mode
GSE stream, and sends the IP packets to a TUN device.

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

## BBFRAME format in UDP packets

The formatting of BBFRAMEs in the UDP packets received by `dvb-gse` needs to
follow these rules:

* The beginning of each BBFRAME should be aligned with the beginning of the
  payload of a UDP packet.

* The BBFRAME padding should have been removed (in other words, the data sent
  for each BBFRAME should equal the 10 byte BBHEADER plus the data field, whose
  length in bits is given by the value of the DFL field in the BBHEADER).

* BBFRAMEs can be fragmented into multiple UDP packets in any way. For most
  FECFRAME configurations it is necessary to use fragmentation unless jumbo
  frames are used.

If these rules are followed, `dvb-gse` will try to recover gracefully from lost
UDP packets.

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
