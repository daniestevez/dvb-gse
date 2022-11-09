# dvb-gse

[![Crates.io][crates-badge]][crates-url]
[![Rust](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml/badge.svg)](https://github.com/daniestevez/dvb-gse/actions/workflows/rust.yml)

[crates-badge]: https://img.shields.io/crates/v/dvb-gse.svg
[crates-url]: https://crates.io/crates/dvb-gse

dvg-se is a Rust implementation of the DVB GSE (Generic Stream Encapsulation)
protocol and related protocols.

It is mainly intended to be used as a CLI application that receives UDP
packets from
[Longmynd](https://github.com/BritishAmateurTelevisionClub/longmynd)
containing fragments of BBFRAMES, obtains IP packets from a continous-mode
GSE stream, and sends the IP packets to a TUN device.

The crate can also be used as a library to process GSE Packets and
DVB-S2/DVB-S2X BBFRAMES.

## Documentation

The documentation for dvb-gse is hosted in
[docs.rs](https://docs.rs/dvg-gse/).

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
