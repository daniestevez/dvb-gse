# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1] - 2024-04-08

### Fixed

- Build error with crc-3.2.0.

## [0.6.0] - 2023-12-12

### Added

- Support for headers preceding the BBFRAMEs using the `--header-length`
  argument.

### Fixed

- Handling of `--isi` argument.

## [0.5.0] - 2023-11-01

### Changed

- `GSEPacketDefrag::defragment` and `GSEPacket::split_bbframe` now return an
  error instead of panicking if the BBFRAME is malformed.

## [0.4.4] - 2023-10-18

### Fixed

- Panic in GSE packet defragmentation with some malformed GSE headers.

## [0.4.3] - 2023-10-17

### Fixed

- Some fixes in the documentation of the bbframe module.

### Changed

- BBFRAME validator object made public.

## [0.4.2] - 2023-10-01

### Changed

- Do not fail if a packet cannot be written to the TUN.
- Add cause when logging errors for the TCP server.

## [0.4.1] - 2023-09-29

### Fixed

- Fixed default value for the `--input` command line argument.

## [0.4.0] - 2023-09-29

### Added

- Support for receiving BBFRAMEs as complete UDP packets and in a TCP stream.

## [0.3.2] - 2023-07-19

### Fixed

- Bug in handling of GSE packets with label re-use.

## [0.3.1] - 2023-05-23

### Fixed

- Maximum BBFRAME length.

### Changed

- Use SO_REUSEADDR when listening on a multicast address.

## [0.3.0] - 2022-12-05

### Added

- Support for skipping GSE total length check

## [0.2.0] - 2022-11-28

### Added

- Support for UDP multicast reception.
- Basic support for Multiple Input Stream mode.

## [0.1.2] - 2022-11-13

### Fixed

- Defragmentation of Longmynd UDP packets carrying only part of the BBHEADER.

## [0.1.1] - 2022-11-09

### Fixed

- Typo in README.

## [0.1.0] - 2022-11-09

### Added

- Initial release.

[unreleased]: https://github.com/daniestevez/dvb-gse/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/daniestevez/dvb-gse/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/daniestevez/dvb-gse/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/daniestevez/dvb-gse/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/daniestevez/dvb-gse/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/daniestevez/dvb-gse/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/daniestevez/dvb-gse/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/daniestevez/dvb-gse/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/daniestevez/dvb-gse/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/daniestevez/dvb-gse/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/daniestevez/dvb-gse/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/daniestevez/dvb-gse/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/daniestevez/dvb-gse/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/daniestevez/dvb-gse/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/daniestevez/dvb-gse/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/daniestevez/dvb-gse/releases/tag/v0.1.0
