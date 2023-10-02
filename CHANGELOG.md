# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] - 2023-10-01

### Changed

- Do not fail if a packet cannot be written to the TUN.

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

[unreleased]: https://github.com/daniestevez/dvb-gse/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/daniestevez/dvb-gse/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/daniestevez/dvb-gse/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/daniestevez/dvb-gse/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/daniestevez/dvb-gse/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/daniestevez/dvb-gse/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/daniestevez/dvb-gse/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/daniestevez/dvb-gse/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/daniestevez/dvb-gse/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/daniestevez/dvb-gse/releases/tag/v0.1.0
