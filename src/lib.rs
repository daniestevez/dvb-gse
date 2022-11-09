//! DVB-GSE.
//!
//! This crate implements the DVB GSE (Generic Stream Encapsulation) protocol
//! and related protocols.
//!
//! It is mainly intended to be used as a CLI application that receives UDP
//! packets from
//! [Longmynd](https://github.com/BritishAmateurTelevisionClub/longmynd)
//! containing fragments of BBFRAMES, obtains IP packets from a continous-mode
//! GSE stream, and sends the IP packets to a TUN device.
//!
//! The crate can also be used as a library to process GSE Packets and
//! DVB-S2/DVB-S2X BBFRAMES.

#![warn(missing_docs)]

type BitSlice = bitvec::slice::BitSlice<u8, bitvec::order::Msb0>;

pub mod bbframe;
pub mod bbheader;
pub mod gseheader;
pub mod gsepacket;

#[cfg(feature = "cli")]
pub mod cli;
