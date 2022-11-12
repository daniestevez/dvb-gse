//! DVB GSE (Generic Stream Encapsulation) Packet.
//!
//! The GSE Packet is a variable-length packet formed by a header and a data
//! field. It contains a full PDU or a fragment of a PDU. One or more GSE Packets are carried in the data field of a BBFRAME. See Section 4.2 in
//! [TS 102
//! 606-1](https://www.etsi.org/deliver/etsi_ts/102600_102699/10260601/01.02.01_60/ts_10260601v010201p.pdf).

use super::bbframe::BBFrame;
use super::bbheader::BBHeader;
use super::gseheader::{GSEHeader, Label};
use bytes::Bytes;
use crc::Digest;
use std::collections::HashMap;

/// GSE Packet.
///
/// This struct contains a GSE Packet.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GSEPacket {
    header: GSEHeader,
    data: Bytes,
}

lazy_static::lazy_static! {
    static ref CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_MPEG_2);
}

impl GSEPacket {
    /// Creates a new GSE Packet by parsing the data at the beginning of a
    /// [`Bytes`].
    ///
    /// The GSE Header at the beginning of `bytes` is parsed and used to
    /// determine the length of the GSE Packet. On success,the GSE Packet is
    /// returned.
    ///
    /// This function returns `None` if the GSE Header cannot be parsed or if
    /// the `bytes` does not fully contain the GSE Packet.
    pub fn from_bytes(bytes: &Bytes, re_used_label: Option<&Label>) -> Option<GSEPacket> {
        let header = GSEHeader::from_slice(bytes, re_used_label)?;
        let header_len = header.len();
        let total_len = 2 + usize::from(header.gse_length());
        if total_len > bytes.len() {
            log::error!("GSE Packet not fully contained inside bytes");
            return None;
        }
        let data = bytes.slice(header_len..total_len);
        Some(GSEPacket { header, data })
    }

    /// Splits a BBFRAME into GSE Packets.
    ///
    /// This function returns an iterator that returns the GSE Packets contained
    /// in the BBFRAME. The iterator stops when the end of the BBFRAME is
    /// reached or when a malformed GSE Packet is found.
    pub fn split_bbframe(bbframe: &BBFrame) -> impl Iterator<Item = GSEPacket> {
        let mut remain = bbframe.slice(BBHeader::LEN..);
        let mut label = None;
        std::iter::from_fn(move || {
            if let Some(packet) = GSEPacket::from_bytes(&remain, label.as_ref()) {
                log::debug!("extracted GSE Packet with header {}", packet.header());
                log::trace!("GSE Packet data field {:?}", packet.data());
                remain = remain.slice(packet.len()..);
                if let Some(l) = packet.header.label() {
                    label = Some(l.clone());
                }
                Some(packet)
            } else {
                log::debug!("no more GSE Packets in BBFRAME");
                None
            }
        })
    }

    /// Gives the length of the GSE Packet in bytes.
    pub fn len(&self) -> usize {
        self.header.len() + self.data.len()
    }

    /// Returns `true` if the GSE Packet has a length of zero bytes.
    ///
    /// This always returns `false`, since a GSE Header never has a length of
    /// zero bytes. This function exists because objects that implement a `len`
    /// method should also implement an `is_empty` method.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Gives access to the header of the GSE Packet.
    pub fn header(&self) -> &GSEHeader {
        &self.header
    }

    /// Gives access to the data field of the GSE Packet.
    pub fn data(&self) -> &Bytes {
        &self.data
    }
}

/// GSE Packet defragmenter.
///
/// This structure performs defragmentation of GSE Packets in order to obtain
/// full [`PDU`]s.
#[derive(Debug)]
pub struct GSEPacketDefrag {
    defrags: HashMap<u8, Defrag>,
}

#[derive(Clone)]
struct Defrag {
    total_length: usize,
    protocol_type: u16,
    label: Label,
    current_length: usize,
    fragments: Vec<Bytes>,
    digest: Digest<'static, u32>,
}

/// PDU.
///
/// This structure represents a PDU. It carriers the PDU data, and its
/// corresponding metadata (the protocol type and the label).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PDU {
    data: Bytes,
    protocol_type: u16,
    label: Label,
}

impl PDU {
    fn from_single_fragment(packet: &GSEPacket) -> Option<PDU> {
        Some(PDU {
            protocol_type: packet.header().protocol_type()?,
            label: packet.header().label()?.clone(),
            data: packet.data().clone(),
        })
    }

    /// Gives access to the data of the PDU.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Returns the protocol type of the PDU.
    pub fn protocol_type(&self) -> u16 {
        self.protocol_type
    }

    /// Gives access to the label of the PDU.
    pub fn label(&self) -> &Label {
        &self.label
    }
}

impl GSEPacketDefrag {
    /// Creates a new GSE Packet defragmenter.
    pub fn new() -> GSEPacketDefrag {
        GSEPacketDefrag {
            defrags: HashMap::new(),
        }
    }

    /// Defragment a BBFRAME.
    ///
    /// This function returns an iterator that produces all the PDUs that can be
    /// completed with the GSE Packets found in the BBFRAME.
    pub fn defragment(&mut self, bbframe: &BBFrame) -> impl Iterator<Item = PDU> + '_ {
        GSEPacket::split_bbframe(bbframe).flat_map(|packet| self.defrag_packet(&packet))
    }

    fn defrag_packet(&mut self, packet: &GSEPacket) -> Option<PDU> {
        if packet.header().is_single_fragment() {
            log::debug!("defragmented GSE Packet as a single fragment");
            return Some(PDU::from_single_fragment(packet).unwrap());
        }
        let frag_id = packet.header().fragment_id().unwrap();
        if packet.header().start() {
            log::debug!("start of GSE fragment ID = {}", frag_id);
            let mut defrag = Defrag::new(packet.header()).unwrap();
            defrag.push(packet);
            self.defrags.insert(frag_id, defrag);
        } else if let Some(defrag) = self.defrags.get_mut(&frag_id) {
            log::debug!("pushing non-start GSE fragment ID = {}", frag_id);
            defrag.push(packet);
        }
        if packet.header.end() {
            if let Some(defrag) = self.defrags.remove(&frag_id) {
                log::debug!("end of GSE fragment ID = {}", frag_id);
                return defrag.reconstruct(frag_id);
            }
        }
        None
    }
}

impl Defrag {
    fn new(header: &GSEHeader) -> Option<Defrag> {
        Some(Defrag {
            total_length: usize::from(header.total_length()?),
            protocol_type: header.protocol_type()?,
            label: header.label()?.clone(),
            current_length: 0,
            fragments: Vec::new(),
            digest: CRC32.digest(),
        })
    }

    fn push(&mut self, packet: &GSEPacket) {
        self.fragments.push(packet.data().clone());
        if let Some(total_length) = packet.header().total_length() {
            self.digest.update(&total_length.to_be_bytes());
        }
        if let Some(protocol_type) = packet.header().protocol_type() {
            self.digest.update(&protocol_type.to_be_bytes());
            self.current_length += std::mem::size_of::<u16>();
        }
        if let Some(label) = packet.header().label() {
            self.digest.update(label.as_slice());
            self.current_length += label.len();
        }
        if packet.header.end() {
            let data = packet.data();
            let crc_size = std::mem::size_of::<u32>();
            if data.len() >= crc_size {
                self.digest
                    .update(&packet.data()[..packet.data().len() - crc_size]);
                self.current_length += packet.data().len() - crc_size;
            } else {
                log::error!(
                    "data size of last GSE fragment is {} bytes, \
			     which is less than the CRC-32 length",
                    data.len()
                );
            }
        } else {
            self.digest.update(packet.data());
            self.current_length += packet.data().len();
        }
    }

    fn reconstruct(self, frag_id: u8) -> Option<PDU> {
        if self.total_length != self.current_length {
            log::debug!(
                "defragmented length {} does not match total length {}",
                self.current_length,
                self.total_length
            );
            return None;
        }
        let data = self.fragments.iter().flatten().copied().collect::<Bytes>();
        let crc_size = std::mem::size_of::<u32>();
        if data.len() < crc_size {
            log::error!("defragmented data is shorter than CRC-32 size");
            return None;
        }
        let crc_calc = self.digest.finalize();
        let crc_data = u32::from_be_bytes(data[data.len() - crc_size..].try_into().unwrap());
        if crc_calc != crc_data {
            log::debug!("invalid CRC-32 for fragment ID = {}", frag_id);
            return None;
        }
        log::debug!("valid CRC-32 for fragment ID = {}", frag_id);
        Some(PDU {
            data: data.slice(..data.len() - crc_size),
            protocol_type: self.protocol_type,
            label: self.label,
        })
    }
}

impl std::fmt::Debug for Defrag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Defrag")
            .field("total_length", &self.total_length)
            .field("fragments", &self.fragments)
            .finish()
    }
}

impl Default for GSEPacketDefrag {
    fn default() -> GSEPacketDefrag {
        GSEPacketDefrag::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    const SINGLE_PACKET: [u8; 104] = hex!(
        "72 00 00 00 02 f0 00 00 00 15 c0 5c 08 00 02 00
         48 55 4c 4b 45 00 00 54 6f aa 40 00 40 01 72 fc
         2c 00 00 01 2c 00 00 02 08 00 4e 94 00 3b 00 04
         19 7d 6b 63 00 00 00 00 5d 79 08 00 00 00 00 00
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37"
    );

    #[test]
    fn defrag_single_packet() {
        let bbframe = Bytes::copy_from_slice(&SINGLE_PACKET);
        let mut defrag = GSEPacketDefrag::new();
        let pdus: Vec<_> = defrag.defragment(&bbframe).collect();
        assert_eq!(pdus.len(), 1);
        let pdu = &pdus[0];
        assert_eq!(&pdu.data()[..], &SINGLE_PACKET[20..]);
        assert_eq!(pdu.protocol_type(), 0x0800);
        assert_eq!(pdu.label().as_slice(), hex!("02 00 48 55 4c 4b"));
    }
}
