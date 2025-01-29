//! DVB GSE (Generic Stream Encapsulation) Packet.
//!
//! The GSE Packet is a variable-length packet formed by a header and a data
//! field. It contains a full PDU or a fragment of a PDU. One or more GSE Packets are carried in the data field of a BBFRAME. See Section 4.2 in
//! [TS 102
//! 606-1](https://www.etsi.org/deliver/etsi_ts/102600_102699/10260601/01.02.01_60/ts_10260601v010201p.pdf).

use super::bbframe::BBFrame;
use super::bbheader::BBHeader;
use super::gseheader::{GSEHeader, Label};
use bytes::{Bytes, BytesMut};
use crc::Digest;
use std::collections::HashMap;
use thiserror::Error;

/// GSE Packet.
///
/// This struct contains a GSE Packet.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GSEPacket {
    header: GSEHeader,
    data: Bytes,
}

/// GSE protocol error.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum GSEError {
    /// The BBFRAME is shorter than the BBHEADER length.
    #[error("the BBFRAME is shorter than the BBHEADER length")]
    BBFrameShort,
    /// The SYNCD field of the GSE-HEM BBFRAME is not a multiple of 8 bits.
    #[error("the SYNCD field of the GSE-HEM BBFRAME is not a multiple of 8 bits")]
    SyncdNotMultiple,
    /// The SYNCD field of the GSE-HEM BBFRAME points beyond the end of the BBFRAME.
    #[error("The SYNCD field of the GSE-HEM BBFRAME points beyond the end of the BBFRAME")]
    SyncdTooLarge,
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
        Self::try_from_bytes(bytes, re_used_label, true)
    }

    fn try_from_bytes(
        bytes: &Bytes,
        re_used_label: Option<&Label>,
        not_contained_is_error: bool,
    ) -> Option<GSEPacket> {
        let header = GSEHeader::from_slice(bytes, re_used_label)?;
        let header_len = header.len();
        let total_len = 2 + usize::from(header.gse_length());
        if total_len > bytes.len() {
            if not_contained_is_error {
                log::error!("GSE Packet not fully contained inside bytes");
            }
            return None;
        }
        if total_len < header_len {
            log::error!("GSE Packet total length is smaller than header length");
            return None;
        }
        let data = bytes.slice(header_len..total_len);
        Some(GSEPacket { header, data })
    }

    /// Splits a [`Bytes`] into GSE Packets.
    ///
    /// This function returns an iterator that returns the GSE Packets contained
    /// in the `Bytes`. The first GSE Packet should start at the beginning of
    /// the `Bytes`. The iterator stops when the end of the `Bytes` is reached,
    /// or when GSE padding or a malformed GSE Packet is found.
    pub fn split_bytes(bytes: &Bytes) -> impl Iterator<Item = GSEPacket> {
        Self::try_split_bytes(bytes, true)
    }

    fn try_split_bytes(
        bytes: &Bytes,
        not_contained_is_error: bool,
    ) -> impl Iterator<Item = GSEPacket> {
        let mut remain = bytes.slice(..);
        let mut label = None;
        std::iter::from_fn(move || {
            if let Some(packet) =
                GSEPacket::try_from_bytes(&remain, label.as_ref(), not_contained_is_error)
            {
                log::debug!("extracted GSE Packet with header {}", packet.header());
                log::trace!(
                    "GSE Packet data field {}",
                    faster_hex::hex_string(packet.data())
                );
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

    /// Splits a non-HEM BBFRAME into GSE Packets.
    ///
    /// This function returns an iterator that returns the GSE Packets contained
    /// in the BBFRAME. The iterator stops when the end of the BBFRAME is
    /// reached, or when GSE padding or a malformed GSE Packet is found.
    ///
    /// The function returns an error if the BBFRAME is malformed. For instance,
    /// if the BBFRAME length is shorter than the BBHEADER length.
    pub fn split_bbframe(bbframe: &BBFrame) -> Result<impl Iterator<Item = GSEPacket>, GSEError> {
        if bbframe.len() < BBHeader::LEN {
            return Err(GSEError::BBFrameShort);
        }
        Ok(GSEPacket::split_bytes(&bbframe.slice(BBHeader::LEN..)))
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
    defragger: Defragger,
    // used to store the leftover partial packet at the end of a GSE-HEM BBFRAME
    hem_leftover: BytesMut,
    // used for label re-use of the leftover partial packet in GSE-HEM
    hem_last_label: Option<Label>,
}

// This intermediate struct is introduce only to avoid borrowing the whole
// GSEPacketDefrag when calling defrag().
#[derive(Debug)]
struct Defragger {
    defrags: HashMap<u8, Defrag>,
    skip_total_length_check: bool,
}

struct Defrag {
    total_length: usize,
    protocol_type: u16,
    label: Label,
    current_length: usize,
    fragments: Vec<Bytes>,
    digest: Digest<'static, u32>,
    // Used because some modulators do not set the Total Length field
    // correctly. See https://github.com/daniestevez/dvb-gse/issues/11
    skip_total_length_check: bool,
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

// This is needed because GSEPacketDefrag::defrag can return an iterator of
// either one of two types, depending on whether the BBFRAME is GSE-HEM or not.
enum EitherIter<AIterType, BIterType> {
    A(AIterType),
    B(BIterType),
}

impl<AIterType, BIterType> Iterator for EitherIter<AIterType, BIterType>
where
    AIterType: Iterator,
    BIterType: Iterator<Item = AIterType::Item>,
{
    type Item = AIterType::Item;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        match self {
            EitherIter::A(it) => it.next(),
            EitherIter::B(it) => it.next(),
        }
    }
}

impl GSEPacketDefrag {
    /// Creates a new GSE Packet defragmenter.
    pub fn new() -> GSEPacketDefrag {
        GSEPacketDefrag {
            defragger: Defragger {
                defrags: HashMap::new(),
                skip_total_length_check: false,
            },
            hem_leftover: BytesMut::new(),
            hem_last_label: None,
        }
    }

    /// Enables or disables the check of the total length field.
    ///
    /// By default, `GSEPacketDefrag` checks that the length of the defragmented
    /// data matches the value specified in the total length check
    /// field. However,
    /// [some modulators set this value incorrectly](https://github.com/daniestevez/dvb-gse/issues/11).
    /// This function can be used to skip the check of the total length
    /// field.
    pub fn set_skip_total_length_check(&mut self, value: bool) {
        self.defragger.skip_total_length_check = value;
    }

    /// Defragment a BBFRAME.
    ///
    /// This function returns an iterator that produces all the PDUs that can be
    /// completed with the GSE Packets found in the BBFRAME.
    ///
    /// The function returns an error if the BBFRAME is malformed. For instance,
    /// if the BBFRAME length is shorter than the BBHEADER length.
    pub fn defragment<'a>(
        &'a mut self,
        bbframe: &'a BBFrame,
    ) -> Result<impl Iterator<Item = PDU> + 'a, GSEError> {
        if bbframe.len() < BBHeader::LEN {
            return Err(GSEError::BBFrameShort);
        }
        let bbheader = bbframe[..BBHeader::LEN].try_into().unwrap();
        let bbheader = BBHeader::new(&bbheader);
        if bbheader.is_gse_hem() {
            let syncd_bits = bbheader.syncd();
            if syncd_bits % 8 != 0 {
                return Err(GSEError::SyncdNotMultiple);
            }
            let syncd_bytes = usize::from(syncd_bits / 8);
            let remaining_start = BBHeader::LEN + syncd_bytes;
            if remaining_start >= bbframe.len() {
                return Err(GSEError::SyncdTooLarge);
            }
            let first_packet = match (self.hem_leftover.is_empty(), syncd_bytes == 0) {
                (true, false) => {
                    log::warn!(
                        "GSE-HEM SYNCD is not zero but we have no leftovers from previous BBFRAME"
                    );
                    None
                }
                (false, true) => {
                    log::warn!(
                        "GSE-HEM SYNCD is zero but we have leftovers from previous BBFRAME; \
                                 dropping leftovers"
                    );
                    self.hem_leftover.truncate(0);
                    None
                }
                (true, true) => None,
                (false, false) => {
                    self.hem_leftover
                        .extend_from_slice(&bbframe[BBHeader::LEN..remaining_start]);
                    let concat = self.hem_leftover.split_off(0).freeze();
                    let hem_last_label = self.hem_last_label.clone();
                    GSEPacket::from_bytes(&concat, hem_last_label.as_ref()).and_then(|packet| {
                        if packet.len() == concat.len() {
                            Some(packet)
                        } else {
                            log::warn!("GSE packet recovered from GSE-HEM leftovers does not match leftovers length; \
                                        dropping packet");
                            None
                        }
                    })
                }
            };
            let remaining = bbframe.slice(remaining_start..);
            let remaining_packets = GSEPacket::try_split_bytes(&remaining, false);
            // use iterator tricks to hook up closures that count the length of
            // GSE packets and update self.hem_leftover accordingly
            let remaining_packets = remaining_packets
                .scan(remaining_start, |end, packet| {
                    *end += packet.len();
                    if let Some(l) = packet.header.label() {
                        self.hem_last_label = Some(l.clone());
                    }
                    Some(Some((*end, packet)))
                })
                .chain(std::iter::once(None))
                .scan(remaining_start, |prev_end, packet| {
                    if let Some((end, packet)) = packet {
                        *prev_end = end;
                        Some(packet)
                    } else {
                        assert!(self.hem_leftover.is_empty());
                        self.hem_leftover.extend_from_slice(&bbframe[*prev_end..]);
                        None
                    }
                });
            Ok(EitherIter::A(
                first_packet
                    .into_iter()
                    .chain(remaining_packets)
                    .flat_map(|packet| self.defragger.defrag_packet(&packet)),
            ))
        } else {
            if !self.hem_leftover.is_empty() {
                log::warn!(
                    "defragmenting non-HEM BBFRAME, but have leftovers from previous HEM BBFRAME; \
                            dropping leftovers"
                );
                self.hem_leftover.truncate(0);
            }
            Ok(EitherIter::B(
                GSEPacket::split_bbframe(bbframe)?
                    .flat_map(|packet| self.defragger.defrag_packet(&packet)),
            ))
        }
    }
}

impl Defragger {
    fn defrag_packet(&mut self, packet: &GSEPacket) -> Option<PDU> {
        if packet.header().is_single_fragment() {
            log::debug!("defragmented GSE Packet as a single fragment");
            return Some(PDU::from_single_fragment(packet).unwrap());
        }
        let frag_id = packet.header().fragment_id().unwrap();
        if packet.header().start() {
            log::debug!("start of GSE fragment ID = {}", frag_id);
            let mut defrag = Defrag::new(packet.header()).unwrap();
            defrag.set_skip_total_length_check(self.skip_total_length_check);
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
            skip_total_length_check: false,
        })
    }

    fn set_skip_total_length_check(&mut self, value: bool) {
        self.skip_total_length_check = value;
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
        if !self.skip_total_length_check && self.total_length != self.current_length {
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
        let pdus: Vec<_> = defrag.defragment(&bbframe).unwrap().collect();
        assert_eq!(pdus.len(), 1);
        let pdu = &pdus[0];
        assert_eq!(&pdu.data()[..], &SINGLE_PACKET[20..]);
        assert_eq!(pdu.protocol_type(), 0x0800);
        assert_eq!(pdu.label().as_slice(), hex!("02 00 48 55 4c 4b"));
    }

    #[test]
    fn test_hem_defrag_multiple() {
        // Create some BBFRAMEs containing GSE packets of the same size
        let dfl_bytes = 400;
        let packet_size_bytes = 75;
        let num_packets = 100;
        // To be filled with SYNCD and CRC-8 ^ MODE
        let bbheader_template = hex!("ba 00 00 00 0c 80 00 00 00 00");
        let bbheader = BBHeader::new(&bbheader_template);
        assert_eq!(usize::from(bbheader.dfl()), dfl_bytes * 8);
        let packets = (0..num_packets)
            .map(|n| {
                // 2 bytes for protocol type (broadcast label for simplicity)
                let gse_length = packet_size_bytes + 2;
                let mut packet = Vec::with_capacity(gse_length + 2);
                packet.push(0xe0);
                packet.push(u8::try_from(gse_length).unwrap());
                // dummy protocol type
                packet.push(0x12);
                packet.push(0x34);
                for j in 0..packet_size_bytes {
                    packet.push((j + n) as u8);
                }
                packet
            })
            .collect::<Vec<Vec<u8>>>();
        let mut bbframes = Vec::new();
        let mut bbframe = BytesMut::new();
        let mut remain = BytesMut::new();
        let mut packets_total = 0;
        let mut packets_in_bbframe = 0;
        for packet in &packets {
            if bbframe.is_empty() {
                let syncd = remain.len() * 8;
                let mut bbheader = bbheader_template;
                bbheader[7] = ((syncd >> 8) & 0xff) as u8;
                bbheader[8] = (syncd & 0xff) as u8;
                let crc = BBHeader::new(&bbheader).compute_crc8();
                bbheader[9] = crc;
                assert!(BBHeader::new(&bbheader).crc_is_valid());
                bbframe.extend_from_slice(&bbheader);
                bbframe.extend_from_slice(&remain);
                packets_in_bbframe = if remain.is_empty() { 0 } else { 1 };
                remain.truncate(0);
            }
            let to_take = (dfl_bytes - (bbframe.len() - BBHeader::LEN)).min(packet.len());
            bbframe.extend_from_slice(&packet[..to_take]);
            if to_take < packet.len() {
                bbframes.push(bbframe.split_off(0).freeze());
                packets_total += packets_in_bbframe;
                assert!(remain.is_empty());
                remain.extend_from_slice(&packet[to_take..]);
            } else {
                packets_in_bbframe += 1;
            }
        }
        // Sanity check that the above has generated a reasonable amount of data
        assert!(packets_total > 75);
        assert!(bbframes.len() > 10);

        // Defragment the BBFRAMEs
        let mut defrag = GSEPacketDefrag::new();
        let mut pdus = Vec::with_capacity(packets_total);
        for bbframe in &bbframes {
            for packet in defrag.defragment(bbframe).unwrap() {
                pdus.push(packet);
            }
        }
        assert_eq!(pdus.len(), packets_total);
        for (n, pdu) in pdus.iter().enumerate() {
            let expected = (0..packet_size_bytes)
                .map(|j| (j + n) as u8)
                .collect::<Vec<u8>>();
            assert_eq!(pdu.data(), &expected);
            assert_eq!(pdu.protocol_type(), 0x1234);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn garbage()
            (g in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..10000), 0..100))
             -> Vec<BBFrame> {
                g.into_iter().map(|v| Bytes::copy_from_slice(&v)).collect::<Vec<BBFrame>>()
            }
    }

    proptest! {
        #[test]
        fn defrag_garbage(garbage_bbframes in garbage()) {
            let mut defrag = GSEPacketDefrag::new();
            for bbframe in &garbage_bbframes {
                if let Ok(pdus) = defrag.defragment(bbframe) {
                    for pdu in pdus {
                        pdu.data();
                        pdu.protocol_type();
                        pdu.label();
                    }
                }
            }
        }
    }
}
