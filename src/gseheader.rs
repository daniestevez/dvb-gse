//! DVB GSE (Generic Stream Encapsulation) Header.
//!
//! The GSE Header is a variable-length header at the start of every GSE
//! Packet. See Section 4.2 in
//! [TS 102 606-1](https://www.etsi.org/deliver/etsi_ts/102600_102699/10260601/01.02.01_60/ts_10260601v010201p.pdf).

use super::BitSlice;
use bitvec::prelude::*;
use num_enum::TryFromPrimitive;
use std::fmt::{Display, Formatter};

/// GSE Header.
///
/// This structure stores the parsed field values from a GSE Header.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GSEHeader {
    start: bool,
    end: bool,
    label_type: LabelType,
    gse_length: u16,
    frag_id: Option<u8>,
    total_length: Option<u16>,
    protocol_type: Option<u16>,
    label: Option<Label>,
}

impl GSEHeader {
    /// Creates a GSE Header by parsing the values in a slice.
    ///
    /// On success, the GSE Header is returned.
    ///
    /// If the slice is not long enough to fully contain the GSE Header, `None`
    /// is returned. Since GSE Headers are variable-length, whether this
    /// function returns `None` or not can depend on the values at the beginning
    /// of the slice, in addition to its length.
    ///
    /// Additionally, `None` is returned if the header corresponds to padding
    /// bytes (i.e., if the contents of its fixed fields are all zero).
    ///
    /// In order to fully parse a GSE Header, due to the concept of "label
    /// re-use", it is necessary to know the label of a previous GSE Header in
    /// the same BBFRAME. This can be provided in the `re_used_label`
    /// parameter. If this parameter is `None` and a GSE Header with START = 1
    /// and label re-use is found in the slice, then this function fails,
    /// returning `None`.
    pub fn from_slice(slice: &[u8], re_used_label: Option<&Label>) -> Option<GSEHeader> {
        let fixed_len = 2;
        if slice.len() < fixed_len {
            return None;
        }
        let fixed = BitSlice::from_slice(&slice[..fixed_len]);
        let start = fixed[0];
        let end = fixed[1];
        let label_type = LabelType::try_from(fixed[2..4].load_be::<u8>()).unwrap();
        if !start && !end && matches!(label_type, LabelType::Label6Byte) {
            // This header corresponds to padding bytes
            return None;
        }
        let gse_length = fixed[4..].load_be::<u16>();
        let mut remain = &slice[fixed_len..];
        let frag_id = if !start || !end {
            let (&value, r) = remain.split_first()?;
            remain = r;
            Some(value)
        } else {
            None
        };
        let total_length = if start && !end {
            if remain.len() < 2 {
                return None;
            }
            let (field, r) = remain.split_at(2);
            remain = r;
            Some(u16::from_be_bytes(field.try_into().unwrap()))
        } else {
            None
        };
        let protocol_type = if start {
            if remain.len() < 2 {
                return None;
            }
            let (field, r) = remain.split_at(2);
            remain = r;
            Some(u16::from_be_bytes(field.try_into().unwrap()))
        } else {
            None
        };
        let label = if start {
            if matches!(label_type, LabelType::ReUse) {
                if let Some(label) = re_used_label {
                    Some(label.clone())
                } else {
                    log::error!("LT = re-use, but not label to re-use");
                    return None;
                }
            } else {
                let label_size = match label_type {
                    LabelType::Label6Byte => LabelSize::Size6Bytes,
                    LabelType::Label3Byte => LabelSize::Size3Bytes,
                    LabelType::Broadcast => LabelSize::Zero,
                    LabelType::ReUse => unreachable!(),
                };
                if remain.len() < label_size.len() {
                    log::error!("not enough bytes for label remain in slice");
                    return None;
                }
                let mut data = [0; 6];
                data[..label_size.len()].copy_from_slice(&remain[..label_size.len()]);
                Some(Label {
                    data,
                    size: label_size,
                })
            }
        } else {
            None
        };
        Some(GSEHeader {
            start,
            end,
            label_type,
            gse_length,
            frag_id,
            total_length,
            protocol_type,
            label,
        })
    }

    /// Gives the value of the Start Indicator field.
    pub fn start(&self) -> bool {
        self.start
    }

    /// Gives the value of the End Indicator field.
    pub fn end(&self) -> bool {
        self.end
    }

    /// Returns `true` if the GSE Packet is not fragmented.
    ///
    /// A GSE Packet is not fragmented if both its Start Indicator and its End
    /// Indicator contain `true`.
    pub fn is_single_fragment(&self) -> bool {
        self.start() && self.end()
    }

    /// Gives the value Label Type Indicator field.
    pub fn label_type(&self) -> LabelType {
        self.label_type
    }

    /// Gives the value of the GSE Length field.
    pub fn gse_length(&self) -> u16 {
        self.gse_length
    }

    /// Gives the value of the Fragment ID field, if present.
    pub fn fragment_id(&self) -> Option<u8> {
        self.frag_id
    }

    /// Gives the value of the Total Length field, if present.
    pub fn total_length(&self) -> Option<u16> {
        self.total_length
    }

    /// Gives the value of the Protocol Type field, if present.
    pub fn protocol_type(&self) -> Option<u16> {
        self.protocol_type
    }

    /// Gives the value of the Label field, if present.
    pub fn label(&self) -> Option<&Label> {
        self.label.as_ref()
    }

    /// Gives the length in bytes of the GSE Header.
    pub fn len(&self) -> usize {
        let mut len = 2; // fixed length
        if self.frag_id.is_some() {
            len += 1;
        }
        if self.total_length.is_some() {
            len += 2;
        }
        if self.protocol_type.is_some() {
            len += 2;
        }
        // When the label type is re-use, the GSEHeader struct contains a label,
        // but this was not transmitted over-the-air in the header, so we should
        // not add the length of the label.
        if !matches!(self.label_type, LabelType::ReUse) {
            if let Some(label) = &self.label {
                len += label.len();
            }
        }
        len
    }

    /// Returns `true` if the GSE Header has a length of zero bytes.
    ///
    /// This always returns `false`, since a GSE Header never has a length of
    /// zero bytes. This function exists because objects that implement a `len`
    /// method should also implement an `is_empty` method.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl Display for GSEHeader {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "GSE Header (S = {}, E = {}, LT = {}, GSE Length = {} bytes",
            self.start, self.end, self.label_type, self.gse_length
        )?;
        if let Some(frag_id) = self.frag_id {
            write!(f, ", Fragment ID = {}", frag_id)?;
        }
        if let Some(total_length) = self.total_length {
            write!(f, ", Total Length = {}", total_length)?;
        }
        if let Some(protocol_type) = self.protocol_type {
            write!(f, ", Protocol Type = {:#06x}", protocol_type)?;
        }
        if let Some(label) = &self.label {
            write!(f, ", Label = {}", label)?;
        }
        write!(f, ")")
    }
}

/// GSE Label.
///
/// GSE Labels are used for address filtering in the receiver. GSE supports
/// three kinds of labels: a 6-byte label (as an Ethernet MAC address), a 3-byte
/// label, and a broadcast label, which is empty.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Label {
    data: [u8; 6],
    size: LabelSize,
}

impl Label {
    /// Gives a slice containing the label data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len()]
    }

    /// Gives the length of the label in bytes.
    pub fn len(&self) -> usize {
        self.size.len()
    }

    /// Returns `true` if the label has a length of zero bytes.
    ///
    /// This function returns `true` if the label is the broadcast label.
    pub fn is_empty(&self) -> bool {
        matches!(self.size, LabelSize::Zero)
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        if let Some((first, rest)) = self.as_slice().split_first() {
            write!(f, "{:02x}", first)?;
            for b in rest {
                write!(f, ":{:02x}", b)?;
            }
            Ok(())
        } else {
            write!(f, "broadcast")
        }
    }
}

/// Label Type field values.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[repr(u8)]
pub enum LabelType {
    /// 6-byte label.
    Label6Byte = 0b00,
    /// 3-byte label.
    Label3Byte = 0b01,
    /// Broadcast label.
    Broadcast = 0b10,
    /// Label re-use.
    ReUse = 0b11,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum LabelSize {
    Size6Bytes,
    Size3Bytes,
    Zero,
}

impl Display for LabelType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                LabelType::Label6Byte => "6 byte label",
                LabelType::Label3Byte => "3 byte label",
                LabelType::Broadcast => "broadcast label",
                LabelType::ReUse => "label re-use",
            }
        )
    }
}

impl LabelSize {
    fn len(&self) -> usize {
        match self {
            LabelSize::Size6Bytes => 6,
            LabelSize::Size3Bytes => 3,
            LabelSize::Zero => 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    const GSE_HEADER_SINGLE_PACKET: [u8; 10] = hex!("c0 5c 08 00 02 00 48 55 4c 4b");

    #[test]
    fn single_packet() {
        let header = GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = true, E = true, LT = 6 byte label, \
	     GSE Length = 92 bytes, Protocol Type = 0x0800, \
	     Label = 02:00:48:55:4c:4b)"
        );
        assert!(header.start());
        assert!(header.end());
        assert!(header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::Label6Byte);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), None);
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), Some(0x0800));
        let label = header.label().unwrap();
        assert_eq!(label.as_slice(), &GSE_HEADER_SINGLE_PACKET[4..]);
        assert_eq!(label.len(), 6);
        assert!(!label.is_empty());
        assert_eq!(header.len(), GSE_HEADER_SINGLE_PACKET.len());
        assert!(!header.is_empty());
    }

    #[test]
    fn too_short() {
        assert!(GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET[..9], None).is_none());
    }

    const GSE_HEADER_FIRST_FRAGMENT: [u8; 13] = hex!("80 5c 17 01 23 08 00 02 00 48 55 4c 4b");

    #[test]
    fn first_fragment() {
        let header = GSEHeader::from_slice(&GSE_HEADER_FIRST_FRAGMENT, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = true, E = false, LT = 6 byte label, \
             GSE Length = 92 bytes, Fragment ID = 23, Total Length = 291, \
             Protocol Type = 0x0800, Label = 02:00:48:55:4c:4b)"
        );
        assert!(header.start());
        assert!(!header.end());
        assert!(!header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::Label6Byte);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), Some(23));
        assert_eq!(header.total_length(), Some(291));
        assert_eq!(header.protocol_type(), Some(0x0800));
        let label = header.label().unwrap();
        assert_eq!(label.as_slice(), &GSE_HEADER_FIRST_FRAGMENT[7..]);
        assert_eq!(label.len(), 6);
        assert!(!label.is_empty());
        assert_eq!(header.len(), GSE_HEADER_FIRST_FRAGMENT.len());
        assert!(!header.is_empty());
    }

    const GSE_HEADER_INTERMEDIATE_FRAGMENT: [u8; 3] = hex!("30 5c 17");

    #[test]
    fn intermediate_fragment() {
        let header = GSEHeader::from_slice(&GSE_HEADER_INTERMEDIATE_FRAGMENT, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = false, E = false, LT = label re-use, \
             GSE Length = 92 bytes, Fragment ID = 23)"
        );
        assert!(!header.start());
        assert!(!header.end());
        assert!(!header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::ReUse);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), Some(23));
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), None);
        assert_eq!(header.label(), None);
        assert_eq!(header.len(), GSE_HEADER_INTERMEDIATE_FRAGMENT.len());
        assert!(!header.is_empty());
    }

    const GSE_HEADER_LAST_FRAGMENT: [u8; 3] = hex!("70 5c 17");

    #[test]
    fn last_fragment() {
        let header = GSEHeader::from_slice(&GSE_HEADER_LAST_FRAGMENT, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = false, E = true, LT = label re-use, \
             GSE Length = 92 bytes, Fragment ID = 23)"
        );
        assert!(!header.start());
        assert!(header.end());
        assert!(!header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::ReUse);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), Some(23));
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), None);
        assert_eq!(header.label(), None);
        assert_eq!(header.len(), GSE_HEADER_LAST_FRAGMENT.len());
        assert!(!header.is_empty());
    }

    const GSE_HEADER_SINGLE_PACKET_3BYTE_LABEL: [u8; 7] = hex!("d0 5c 08 00 55 4c 4b");

    #[test]
    fn single_packet_3byte_label() {
        let header = GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET_3BYTE_LABEL, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = true, E = true, LT = 3 byte label, \
	     GSE Length = 92 bytes, Protocol Type = 0x0800, \
	     Label = 55:4c:4b)"
        );
        assert!(header.start());
        assert!(header.end());
        assert!(header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::Label3Byte);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), None);
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), Some(0x0800));
        let label = header.label().unwrap();
        assert_eq!(label.as_slice(), &GSE_HEADER_SINGLE_PACKET_3BYTE_LABEL[4..]);
        assert_eq!(label.len(), 3);
        assert!(!label.is_empty());
        assert_eq!(header.len(), GSE_HEADER_SINGLE_PACKET_3BYTE_LABEL.len());
        assert!(!header.is_empty());
    }

    const GSE_HEADER_SINGLE_PACKET_BROADCAST_LABEL: [u8; 4] = hex!("e0 5c 08 00");

    #[test]
    fn single_packet_broadcast_label() {
        let header =
            GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET_BROADCAST_LABEL, None).unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = true, E = true, LT = broadcast label, \
	     GSE Length = 92 bytes, Protocol Type = 0x0800, Label = broadcast)"
        );
        assert!(header.start());
        assert!(header.end());
        assert!(header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::Broadcast);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), None);
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), Some(0x0800));
        let label = header.label().unwrap();
        assert_eq!(label.as_slice(), &[]);
        assert_eq!(label.len(), 0);
        assert!(label.is_empty());
        assert_eq!(header.len(), GSE_HEADER_SINGLE_PACKET_BROADCAST_LABEL.len());
        assert!(!header.is_empty());
    }

    const GSE_HEADER_SINGLE_PACKET_LABEL_REUSE: [u8; 4] = hex!("f0 5c 08 00");

    #[test]
    fn single_packet_label_reuse() {
        let g0 = GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET, None).unwrap();
        let re_used_label = g0.label().unwrap();
        let header =
            GSEHeader::from_slice(&GSE_HEADER_SINGLE_PACKET_LABEL_REUSE, Some(re_used_label))
                .unwrap();
        assert_eq!(
            format!("{}", header),
            "GSE Header (S = true, E = true, LT = label re-use, \
	     GSE Length = 92 bytes, Protocol Type = 0x0800, \
             Label = 02:00:48:55:4c:4b)"
        );
        assert!(header.start());
        assert!(header.end());
        assert!(header.is_single_fragment());
        assert_eq!(header.label_type(), LabelType::ReUse);
        assert_eq!(header.gse_length(), 92);
        assert_eq!(header.fragment_id(), None);
        assert_eq!(header.total_length(), None);
        assert_eq!(header.protocol_type(), Some(0x0800));
        let label = header.label().unwrap();
        assert_eq!(label, re_used_label);
        assert_eq!(header.len(), GSE_HEADER_SINGLE_PACKET_LABEL_REUSE.len());
        assert!(!header.is_empty());
    }

    #[test]
    fn padding_packet() {
        assert_eq!(GSEHeader::from_slice(&[0; 2], None), None);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn random_header(header in proptest::collection::vec(any::<u8>(), 0..=32)) {
            if let Some(header) = GSEHeader::from_slice(&header, None) {
                format!("{}", header);
                header.start();
                header.end();
                header.is_single_fragment();
                header.label_type();
                header.gse_length();
                header.fragment_id();
                header.total_length();
                header.protocol_type();
                if let Some(label) = header.label() {
                    label.as_slice();
                    let len = label.len();
                    assert_eq!(label.is_empty(), len == 0);
                }
                assert!(header.len() >= 3);
                assert!(!header.is_empty());
            }
        }
    }
}
