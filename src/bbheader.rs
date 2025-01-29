//! DVB-S2 Base-Band Header (BBHEADER).
//!
//! The BBHEADER (Base-Band Header) is a 10-byte header at the start of every
//! DVB-S2 BBFRAME (Base-Band Frame). See Section 5.1.6 in
//! [EN 302 307-1](https://www.etsi.org/deliver/etsi_en/302300_302399/30230701/01.04.01_60/en_30230701v010401p.pdf) and in the
//! the [DVB BlueBook A083-2r3](https://dvb.org/wp-content/uploads/2021/07/A083-2r3_DVB-S2X_Draft-EN-302-307-2-v141_Feb_2022.pdf)
//! for the features specific to DVB-S2X.

use super::BitSlice;
use bitvec::prelude::*;
use num_enum::TryFromPrimitive;
use std::fmt::{Display, Formatter};

/// DVB-S2 BBHEADER.
///
/// This struct is used to parse the fields of a BBHEADER. It is simply a
/// wrapper over an array reference `&[u8; 10]`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BBHeader<'a>(&'a [u8; BBHeader::LEN]);

lazy_static::lazy_static! {
    static ref CRC8: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_DVB_S2);
}

impl BBHeader<'_> {
    /// Length of a BBHEADER in bytes.
    pub const LEN: usize = 10;

    /// Creates a new BBHEADER.
    pub fn new(data: &[u8; BBHeader::LEN]) -> BBHeader {
        BBHeader(data)
    }

    fn matype1(&self) -> &BitSlice {
        BitSlice::from_slice(&self.0[..1])
    }

    /// Gives the value of the TS/GS (Transport Stream Input or Generic Stream
    /// Input) field.
    pub fn tsgs(&self) -> TsGs {
        TsGs::try_from(self.matype1()[..2].load_be::<u8>()).unwrap()
    }

    /// Returns `true` if the BBFRAME is a GSE-HEM BBFRAME.
    ///
    /// GSE-HEM BBFRAMEs have a different layout and omit some fields.
    pub fn is_gse_hem(&self) -> bool {
        matches!(self.tsgs(), TsGs::GseHem)
    }

    /// Give the value of the SIS/MIS (Single Input Stream or Multiple Input
    /// Stream) field.
    pub fn sismis(&self) -> SisMis {
        SisMis::try_from(self.matype1()[2..3].load_be::<u8>()).unwrap()
    }

    /// Gives the value of the CCM/ACM (Constant Coding and Modulation or
    /// Adaptive Coding and Modulation) field.
    pub fn ccmacm(&self) -> CcmAcm {
        CcmAcm::try_from(self.matype1()[3..4].load_be::<u8>()).unwrap()
    }

    /// Gives the value of ISSY (Input Stream Synchronization Indicator) field.
    pub fn issyi(&self) -> bool {
        self.matype1()[4]
    }

    /// Gives the value of the NPD (Null-packet Deletion) field.
    pub fn npd(&self) -> bool {
        self.matype1()[5]
    }

    /// Gives the value of the GSE-Lite field.
    ///
    /// This field is used in DVB-S2X only and replaces the NPD field in GSE modes.
    pub fn gse_lite(&self) -> bool {
        self.npd()
    }

    /// Gives the value of the roll-off (RO) field.
    pub fn rolloff(&self) -> RollOff {
        RollOff::try_from_primitive(self.matype1()[6..8].load_be::<u8>()).unwrap()
    }

    /// Gives the value of the ISI (Input Stream Identifier) field.
    ///
    /// This field corresponds to the MATYPE-2 byte and is only used in Multiple
    /// Input Stream mode.
    pub fn isi(&self) -> u8 {
        self.0[1]
    }

    /// Gives the value of the UPL (User Packet Length) field.
    ///
    /// The function returns `None` if the UPL field is not present, which is
    /// the case in GSE-HEM mode.
    pub fn upl(&self) -> Option<u16> {
        if self.is_gse_hem() {
            None
        } else {
            Some(u16::from_be_bytes(self.0[2..4].try_into().unwrap()))
        }
    }

    /// Gives the value of the ISSY field.
    ///
    /// The ISSY field is only present in GSE-HEM BBFRAMEs which have the ISSYI
    /// bit asserted. If the ISSY field is not present, this function returns
    /// `None`. The ISSY field is split into 2-byte field and a 1-byte field in
    /// the BBHEADER. These are concatenated into a 3-byte array in the output
    /// of this function.
    pub fn issy(&self) -> Option<[u8; 3]> {
        if self.is_gse_hem() && self.issyi() {
            let mut field = [0; 3];
            field[0] = self.0[2];
            field[1] = self.0[3];
            field[2] = self.0[6];
            Some(field)
        } else {
            None
        }
    }

    /// Gives the value of the DFL (Data Field Length) field.
    pub fn dfl(&self) -> u16 {
        u16::from_be_bytes(self.0[4..6].try_into().unwrap())
    }

    /// Gives the value of the SYNC (User Packet Sync-byte) field.
    ///
    /// The function returns `None` if the SYNC field is not present, which is
    /// the case in GSE-HEM mode.
    pub fn sync(&self) -> Option<u8> {
        if self.is_gse_hem() {
            None
        } else {
            Some(self.0[6])
        }
    }

    /// Gives the value of the SYNCD field.
    pub fn syncd(&self) -> u16 {
        u16::from_be_bytes(self.0[7..9].try_into().unwrap())
    }

    /// Gives the value of the CRC-8 field.
    pub fn crc8(&self) -> u8 {
        self.0[BBHeader::LEN - 1]
    }

    /// Computes and returns the CRC-8 of the BBHEADER.
    pub fn compute_crc8(&self) -> u8 {
        let crc = CRC8.checksum(&self.0[..BBHeader::LEN - 1]);
        if self.is_gse_hem() {
            // ETSI EN 302 307-2 V1.3.1 (2021-07) says that the CRC8_MODE field
            // in GSE-HEM is the EXOR of the MODE field with CRC-8, and that the
            // MODE field has the value 1_D.
            //
            // To confirm if this indeeds refers to the value 1 in decimal.
            crc ^ 1
        } else {
            crc
        }
    }

    /// Checks if the CRC-8 of the BBHEADER is valid.
    pub fn crc_is_valid(&self) -> bool {
        self.crc8() == self.compute_crc8()
    }
}

impl Display for BBHeader<'_> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "BBHEADER(TS/GS = {}, SIS/MIS = {}, CCM/ACM = {}, ISSYI = {}, \
		   NPD/GSE-Lite = {}, {}, ISI = {}, ",
            self.tsgs(),
            self.sismis(),
            self.ccmacm(),
            self.issyi(),
            self.npd(),
            self.rolloff(),
            self.isi(),
        )?;
        if let Some(upl) = self.upl() {
            write!(f, "UPL = {} bits, ", upl)?;
        }
        if let Some(issy) = self.issy() {
            let issy = (u32::from(issy[0]) << 16) | (u32::from(issy[1]) << 8) | u32::from(issy[2]);
            write!(f, "ISSY = {:#06x}, ", issy)?;
        }
        write!(f, "DFL = {} bits, ", self.dfl())?;
        if let Some(sync) = self.sync() {
            write!(f, "SYNC = {:#04x}, ", sync)?;
        }
        write!(f, "SYNCD = {:#06x})", self.syncd())
    }
}

/// TS/GS (Transport Stream Input or Generic Stream Input) field value.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[repr(u8)]
pub enum TsGs {
    /// Transport stream mode.
    Transport = 0b11,
    /// Generic packetized mode.
    GenericPacketized = 0b00,
    /// Generic continuous mode.
    GenericContinuous = 0b01,
    /// GSE-HEM (GSE High Efficiency Mode).
    ///
    /// This is used only in DVB-S2X.
    GseHem = 0b10,
}

impl Display for TsGs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                TsGs::Transport => "Transport",
                TsGs::GenericPacketized => "Generic packetized",
                TsGs::GenericContinuous => "Generic continuous",
                TsGs::GseHem => "GSE-HEM",
            }
        )
    }
}

/// SIS/MIS (Single Input Stream or Multiple Input Stream) field value.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[repr(u8)]
pub enum SisMis {
    /// Single input stream.
    Sis = 0b1,
    /// Multiple input streams.
    Mis = 0b0,
}

impl Display for SisMis {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                SisMis::Sis => "single",
                SisMis::Mis => "multiple",
            }
        )
    }
}

/// CCM/ACM (Constant Coding and Modulation or Adaptive Coding and Modulation)
/// field value.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[repr(u8)]
pub enum CcmAcm {
    /// Constant coding and modulation.
    Ccm = 0b1,
    /// Adaptive coding and modulation.
    ///
    /// This value is also used for VCM (variable coding and modulation).
    Acm = 0b0,
}

impl Display for CcmAcm {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                CcmAcm::Ccm => "CCM",
                CcmAcm::Acm => "ACM",
            }
        )
    }
}

/// Roll-off field values.
///
/// In DVB-S2X, there are two tables of roll-off field values, depending on
/// whether the value is alternated with the reserved value `0b11` in every
/// other BBFRAME or not. The values given here correspond to the case when
/// alternation with `0b11` is not used. These values are backwards compatible
/// with DVB-S2.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, TryFromPrimitive)]
#[repr(u8)]
// For DVB-S2X, these values correspond to no alternation with 0b11
pub enum RollOff {
    /// Roll-off factor 0.35.
    Ro0_35 = 0b00,
    /// Roll-off factor 0.25.
    Ro0_25 = 0b01,
    /// Roll-off factor 0.20.
    Ro0_20 = 0b10,
    /// Reserved value.
    ///
    /// In DVB-S2, this value is reserved. In DVB-S2X, this value is used to
    /// access an additional table with 3 narrower roll-off factors, by using
    /// alternation as described above.
    Reserved = 0b11,
}

impl Display for RollOff {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "α = {}",
            match self {
                RollOff::Ro0_35 => "0.35",
                RollOff::Ro0_25 => "0.25",
                RollOff::Ro0_20 => "0.20",
                RollOff::Reserved => "reserved",
            }
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    const CONTINUOUS_GSE_HEADER: [u8; 10] = hex!("72 00 00 00 02 f0 00 00 00 15");
    const GSE_HEM_HEADER: [u8; 10] = hex!("b2 00 00 00 02 f0 00 00 00 87");
    const GSE_HEM_HEADER_ISSY: [u8; 10] = hex!("ba 00 12 34 02 f0 56 02 11 7c");

    #[test]
    fn continuous_gse_header() {
        let header = BBHeader::new(&CONTINUOUS_GSE_HEADER);
        assert_eq!(
            format!("{}", header),
            "BBHEADER(TS/GS = Generic continuous, SIS/MIS = single, CCM/ACM = CCM, \
	     ISSYI = false, NPD/GSE-Lite = false, α = 0.20, ISI = 0, UPL = 0 bits, \
	     DFL = 752 bits, SYNC = 0x00, SYNCD = 0x0000)"
        );
        assert_eq!(header.tsgs(), TsGs::GenericContinuous);
        assert_eq!(header.sismis(), SisMis::Sis);
        assert_eq!(header.ccmacm(), CcmAcm::Ccm);
        assert!(!header.issyi());
        assert!(!header.npd());
        assert!(!header.gse_lite());
        assert_eq!(header.rolloff(), RollOff::Ro0_20);
        assert_eq!(header.isi(), 0);
        assert_eq!(header.issy(), None);
        assert_eq!(header.upl(), Some(0));
        assert_eq!(header.dfl(), 752);
        assert_eq!(header.sync(), Some(0));
        assert_eq!(header.syncd(), 0);
        assert_eq!(header.crc8(), CONTINUOUS_GSE_HEADER[9]);
        assert_eq!(header.compute_crc8(), header.crc8());
        assert!(header.crc_is_valid());
    }

    #[test]
    fn gse_hem_header() {
        let header = BBHeader::new(&GSE_HEM_HEADER);
        assert_eq!(
            format!("{}", header),
            "BBHEADER(TS/GS = GSE-HEM, SIS/MIS = single, CCM/ACM = CCM, \
	     ISSYI = false, NPD/GSE-Lite = false, α = 0.20, ISI = 0, \
	     DFL = 752 bits, SYNCD = 0x0000)"
        );
        assert_eq!(header.tsgs(), TsGs::GseHem);
        assert_eq!(header.sismis(), SisMis::Sis);
        assert_eq!(header.ccmacm(), CcmAcm::Ccm);
        assert!(!header.issyi());
        assert!(!header.npd());
        assert!(!header.gse_lite());
        assert_eq!(header.rolloff(), RollOff::Ro0_20);
        assert_eq!(header.isi(), 0);
        assert_eq!(header.issy(), None);
        assert_eq!(header.upl(), None);
        assert_eq!(header.dfl(), 752);
        assert_eq!(header.sync(), None);
        assert_eq!(header.syncd(), 0);
        assert_eq!(header.crc8(), GSE_HEM_HEADER[9]);
        assert_eq!(header.compute_crc8(), header.crc8());
        assert!(header.crc_is_valid());
    }

    #[test]
    fn gse_hem_header_issy() {
        let header = BBHeader::new(&GSE_HEM_HEADER_ISSY);
        assert_eq!(
            format!("{}", header),
            "BBHEADER(TS/GS = GSE-HEM, SIS/MIS = single, CCM/ACM = CCM, \
	     ISSYI = true, NPD/GSE-Lite = false, α = 0.20, ISI = 0, \
	     ISSY = 0x123456, DFL = 752 bits, SYNCD = 0x0211)"
        );
        assert_eq!(header.tsgs(), TsGs::GseHem);
        assert_eq!(header.sismis(), SisMis::Sis);
        assert_eq!(header.ccmacm(), CcmAcm::Ccm);
        assert!(header.issyi());
        assert!(!header.npd());
        assert!(!header.gse_lite());
        assert_eq!(header.rolloff(), RollOff::Ro0_20);
        assert_eq!(header.isi(), 0);
        assert_eq!(header.issy(), Some([0x12, 0x34, 0x56]));
        assert_eq!(header.upl(), None);
        assert_eq!(header.dfl(), 752);
        assert_eq!(header.sync(), None);
        assert_eq!(header.syncd(), 0x211);
        assert_eq!(header.crc8(), GSE_HEM_HEADER_ISSY[9]);
        assert_eq!(header.compute_crc8(), header.crc8());
        assert!(header.crc_is_valid());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn doesnt_panic(header: [u8; 10]) {
            let header = BBHeader::new(&header);
            header.tsgs();
            header.sismis();
            header.ccmacm();
            header.issyi();
            header.npd();
            header.gse_lite();
            header.rolloff();
            header.isi();
            header.upl();
            header.dfl();
            header.sync();
            header.syncd();
            header.crc8();
            header.compute_crc8();
            header.crc_is_valid();
            let _ = format!("{header}");
        }
    }
}
