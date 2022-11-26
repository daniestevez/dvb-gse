//! DVB-S2 Base-Band Frame (BBFRAME).
//!
//! The DVB-S2 BBFRAME corresponds to the input of the BCH encoder. It is
//! composed by a BBHEADER, a data field, and padding reach to the BCH codeword
//! size (which depends on the coding rate and the short or normal FECFRAMES are
//! used). See Section 5 in [EN 302
//! 307-1](https://www.etsi.org/deliver/etsi_en/302300_302399/30230701/01.04.01_60/en_30230701v010401p.pdf).

use super::bbheader::{BBHeader, SisMis, TsGs};
use bytes::Bytes;
use std::io::Result;
use std::net::UdpSocket;

// The maximum BBFRAME size possible corresponds to r=154/180 DVB-S2X with
// normal FECFRAMEs, which is 55248 bits or 6906 bytes.
const BBFRAME_MAX_LEN: usize = 6906;

/// BBFRAME defragmenter.
///
/// This receivers BBFRAME fragments from an object that implements the
/// [`RecvFragment`] trait and performs defragmentation to obtain and return
/// full BBFRAMES.
#[derive(Debug)]
pub struct BBFrameDefrag<R> {
    recv_fragment: R,
    buffer: Box<[u8]>,
    occupied_bytes: usize,
    isi: Option<u8>,
}

/// BBFRAME (Base-Band Frame).
///
/// This is an alias for [`Bytes`]. BBFRAMES are represented by the `Bytes` that
/// contains its data.
pub type BBFrame = Bytes;

/// The `RecvFragment` trait allows receiving BBFRAME fragments.
///
/// This trait is modeled around [`UdpSocket::recv_from`], since the main method
/// to receive BBFRAME fragments is as datagrams received from a UDP socket.
///
/// The BBFRAME fragments are required to be such that the start of each BBFRAME
/// is always at the start of a fragment.
pub trait RecvFragment {
    /// Receives a single fragment into the buffer. On success, returns the
    /// number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient
    /// size to hold the message bytes. If a message is too long to fit in the
    /// supplied buffer, excess bytes may be discarded.
    fn recv_fragment(&mut self, buf: &mut [u8]) -> Result<usize>;
}

impl RecvFragment for UdpSocket {
    fn recv_fragment(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.recv_from(buf).map(|x| x.0)
    }
}

impl<F> RecvFragment for F
where
    F: FnMut(&mut [u8]) -> Result<usize>,
{
    fn recv_fragment(&mut self, buf: &mut [u8]) -> Result<usize> {
        self(buf)
    }
}

impl<R> BBFrameDefrag<R> {
    /// Creates a new BBFRAME defragmenter.
    ///
    /// The `recv_fragment` object is intended to be an implementor of
    /// [`RecvFragment`] that will be used to receive BBFRAME fragments.
    pub fn new(recv_fragment: R) -> BBFrameDefrag<R> {
        let buffer = vec![0; BBFRAME_MAX_LEN].into_boxed_slice();
        BBFrameDefrag {
            recv_fragment,
            buffer,
            occupied_bytes: 0,
            isi: None,
        }
    }

    /// Set the ISI (Input Stream Indicator) to process.
    ///
    /// When this function is called with `Some(n)`, the defragmenter will
    /// expect an MIS (Multiple Input Stream) signal and will only process the
    /// indicated ISI. When this function is called with `None`, the
    /// defragmenter will expect a SIS (Single Input Stream) signal.
    ///
    /// The default after the construction of [`BBFrameDefrag`] is SIS mode.
    pub fn set_isi(&mut self, isi: Option<u8>) {
        self.isi = isi;
    }
}

impl<R: RecvFragment> BBFrameDefrag<R> {
    /// Get and return a new BBFRAME.
    ///
    /// This function calls the [`RecvFragment::recv_fragment`] method of the
    /// `RecvFragment` object owned by the defragmented until a complete BBFRAME
    /// has been reassembled. On success, the BBFRAME is returned.
    pub fn get_bbframe(&mut self) -> Result<BBFrame> {
        loop {
            self.occupied_bytes = 0;
            // Get UDP packets until we have a full BBHEADER (typically a single
            // packet will suffice).
            while self.occupied_bytes < BBHeader::LEN {
                self.recv()?;
            }
            if !self.bbheader_is_valid() {
                continue;
            }
            let bbframe_len = usize::from(self.bbheader().dfl() / 8) + BBHeader::LEN;
            while self.occupied_bytes < bbframe_len {
                self.recv()?;
            }
            if self.occupied_bytes > bbframe_len {
                log::warn!("received unexpected extra data at the end of BBFRAME data field");
            }
            let bbframe = Bytes::copy_from_slice(&self.buffer[..bbframe_len]);
            log::trace!("completed BBFRAME {:?}", bbframe);
            return Ok(bbframe);
        }
    }

    fn recv(&mut self) -> Result<()> {
        let n = self
            .recv_fragment
            .recv_fragment(&mut self.buffer[self.occupied_bytes..])?;
        self.occupied_bytes += n;
        Ok(())
    }

    fn bbheader(&self) -> BBHeader {
        BBHeader::new(self.buffer[..BBHeader::LEN].try_into().unwrap())
    }

    fn bbheader_is_valid(&self) -> bool {
        let header = self.bbheader();
        if !header.crc_is_valid() {
            return false;
        }
        log::trace!("received {} with valid CRC", header);
        if !matches!(header.tsgs(), TsGs::GenericContinuous) {
            log::error!(
                "unsupported TS/GS type '{}' (only 'Generic continous' is supported)",
                header.tsgs()
            );
            return false;
        }
        match self.isi {
            None => {
                if !matches!(header.sismis(), SisMis::Sis) {
                    log::error!("MIS (multiple input stream) BBFRAME unsupported in SIS mode");
                    return false;
                }
            }
            Some(isi) => {
                if !matches!(header.sismis(), SisMis::Mis) {
                    log::error!("SIS (single input stream) BBFRAME unsupported in MIS mode");
                    return false;
                }
                if header.isi() != isi {
                    log::debug!("dropping BBFRAME with ISI = {}", header.isi());
                    return false;
                }
            }
        }
        if header.issyi() {
            log::error!("ISSYI unsupported");
            return false;
        }
        if header.dfl() % 8 != 0 {
            log::error!("unsupported data field length not a multiple of 8 bits");
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    const SINGLE_FRAGMENT: [u8; 104] = hex!(
        "72 00 00 00 02 f0 00 00 00 15 c0 5c 08 00 02 00
         48 55 4c 4b 45 00 00 54 6f aa 40 00 40 01 72 fc
         2c 00 00 01 2c 00 00 02 08 00 4e 94 00 3b 00 04
         19 7d 6b 63 00 00 00 00 5d 79 08 00 00 00 00 00
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37"
    );

    static FRAGMENT0: [u8; 510] = hex!(
        "72 00 00 00 26 b0 00 00 00 66 c4 d4 08 00 02 00
         48 55 4c 4b 45 00 04 cc a2 89 40 00 40 01 3b a5
         2c 00 00 01 2c 00 00 02 08 00 3e b0 00 3c 00 01
         b7 88 6b 63 00 00 00 00 ba 09 0d 00 00 00 00 00
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
         40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f
         50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
         60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
         70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f
         80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
         90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
         a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af
         b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf
         c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf
         d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df
         e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef
         f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff
         00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f
         40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f
         50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f
         60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f
         70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f
         80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
         90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
         a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af
         b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf
         c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd"
    );

    static FRAGMENT1: [u8; 510] = hex!(
        "ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd
         de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed
         ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd
         fe ff 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d
         0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d
         1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d
         2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d
         3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
         4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d
         5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d
         6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d
         7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d
         8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d
         9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad
         ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd
         be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd
         ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd
         de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed
         ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd
         fe ff 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d
         0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d
         1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d
         2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d
         3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d
         4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d
         5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d
         6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d
         7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d
         8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d
         9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad
         ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd
         be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb"
    );

    static FRAGMENT2: [u8; 228] = hex!(
        "cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db
         dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb
         ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb
         fc fd fe ff 00 01 02 03 04 05 06 07 08 09 0a 0b
         0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b
         1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b
         2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b
         3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b
         4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 5b
         5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b
         6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 7b
         7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b
         8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b
         9c 9d 9e 9f a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab
         ac ad ae af"
    );

    static MULTIPLE_FRAGMENTS: [&'static [u8]; 3] = [&FRAGMENT0, &FRAGMENT1, &FRAGMENT2];

    #[test]
    fn single_fragment() {
        let times_called = std::cell::Cell::new(0);
        let mut defrag = BBFrameDefrag::new(|buff: &mut [u8]| {
            times_called.replace(times_called.get() + 1);
            buff[..SINGLE_FRAGMENT.len()].copy_from_slice(&SINGLE_FRAGMENT);
            Ok(SINGLE_FRAGMENT.len())
        });
        assert_eq!(
            defrag.get_bbframe().unwrap(),
            Bytes::from_static(&SINGLE_FRAGMENT)
        );
        assert_eq!(times_called.get(), 1);
    }

    #[test]
    fn multiple_fragments() {
        let times_called = std::cell::Cell::new(0);
        let mut defrag = BBFrameDefrag::new(|buff: &mut [u8]| {
            let fragment = MULTIPLE_FRAGMENTS[times_called.get()];
            times_called.replace(times_called.get() + 1);
            buff[..fragment.len()].copy_from_slice(fragment);
            Ok(fragment.len())
        });
        let mut expected = bytes::BytesMut::new();
        for fragment in &MULTIPLE_FRAGMENTS {
            expected.extend_from_slice(fragment);
        }
        assert_eq!(defrag.get_bbframe().unwrap(), expected);
        assert_eq!(times_called.get(), 3);
    }
}
