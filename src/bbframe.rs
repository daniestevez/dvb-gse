//! DVB-S2 Base-Band Frame (BBFRAME).
//!
//! The DVB-S2 BBFRAME corresponds to the input of the BCH encoder. It is
//! composed by a BBHEADER, a data field, and padding reach to the BCH codeword
//! size (which depends on the coding rate and the short or normal FECFRAMES are
//! used). See Section 5 in [EN 302
//! 307-1](https://www.etsi.org/deliver/etsi_en/302300_302399/30230701/01.04.01_60/en_30230701v010401p.pdf).

use super::bbheader::{BBHeader, SisMis, TsGs};
use bytes::Bytes;
use std::io::{Read, Result};
use std::net::UdpSocket;

// This import is used by rustdoc
#[allow(unused_imports)]
use std::net::TcpStream;

/// Maximum header length in bytes.
///
/// This is used to allocate buffers for the BBFRAMEs, taking into account that
/// they can optionally be preceded by a header whose maximum length is given by
/// this constant. The value of the constant is set to a somewhat arbitrary
/// choice that should be good for most use cases.
pub const HEADER_MAX_LEN: usize = 64;

/// Maximum BBFRAME length in bytes (including header).
///
/// The maximum BBFRAME size possible corresponds to r=9/10 DVB-S2 with normal
/// FECFRAMEs, which is 58192 bits or 7274 bytes.
///
/// The constant includes the [`HEADER_MAX_LEN`] in the calculation of the
/// maximum BBFRAME length.
pub const BBFRAME_MAX_LEN: usize = 7274 + HEADER_MAX_LEN;

/// BBFRAME defragmenter.
///
/// This receives BBFRAME fragments from an object that implements the
/// [`RecvFragment`] trait and performs defragmentation and validation to obtain
/// and return full BBFRAMES.
#[derive(Debug)]
pub struct BBFrameDefrag<R> {
    recv_fragment: R,
    buffer: Box<[u8; BBFRAME_MAX_LEN]>,
    occupied_bytes: usize,
    validator: BBFrameValidator,
    header_bytes: usize,
}

/// BBFRAME receiver.
///
/// This receives complete BBFRAMEs from an object that implements the
/// [`RecvBBFrame`] trait and performs validation to return valid BBFRAMES.
#[derive(Debug)]
pub struct BBFrameRecv<R> {
    recv_bbframe: R,
    buffer: Box<[u8; BBFRAME_MAX_LEN]>,
    validator: BBFrameValidator,
    header_bytes: usize,
}

/// BBFRAME stream receiver.
///
/// This receives BBFRAMEs from a stream object that implements the
/// [`RecvStream`] trait and performs validation to return valid BBFRAMES.
#[derive(Debug)]
pub struct BBFrameStream<R> {
    recv_stream: R,
    buffer: Box<[u8; BBFRAME_MAX_LEN]>,
    validator: BBFrameValidator,
    header_bytes: usize,
}

/// Receiver of BBFrames.
///
/// This trait generalizes reception of BBFRAMEs and provides a method to
/// receive validated BBFRAMEs one by one.
pub trait BBFrameReceiver {
    /// Get and return a new validated BBFRAME.
    fn get_bbframe(&mut self) -> Result<BBFrame>;
}

/// BBFRAME validator.
///
/// This object checks if a BBFRAME is a valid BBFRAME containing GSE data in
/// the appropriate ISI (Input Stream Indicator).
#[derive(Debug, Default)]
pub struct BBFrameValidator {
    isi: Option<u8>,
}

impl BBFrameValidator {
    /// Creates a BBFRAME validator.
    pub fn new() -> BBFrameValidator {
        BBFrameValidator::default()
    }

    /// Set the ISI (Input Stream Indicator) to process.
    ///
    /// When this function is called with `Some(n)`, the validator will expect
    /// an MIS (Multiple Input Stream) signal and only declare as valid BBFRAMEs
    /// from the the indicated ISI. When this function is called with `None`,
    /// the validator will expect a SIS (Single Input Stream) signal.
    ///
    /// The default after the construction of the validator is SIS mode.
    pub fn set_isi(&mut self, isi: Option<u8>) {
        self.isi = isi;
    }

    /// Checks if a BBHEADER is valid.
    ///
    /// The following conditions are tested:
    ///
    /// - CRC of the BBHEADER.
    ///
    /// - TS/GS type matching generic continuous.
    ///
    /// - SIS/MIS and ISI matching what expected according to the last
    ///   [`BBFrameValidator::set_isi`] call.
    ///
    /// - ISSYI disabled.
    ///
    /// - The DFL is a multiple of 8 bits and not larger than the maximum
    ///   BBFRAME length.
    ///
    /// If the BBFRAME is not valid, this function logs the reason using
    /// the [`log`] crate.
    pub fn bbheader_is_valid(&self, bbheader: BBHeader) -> bool {
        if !bbheader.crc_is_valid() {
            return false;
        }
        log::trace!("received {} with valid CRC", bbheader);
        if !matches!(bbheader.tsgs(), TsGs::GenericContinuous) {
            log::error!(
                "unsupported TS/GS type '{}' (only 'Generic continous' is supported)",
                bbheader.tsgs()
            );
            return false;
        }
        match self.isi {
            None => {
                if !matches!(bbheader.sismis(), SisMis::Sis) {
                    log::error!("MIS (multiple input stream) BBFRAME unsupported in SIS mode");
                    return false;
                }
            }
            Some(isi) => {
                if !matches!(bbheader.sismis(), SisMis::Mis) {
                    log::error!("SIS (single input stream) BBFRAME unsupported in MIS mode");
                    return false;
                }
                if bbheader.isi() != isi {
                    log::debug!("dropping BBFRAME with ISI = {}", bbheader.isi());
                    return false;
                }
            }
        }
        if bbheader.issyi() {
            log::error!("ISSYI unsupported");
            return false;
        }
        if bbheader.dfl() % 8 != 0 {
            log::error!("unsupported data field length not a multiple of 8 bits");
            return false;
        }
        if usize::from(bbheader.dfl() / 8) > BBFRAME_MAX_LEN - BBHeader::LEN - HEADER_MAX_LEN {
            log::error!("DFL value {} too large", bbheader.dfl());
            return false;
        }
        true
    }
}

/// BBFRAME (Base-Band Frame).
///
/// This is an alias for [`Bytes`]. BBFRAMES are represented by the `Bytes` that
/// contains their data.
pub type BBFrame = Bytes;

/// Receiver of BBFRAME fragments.
///
/// This trait is modeled around [`UdpSocket::recv_from`], since the main way to
/// receive BBFRAME fragments is as datagrams received from a UDP socket.
///
/// The BBFRAME fragments are required to be such that the start of each BBFRAME
/// is always at the start of a fragment. The BBFRAMEs may or may not have
/// padding at the end. The `recv_fragment` function is allowed to skip
/// supplying some fragments, which happens for instance if UDP packets are lost
/// (when this trait is implemented by a UDP socket).
pub trait RecvFragment {
    /// Receives a single fragment into the buffer. On success, returns the
    /// number of bytes read.
    ///
    /// The function must be called with a valid byte slice `buf` of sufficient
    /// size to hold the fragment. If a fragment is too long to fit in the
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

/// Receiver of complete BBFRAMEs.
///
/// This trait is modeled around [`UdpSocket::recv_from`], since the main way to
/// receive complete BBFRAMEs is as jumbo datagrams received from a UDP socket.
///
/// The BBFRAMEs may or may not have padding at the end. The `recv_fragment`
/// function is allowed to skip suppyling some complete BBFRAMEs, which happens
/// for instance if UDP packets are lost (when this trait is implemented by a
/// UDP socket).
pub trait RecvBBFrame {
    /// Receives a single fragment into the buffer. On success, returns the
    /// number of bytes read.
    ///
    /// The function is called with a byte array `buf` of sufficient
    /// size to hold the message bytes.
    fn recv_bbframe(&mut self, buf: &mut [u8; BBFRAME_MAX_LEN]) -> Result<usize>;
}

impl RecvBBFrame for UdpSocket {
    fn recv_bbframe(&mut self, buf: &mut [u8; BBFRAME_MAX_LEN]) -> Result<usize> {
        self.recv_from(&mut buf[..]).map(|x| x.0)
    }
}

impl<F> RecvBBFrame for F
where
    F: FnMut(&mut [u8; BBFRAME_MAX_LEN]) -> Result<usize>,
{
    fn recv_bbframe(&mut self, buf: &mut [u8; BBFRAME_MAX_LEN]) -> Result<usize> {
        self(buf)
    }
}

/// Receiver of a stream of BBFRAMEs.
///
/// This trait is modeled around [`TcpStream::read_exact`], since it is the main
/// way to receive a stream of BBFRAMEs.
///
/// The BBFRAMEs cannot have padding at the end (the length of the BBFRAME must
/// be equal to the DFL plus the BBHEADER). They need to be present back-to-back
/// in the stream.  The stream is allowed to skip supplying some complete
/// BBFRAMEs (this may happened with a TCP stream if BBFRAMEs overflow a buffer
/// before being written to the TCP socket).
pub trait RecvStream {
    /// Reads the exact number of bytes required to fill `buf`.
    fn recv_stream(&mut self, buf: &mut [u8]) -> Result<()>;
}

impl<R: Read> RecvStream for R {
    fn recv_stream(&mut self, buf: &mut [u8]) -> Result<()> {
        self.read_exact(buf)
    }
}

trait BBFrameRecvCommon {
    fn buffer(&self) -> &[u8; BBFRAME_MAX_LEN];

    fn bbheader(&self) -> BBHeader {
        BBHeader::new(self.buffer()[..BBHeader::LEN].try_into().unwrap())
    }
}

macro_rules! impl_recv_common {
    ($($id:ident),*) => {
        $(
            impl<R> BBFrameRecvCommon for $id<R> {
                fn buffer(&self) -> &[u8; BBFRAME_MAX_LEN] {
                    &self.buffer
                }
            }
        )*
    }
}

impl_recv_common!(BBFrameDefrag, BBFrameRecv, BBFrameStream);

macro_rules! impl_set_isi {
    ($t:ident) => {
        /// Set the ISI (Input Stream Indicator) to process.
        ///
        /// When this function is called with `Some(n)`, the BBFRAME receiver
        /// will expect an MIS (Multiple Input Stream) signal and will only
        /// process the indicated ISI. When this function is called with `None`,
        /// the defragmenter will expect a SIS (Single Input Stream) signal.
        ///
        /// The default after the construction of the receiver is SIS mode.
        pub fn set_isi(&mut self, isi: Option<u8>) {
            self.validator.set_isi(isi);
        }
    };
}

impl<R> BBFrameDefrag<R> {
    /// Creates a new BBFRAME defragmenter.
    ///
    /// The `recv_fragment` object is intended to be an implementor of
    /// [`RecvFragment`] that will be used to receive BBFRAME fragments.
    pub fn new(recv_fragment: R) -> BBFrameDefrag<R> {
        BBFrameDefrag {
            recv_fragment,
            buffer: Box::new([0; BBFRAME_MAX_LEN]),
            occupied_bytes: 0,
            validator: BBFrameValidator::new(),
            header_bytes: 0,
        }
    }

    impl_set_isi!(BBFrameDefrag);

    /// Sets the number of bytes used in the header in each fragment.
    ///
    /// The header is removed before reading the rest of the fragment, which
    /// should correpond to a BBFRAME fragment. By default, a header length of
    /// zero bytes is assumed.
    ///
    /// The function returns an error if `header_bytes` is larger than
    /// [`HEADER_MAX_LEN`].
    pub fn set_header_bytes(&mut self, header_bytes: usize) -> Result<()> {
        if header_bytes > HEADER_MAX_LEN {
            log::error!("header bytes larger than maximum header size");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header bytes larger than maximum header size",
            ));
        }
        self.header_bytes = header_bytes;
        Ok(())
    }
}

impl<R: RecvFragment> BBFrameReceiver for BBFrameDefrag<R> {
    /// Get and return a new validated BBFRAME.
    ///
    /// This function calls the [`RecvFragment::recv_fragment`] method of the
    /// `RecvFragment` object owned by the defragmenter until a complete BBFRAME
    /// has been reassembled. On success, the BBFRAME is returned.
    fn get_bbframe(&mut self) -> Result<BBFrame> {
        loop {
            self.occupied_bytes = 0;
            // Get UDP packets until we have a full BBHEADER (typically a single
            // packet will suffice).
            while self.occupied_bytes < BBHeader::LEN {
                self.recv()?;
            }
            if !self.validator.bbheader_is_valid(self.bbheader()) {
                continue;
            }
            let bbframe_len = usize::from(self.bbheader().dfl() / 8) + BBHeader::LEN;
            while self.occupied_bytes < bbframe_len {
                self.recv()?;
            }
            let bbframe = Bytes::copy_from_slice(&self.buffer[..bbframe_len]);
            log::trace!("completed BBFRAME {}", faster_hex::hex_string(&bbframe));
            return Ok(bbframe);
        }
    }
}

impl<R: RecvFragment> BBFrameDefrag<R> {
    fn recv(&mut self) -> Result<()> {
        let n = self
            .recv_fragment
            .recv_fragment(&mut self.buffer[self.occupied_bytes..])?;
        if self.header_bytes != 0 {
            if self.header_bytes > n {
                log::error!("received a fragment smaller than the header size");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "BBFRAME is too short",
                ));
            }
            // overwrite the header with the rest of the data
            self.buffer.copy_within(
                self.occupied_bytes + self.header_bytes..self.occupied_bytes + n,
                self.occupied_bytes,
            );
        }
        self.occupied_bytes += n - self.header_bytes;
        Ok(())
    }
}

impl<R> BBFrameRecv<R> {
    /// Creates a new BBFRAME receiver.
    ///
    /// The `recv_bbframe` object is intended to be an implementor of
    /// [`RecvBBFrame`] that will be used to receive complete BBFRAMEs.
    pub fn new(recv_bbframe: R) -> BBFrameRecv<R> {
        BBFrameRecv {
            recv_bbframe,
            buffer: Box::new([0; BBFRAME_MAX_LEN]),
            validator: BBFrameValidator::new(),
            header_bytes: 0,
        }
    }

    impl_set_isi!(BBFrameRecv);

    /// Sets the number of bytes used in the header in each BBFRAME.
    ///
    /// The header is removed before reading the BBFRAME. By default, a header
    /// length of zero bytes is assumed.
    ///
    /// The function returns an error if `header_bytes` is larger than
    /// [`HEADER_MAX_LEN`].
    pub fn set_header_bytes(&mut self, header_bytes: usize) -> Result<()> {
        if header_bytes > HEADER_MAX_LEN {
            log::error!("header bytes larger than maximum header size");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header bytes larger than maximum header size",
            ));
        }
        self.header_bytes = header_bytes;
        Ok(())
    }
}

impl<R: RecvBBFrame> BBFrameReceiver for BBFrameRecv<R> {
    /// Get and return a new validated BBFRAME.
    ///
    /// This function calls the [`RecvBBFrame::recv_bbframe`] method of the
    /// `RecvBBFrame` object owned by the receiver and validates the received
    /// BBFRAME, returning an error if the BBFRAME is not valid or if there is
    /// an error in reception.
    fn get_bbframe(&mut self) -> Result<BBFrame> {
        let recv_len = self.recv_bbframe.recv_bbframe(&mut self.buffer)?;
        if self.header_bytes != 0 {
            if self.header_bytes > recv_len {
                log::error!("received a fragment smaller than the header size");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "BBFRAME is too short",
                ));
            }
            // This could be removed if we allowed the functions below to use an
            // offset in the buffer to access the BBFRAME.
            self.buffer.copy_within(self.header_bytes..recv_len, 0);
        }
        let recv_len = recv_len - self.header_bytes;
        if recv_len < BBHeader::LEN {
            log::error!("received BBFRAME is too short (length {recv_len})");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "BBFRAME is too short",
            ));
        }
        if !self.validator.bbheader_is_valid(self.bbheader()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid BBFRAME received",
            ));
        }
        let bbframe_len = usize::from(self.bbheader().dfl() / 8) + BBHeader::LEN;
        if recv_len < bbframe_len {
            log::error!(
                "received BBFRAME has length {recv_len}, \
                         but according to DFL it should have length {bbframe_len}"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "BBFRAME is too short",
            ));
        }
        let bbframe = Bytes::copy_from_slice(&self.buffer[..bbframe_len]);
        log::trace!("completed BBFRAME {}", faster_hex::hex_string(&bbframe));
        Ok(bbframe)
    }
}

impl<R> BBFrameStream<R> {
    /// Creates a new BBFRAME stream receiver.
    ///
    /// The `recv_stream` object is intended to be an implementor of
    /// [`RecvStream`] that will be used to receive BBFRAMEs from a stream.
    pub fn new(recv_stream: R) -> BBFrameStream<R> {
        BBFrameStream {
            recv_stream,
            buffer: Box::new([0; BBFRAME_MAX_LEN]),
            validator: BBFrameValidator::new(),
            header_bytes: 0,
        }
    }

    impl_set_isi!(BBFrameStream);

    /// Sets the number of bytes used in the header in each BBFRAME.
    ///
    /// The function returns an error if `header_bytes` is larger than
    /// [`HEADER_MAX_LEN`].
    pub fn set_header_bytes(&mut self, header_bytes: usize) -> Result<()> {
        if header_bytes > HEADER_MAX_LEN {
            log::error!("header bytes larger than maximum header size");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header bytes larger than maximum header size",
            ));
        }
        self.header_bytes = header_bytes;
        Ok(())
    }
}

impl<R: RecvStream> BBFrameReceiver for BBFrameStream<R> {
    /// Get and return a new validated BBFRAME.
    ///
    /// This function calls the [`RecvStream::recv_stream] method of the
    /// `RecvStream` object owned by the receiver and validates the received
    /// BBFRAME, returning an error if the BBFRAME is not valid or if there is
    /// an error in reception.
    fn get_bbframe(&mut self) -> Result<BBFrame> {
        if self.header_bytes != 0 {
            // read header (will be discarded)
            self.recv_stream
                .recv_stream(&mut self.buffer[..self.header_bytes])?;
        }
        // read full BBHEADER
        self.recv_stream
            .recv_stream(&mut self.buffer[..BBHeader::LEN])?;
        if !self.validator.bbheader_is_valid(self.bbheader()) {
            // BBHeader is invalid, but we try to honor its DFL and read the
            // data field to recover from the error, unless the DFL is too large
            let bbframe_len = usize::from(self.bbheader().dfl() / 8) + BBHeader::LEN;
            if bbframe_len <= BBFRAME_MAX_LEN {
                self.recv_stream
                    .recv_stream(&mut self.buffer[BBHeader::LEN..bbframe_len])?;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid BBHEADER received",
            ));
        }
        let bbframe_len = usize::from(self.bbheader().dfl() / 8) + BBHeader::LEN;
        // read data field
        self.recv_stream
            .recv_stream(&mut self.buffer[BBHeader::LEN..bbframe_len])?;
        let bbframe = Bytes::copy_from_slice(&self.buffer[..bbframe_len]);
        log::trace!("completed BBFRAME {}", faster_hex::hex_string(&bbframe));
        Ok(bbframe)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    pub const SINGLE_FRAGMENT: [u8; 104] = hex!(
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

    const SINGLE_FRAGMENT_MIS: [u8; 104] = hex!(
        "52 2a 00 00 02 f0 00 00 00 dc c0 5c 08 00 02 00
         48 55 4c 4b 45 00 00 54 6f aa 40 00 40 01 72 fc
         2c 00 00 01 2c 00 00 02 08 00 4e 94 00 3b 00 04
         19 7d 6b 63 00 00 00 00 5d 79 08 00 00 00 00 00
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37"
    );

    const SINGLE_FRAGMENT_MIS_OTHER_STREAM: [u8; 104] = hex!(
        "52 2b 00 00 02 f0 00 00 00 9f c0 5c 08 00 02 00
         48 55 4c 4b 45 00 00 54 6f aa 40 00 40 01 72 fc
         2c 00 00 01 2c 00 00 02 08 00 4e 94 00 3b 00 04
         19 7d 6b 63 00 00 00 00 5d 79 08 00 00 00 00 00
         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
         20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
         30 31 32 33 34 35 36 37"
    );

    static MULTIPLE_FRAGMENTS: [&[u8]; 3] = [&FRAGMENT0, &FRAGMENT1, &FRAGMENT2];

    #[test]
    fn single_fragment_defrag() {
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
    fn single_fragment_defrag_mis() {
        let isi = 0x2a;
        let times_called = std::cell::Cell::new(0);
        let mut defrag = BBFrameDefrag::new(|buff: &mut [u8]| {
            let fragment = if times_called.get() % 2 == 0 {
                &SINGLE_FRAGMENT_MIS_OTHER_STREAM
            } else {
                &SINGLE_FRAGMENT_MIS
            };
            times_called.replace(times_called.get() + 1);
            buff[..fragment.len()].copy_from_slice(fragment);
            Ok(fragment.len())
        });
        defrag.set_isi(Some(isi));
        assert_eq!(
            defrag.get_bbframe().unwrap(),
            Bytes::from_static(&SINGLE_FRAGMENT_MIS)
        );
        assert_eq!(times_called.get(), 2);
    }

    #[test]
    fn multiple_fragments_defrag() {
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

    #[test]
    fn recv_one_bbframe() {
        let times_called = std::cell::Cell::new(0);
        let mut defrag = BBFrameRecv::new(|buff: &mut [u8; BBFRAME_MAX_LEN]| {
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
    fn recv_one_bbframe_with_header() {
        let header_bytes = 4;
        let times_called = std::cell::Cell::new(0);
        let mut defrag = BBFrameRecv::new(|buff: &mut [u8; BBFRAME_MAX_LEN]| {
            times_called.replace(times_called.get() + 1);
            buff[..header_bytes].fill(0);
            let total_len = header_bytes + SINGLE_FRAGMENT.len();
            buff[header_bytes..total_len].copy_from_slice(&SINGLE_FRAGMENT);
            Ok(total_len)
        });
        defrag.set_header_bytes(header_bytes).unwrap();
        assert_eq!(
            defrag.get_bbframe().unwrap(),
            Bytes::from_static(&SINGLE_FRAGMENT)
        );
        assert_eq!(times_called.get(), 1);
    }

    #[test]
    fn stream_one_bbframe() {
        let stream = &SINGLE_FRAGMENT[..];
        let mut defrag = BBFrameStream::new(stream);
        assert_eq!(
            defrag.get_bbframe().unwrap(),
            Bytes::from_static(&SINGLE_FRAGMENT)
        );
    }

    #[test]
    fn validator() {
        let valid_header = hex!("72 00 00 00 02 f0 00 00 00 15");
        let mut validator = BBFrameValidator::new();
        assert!(validator.bbheader_is_valid(BBHeader::new(&valid_header)));

        let wrong_crc = hex!("72 00 00 00 02 f0 00 00 00 14");
        assert!(!BBHeader::new(&wrong_crc).crc_is_valid());
        assert!(!validator.bbheader_is_valid(BBHeader::new(&wrong_crc)));

        fn test_invalid(validator: &BBFrameValidator, bbheader: &[u8; 10]) {
            let bbheader = BBHeader::new(bbheader);
            assert!(bbheader.crc_is_valid());
            assert!(!validator.bbheader_is_valid(bbheader));
        }

        let ts_header = hex!("f2 00 00 00 02 f0 00 00 00 44");
        test_invalid(&validator, &ts_header);
        let packetized_header = hex!("32 00 00 00 02 f0 00 00 00 d7");
        test_invalid(&validator, &packetized_header);
        let hem_header = hex!("b2 00 00 00 02 f0 00 00 00 86");
        test_invalid(&validator, &hem_header);
        let mis_header = hex!("52 2a 00 00 02 f0 00 00 00 dc");
        test_invalid(&validator, &mis_header);
        let issyi_header = hex!("7a 00 00 00 02 f0 00 00 00 78");
        test_invalid(&validator, &issyi_header);
        let dfl_not_divisible = hex!("72 00 00 00 02 f1 00 00 00 50");
        test_invalid(&validator, &dfl_not_divisible);
        let dfl_too_large = hex!("72 00 00 00 e3 08 00 00 00 36");
        test_invalid(&validator, &dfl_too_large);

        let isi = 0x2a;
        validator.set_isi(Some(isi));
        assert!(!validator.bbheader_is_valid(BBHeader::new(&valid_header)));
        assert!(validator.bbheader_is_valid(BBHeader::new(&mis_header)));
        let other_isi_header = hex!("52 2b 00 00 02 f0 00 00 00 9f");
        test_invalid(&validator, &other_isi_header);

        validator.set_isi(None);
        assert!(validator.bbheader_is_valid(BBHeader::new(&valid_header)));
        assert!(!validator.bbheader_is_valid(BBHeader::new(&mis_header)));
    }
}

#[cfg(test)]
mod proptests {
    use super::test::SINGLE_FRAGMENT;
    use super::*;
    use proptest::prelude::*;

    fn garbage() -> impl Strategy<Value = Vec<Vec<u8>>> {
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..10000), 0..100)
    }

    proptest! {
        /// Supplies garbage fragments from a Vec until all the garbage
        /// fragments are exhausted. Then it supplies a valid single
        /// fragment. The defragmenter must obtain the good frame without
        /// failing.
        #[test]
        fn bbframe_defrag_garbage(garbage_data in garbage()) {
            let times_called = std::cell::Cell::new(0);
            let single_fragment = SINGLE_FRAGMENT.to_vec();
            let mut defrag = BBFrameDefrag::new(|buff: &mut [u8]| {
                let j = times_called.get();
                let fragment = if j < garbage_data.len() {
                    &garbage_data[j]
                } else {
                    // Used to force termination of get_bbframe succesfully
                    // (sometimes there is an earlier exit if the garbage is a
                    // valid frame just by chance).
                    &single_fragment
                };
                times_called.replace(times_called.get() + 1);
                let copy_len = fragment.len().min(buff.len());
                buff[..copy_len].copy_from_slice(&fragment[..copy_len]);
                Ok(fragment.len())
            });
            let bbframe = defrag.get_bbframe().unwrap();
            // Sometimes
            //   times_called.get() == garbage_data.len() + 2
            // because the SINGLE_FRAGMENT needs to be returned
            // twice in order to flush a partial BBHEADER left
            // by the garbage.
            assert!(times_called.get() <= garbage_data.len() + 2);
            if times_called.get() > garbage_data.len() {
                assert_eq!(bbframe, Bytes::from_static(&SINGLE_FRAGMENT));
            }
        }
    }

    proptest! {
        /// Supplies garbage frames from a Vec until all the garbage frames are
        /// exhausted, then a valid fragment. The receiver get_bbframe() is
        /// allowed to fail, but it is called repeatedly until all the garbage
        /// has been consumed.
        #[test]
        fn bbframe_recv_garbage(garbage_data in garbage()) {
            let times_called = std::cell::Cell::new(0);
            let single_fragment = SINGLE_FRAGMENT.to_vec();
            let mut recv = BBFrameRecv::new(|buff: &mut [u8; BBFRAME_MAX_LEN]| {
                let j = times_called.get();
                let fragment = if j < garbage_data.len() {
                    &garbage_data[j]
                } else {
                    // Used to force termination of get_bbframe succesfully
                    // (sometimes there is an earlier exit if the garbage is a
                    // valid frame just by chance).
                    &single_fragment
                };
                times_called.replace(times_called.get() + 1);
                let copy_len = fragment.len().min(buff.len());
                buff[..copy_len].copy_from_slice(&fragment[..copy_len]);
                Ok(fragment.len())
            });
            while times_called.get() <= garbage_data.len() {
                if let Ok(bbframe) = recv.get_bbframe() {
                    assert!(times_called.get() <= garbage_data.len() + 1);
                    if times_called.get() > garbage_data.len() {
                        assert_eq!(bbframe, Bytes::from_static(&SINGLE_FRAGMENT));
                    }
                }
            }
        }
    }

    #[derive(Debug)]
    struct Garbage {
        times_called: std::rc::Rc<std::cell::Cell<usize>>,
        garbage_data: Vec<Vec<u8>>,
    }

    impl RecvStream for Garbage {
        fn recv_stream(&mut self, buff: &mut [u8]) -> Result<()> {
            let j = self.times_called.get();
            self.times_called.replace(j + 1);
            let fragment = if j < self.garbage_data.len() {
                &self.garbage_data[j]
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "no more garbage",
                ));
            };
            let copy_len = fragment.len().min(buff.len());
            buff[..copy_len].copy_from_slice(&fragment[..copy_len]);
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn bbframe_stream_garbage(garbage_data in garbage()) {
            let times_called = std::rc::Rc::new(std::cell::Cell::new(0));
            let len_garbage_data = garbage_data.len();
            let mut stream = BBFrameStream::new(Garbage { times_called: times_called.clone(),
                                                          garbage_data });
            while times_called.get() < len_garbage_data {
                let _ = stream.get_bbframe();
            }
        }
    }
}
