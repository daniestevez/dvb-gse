//! Metrics reporting.
//!
//! This module defines a trait that allows users to define custom metrics
//! reporting.

use crate::gsepacket::PDU;
use bytes::Bytes;

/// dvb-gse metrics reporting.
///
/// This trait is used to implement custom metrics reporting for dvb-gse. The
/// methods defined by this trait are called when certain events happen in the
/// dvb-gse processing. By default, all the methods do nothing. Trait
/// implementors can override some or all of these methods to update and report
/// metrics.
///
/// Metrics objects are cloned in some situations. For instance the CLI
/// application in [`cli`](crate::cli) clones the metrics object for each TCP
/// connection that is handled. Therefore, it is generally expected that cloning
/// a metrics object results in an object that shares the same state, via
/// atomics or mutexes.
pub trait Metrics {
    /// This function is called when a BBFRAME is successfully received.
    ///
    /// The BBFRAME is passed as an argument.
    fn bbframe_received(&mut self, _bbframe: &Bytes) {}

    /// This function is called when an error happens during BBFRAME reception.
    ///
    /// The error is passed as an argument.
    fn bbframe_error(&mut self, _error: &std::io::Error) {}

    /// This function is called when a GSE PDU is successfully received.
    ///
    /// The function is called for all GSE PDUs. Even those which are dropped by
    /// label filtering.
    ///
    /// The GSE PDU is passed as an argument.
    fn gse_pdu_received(&mut self, _pdu: &PDU) {}

    /// This function is called when a GSE PDU is dropped by label filtering.
    ///
    /// The GSE PDU that is dropped is passed as an argument.
    fn gse_pdu_dropped_label_filtering(&mut self, _pdu: &PDU) {}

    /// This function is called when a worker thread is spawned to handle a TCP
    /// client.
    fn tcp_client_connected(&mut self, _stream: &std::net::TcpStream) {}

    /// This function is called when a worker thread that is spawned to handle a
    /// TCP client terminates.
    fn tcp_client_finished(&mut self) {}

    /// This function is called when the payload of a GSE PDU cannot be written
    /// to the TUN device.
    ///
    /// The error and the PDU that caused the error are passed as arguments.
    fn tun_error(&mut self, _error: &std::io::Error, _pdu: &PDU) {}
}

/// Implementation of [`Metrics`] for `()`.
///
/// The type `()` is used when the user does not provide a custom object
/// implementing metrics. This implementation ignores all the calls to the trait
/// methods.
impl Metrics for () {}
