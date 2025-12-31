//! Framed I/O helpers for handshake packets and transport frames.
//!
//! This module provides blocking, synchronous read/write utilities for
//! `HandshakePacket` and `TransportFrame` over any `std::io::Read + Write` stream.
//!
//! These helpers are intended as building blocks for higher-level connection
//! management. Later async/P2P layers can wrap or re-implement them with
//! non-blocking I/O.

use std::io::{self, Read, Write};

use crate::handshake_packet::HandshakePacket;
use crate::transport::TransportFrame;

/// Upper bound for handshake payload to avoid unbounded allocations from bogus length fields.
/// Conservative limit: 16 KiB should be more than enough for any handshake message.
pub const MAX_HANDSHAKE_PAYLOAD: usize = 16 * 1024;

/// Upper bound for transport ciphertext to avoid unbounded allocations from bogus length fields.
/// Conservative limit: 16 MiB should handle any reasonable application message.
pub const MAX_TRANSPORT_CIPHERTEXT: usize = 16 * 1024 * 1024;

/// Write a `HandshakePacket` to a blocking stream.
///
/// Encodes the packet to its wire format and writes the entire frame,
/// then flushes the writer.
///
/// # Errors
///
/// Returns an `io::Error` if the write or flush fails.
pub fn write_handshake_packet<W: Write>(writer: &mut W, packet: &HandshakePacket) -> io::Result<()> {
    let encoded = packet.encode();
    writer.write_all(&encoded)?;
    writer.flush()
}

/// Read a `HandshakePacket` from a blocking stream.
///
/// Reads the 3-byte header (msg_type: u8, len: u16 BE), validates the length,
/// then reads the payload and decodes the packet.
///
/// # Errors
///
/// - Returns `io::ErrorKind::UnexpectedEof` if the stream is truncated.
/// - Returns `io::ErrorKind::InvalidData` if the length exceeds `MAX_HANDSHAKE_PAYLOAD`
///   or if decoding fails.
pub fn read_handshake_packet<R: Read>(reader: &mut R) -> io::Result<HandshakePacket> {
    // Read the 3-byte header: msg_type (u8) + len (u16 BE)
    let mut header = [0u8; 3];
    reader.read_exact(&mut header)?;

    let len = u16::from_be_bytes([header[1], header[2]]) as usize;

    // Enforce size limit to prevent unbounded allocations
    if len > MAX_HANDSHAKE_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "handshake payload length exceeds maximum",
        ));
    }

    // Allocate buffer for full frame (header + payload) and read payload
    let mut buf = Vec::with_capacity(3 + len);
    buf.extend_from_slice(&header);
    buf.resize(3 + len, 0);
    reader.read_exact(&mut buf[3..])?;

    // Decode the packet
    HandshakePacket::decode(&buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode handshake packet: {:?}", e),
        )
    })
}

/// Write a `TransportFrame` to a blocking stream.
///
/// Encodes the frame to its wire format and writes the entire frame,
/// then flushes the writer.
///
/// # Errors
///
/// Returns an `io::Error` if encoding, write, or flush fails.
pub fn write_transport_frame<W: Write>(writer: &mut W, frame: &TransportFrame) -> io::Result<()> {
    let encoded = frame.encode().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to encode transport frame: {:?}", e),
        )
    })?;
    writer.write_all(&encoded)?;
    writer.flush()
}

/// Read a `TransportFrame` from a blocking stream.
///
/// Reads the 5-byte header (msg_type: u8, len: u32 BE), validates the length,
/// then reads the ciphertext and decodes the frame.
///
/// # Errors
///
/// - Returns `io::ErrorKind::UnexpectedEof` if the stream is truncated.
/// - Returns `io::ErrorKind::InvalidData` if the length exceeds `MAX_TRANSPORT_CIPHERTEXT`
///   or if decoding fails.
pub fn read_transport_frame<R: Read>(reader: &mut R) -> io::Result<TransportFrame> {
    // Read the 5-byte header: msg_type (u8) + len (u32 BE)
    let mut header = [0u8; 5];
    reader.read_exact(&mut header)?;

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    // Enforce size limit to prevent unbounded allocations
    if len > MAX_TRANSPORT_CIPHERTEXT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "transport ciphertext length exceeds maximum",
        ));
    }

    // Allocate buffer for full frame (header + ciphertext) and read ciphertext
    let mut buf = Vec::with_capacity(5 + len);
    buf.extend_from_slice(&header);
    buf.resize(5 + len, 0);
    reader.read_exact(&mut buf[5..])?;

    // Decode the frame
    TransportFrame::decode(&buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode transport frame: {:?}", e),
        )
    })
}