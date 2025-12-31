//! Handshake packet framing layer for KEMTLS messages.
//!
//! This module provides a simple binary framing protocol for handshake messages
//! (ClientInit, ServerAccept, ServerCookie) used in the KEMTLS handshake.

use crate::error::NetError;
use cano_wire::io::{WireDecode, WireEncode};
use cano_wire::net::{ClientInit, ServerAccept, ServerCookie};

/// Handshake message type for ClientInit.
pub const HANDSHAKE_TYPE_CLIENT_INIT: u8 = 0x01;
/// Handshake message type for ServerAccept.
pub const HANDSHAKE_TYPE_SERVER_ACCEPT: u8 = 0x02;
/// Handshake message type for ServerCookie.
pub const HANDSHAKE_TYPE_SERVER_COOKIE: u8 = 0x03;

/// Simple handshake packet wrapper for on-the-wire framing.
///
/// Wire format (big-endian):
///   - msg_type: u8
///   - len: u16
///   - payload: [u8; len]
///
/// The `payload` is the encoded cano-wire::net message (ClientInit, ServerAccept, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePacket {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl HandshakePacket {
    /// Encode this packet to a length-prefixed binary frame.
    ///
    /// Layout:
    ///   - msg_type: u8
    ///   - len: u16 (big-endian)
    ///   - payload: [u8; len]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len();
        assert!(
            len <= u16::MAX as usize,
            "payload too large for handshake packet"
        );

        let mut out = Vec::with_capacity(1 + 2 + len);
        out.push(self.msg_type);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a HandshakePacket from a buffer.
    ///
    /// Expects the entire frame to be present; does not support streaming.
    pub fn decode(buf: &[u8]) -> Result<Self, NetError> {
        if buf.len() < 3 {
            return Err(NetError::Protocol("handshake packet too short"));
        }

        let msg_type = buf[0];
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;

        if buf.len() < 3 + len {
            return Err(NetError::Protocol("handshake packet payload truncated"));
        }

        let payload = buf[3..3 + len].to_vec();

        Ok(HandshakePacket { msg_type, payload })
    }
}

// ============================================================================
// Pack/unpack helpers for specific handshake message types
// ============================================================================

/// Pack a ClientInit message into a HandshakePacket.
pub fn pack_client_init(msg: &ClientInit) -> Result<HandshakePacket, NetError> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    Ok(HandshakePacket {
        msg_type: HANDSHAKE_TYPE_CLIENT_INIT,
        payload: buf,
    })
}

/// Unpack a ClientInit message from a HandshakePacket.
pub fn unpack_client_init(pkt: &HandshakePacket) -> Result<ClientInit, NetError> {
    if pkt.msg_type != HANDSHAKE_TYPE_CLIENT_INIT {
        return Err(NetError::Protocol(
            "unexpected handshake type for ClientInit",
        ));
    }
    let mut cursor = &pkt.payload[..];
    ClientInit::decode(&mut cursor).map_err(|_| NetError::Protocol("decode ClientInit failed"))
}

/// Pack a ServerAccept message into a HandshakePacket.
pub fn pack_server_accept(msg: &ServerAccept) -> Result<HandshakePacket, NetError> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    Ok(HandshakePacket {
        msg_type: HANDSHAKE_TYPE_SERVER_ACCEPT,
        payload: buf,
    })
}

/// Unpack a ServerAccept message from a HandshakePacket.
pub fn unpack_server_accept(pkt: &HandshakePacket) -> Result<ServerAccept, NetError> {
    if pkt.msg_type != HANDSHAKE_TYPE_SERVER_ACCEPT {
        return Err(NetError::Protocol(
            "unexpected handshake type for ServerAccept",
        ));
    }
    let mut cursor = &pkt.payload[..];
    ServerAccept::decode(&mut cursor)
        .map_err(|_| NetError::Protocol("decode ServerAccept failed"))
}

/// Pack a ServerCookie message into a HandshakePacket.
pub fn pack_server_cookie(msg: &ServerCookie) -> Result<HandshakePacket, NetError> {
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    Ok(HandshakePacket {
        msg_type: HANDSHAKE_TYPE_SERVER_COOKIE,
        payload: buf,
    })
}

/// Unpack a ServerCookie message from a HandshakePacket.
pub fn unpack_server_cookie(pkt: &HandshakePacket) -> Result<ServerCookie, NetError> {
    if pkt.msg_type != HANDSHAKE_TYPE_SERVER_COOKIE {
        return Err(NetError::Protocol(
            "unexpected handshake type for ServerCookie",
        ));
    }
    let mut cursor = &pkt.payload[..];
    ServerCookie::decode(&mut cursor)
        .map_err(|_| NetError::Protocol("decode ServerCookie failed"))
}