//! Peer abstraction for encrypted network communication.
//!
//! This module provides `Peer`, which wraps a `SecureChannel` and adds
//! wire-level encoding/decoding of `NetMessage` types.

use std::io;

use crate::secure_channel::{ChannelError, SecureChannel};
use cano_wire::error::WireError;
use cano_wire::net::NetMessage;

/// Placeholder peer identifier.
///
/// This is a temporary stand-in that will later be wired to the real
/// validator/peer identity (e.g., AccountId or a dedicated ValidatorId type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

/// A peer connection over an encrypted secure channel.
///
/// `Peer` wraps a `SecureChannel` and provides higher-level methods for
/// sending and receiving wire-encoded `NetMessage` types.
#[derive(Debug)]
pub struct Peer {
    pub id: PeerId,
    channel: SecureChannel,
}

impl Peer {
    /// Create a new Peer with the given ID and secure channel.
    pub fn new(id: PeerId, channel: SecureChannel) -> Self {
        Peer { id, channel }
    }

    /// Check if the underlying channel is established and ready for app data.
    pub fn is_established(&self) -> bool {
        self.channel.is_established()
    }

    /// Encode and send a single `NetMessage` over the encrypted channel.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if encoding fails or the underlying send fails.
    pub fn send_msg(&mut self, msg: &NetMessage) -> Result<(), ChannelError> {
        let bytes = msg.encode_to_vec().map_err(wire_error_to_channel_error)?;
        self.channel.send_app(&bytes)?;
        Ok(())
    }

    /// Receive and decode a single `NetMessage` from the encrypted channel.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the underlying receive fails or decoding fails.
    pub fn recv_msg(&mut self) -> Result<NetMessage, ChannelError> {
        let bytes = self.channel.recv_app()?;
        let msg = NetMessage::decode_from_slice(&bytes).map_err(wire_error_to_channel_error)?;
        Ok(msg)
    }

    /// Accessor to the inner `SecureChannel` if needed later.
    pub fn channel(&mut self) -> &mut SecureChannel {
        &mut self.channel
    }
}

/// Convert a WireError into a ChannelError.
fn wire_error_to_channel_error(e: WireError) -> ChannelError {
    match e {
        WireError::TooLarge { actual, max } => ChannelError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("net message too large: {} > {}", actual, max),
        )),
        other => ChannelError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode net msg: {:?}", other),
        )),
    }
}