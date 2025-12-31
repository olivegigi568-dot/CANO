//! Peer abstraction for encrypted network communication.
//!
//! This module provides `Peer`, which wraps a `SecureChannel` and adds
//! wire-level encoding/decoding of `NetMessage` types.

use std::io;
use std::time::{Duration, Instant};

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
///
/// The `last_ping` and `last_pong` fields provide temporary liveness tracking.
/// These will be refactored later when we have a real event loop.
#[derive(Debug)]
pub struct Peer {
    pub id: PeerId,
    channel: SecureChannel,
    /// Timestamp of the last Ping sent by this peer.
    last_ping: Option<Instant>,
    /// Timestamp of the last Pong received by this peer.
    last_pong: Option<Instant>,
}

impl Peer {
    /// Create a new Peer with the given ID and secure channel.
    pub fn new(id: PeerId, channel: SecureChannel) -> Self {
        Peer {
            id,
            channel,
            last_ping: None,
            last_pong: None,
        }
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

    // ========================================================================
    // Ping/Pong liveness methods
    // ========================================================================

    /// Send a Ping with the given nonce.
    ///
    /// Updates `last_ping` timestamp on success.
    pub fn send_ping(&mut self, nonce: u64) -> Result<(), ChannelError> {
        let msg = NetMessage::Ping(nonce);
        self.send_msg(&msg)?;
        self.last_ping = Some(Instant::now());
        Ok(())
    }

    /// Handle an incoming Ping and reply with a Pong with the same nonce.
    pub fn handle_incoming_ping(&mut self, nonce: u64) -> Result<(), ChannelError> {
        let msg = NetMessage::Pong(nonce);
        self.send_msg(&msg)
    }

    /// Handle an incoming Pong and update liveness.
    ///
    /// Note: Currently we don't validate that the nonce matches a sent ping.
    /// This is intentional for this minimal implementation - we just mark that
    /// the peer is responsive. Nonce validation can be added later if replay
    /// protection is needed.
    pub fn handle_incoming_pong(&mut self, _nonce: u64) {
        self.last_pong = Some(Instant::now());
    }

    /// Returns true if we have seen a Pong within the given timeout.
    pub fn is_live(&self, timeout: Duration) -> bool {
        match self.last_pong {
            Some(ts) => ts.elapsed() <= timeout,
            None => false,
        }
    }

    /// Get the timestamp of the last Ping sent (for testing/debugging).
    pub fn last_ping(&self) -> Option<Instant> {
        self.last_ping
    }

    /// Get the timestamp of the last Pong received (for testing/debugging).
    pub fn last_pong(&self) -> Option<Instant> {
        self.last_pong
    }

    /// Set the last_pong timestamp directly (for testing purposes only).
    ///
    /// This method is intended for use in tests to simulate timeout scenarios
    /// without requiring actual time to pass.
    pub fn set_last_pong_for_test(&mut self, ts: Option<Instant>) {
        self.last_pong = ts;
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