//! Peer manager for tracking and communicating with multiple peers.
//!
//! This module provides `PeerManager`, which maintains a set of peer connections
//! and supports sending/receiving messages to/from peers.

use std::collections::HashMap;
use std::io;
use std::net::TcpStream;

use cano_net::{ClientConnectionConfig, ServerConnectionConfig};

use crate::peer::{Peer, PeerId};
use crate::secure_channel::{ChannelError, SecureChannel};

use cano_wire::net::NetMessage;

/// Error type for `PeerManager` operations.
#[derive(Debug)]
pub enum PeerManagerError {
    /// I/O error.
    Io(io::Error),
    /// Channel error (crypto/protocol).
    Channel(ChannelError),
    /// A peer with the given ID already exists.
    PeerExists(PeerId),
    /// No peer with the given ID was found.
    PeerNotFound(PeerId),
}

impl From<io::Error> for PeerManagerError {
    fn from(e: io::Error) -> Self {
        PeerManagerError::Io(e)
    }
}

impl From<ChannelError> for PeerManagerError {
    fn from(e: ChannelError) -> Self {
        PeerManagerError::Channel(e)
    }
}

/// A manager for tracking and communicating with multiple peers.
///
/// `PeerManager` maintains a `HashMap` of `PeerId` → `Peer` and provides
/// methods for adding peers (outbound or inbound), sending messages to
/// individual or all peers, and receiving messages from any peer.
#[derive(Debug)]
pub struct PeerManager {
    peers: HashMap<PeerId, Peer>,
}

impl PeerManager {
    /// Create a new, empty `PeerManager`.
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
        }
    }

    /// Return the number of peers in the manager.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Return `true` if the manager has no peers.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Create an outbound peer by connecting to `addr` and performing KEMTLS handshake.
    ///
    /// # Errors
    ///
    /// Returns `PeerManagerError::PeerExists` if a peer with the given ID already exists.
    /// Returns `PeerManagerError::Channel` or `PeerManagerError::Io` if the connection
    /// or handshake fails.
    pub fn add_outbound_peer(
        &mut self,
        id: PeerId,
        addr: &str,
        cfg: ClientConnectionConfig,
    ) -> Result<(), PeerManagerError> {
        if self.peers.contains_key(&id) {
            return Err(PeerManagerError::PeerExists(id));
        }

        let chan = SecureChannel::connect(addr, cfg)?;
        let peer = Peer::new(id, chan);

        self.peers.insert(id, peer);
        Ok(())
    }

    /// Wrap an already-accepted TCP stream into a `SecureChannel` / `Peer`.
    ///
    /// # Errors
    ///
    /// Returns `PeerManagerError::PeerExists` if a peer with the given ID already exists.
    /// Returns `PeerManagerError::Channel` or `PeerManagerError::Io` if the handshake fails.
    pub fn add_inbound_peer(
        &mut self,
        id: PeerId,
        stream: TcpStream,
        cfg: ServerConnectionConfig,
    ) -> Result<(), PeerManagerError> {
        if self.peers.contains_key(&id) {
            return Err(PeerManagerError::PeerExists(id));
        }

        let chan = SecureChannel::from_accepted(stream, cfg)?;
        let peer = Peer::new(id, chan);

        self.peers.insert(id, peer);
        Ok(())
    }

    /// Send a message to a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `PeerManagerError::PeerNotFound` if no peer with the given ID exists.
    /// Returns `PeerManagerError::Channel` if the send fails.
    pub fn send_to(&mut self, id: PeerId, msg: &NetMessage) -> Result<(), PeerManagerError> {
        let peer = self
            .peers
            .get_mut(&id)
            .ok_or(PeerManagerError::PeerNotFound(id))?;
        peer.send_msg(msg)?;
        Ok(())
    }

    /// Broadcast a message to all peers.
    ///
    /// If any peer fails, the method returns that error immediately; remaining
    /// peers are not sent to. This is simple behavior for now.
    ///
    /// # Errors
    ///
    /// Returns `PeerManagerError::Channel` if sending to any peer fails.
    pub fn broadcast(&mut self, msg: &NetMessage) -> Result<(), PeerManagerError> {
        for peer in self.peers.values_mut() {
            peer.send_msg(msg)?;
        }
        Ok(())
    }

    /// Try receiving from any peer in round-robin order.
    ///
    /// For now, this is a simple blocking call: it iterates peers and
    /// returns as soon as one yields a message. In a real node, this would
    /// be event-driven / async.
    ///
    /// # Errors
    ///
    /// Returns `PeerManagerError::Channel` if a peer fails with a non-WouldBlock error.
    /// Returns `PeerManagerError::Io` with `WouldBlock` if no peer had data ready.
    pub fn recv_from_any(&mut self) -> Result<(PeerId, NetMessage), PeerManagerError> {
        for (&id, peer) in self.peers.iter_mut() {
            // For now, just try a blocking recv; in tests we arrange to have a message ready.
            match peer.recv_msg() {
                Ok(msg) => return Ok((id, msg)),
                Err(ChannelError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data yet, try next peer.
                    continue;
                }
                Err(e) => {
                    // Any other error is fatal for now.
                    return Err(PeerManagerError::Channel(e));
                }
            }
        }

        Err(PeerManagerError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "no peer had data ready",
        )))
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}