//! Consensus networking adapter for the cano node.
//!
//! This module provides `ConsensusNetAdapter`, which wraps a `PeerManager` and
//! presents a clean API in terms of `Vote` and `BlockProposal` instead of raw
//! `NetMessage`. This adapter is used by the consensus engine (`cano-consensus`)
//! in tests and in the node.
//!
//! The adapter also implements `cano_consensus::ConsensusNetwork`, allowing
//! the consensus engine to depend only on an abstract trait rather than
//! concrete networking types.

use std::io;

use crate::peer::PeerId;
use crate::peer_manager::{PeerManager, PeerManagerError};
use cano_consensus::{ConsensusNetwork, ConsensusNetworkEvent, NetworkError};
use cano_wire::consensus::{BlockProposal, Vote};
use cano_wire::net::NetMessage;

// ============================================================================
// ConsensusNetError
// ============================================================================

/// Error type for `ConsensusNetAdapter` operations.
#[derive(Debug)]
pub enum ConsensusNetError {
    /// Error from the underlying PeerManager.
    PeerManager(PeerManagerError),
    /// I/O error.
    Io(io::Error),
}

impl From<PeerManagerError> for ConsensusNetError {
    fn from(e: PeerManagerError) -> Self {
        ConsensusNetError::PeerManager(e)
    }
}

impl From<io::Error> for ConsensusNetError {
    fn from(e: io::Error) -> Self {
        ConsensusNetError::Io(e)
    }
}

// ============================================================================
// ConsensusNetEvent
// ============================================================================

/// Events that the consensus engine will see when polling the network.
#[derive(Debug)]
pub enum ConsensusNetEvent {
    /// An incoming vote from a peer.
    IncomingVote {
        /// The peer that sent the vote.
        from: PeerId,
        /// The vote message.
        vote: Vote,
    },
    /// An incoming block proposal from a peer.
    IncomingProposal {
        /// The peer that sent the proposal.
        from: PeerId,
        /// The block proposal message.
        proposal: BlockProposal,
    },
    // (Future: PeerConnected, PeerDisconnected, etc.)
}

// ============================================================================
// ConsensusNetAdapter
// ============================================================================

/// A consensus networking adapter that wraps a `PeerManager`.
///
/// This adapter hides the underlying `NetMessage` representation and provides
/// a clean API in terms of `Vote` and `BlockProposal` for use by the consensus
/// engine.
#[derive(Debug)]
pub struct ConsensusNetAdapter {
    peers: PeerManager,
}

impl ConsensusNetAdapter {
    /// Create a new `ConsensusNetAdapter` wrapping the given `PeerManager`.
    pub fn new(peers: PeerManager) -> Self {
        ConsensusNetAdapter { peers }
    }

    /// Borrow the inner `PeerManager` if the node needs direct access.
    pub fn peers(&mut self) -> &mut PeerManager {
        &mut self.peers
    }
}

// ============================================================================
// Outbound API
// ============================================================================

impl ConsensusNetAdapter {
    /// Broadcast a block proposal to all connected peers.
    pub fn broadcast_proposal(
        &mut self,
        proposal: &BlockProposal,
    ) -> Result<(), ConsensusNetError> {
        let msg = NetMessage::BlockProposal(proposal.clone());
        self.peers.broadcast(&msg)?;
        Ok(())
    }

    /// Broadcast a vote to all connected peers.
    pub fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), ConsensusNetError> {
        let msg = NetMessage::ConsensusVote(vote.clone());
        self.peers.broadcast(&msg)?;
        Ok(())
    }

    /// Send a vote to a specific peer.
    pub fn send_vote_to(
        &mut self,
        to: PeerId,
        vote: &Vote,
    ) -> Result<(), ConsensusNetError> {
        let msg = NetMessage::ConsensusVote(vote.clone());
        self.peers.send_to(to, &msg)?;
        Ok(())
    }
}

// ============================================================================
// Inbound API
// ============================================================================

impl ConsensusNetAdapter {
    /// Blocking receive of one consensus-related message from any peer.
    ///
    /// For now this just wraps `PeerManager::recv_from_any` and translates
    /// `NetMessage` into `ConsensusNetEvent`. Non-consensus messages are
    /// treated as an error for now.
    pub fn recv_one(&mut self) -> Result<ConsensusNetEvent, ConsensusNetError> {
        let (from, msg) = self.peers.recv_from_any()?;

        let event = match msg {
            NetMessage::ConsensusVote(vote) => ConsensusNetEvent::IncomingVote { from, vote },
            NetMessage::BlockProposal(proposal) => {
                ConsensusNetEvent::IncomingProposal { from, proposal }
            }
            NetMessage::Ping(_) => {
                return Err(ConsensusNetError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected Ping message in consensus adapter",
                )));
            }
            NetMessage::Pong(_) => {
                return Err(ConsensusNetError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected Pong message in consensus adapter",
                )));
            }
        };

        Ok(event)
    }
}

// ============================================================================
// ConsensusNetwork trait implementation
// ============================================================================

/// Implementation of the abstract `ConsensusNetwork` trait from `cano-consensus`.
///
/// This allows the consensus engine to use `ConsensusNetAdapter` through the
/// trait interface without depending on node-specific types like `PeerManager`
/// or `NetMessage`.
///
/// # ID Mapping
///
/// The trait uses `PeerId` as the `Id` type directly. `PeerId` is a simple
/// `PeerId(u64)` wrapper defined in `cano-node::peer`. If the consensus crate
/// needs a different ID type in the future, conversion traits (`From`/`Into`)
/// can be added to map between them.
impl ConsensusNetwork for ConsensusNetAdapter {
    type Id = PeerId;

    fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        // Delegate to the inherent method and map the error
        ConsensusNetAdapter::broadcast_proposal(self, proposal)
            .map_err(|e| NetworkError::Other(format!("{:?}", e)))
    }

    fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        // Delegate to the inherent method and map the error
        ConsensusNetAdapter::broadcast_vote(self, vote)
            .map_err(|e| NetworkError::Other(format!("{:?}", e)))
    }

    fn send_vote_to(&mut self, to: Self::Id, vote: &Vote) -> Result<(), NetworkError> {
        // Delegate to the inherent method and map the error
        ConsensusNetAdapter::send_vote_to(self, to, vote)
            .map_err(|e| NetworkError::Other(format!("{:?}", e)))
    }

    fn recv_one(&mut self) -> Result<ConsensusNetworkEvent<Self::Id>, NetworkError> {
        // Delegate to the inherent method and map the result
        let event = ConsensusNetAdapter::recv_one(self)
            .map_err(|e| NetworkError::Other(format!("{:?}", e)))?;

        // Convert node-level ConsensusNetEvent to trait-level ConsensusNetworkEvent
        let mapped = match event {
            ConsensusNetEvent::IncomingVote { from, vote } => {
                ConsensusNetworkEvent::IncomingVote { from, vote }
            }
            ConsensusNetEvent::IncomingProposal { from, proposal } => {
                ConsensusNetworkEvent::IncomingProposal { from, proposal }
            }
        };

        Ok(mapped)
    }
}