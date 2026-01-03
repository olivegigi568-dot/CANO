//! Consensus networking abstraction.
//!
//! This module defines the `ConsensusNetwork` trait, which abstracts the
//! consensus engine's view of the network. This allows the consensus logic
//! to depend only on an abstract trait rather than concrete networking
//! implementations like `PeerManager` or `NetMessage`.
//!
//! Also provides a `MockConsensusNetwork` for testing consensus logic
//! without a real network.

use std::collections::VecDeque;
use std::io;

use cano_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// NetworkError
// ============================================================================

/// Error type for consensus network operations.
#[derive(Debug)]
pub enum NetworkError {
    /// I/O error from underlying transport.
    Io(io::Error),
    /// Other error with description.
    Other(String),
}

impl From<io::Error> for NetworkError {
    fn from(e: io::Error) -> Self {
        NetworkError::Io(e)
    }
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::Io(e) => write!(f, "network I/O error: {}", e),
            NetworkError::Other(s) => write!(f, "network error: {}", s),
        }
    }
}

impl std::error::Error for NetworkError {}

// ============================================================================
// ConsensusNetworkEvent
// ============================================================================

/// Events that the consensus engine can receive from the network.
///
/// The `Id` type parameter represents the peer identifier. This allows the
/// trait to be generic over different ID types used in different contexts
/// (e.g., `PeerId` in the node vs. `u64` in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusNetworkEvent<Id> {
    /// An incoming vote from a peer.
    IncomingVote {
        /// The peer that sent the vote.
        from: Id,
        /// The vote message.
        vote: Vote,
    },
    /// An incoming block proposal from a peer.
    IncomingProposal {
        /// The peer that sent the proposal.
        from: Id,
        /// The block proposal message.
        proposal: BlockProposal,
    },
    // In future: PeerConnected, PeerDisconnected, etc.
}

// ============================================================================
// ConsensusNetwork trait
// ============================================================================

/// Trait that abstracts the consensus engine's view of networking.
///
/// Implementors of this trait provide the ability to broadcast proposals and
/// votes, send votes to specific peers, and receive consensus-related events
/// from the network.
pub trait ConsensusNetwork {
    /// The peer identifier type used by this network implementation.
    type Id;

    /// Broadcast a proposal to all validators.
    fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError>;

    /// Broadcast a vote to all validators (or a configured subset).
    fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError>;

    /// Send a vote directly to a specific validator.
    fn send_vote_to(&mut self, to: Self::Id, vote: &Vote) -> Result<(), NetworkError>;

    /// Blocking receive of one consensus-related event from the network.
    fn recv_one(&mut self) -> Result<ConsensusNetworkEvent<Self::Id>, NetworkError>;

    /// Non-blocking receive of one consensus-related event from the network.
    ///
    /// Returns:
    /// - `Ok(Some(event))` if an event is available
    /// - `Ok(None)` if no event is currently available
    /// - `Err(NetworkError)` on real errors
    fn try_recv_one(
        &mut self,
    ) -> Result<Option<ConsensusNetworkEvent<Self::Id>>, NetworkError>;
}

// ============================================================================
// MockConsensusNetwork
// ============================================================================

/// A simple in-memory mock implementation of `ConsensusNetwork` for testing.
///
/// - `outbound` records votes we "send" (both broadcast and targeted).
/// - `outbound_proposals` records proposals we "send".
/// - `inbound` is a queue of events that `recv_one` will pop from.
#[derive(Debug, Default)]
pub struct MockConsensusNetwork<Id> {
    /// Records outbound votes: (destination, vote). `None` means broadcast.
    pub outbound: Vec<(Option<Id>, Vote)>,
    /// Records outbound proposals: (destination, proposal). `None` means broadcast.
    pub outbound_proposals: Vec<(Option<Id>, BlockProposal)>,
    /// Queue of inbound events to return from `recv_one`.
    pub inbound: VecDeque<ConsensusNetworkEvent<Id>>,
}

impl<Id> MockConsensusNetwork<Id> {
    /// Create a new empty mock network.
    pub fn new() -> Self {
        MockConsensusNetwork {
            outbound: Vec::new(),
            outbound_proposals: Vec::new(),
            inbound: VecDeque::new(),
        }
    }

    /// Enqueue an event to be returned by the next `recv_one` call.
    pub fn enqueue_event(&mut self, event: ConsensusNetworkEvent<Id>) {
        self.inbound.push_back(event);
    }
}

impl<Id: Clone> ConsensusNetwork for MockConsensusNetwork<Id> {
    type Id = Id;

    fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        self.outbound_proposals.push((None, proposal.clone()));
        Ok(())
    }

    fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        self.outbound.push((None, vote.clone()));
        Ok(())
    }

    fn send_vote_to(&mut self, to: Self::Id, vote: &Vote) -> Result<(), NetworkError> {
        self.outbound.push((Some(to), vote.clone()));
        Ok(())
    }

    fn recv_one(&mut self) -> Result<ConsensusNetworkEvent<Self::Id>, NetworkError> {
        self.inbound.pop_front().ok_or_else(|| {
            NetworkError::Io(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no events in mock queue",
            ))
        })
    }

    fn try_recv_one(
        &mut self,
    ) -> Result<Option<ConsensusNetworkEvent<Self::Id>>, NetworkError> {
        Ok(self.inbound.pop_front())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a dummy Vote for testing.
    fn make_dummy_vote(height: u64, round: u64) -> Vote {
        Vote {
            version: 1,
            chain_id: 1,
            height,
            round,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            reserved: 0,
            signature: vec![],
        }
    }

    /// Create a dummy BlockProposal for testing.
    fn make_dummy_proposal(height: u64, round: u64) -> BlockProposal {
        use cano_wire::consensus::BlockHeader;
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                height,
                round,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                reserved: 0,
                tx_count: 0,
                timestamp: 0,
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        }
    }

    #[test]
    fn mock_network_records_broadcast_vote_and_send_vote_to() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let vote1 = make_dummy_vote(1, 0);
        let vote2 = make_dummy_vote(2, 1);
        let vote3 = make_dummy_vote(3, 2);

        // Broadcast a vote
        mock.broadcast_vote(&vote1).unwrap();
        assert_eq!(mock.outbound.len(), 1);
        assert_eq!(mock.outbound[0].0, None);
        assert_eq!(mock.outbound[0].1, vote1);

        // Send a vote to a specific peer
        mock.send_vote_to(42, &vote2).unwrap();
        assert_eq!(mock.outbound.len(), 2);
        assert_eq!(mock.outbound[1].0, Some(42));
        assert_eq!(mock.outbound[1].1, vote2);

        // Broadcast another vote
        mock.broadcast_vote(&vote3).unwrap();
        assert_eq!(mock.outbound.len(), 3);
        assert_eq!(mock.outbound[2].0, None);
        assert_eq!(mock.outbound[2].1, vote3);
    }

    #[test]
    fn mock_network_records_broadcast_proposal() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let proposal = make_dummy_proposal(10, 5);

        mock.broadcast_proposal(&proposal).unwrap();

        assert_eq!(mock.outbound_proposals.len(), 1);
        assert_eq!(mock.outbound_proposals[0].0, None);
        assert_eq!(mock.outbound_proposals[0].1, proposal);
    }

    #[test]
    fn mock_network_recv_one_yields_queued_events_in_order() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let vote1 = make_dummy_vote(1, 0);
        let vote2 = make_dummy_vote(2, 1);
        let proposal = make_dummy_proposal(3, 2);

        // Enqueue events in order
        mock.enqueue_event(ConsensusNetworkEvent::IncomingVote {
            from: 100,
            vote: vote1.clone(),
        });
        mock.enqueue_event(ConsensusNetworkEvent::IncomingProposal {
            from: 200,
            proposal: proposal.clone(),
        });
        mock.enqueue_event(ConsensusNetworkEvent::IncomingVote {
            from: 300,
            vote: vote2.clone(),
        });

        // Receive events and verify order
        let event1 = mock.recv_one().unwrap();
        assert!(matches!(
            event1,
            ConsensusNetworkEvent::IncomingVote { from: 100, .. }
        ));
        if let ConsensusNetworkEvent::IncomingVote { vote, .. } = event1 {
            assert_eq!(vote, vote1);
        }

        let event2 = mock.recv_one().unwrap();
        assert!(matches!(
            event2,
            ConsensusNetworkEvent::IncomingProposal { from: 200, .. }
        ));
        if let ConsensusNetworkEvent::IncomingProposal {
            proposal: p,
            ..
        } = event2
        {
            assert_eq!(p, proposal);
        }

        let event3 = mock.recv_one().unwrap();
        assert!(matches!(
            event3,
            ConsensusNetworkEvent::IncomingVote { from: 300, .. }
        ));
        if let ConsensusNetworkEvent::IncomingVote { vote, .. } = event3 {
            assert_eq!(vote, vote2);
        }

        // Queue is now empty, should return WouldBlock error
        let err = mock.recv_one().unwrap_err();
        assert!(matches!(err, NetworkError::Io(_)));
    }

    #[test]
    fn mock_network_recv_one_returns_error_when_empty() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let result = mock.recv_one();
        assert!(result.is_err());

        if let Err(NetworkError::Io(e)) = result {
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        } else {
            panic!("expected Io error with WouldBlock");
        }
    }

    #[test]
    fn mock_network_try_recv_one_returns_none_when_empty() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        // When the inbound queue is empty, try_recv_one should return Ok(None)
        let result = mock.try_recv_one();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn mock_network_try_recv_one_returns_some_in_fifo_order() {
        let mut mock: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let vote1 = make_dummy_vote(1, 0);
        let vote2 = make_dummy_vote(2, 1);
        let proposal = make_dummy_proposal(3, 2);

        // Enqueue events in order
        mock.enqueue_event(ConsensusNetworkEvent::IncomingVote {
            from: 100,
            vote: vote1.clone(),
        });
        mock.enqueue_event(ConsensusNetworkEvent::IncomingProposal {
            from: 200,
            proposal: proposal.clone(),
        });
        mock.enqueue_event(ConsensusNetworkEvent::IncomingVote {
            from: 300,
            vote: vote2.clone(),
        });

        // Use try_recv_one to receive events in FIFO order
        let event1 = mock.try_recv_one().unwrap();
        assert!(event1.is_some());
        let event1 = event1.unwrap();
        assert!(matches!(
            event1,
            ConsensusNetworkEvent::IncomingVote { from: 100, .. }
        ));
        if let ConsensusNetworkEvent::IncomingVote { vote, .. } = event1 {
            assert_eq!(vote, vote1);
        }

        let event2 = mock.try_recv_one().unwrap();
        assert!(event2.is_some());
        let event2 = event2.unwrap();
        assert!(matches!(
            event2,
            ConsensusNetworkEvent::IncomingProposal { from: 200, .. }
        ));
        if let ConsensusNetworkEvent::IncomingProposal {
            proposal: p,
            ..
        } = event2
        {
            assert_eq!(p, proposal);
        }

        let event3 = mock.try_recv_one().unwrap();
        assert!(event3.is_some());
        let event3 = event3.unwrap();
        assert!(matches!(
            event3,
            ConsensusNetworkEvent::IncomingVote { from: 300, .. }
        ));
        if let ConsensusNetworkEvent::IncomingVote { vote, .. } = event3 {
            assert_eq!(vote, vote2);
        }

        // Queue is now empty, should return Ok(None)
        let result = mock.try_recv_one();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}