//! Consensus engine driver interface.
//!
//! This module provides a thin, explicit driver interface that a node can use
//! to "run consensus". It wraps the existing HotStuff-style consensus engine
//! in a clean interface that separates:
//!
//! - Engine logic: deciding what to do based on incoming events
//! - Node logic: when to poll the network and how to apply resulting actions
//!
//! # Key Types
//!
//! - [`ConsensusEngineAction`]: Actions the engine wants the driver to perform
//! - [`ConsensusEngineDriver`]: Trait for driving a consensus engine
//! - [`HotStuffDriver`]: Thin wrapper around the HotStuff consensus state

use crate::network::{ConsensusNetwork, ConsensusNetworkEvent, NetworkError};
use cano_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// ConsensusEngineAction
// ============================================================================

/// Actions that the consensus engine wants the driver to perform on the network.
///
/// This enum represents the possible network actions that result from processing
/// consensus events. The node is responsible for actually executing these actions
/// on the network.
#[derive(Debug, Clone)]
pub enum ConsensusEngineAction<Id> {
    /// Broadcast a new proposal to all validators.
    BroadcastProposal(BlockProposal),

    /// Broadcast a vote to all validators (or according to policy).
    BroadcastVote(Vote),

    /// Send a direct vote to a specific peer (e.g., the leader).
    SendVoteTo {
        /// The target peer to send the vote to.
        to: Id,
        /// The vote to send.
        vote: Vote,
    },

    /// No-op / internal state update only.
    ///
    /// Indicates that the engine processed an event but no network action
    /// is required.
    Noop,
}

// ============================================================================
// ConsensusEngineDriver trait
// ============================================================================

/// Trait for driving a consensus engine.
///
/// This trait defines the interface that a node uses to run a consensus engine.
/// The engine processes incoming network events and returns a list of actions
/// that the node should perform on the network.
///
/// # Usage Pattern
///
/// ```ignore
/// loop {
///     // 1. Poll the network for events
///     let maybe_event = net.try_recv_one()?;
///
///     // 2. Step the consensus engine
///     let actions = driver.step(&mut net, maybe_event)?;
///
///     // 3. Apply actions to the network
///     for action in actions {
///         match action {
///             ConsensusEngineAction::BroadcastProposal(p) => net.broadcast_proposal(&p)?,
///             ConsensusEngineAction::BroadcastVote(v) => net.broadcast_vote(&v)?,
///             ConsensusEngineAction::SendVoteTo { to, vote } => net.send_vote_to(to, &vote)?,
///             ConsensusEngineAction::Noop => {}
///         }
///     }
/// }
/// ```
pub trait ConsensusEngineDriver<N>
where
    N: ConsensusNetwork,
{
    /// One iteration of the consensus engine driven by network + timers.
    ///
    /// # Arguments
    ///
    /// - `net`: The network implementation (e.g., `ConsensusNetAdapter<'_>` in the node)
    /// - `maybe_event`: An optional incoming network event (if already polled)
    ///
    /// # Returns
    ///
    /// A list of actions the driver wants performed, which the caller is
    /// responsible for applying to the network.
    fn step(
        &mut self,
        net: &mut N,
        maybe_event: Option<ConsensusNetworkEvent<N::Id>>,
    ) -> Result<Vec<ConsensusEngineAction<N::Id>>, NetworkError>;
}

// ============================================================================
// HotStuffDriver
// ============================================================================

/// A thin wrapper around the HotStuff consensus state that implements
/// [`ConsensusEngineDriver`].
///
/// This driver processes incoming votes and proposals, updating the internal
/// consensus state and returning appropriate actions. Currently, it focuses
/// on correctly routing events to the underlying engine; full proposal
/// generation and vote emission will be added in future tasks.
///
/// # Type Parameter
///
/// - `E`: The underlying consensus engine type (typically `HotStuffState`)
#[derive(Debug)]
pub struct HotStuffDriver<E> {
    /// The underlying consensus engine.
    engine: E,
    /// Counter for received votes (for testing/debugging).
    votes_received: u64,
    /// Counter for received proposals (for testing/debugging).
    proposals_received: u64,
}

impl<E> HotStuffDriver<E> {
    /// Create a new `HotStuffDriver` wrapping the given engine.
    pub fn new(engine: E) -> Self {
        HotStuffDriver {
            engine,
            votes_received: 0,
            proposals_received: 0,
        }
    }

    /// Access the underlying engine.
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Mutably access the underlying engine.
    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    /// Get the number of votes received.
    pub fn votes_received(&self) -> u64 {
        self.votes_received
    }

    /// Get the number of proposals received.
    pub fn proposals_received(&self) -> u64 {
        self.proposals_received
    }
}

impl<E, N> ConsensusEngineDriver<N> for HotStuffDriver<E>
where
    N: ConsensusNetwork,
{
    fn step(
        &mut self,
        _net: &mut N,
        maybe_event: Option<ConsensusNetworkEvent<N::Id>>,
    ) -> Result<Vec<ConsensusEngineAction<N::Id>>, NetworkError> {
        let mut actions = Vec::new();

        if let Some(event) = maybe_event {
            match event {
                ConsensusNetworkEvent::IncomingVote { from, vote } => {
                    // Track that we received a vote.
                    // TODO: Delegate to underlying engine for actual vote processing:
                    // - Verify vote signature (from: sender ID, vote: vote data)
                    // - Collect votes for QC formation
                    // - Emit actions if QC threshold is reached
                    let _ = (from, vote); // Silence unused warnings until TODO is implemented
                    self.votes_received += 1;

                    // For now, return Noop to indicate the event was processed
                    // but no network action is required.
                    actions.push(ConsensusEngineAction::Noop);
                }
                ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                    // Track that we received a proposal.
                    // TODO: Delegate to underlying engine for actual proposal processing:
                    // - Verify proposal structure and QC (from: sender ID, proposal: block data)
                    // - Check HotStuff locking rules
                    // - Decide whether to vote
                    // - Emit BroadcastVote or SendVoteTo action if voting
                    let _ = (from, proposal); // Silence unused warnings until TODO is implemented
                    self.proposals_received += 1;

                    // For now, return Noop to indicate the event was processed
                    // but no network action is required.
                    actions.push(ConsensusEngineAction::Noop);
                }
            }
        }

        // TODO: Add timer-based logic for:
        // - Proposal generation (if we are the leader)
        // - View change / timeout handling

        Ok(actions)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MockConsensusNetwork;
    use crate::HotStuffState;

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
        }
    }

    #[test]
    fn driver_new_creates_wrapper_with_zero_counters() {
        let engine = HotStuffState::new_at_height(1);
        let driver = HotStuffDriver::new(engine);

        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.proposals_received(), 0);
        assert_eq!(driver.engine().height(), 1);
    }

    #[test]
    fn driver_step_with_no_event_returns_empty_actions() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let actions = driver.step(&mut net, None).unwrap();

        assert!(actions.is_empty());
        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.proposals_received(), 0);
    }

    #[test]
    fn driver_receives_vote_event_increments_counter() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let vote = make_dummy_vote(1, 0);
        let event = ConsensusNetworkEvent::IncomingVote { from: 42, vote };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        assert_eq!(driver.votes_received(), 1);
        assert_eq!(driver.proposals_received(), 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }

    #[test]
    fn driver_receives_proposal_event_increments_counter() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let proposal = make_dummy_proposal(1, 0);
        let event = ConsensusNetworkEvent::IncomingProposal {
            from: 99,
            proposal,
        };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.proposals_received(), 1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }

    #[test]
    fn driver_handles_multiple_events_in_sequence() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        // First event: vote
        let vote = make_dummy_vote(1, 0);
        let event1 = ConsensusNetworkEvent::IncomingVote {
            from: 1,
            vote: vote.clone(),
        };
        let _ = driver.step(&mut net, Some(event1)).unwrap();

        // Second event: proposal
        let proposal = make_dummy_proposal(1, 0);
        let event2 = ConsensusNetworkEvent::IncomingProposal {
            from: 2,
            proposal,
        };
        let _ = driver.step(&mut net, Some(event2)).unwrap();

        // Third event: another vote
        let event3 = ConsensusNetworkEvent::IncomingVote { from: 3, vote };
        let _ = driver.step(&mut net, Some(event3)).unwrap();

        assert_eq!(driver.votes_received(), 2);
        assert_eq!(driver.proposals_received(), 1);
    }

    #[test]
    fn driver_engine_accessors_work() {
        let engine = HotStuffState::new_at_height(5);
        let mut driver = HotStuffDriver::new(engine);

        assert_eq!(driver.engine().height(), 5);

        driver.engine_mut().advance_height(10).unwrap();
        assert_eq!(driver.engine().height(), 10);
    }
}