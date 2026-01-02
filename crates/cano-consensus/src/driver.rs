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
//! - [`ValidatorContext`]: Wrapper around validator set for membership and quorum checks

use crate::ids::ValidatorId;
use crate::network::{ConsensusNetwork, ConsensusNetworkEvent, NetworkError};
use crate::qc::QuorumCertificate;
use crate::validator_set::ConsensusValidatorSet;
use cano_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// ValidatorContext
// ============================================================================

/// Context for validator set membership and quorum checks.
///
/// This struct wraps a `ConsensusValidatorSet` and provides convenient methods
/// for checking validator membership and quorum requirements.
#[derive(Debug, Clone)]
pub struct ValidatorContext {
    /// The underlying validator set.
    pub set: ConsensusValidatorSet,
}

impl ValidatorContext {
    /// Create a new `ValidatorContext` with the given validator set.
    pub fn new(set: ConsensusValidatorSet) -> Self {
        ValidatorContext { set }
    }

    /// Checks if a validator is in the set.
    pub fn is_member(&self, id: ValidatorId) -> bool {
        self.set.contains(id)
    }

    /// Returns index of validator in the set, if known.
    pub fn index_of(&self, id: ValidatorId) -> Option<usize> {
        self.set.index_of(id)
    }

    /// Returns whether the given ids reach quorum.
    pub fn has_quorum<I>(&self, ids: I) -> bool
    where
        I: IntoIterator<Item = ValidatorId>,
    {
        self.set.has_quorum(ids)
    }
}

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
/// # Type Parameters
///
/// - `E`: The underlying consensus engine type (typically `HotStuffState` or `HotStuffStateEngine`)
/// - `BlockIdT`: The block identifier type (typically `[u8; 32]`)
#[derive(Debug)]
pub struct HotStuffDriver<E, BlockIdT = [u8; 32]> {
    /// The underlying consensus engine.
    engine: E,
    /// Optional validator context for membership checks.
    validators: Option<ValidatorContext>,
    /// Counter for received votes (for testing/debugging).
    votes_received: u64,
    /// Counter for received proposals (for testing/debugging).
    proposals_received: u64,
    /// Counter for rejected votes from non-members (for testing/debugging).
    rejected_votes: u64,
    /// Counter for rejected proposals from non-members (for testing/debugging).
    rejected_proposals: u64,
    /// Counter for QCs formed (for testing/debugging).
    qcs_formed: u64,
    /// Last QC formed, if any.
    last_qc: Option<QuorumCertificate<BlockIdT>>,
}

impl<E, BlockIdT> HotStuffDriver<E, BlockIdT>
where
    BlockIdT: Clone,
{
    /// Create a new `HotStuffDriver` wrapping the given engine.
    ///
    /// This constructor creates a driver without a validator context.
    /// Use `with_validators` to add a validator context for membership checks.
    pub fn new(engine: E) -> Self {
        HotStuffDriver {
            engine,
            validators: None,
            votes_received: 0,
            proposals_received: 0,
            rejected_votes: 0,
            rejected_proposals: 0,
            qcs_formed: 0,
            last_qc: None,
        }
    }

    /// Create a new `HotStuffDriver` with a validator context.
    ///
    /// When a validator context is provided, the driver will check that
    /// incoming votes and proposals are from known validators in the set.
    pub fn with_validators(engine: E, validators: ValidatorContext) -> Self {
        HotStuffDriver {
            engine,
            validators: Some(validators),
            votes_received: 0,
            proposals_received: 0,
            rejected_votes: 0,
            rejected_proposals: 0,
            qcs_formed: 0,
            last_qc: None,
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

    /// Access the validator context, if any.
    pub fn validators(&self) -> Option<&ValidatorContext> {
        self.validators.as_ref()
    }

    /// Get the number of votes received.
    pub fn votes_received(&self) -> u64 {
        self.votes_received
    }

    /// Get the number of proposals received.
    pub fn proposals_received(&self) -> u64 {
        self.proposals_received
    }

    /// Get the number of rejected votes from non-members.
    pub fn rejected_votes(&self) -> u64 {
        self.rejected_votes
    }

    /// Get the number of rejected proposals from non-members.
    pub fn rejected_proposals(&self) -> u64 {
        self.rejected_proposals
    }

    /// Get the number of QCs formed.
    pub fn qcs_formed(&self) -> u64 {
        self.qcs_formed
    }

    /// Get the last QC formed, if any.
    pub fn last_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.last_qc.as_ref()
    }

    /// Record that a QC was formed.
    ///
    /// This method is called internally when a QC is formed, but can also
    /// be called externally to record QCs formed outside the driver.
    pub fn record_qc(&mut self, qc: QuorumCertificate<BlockIdT>) {
        self.qcs_formed += 1;
        self.last_qc = Some(qc);
    }

    /// Check if a validator ID is a member when validator context is available.
    /// Returns true if no validator context is set (permissive mode) or if the validator is a member.
    fn check_membership(&self, id: ValidatorId) -> bool {
        match &self.validators {
            Some(ctx) => ctx.is_member(id),
            None => true, // No validator context means permissive mode
        }
    }
}

// ============================================================================
// ToValidatorId trait - for converting network IDs to ValidatorIds
// ============================================================================

/// Trait for converting network IDs to `ValidatorId` for membership checks.
///
/// This trait enables the driver to check validator membership regardless of
/// the network's ID type, as long as the ID can be converted to a `ValidatorId`.
pub trait ToValidatorId {
    /// Convert this ID to a `ValidatorId`.
    fn to_validator_id(&self) -> ValidatorId;
}

impl ToValidatorId for ValidatorId {
    fn to_validator_id(&self) -> ValidatorId {
        *self
    }
}

impl ToValidatorId for u64 {
    fn to_validator_id(&self) -> ValidatorId {
        ValidatorId::new(*self)
    }
}

// ============================================================================
// ConsensusEngineDriver implementation for HotStuffDriver
// ============================================================================

impl<E, N, BlockIdT> ConsensusEngineDriver<N> for HotStuffDriver<E, BlockIdT>
where
    N: ConsensusNetwork,
    N::Id: ToValidatorId,
    BlockIdT: Clone,
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
                    // Check validator membership if validator context is set
                    let validator_id = from.to_validator_id();
                    if !self.check_membership(validator_id) {
                        // Vote from non-member: reject
                        self.rejected_votes += 1;
                        actions.push(ConsensusEngineAction::Noop);
                    } else {
                        // Track that we received a vote.
                        // TODO: Delegate to underlying engine for actual vote processing:
                        // - Verify vote signature (from: sender ID, vote: vote data)
                        // - Collect votes for QC formation
                        // - Emit actions if QC threshold is reached
                        let _ = vote; // Silence unused warnings until TODO is implemented
                        self.votes_received += 1;

                        // For now, return Noop to indicate the event was processed
                        // but no network action is required.
                        actions.push(ConsensusEngineAction::Noop);
                    }
                }
                ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                    // Check validator membership if validator context is set
                    let validator_id = from.to_validator_id();
                    if !self.check_membership(validator_id) {
                        // Proposal from non-member: reject
                        self.rejected_proposals += 1;
                        actions.push(ConsensusEngineAction::Noop);
                    } else {
                        // Track that we received a proposal.
                        // TODO: Delegate to underlying engine for actual proposal processing:
                        // - Verify proposal structure and QC (from: sender ID, proposal: block data)
                        // - Check HotStuff locking rules
                        // - Decide whether to vote
                        // - Emit BroadcastVote or SendVoteTo action if voting
                        let _ = proposal; // Silence unused warnings until TODO is implemented
                        self.proposals_received += 1;

                        // For now, return Noop to indicate the event was processed
                        // but no network action is required.
                        actions.push(ConsensusEngineAction::Noop);
                    }
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
        let driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.proposals_received(), 0);
        assert_eq!(driver.engine().height(), 1);
    }

    #[test]
    fn driver_step_with_no_event_returns_empty_actions() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

        let actions = driver.step(&mut net, None).unwrap();

        assert!(actions.is_empty());
        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.proposals_received(), 0);
    }

    #[test]
    fn driver_receives_vote_event_increments_counter() {
        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
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
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
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
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
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
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

        assert_eq!(driver.engine().height(), 5);

        driver.engine_mut().advance_height(10).unwrap();
        assert_eq!(driver.engine().height(), 10);
    }

    #[test]
    fn validator_context_membership_checks() {
        use crate::validator_set::ValidatorSetEntry;

        // Create a validator set with two validators
        let validators = vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 20 },
        ];
        let set = crate::validator_set::ConsensusValidatorSet::new(validators).unwrap();
        let ctx = ValidatorContext::new(set);

        assert!(ctx.is_member(ValidatorId::new(1)));
        assert!(ctx.is_member(ValidatorId::new(2)));
        assert!(!ctx.is_member(ValidatorId::new(3)));
        assert!(!ctx.is_member(ValidatorId::new(999)));

        assert_eq!(ctx.index_of(ValidatorId::new(1)), Some(0));
        assert_eq!(ctx.index_of(ValidatorId::new(2)), Some(1));
        assert_eq!(ctx.index_of(ValidatorId::new(3)), None);
    }

    #[test]
    fn driver_with_validators_rejects_vote_from_non_member() {
        use crate::validator_set::ValidatorSetEntry;

        // Create a validator set with validators 1 and 2
        let validators = vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 20 },
        ];
        let set = crate::validator_set::ConsensusValidatorSet::new(validators).unwrap();
        let ctx = ValidatorContext::new(set);

        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(engine, ctx);
        let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

        // Send a vote from a non-member (validator 999)
        let vote = make_dummy_vote(1, 0);
        let event = ConsensusNetworkEvent::IncomingVote {
            from: ValidatorId::new(999),
            vote,
        };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        // Vote should be rejected, not counted as received
        assert_eq!(driver.votes_received(), 0);
        assert_eq!(driver.rejected_votes(), 1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }

    #[test]
    fn driver_with_validators_accepts_vote_from_member() {
        use crate::validator_set::ValidatorSetEntry;

        // Create a validator set with validators 1 and 2
        let validators = vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 20 },
        ];
        let set = crate::validator_set::ConsensusValidatorSet::new(validators).unwrap();
        let ctx = ValidatorContext::new(set);

        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(engine, ctx);
        let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

        // Send a vote from a member (validator 1)
        let vote = make_dummy_vote(1, 0);
        let event = ConsensusNetworkEvent::IncomingVote {
            from: ValidatorId::new(1),
            vote,
        };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        // Vote should be accepted
        assert_eq!(driver.votes_received(), 1);
        assert_eq!(driver.rejected_votes(), 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }

    #[test]
    fn driver_with_validators_rejects_proposal_from_non_member() {
        use crate::validator_set::ValidatorSetEntry;

        // Create a validator set with validators 1 and 2
        let validators = vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 20 },
        ];
        let set = crate::validator_set::ConsensusValidatorSet::new(validators).unwrap();
        let ctx = ValidatorContext::new(set);

        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(engine, ctx);
        let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

        // Send a proposal from a non-member (validator 999)
        let proposal = make_dummy_proposal(1, 0);
        let event = ConsensusNetworkEvent::IncomingProposal {
            from: ValidatorId::new(999),
            proposal,
        };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        // Proposal should be rejected, not counted as received
        assert_eq!(driver.proposals_received(), 0);
        assert_eq!(driver.rejected_proposals(), 1);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }

    #[test]
    fn driver_without_validators_accepts_all_votes() {
        // Driver without validator context should accept all votes (permissive mode)
        let engine = HotStuffState::new_at_height(1);
        let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
        let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

        // Send a vote from any validator (even unknown)
        let vote = make_dummy_vote(1, 0);
        let event = ConsensusNetworkEvent::IncomingVote {
            from: ValidatorId::new(999),
            vote,
        };

        let actions = driver.step(&mut net, Some(event)).unwrap();

        // Vote should be accepted (no validator context means permissive)
        assert_eq!(driver.votes_received(), 1);
        assert_eq!(driver.rejected_votes(), 0);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ConsensusEngineAction::Noop));
    }
}