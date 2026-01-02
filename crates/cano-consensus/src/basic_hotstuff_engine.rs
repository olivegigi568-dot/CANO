//! BasicHotStuffEngine: A concrete HotStuff engine with static leader scheduling.
//!
//! This module provides a complete HotStuff-like consensus engine that:
//! - Uses a static leader schedule (round-robin based on view % n)
//! - Generates proposals when acting as leader
//! - Votes on valid proposals from the leader
//! - Integrates with `HotStuffStateEngine` for QC formation and commit tracking
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation for T56. It implements:
//! - Static leader election (view % num_validators)
//! - Basic proposal generation and voting
//! - QC formation via vote accumulation
//! - 3-chain commit rule via `HotStuffStateEngine`
//!
//! It does NOT implement:
//! - Timeouts or view-change mechanics
//! - Equivocation handling
//! - Leader rotation policies beyond simple round-robin

use crate::driver::{ConsensusEngineAction, HasCommitLog};
use crate::hotstuff_state_engine::{CommittedEntry, HotStuffStateEngine};
use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;

// ============================================================================
// BasicHotStuffEngine
// ============================================================================

/// A concrete HotStuff engine with static leader scheduling.
///
/// This struct wraps a `HotStuffStateEngine` and adds:
/// - Local validator identity
/// - View tracking
/// - Static leader schedule
/// - Proposal and vote generation logic
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
#[derive(Debug)]
pub struct BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Local validator id (identity of this node in the validator set).
    local_id: ValidatorId,

    /// Underlying HotStuff state (block tree, QCs, commits).
    state: HotStuffStateEngine<BlockIdT>,

    /// Simple view counter for this node.
    current_view: u64,

    /// Cached leader ordering for this validator set (static, sorted ascending).
    leaders: Vec<ValidatorId>,

    /// Whether we have already proposed in the current view.
    proposed_in_view: bool,

    /// Whether we have already voted in the current view.
    voted_in_view: bool,
}

impl<BlockIdT> BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new `BasicHotStuffEngine` with the given local id and validator set.
    ///
    /// The engine starts at view 0 with no blocks, no locked QC, and no commits.
    pub fn new(local_id: ValidatorId, validators: ConsensusValidatorSet) -> Self {
        let mut ids: Vec<ValidatorId> = validators.iter().map(|v| v.id).collect();
        ids.sort_by_key(|id| id.0);

        BasicHotStuffEngine {
            local_id,
            state: HotStuffStateEngine::new(validators),
            current_view: 0,
            leaders: ids,
            proposed_in_view: false,
            voted_in_view: false,
        }
    }

    /// Get the local validator id.
    pub fn local_id(&self) -> ValidatorId {
        self.local_id
    }

    /// Get the current view.
    pub fn current_view(&self) -> u64 {
        self.current_view
    }

    /// Get the leader for a given view (round-robin).
    ///
    /// # Panics
    ///
    /// Panics if the validator set is empty. This should never happen since
    /// `ConsensusValidatorSet::new` enforces non-empty validator sets.
    pub fn leader_for_view(&self, view: u64) -> ValidatorId {
        let n = self.leaders.len() as u64;
        assert!(n > 0, "validator set must not be empty");
        let idx = (view % n) as usize;
        self.leaders[idx]
    }

    /// Check if this node is the leader for the current view.
    pub fn is_leader_for_current_view(&self) -> bool {
        self.leader_for_view(self.current_view) == self.local_id
    }

    /// Get the underlying state engine.
    pub fn state(&self) -> &HotStuffStateEngine<BlockIdT> {
        &self.state
    }

    /// Mutably access the underlying state engine.
    pub fn state_mut(&mut self) -> &mut HotStuffStateEngine<BlockIdT> {
        &mut self.state
    }

    /// Get the current locked QC, if any.
    pub fn locked_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.state.locked_qc()
    }

    /// Get the latest committed block id, if any.
    pub fn committed_block(&self) -> Option<&BlockIdT> {
        self.state.committed_block()
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        self.state.validators()
    }

    /// Get the commit log (sequence of committed blocks).
    pub fn commit_log(&self) -> &[crate::hotstuff_state_engine::CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }

    /// Advance to the next view.
    ///
    /// This resets the `proposed_in_view` and `voted_in_view` flags.
    pub fn advance_view(&mut self) {
        self.current_view += 1;
        self.proposed_in_view = false;
        self.voted_in_view = false;
    }
}

// ============================================================================
// HasCommitLog implementation for BasicHotStuffEngine
// ============================================================================

impl<BlockIdT> HasCommitLog<BlockIdT> for BasicHotStuffEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        self.state.commit_log()
    }
}

// ============================================================================
// BlockIdT = [u8; 32] specific implementation
// ============================================================================

impl BasicHotStuffEngine<[u8; 32]> {
    /// Generate a deterministic block id based on proposal header fields.
    ///
    /// This creates a consistent block_id that both the proposer and followers
    /// can derive from the same proposal header.
    fn derive_block_id_from_header(
        proposer: ValidatorId,
        view: u64,
        parent_block_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut id = [0u8; 32];
        // Encode proposer id in the first 8 bytes
        let proposer_bytes = proposer.0.to_le_bytes();
        id[..8].copy_from_slice(&proposer_bytes);
        // Encode view in bytes 8-15
        let view_bytes = view.to_le_bytes();
        id[8..16].copy_from_slice(&view_bytes);
        // Copy first 16 bytes of parent_block_id for uniqueness
        id[16..32].copy_from_slice(&parent_block_id[..16]);
        id
    }

    /// Generate a block id for the current view (as leader).
    fn make_block_id(&mut self, parent_block_id: &[u8; 32]) -> [u8; 32] {
        Self::derive_block_id_from_header(self.local_id, self.current_view, parent_block_id)
    }

    /// Called when this node is leader for the current view.
    ///
    /// Returns a `BroadcastProposal` action if a proposal should be generated,
    /// or `None` if we are not the leader or have already proposed.
    pub fn on_leader_step(&mut self) -> Option<ConsensusEngineAction<ValidatorId>> {
        if !self.is_leader_for_current_view() {
            return None;
        }

        if self.proposed_in_view {
            return None;
        }

        let view = self.current_view;

        // Parent is the locked block or committed block or none
        let parent_id = self
            .state
            .locked_qc()
            .map(|qc| qc.block_id)
            .or_else(|| self.state.committed_block().cloned());

        let parent_block_id = parent_id.unwrap_or([0u8; 32]);

        // Build a proposal - use consistent block_id derivation
        let block_id = self.make_block_id(&parent_block_id);

        let justify_qc = self.state.locked_qc().cloned();

        // Register the block in our local state
        self.state
            .register_block(block_id, view, parent_id, justify_qc.clone());

        // Build the wire-format proposal
        use cano_wire::consensus::{BlockHeader, BlockProposal};

        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                height: view,
                round: view,
                parent_block_id,
                payload_hash: [0u8; 32],
                proposer_index: self.local_id.0 as u16,
                reserved: 0,
                tx_count: 0,
                timestamp: 0,
            },
            qc: justify_qc.map(|qc| {
                // Convert our logical QC to wire format
                use cano_wire::consensus::QuorumCertificate as WireQc;
                WireQc {
                    version: 1,
                    chain_id: 1,
                    height: qc.view,
                    round: qc.view,
                    step: 0,
                    block_id: qc.block_id,
                    signer_bitmap: vec![],
                    signatures: vec![],
                }
            }),
            txs: vec![],
        };

        self.proposed_in_view = true;

        // Vote for our own proposal
        let result = self.state.on_vote(self.local_id, view, &block_id);
        self.voted_in_view = true;

        // If a QC was formed immediately (e.g., single node), advance view
        if let Ok(Some(_qc)) = result {
            self.advance_view();
        }

        Some(ConsensusEngineAction::BroadcastProposal(proposal))
    }

    /// Called when we receive a proposal from the network.
    ///
    /// Returns a `BroadcastVote` action if we should vote for the proposal,
    /// or `None` if we should not vote.
    pub fn on_proposal_event(
        &mut self,
        from: ValidatorId,
        proposal: &cano_wire::consensus::BlockProposal,
    ) -> Option<ConsensusEngineAction<ValidatorId>> {
        let view = proposal.header.height;

        // If proposal is for a future view, advance directly to it
        if view > self.current_view {
            self.current_view = view;
            self.proposed_in_view = false;
            self.voted_in_view = false;
        }

        // Only process proposals for our current view
        if view != self.current_view {
            return None;
        }

        // Only accept proposals from the leader for this view
        let expected_leader = self.leader_for_view(view);
        if from != expected_leader {
            return None;
        }

        // Don't vote twice in the same view
        if self.voted_in_view {
            return None;
        }

        // Derive the block_id consistently using the same function as the proposer
        let block_id = Self::derive_block_id_from_header(
            from,  // proposer's id
            view,
            &proposal.header.parent_block_id,
        );

        // Parse justify QC from proposal
        let justify_qc = proposal.qc.as_ref().map(|wire_qc| {
            QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![])
        });

        // Register the block in our state
        let parent_id = if proposal.header.parent_block_id == [0u8; 32] {
            None
        } else {
            Some(proposal.header.parent_block_id)
        };
        self.state
            .register_block(block_id, view, parent_id, justify_qc);

        // Enforce locked-block safety: only vote if this block is on a chain
        // that includes the locked block as an ancestor (or if there is no lock yet).
        if !self.state.is_safe_to_vote_on_block(&block_id) {
            // Proposal is on a conflicting fork; do not vote.
            return None;
        }

        // Create and ingest our own vote
        // Errors here would indicate a bug in our code (voting for a block we just registered)
        let vote_result = self.state.on_vote(self.local_id, view, &block_id);
        debug_assert!(
            vote_result.is_ok(),
            "self-vote should not fail: {:?}",
            vote_result
        );

        self.voted_in_view = true;

        // Create a vote to broadcast
        use cano_wire::consensus::Vote;

        let vote = Vote {
            version: 1,
            chain_id: 1,
            height: view,
            round: view,
            step: 0,
            block_id,
            validator_index: self.local_id.0 as u16,
            reserved: 0,
            signature: vec![],
        };

        // After voting, advance to the next view (optimistic view advancement)
        // This allows the protocol to progress even before seeing the QC
        self.advance_view();

        Some(ConsensusEngineAction::BroadcastVote(vote))
    }

    /// Called when we receive a vote from the network.
    ///
    /// This ingests the vote into our state engine. If a QC is formed,
    /// we advance to the next view.
    ///
    /// Returns `None` as we don't emit further network actions on vote receipt.
    pub fn on_vote_event(
        &mut self,
        from: ValidatorId,
        vote: &cano_wire::consensus::Vote,
    ) -> Result<Option<QuorumCertificate<[u8; 32]>>, QcValidationError> {
        let view = vote.height;
        let block_id = vote.block_id;

        // Ingest the vote
        let result = self.state.on_vote(from, view, &block_id)?;

        // If a QC was formed, advance view
        if result.is_some() && view >= self.current_view {
            self.advance_view();
        }

        Ok(result)
    }

    /// Process a single step of the engine.
    ///
    /// This is called by the driver on each iteration. It:
    /// 1. Checks if we are leader and should propose
    /// 2. Returns any actions that should be broadcast
    ///
    /// The event parameter is the event from the network, if any.
    /// The driver should call `on_proposal_event` or `on_vote_event` before calling this.
    pub fn try_propose(&mut self) -> Option<ConsensusEngineAction<ValidatorId>> {
        self.on_leader_step()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::ValidatorSetEntry;

    fn make_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    #[test]
    fn basic_engine_leader_for_view_round_robin() {
        let validators = make_validator_set(3);
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Leaders are sorted: [1, 2, 3]
        // view 0 -> 0 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(0), ValidatorId(1));
        // view 1 -> 1 % 3 = 1 -> leader[1] = 2
        assert_eq!(engine.leader_for_view(1), ValidatorId(2));
        // view 2 -> 2 % 3 = 2 -> leader[2] = 3
        assert_eq!(engine.leader_for_view(2), ValidatorId(3));
        // view 3 -> 3 % 3 = 0 -> leader[0] = 1
        assert_eq!(engine.leader_for_view(3), ValidatorId(1));
    }

    #[test]
    fn basic_engine_is_leader_for_current_view() {
        let validators = make_validator_set(3);

        // Node 1 at view 0: is leader
        let engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators.clone());
        assert!(engine.is_leader_for_current_view());

        // Node 2 at view 0: not leader
        let engine2: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);
        assert!(!engine2.is_leader_for_current_view());
    }

    #[test]
    fn basic_engine_advance_view() {
        let validators = make_validator_set(2);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        assert_eq!(engine.current_view(), 0);
        engine.advance_view();
        assert_eq!(engine.current_view(), 1);
        engine.advance_view();
        assert_eq!(engine.current_view(), 2);
    }

    #[test]
    fn basic_engine_on_leader_step_produces_proposal() {
        let validators = make_validator_set(1);
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(1), validators);

        // Single node is always leader
        let action = engine.on_leader_step();
        assert!(action.is_some());

        if let Some(ConsensusEngineAction::BroadcastProposal(proposal)) = action {
            assert_eq!(proposal.header.height, 0);
            assert_eq!(proposal.header.proposer_index, 1);
        } else {
            panic!("Expected BroadcastProposal action");
        }

        // With a single node, QC forms immediately, view advances to 1
        // So the second call produces another proposal (for view 1)
        // This is correct behavior with optimistic view advancement
        let action2 = engine.on_leader_step();
        assert!(action2.is_some());

        if let Some(ConsensusEngineAction::BroadcastProposal(proposal2)) = action2 {
            assert_eq!(proposal2.header.height, 1);
        } else {
            panic!("Expected BroadcastProposal action for view 1");
        }
    }

    #[test]
    fn basic_engine_non_leader_does_not_propose() {
        let validators = make_validator_set(3);
        // Node 2 is not leader at view 0
        let mut engine: BasicHotStuffEngine<[u8; 32]> =
            BasicHotStuffEngine::new(ValidatorId(2), validators);

        let action = engine.on_leader_step();
        assert!(action.is_none());
    }
}