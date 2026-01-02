//! HotStuff state machine with QC-based locking and commit bookkeeping.
//!
//! This module provides a minimal HotStuff state machine that:
//! - Maintains a simple "block tree" keyed by block id
//! - Tracks `locked_qc` (latest QC on a locked block)
//! - Tracks the latest committed block id
//! - Integrates `VoteAccumulator` for QC formation
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation for T54. It implements:
//! - QC-based locking (locked_qc updated when a higher-view QC is formed)
//! - Basic vote accumulation and QC formation
//!
//! It does NOT yet implement:
//! - Timeouts or view-change mechanics
//! - Full 3-chain commit rule (committed_block stays None for now)
//!
//! These will be added in future tasks.

use std::collections::HashMap;

use crate::block_state::BlockNode;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;
use crate::vote_accumulator::VoteAccumulator;
use crate::ids::ValidatorId;

/// HotStuff state machine managing block tree, locking, and commit tracking.
///
/// This struct maintains the consensus state for a HotStuff-like protocol:
/// - Known block nodes keyed by block id
/// - Current locked QC (the "lock" on a block)
/// - Latest committed block id
/// - Vote accumulator for QC formation
/// - Validator set for quorum checks
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
#[derive(Debug)]
pub struct HotStuffStateEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Known block nodes keyed by block id.
    blocks: HashMap<BlockIdT, BlockNode<BlockIdT>>,

    /// Current locked QC (HotStuff "lock" on a block).
    locked_qc: Option<QuorumCertificate<BlockIdT>>,

    /// Latest committed block id, if any.
    committed_block: Option<BlockIdT>,

    /// Vote accumulator for QC formation.
    votes: VoteAccumulator<BlockIdT>,

    /// Validator set for quorum checks.
    validators: ConsensusValidatorSet,
}

impl<BlockIdT> HotStuffStateEngine<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new `HotStuffStateEngine` with the given validator set.
    ///
    /// The engine starts with:
    /// - No known blocks
    /// - No locked QC
    /// - No committed block
    /// - Empty vote accumulator
    pub fn new(validators: ConsensusValidatorSet) -> Self {
        HotStuffStateEngine {
            blocks: HashMap::new(),
            locked_qc: None,
            committed_block: None,
            votes: VoteAccumulator::new(),
            validators,
        }
    }

    /// Get the current locked QC, if any.
    pub fn locked_qc(&self) -> Option<&QuorumCertificate<BlockIdT>> {
        self.locked_qc.as_ref()
    }

    /// Get the latest committed block id, if any.
    pub fn committed_block(&self) -> Option<&BlockIdT> {
        self.committed_block.as_ref()
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        &self.validators
    }

    /// Get a block node by its id, if known.
    pub fn get_block(&self, id: &BlockIdT) -> Option<&BlockNode<BlockIdT>> {
        self.blocks.get(id)
    }

    /// Returns the number of known blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    // ========================================================================
    // Hook 1: Registering proposals into the block tree
    // ========================================================================

    /// Register a block node in the block tree.
    ///
    /// This method adds or updates a block in the internal block tree.
    /// It can be used when processing proposals to track known blocks.
    ///
    /// # Arguments
    ///
    /// - `id`: The block identifier
    /// - `view`: The view/round at which this block was proposed
    /// - `parent_id`: The parent block id, if any
    /// - `justify_qc`: The QC that justifies this block, if any
    pub fn register_block(
        &mut self,
        id: BlockIdT,
        view: u64,
        parent_id: Option<BlockIdT>,
        justify_qc: Option<QuorumCertificate<BlockIdT>>,
    ) {
        let node = BlockNode::new(id.clone(), view, parent_id, justify_qc);
        self.blocks.insert(id, node);
    }

    // ========================================================================
    // Hook 2: Vote ingestion → QC → locking/commit
    // ========================================================================

    /// Ingest a vote and if quorum is reached, form and process a QC.
    ///
    /// This method:
    /// 1. Validates that the voter is a member of the validator set
    /// 2. Records the vote in the accumulator
    /// 3. Attempts to form a QC if quorum is reached
    /// 4. If a QC is formed, applies locking logic
    ///
    /// # Arguments
    ///
    /// - `voter`: The validator who cast the vote
    /// - `view`: The view/round number of the vote
    /// - `block_id`: The block being voted for
    ///
    /// # Returns
    ///
    /// - `Ok(Some(qc))` if a QC was formed and applied
    /// - `Ok(None)` if the vote was recorded but no QC formed yet
    /// - `Err(QcValidationError)` if the voter is not a member
    pub fn on_vote(
        &mut self,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<Option<QuorumCertificate<BlockIdT>>, QcValidationError> {
        // 1. Ingest vote into accumulator (membership & duplicate checks).
        let _is_new = self.votes.on_vote(&self.validators, voter, view, block_id)?;

        // 2. Attempt to form QC for this (view, block_id).
        let qc = self.votes.maybe_qc_for(&self.validators, view, block_id)?;

        if let Some(ref qc) = qc {
            // 3. Apply locking logic with the new QC.
            self.on_qc(qc)?;
        }

        Ok(qc)
    }

    /// Handle a newly formed QC.
    ///
    /// This method implements minimal HotStuff-style locking logic:
    /// - Updates `locked_qc` to the QC if its view is higher than the current lock
    ///
    /// # Note
    ///
    /// For T54, we implement Option A (simpler): only locking is implemented.
    /// The `committed_block` remains None. Full 3-chain commit logic will be
    /// added in a future task.
    fn on_qc(&mut self, qc: &QuorumCertificate<BlockIdT>) -> Result<(), QcValidationError> {
        // Minimal HotStuff-style locking:
        // - Update locked_qc to the highest-view QC.
        let replace_lock = match &self.locked_qc {
            None => true,
            Some(existing) => qc.view > existing.view,
        };

        if replace_lock {
            self.locked_qc = Some(qc.clone());
        }

        // TODO(future task): Implement 3-chain commit rule.
        // The commit logic should:
        // 1. Track the "3-chain" relationship: grandparent -> parent -> child
        // 2. When a QC is formed for a block whose justify_qc points to a parent,
        //    and that parent's justify_qc points to a grandparent with consecutive views,
        //    commit the grandparent block.
        // 3. Update committed_block to the newly committed block id.
        // For T54, committed_block stays None.

        Ok(())
    }

    /// Directly set a locked QC (for testing or initialization).
    ///
    /// This bypasses the normal QC formation process and directly sets
    /// the locked QC. Useful for testing locking behavior.
    pub fn set_locked_qc(&mut self, qc: QuorumCertificate<BlockIdT>) {
        self.locked_qc = Some(qc);
    }

    /// Get the current vote count for a (view, block_id) pair.
    ///
    /// Returns 0 if no votes have been received for this pair.
    pub fn vote_count(&self, view: u64, block_id: &BlockIdT) -> usize {
        self.votes.vote_count(view, block_id)
    }
}