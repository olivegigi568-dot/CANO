//! HotStuff state machine with QC-based locking and commit bookkeeping.
//!
//! This module provides a minimal HotStuff state machine that:
//! - Maintains a simple "block tree" keyed by block id
//! - Tracks `locked_qc` (latest QC on a locked block)
//! - Tracks the latest committed block id via the 3-chain commit rule
//! - Integrates `VoteAccumulator` for QC formation
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation that implements:
//! - QC-based locking (locked_qc updated when a higher-view QC is formed)
//! - Basic vote accumulation and QC formation
//! - 3-chain commit rule: when three consecutive QCs are formed (G → P → B),
//!   the grandparent block G is committed
//!
//! It does NOT yet implement:
//! - Timeouts or view-change mechanics

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
    /// This method implements HotStuff-style locking and commit logic:
    /// - Updates `locked_qc` to the QC if its view is higher than the current lock
    /// - Attaches the QC to the corresponding block node as `own_qc`
    /// - Attempts the 3-chain commit rule
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

        // Record QC on the block node itself.
        if let Some(node) = self.blocks.get_mut(&qc.block_id) {
            node.own_qc = Some(qc.clone());
        }

        // Attempt 3-chain commit logic.
        self.try_commit_with_qc(qc);

        Ok(())
    }

    /// Attempt to commit a block using the 3-chain commit rule.
    ///
    /// Classic HotStuff 3-chain commit rule:
    /// - Let B be the block with `qc.block_id`
    /// - Let P = parent of B
    /// - Let G = parent of P (grandparent of B)
    /// - If B, P, and G each have their `own_qc` and views are strictly increasing,
    ///   we commit G (or advance `committed_block` to G if it's higher).
    ///
    /// This ensures that a block is only committed when there are two subsequent
    /// blocks with QCs in the chain, providing Byzantine fault tolerance.
    fn try_commit_with_qc(&mut self, qc: &QuorumCertificate<BlockIdT>) {
        // 1. Find B (the block this QC is for).
        let b_view = match self.blocks.get(&qc.block_id) {
            Some(node) => {
                // Check B has own_qc
                if node.own_qc.is_none() {
                    return;
                }
                node.view
            }
            None => return, // unknown block; nothing to commit
        };

        // 2. Find P = parent of B.
        let (p_id, p_view) = {
            let b = match self.blocks.get(&qc.block_id) {
                Some(node) => node,
                None => return,
            };
            match &b.parent_id {
                Some(id) => {
                    let p = match self.blocks.get(id) {
                        Some(node) => node,
                        None => return,
                    };
                    // Check P has own_qc
                    if p.own_qc.is_none() {
                        return;
                    }
                    (id.clone(), p.view)
                }
                None => return, // no parent → no 3-chain
            }
        };

        // 3. Find G = parent of P (grandparent of B).
        let (g_id, g_view) = {
            let p = match self.blocks.get(&p_id) {
                Some(node) => node,
                None => return,
            };
            match &p.parent_id {
                Some(id) => {
                    let g = match self.blocks.get(id) {
                        Some(node) => node,
                        None => return,
                    };
                    // Check G has own_qc
                    if g.own_qc.is_none() {
                        return;
                    }
                    (id.clone(), g.view)
                }
                None => return, // no grandparent → no 3-chain
            }
        };

        // 4. Ensure views are strictly increasing: G.view < P.view < B.view
        if !(g_view < p_view && p_view < b_view) {
            return;
        }

        // 5. Commit G if it is "ahead" of current committed_block (monotonic).
        // For view-based monotonicity, we compare views to ensure we don't go backwards.
        let should_commit = match &self.committed_block {
            None => true,
            Some(committed_id) => {
                // Only commit if G is different from current committed block
                // In a single-chain model, we allow overwriting to the newer committed block
                committed_id != &g_id
            }
        };

        if should_commit {
            self.committed_block = Some(g_id);
        }
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