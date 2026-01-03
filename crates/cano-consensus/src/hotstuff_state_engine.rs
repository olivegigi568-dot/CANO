//! HotStuff state machine with QC-based locking and commit bookkeeping.
//!
//! This module provides a minimal HotStuff state machine that:
//! - Maintains a simple "block tree" keyed by block id
//! - Tracks `locked_qc` (latest QC on a locked block)
//! - Tracks the latest committed block id via the 3-chain commit rule
//! - Integrates `VoteAccumulator` for QC formation
//! - Detects equivocation (double-voting) and tracks metrics
//!
//! # Design Note
//!
//! This is a simplified HotStuff implementation that implements:
//! - QC-based locking (locked_qc updated when a higher-view QC is formed)
//! - Basic vote accumulation and QC formation
//! - 3-chain commit rule: when three consecutive QCs are formed (G → P → B),
//!   the grandparent block G is committed
//! - Equivocation detection: detects when a validator votes for different blocks
//!   in the same view
//!
//! It does NOT yet implement:
//! - Timeouts or view-change mechanics

use std::collections::{HashMap, HashSet};

use crate::block_state::BlockNode;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;
use crate::vote_accumulator::VoteAccumulator;
use crate::ids::ValidatorId;

/// An entry in the commit log recording a committed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEntry<BlockIdT> {
    /// The block identifier that was committed.
    pub block_id: BlockIdT,
    /// The view at which the block was proposed.
    pub view: u64,
    /// The height of the block in the chain from genesis.
    pub height: u64,
}

/// Outcome of recording a vote in the history tracker.
///
/// This enum is used internally to distinguish between:
/// - First time we see a (view, validator) pair
/// - Duplicate vote for the same block (benign)
/// - Equivocation: different block in the same view
#[derive(Debug, Clone, PartialEq, Eq)]
enum VoteHistoryOutcome<BlockIdT> {
    /// First time we see this (view, validator) pair.
    FirstVote,
    /// Duplicate vote for the same block_id (benign duplicate).
    DuplicateSameBlock,
    /// Equivocation: same (view, validator), different block.
    Equivocation {
        /// The block the validator previously voted for.
        previous_block: BlockIdT,
    },
}

/// HotStuff state machine managing block tree, locking, and commit tracking.
///
/// This struct maintains the consensus state for a HotStuff-like protocol:
/// - Known block nodes keyed by block id
/// - Current locked QC (the "lock" on a block)
/// - Latest committed block id
/// - Vote accumulator for QC formation
/// - Validator set for quorum checks
/// - Equivocation detection and metrics
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

    /// Latest committed height, if any.
    committed_height: Option<u64>,

    /// Simple append-only commit log for tests/inspection.
    commit_log: Vec<CommittedEntry<BlockIdT>>,

    /// Vote accumulator for QC formation.
    votes: VoteAccumulator<BlockIdT>,

    /// Validator set for quorum checks.
    validators: ConsensusValidatorSet,

    /// For each (view, validator), remember which block they voted for.
    /// Used for equivocation detection.
    votes_by_view: HashMap<(u64, ValidatorId), BlockIdT>,

    /// Count of detected equivocations (double-votes per view).
    equivocations_detected: u64,

    /// Set of validators that ever equivocated (per this engine instance).
    equivocating_validators: HashSet<ValidatorId>,
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
    /// - Empty equivocation tracking
    pub fn new(validators: ConsensusValidatorSet) -> Self {
        HotStuffStateEngine {
            blocks: HashMap::new(),
            locked_qc: None,
            committed_block: None,
            committed_height: None,
            commit_log: Vec::new(),
            votes: VoteAccumulator::new(),
            validators,
            votes_by_view: HashMap::new(),
            equivocations_detected: 0,
            equivocating_validators: HashSet::new(),
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

    /// Get the latest committed height, if any.
    pub fn committed_height(&self) -> Option<u64> {
        self.committed_height
    }

    /// Get the commit log (sequence of committed blocks).
    pub fn commit_log(&self) -> &[CommittedEntry<BlockIdT>] {
        &self.commit_log
    }

    /// Get a reference to the validator set.
    pub fn validators(&self) -> &ConsensusValidatorSet {
        &self.validators
    }

    /// Get the count of detected equivocations (double-votes per view).
    pub fn equivocations_detected(&self) -> u64 {
        self.equivocations_detected
    }

    /// Get a reference to the set of validators that have equivocated.
    pub fn equivocating_validators(&self) -> &HashSet<ValidatorId> {
        &self.equivocating_validators
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
    /// The block's height is computed as parent's height + 1, or 0 if no parent
    /// (genesis) or if the parent is not yet registered.
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
        // Compute height: 0 if no parent, otherwise parent.height + 1
        let height = match parent_id.as_ref() {
            None => 0,
            Some(pid) => self
                .blocks
                .get(pid)
                .map(|p| p.height + 1)
                .unwrap_or(0),
        };

        let node = BlockNode::new(id.clone(), view, parent_id, justify_qc, height);
        self.blocks.insert(id, node);
    }

    // ========================================================================
    // Hook 2: Vote ingestion → QC → locking/commit
    // ========================================================================

    /// Internal helper to record vote history and detect equivocation.
    ///
    /// This method tracks which block each (view, validator) pair has voted for.
    /// It returns the outcome of this check:
    /// - `FirstVote`: First time we see this (view, validator) pair
    /// - `DuplicateSameBlock`: Same validator voted for the same block in the same view
    /// - `Equivocation`: Same validator voted for a different block in the same view
    fn record_vote_history(
        &mut self,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> VoteHistoryOutcome<BlockIdT> {
        let key = (view, voter);
        match self.votes_by_view.get(&key) {
            None => {
                // First time we see this (view, validator) pair.
                self.votes_by_view.insert(key, block_id.clone());
                VoteHistoryOutcome::FirstVote
            }
            Some(prev_block) => {
                if prev_block == block_id {
                    // Same block as before: benign duplicate.
                    VoteHistoryOutcome::DuplicateSameBlock
                } else {
                    // Different block: equivocation.
                    VoteHistoryOutcome::Equivocation {
                        previous_block: prev_block.clone(),
                    }
                }
            }
        }
    }

    /// Ingest a vote and if quorum is reached, form and process a QC.
    ///
    /// This method:
    /// 1. Detects equivocation (same validator voting for different blocks in the same view)
    /// 2. If equivocation is detected, records metrics and ignores the vote
    /// 3. Validates that the voter is a member of the validator set
    /// 4. Records the vote in the accumulator
    /// 5. Attempts to form a QC if quorum is reached
    /// 6. If a QC is formed, applies locking logic
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
    /// - `Ok(None)` if the vote was recorded but no QC formed yet, or if the vote
    ///   was an equivocation and was ignored
    /// - `Err(QcValidationError)` if the voter is not a member
    pub fn on_vote(
        &mut self,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<Option<QuorumCertificate<BlockIdT>>, QcValidationError> {
        // 1. Equivocation detection.
        match self.record_vote_history(voter, view, block_id) {
            VoteHistoryOutcome::Equivocation { previous_block: _ } => {
                // Record metrics and ignore this vote for QC formation.
                self.equivocations_detected += 1;
                self.equivocating_validators.insert(voter);
                // For now we silently ignore; later we may want to expose this
                // via a separate error or event.
                return Ok(None);
            }
            VoteHistoryOutcome::FirstVote | VoteHistoryOutcome::DuplicateSameBlock => {
                // Proceed to feed vote into accumulator.
            }
        }

        // 2. Ingest vote into accumulator (membership & duplicate checks).
        let _is_new = self.votes.on_vote(&self.validators, voter, view, block_id)?;

        // 3. Attempt to form QC for this (view, block_id).
        let qc = self.votes.maybe_qc_for(&self.validators, view, block_id)?;

        if let Some(ref qc) = qc {
            // 4. Apply locking logic with the new QC.
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
        let (g_id, g_view, g_height) = {
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
                    (id.clone(), g.view, g.height)
                }
                None => return, // no grandparent → no 3-chain
            }
        };

        // 4. Ensure views are strictly increasing: G.view < P.view < B.view
        if !(g_view < p_view && p_view < b_view) {
            return;
        }

        // 5. Commit G if it is "ahead" of current committed_block (monotonic).
        // For height-based monotonicity, we compare heights to ensure we don't go backwards.
        let height_ok = match self.committed_height {
            None => true,
            Some(h) => g_height > h,
        };

        let should_commit = match &self.committed_block {
            None => true,
            Some(committed_id) => {
                if committed_id == &g_id {
                    // Already committed this block
                    false
                } else {
                    // Check if G's view is higher than the current committed block's view
                    // to ensure we don't go backwards
                    match self.blocks.get(committed_id) {
                        Some(committed_node) => g_view > committed_node.view,
                        None => {
                            // Current committed block not in our tree (shouldn't happen normally)
                            // Allow commit to move forward
                            true
                        }
                    }
                }
            }
        };

        if should_commit && height_ok {
            self.committed_block = Some(g_id.clone());
            self.committed_height = Some(g_height);

            // Avoid duplicate log entries: only push if last entry is different.
            let push_entry = match self.commit_log.last() {
                None => true,
                Some(last) => last.block_id != g_id,
            };
            if push_entry {
                self.commit_log.push(CommittedEntry {
                    block_id: g_id,
                    view: g_view,
                    height: g_height,
                });
            }
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

    /// Returns true if it is safe to vote for the given block.
    ///
    /// This implements the standard HotStuff safe-voting rule. It is safe to
    /// vote for a block B with justify_qc if EITHER:
    /// 1. There is no locked QC yet, OR
    /// 2. B extends the currently locked block (locked block is in B's ancestor chain), OR
    /// 3. B's justify_qc.view >= locked_qc.view
    ///
    /// This rule preserves safety while allowing liveness: a node will not vote
    /// for a block that conflicts with its lock unless the block has a QC from
    /// a view at least as recent as the lock.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The identifier of the block to check
    ///
    /// # Returns
    ///
    /// - `true` if it is safe to vote for this block
    /// - `false` if voting for this block would violate the safety rule
    pub fn is_safe_to_vote_on_block(&self, block_id: &BlockIdT) -> bool {
        // 1. If no locked qc yet, allow.
        let locked = match self.locked_qc.as_ref() {
            None => return true,
            Some(qc) => qc,
        };

        // 2. Find this block's node.
        let block_node = match self.blocks.get(block_id) {
            Some(node) => node,
            None => {
                // If the block is not yet registered, return false for safety
                // since we cannot verify the ancestor chain without the block data.
                // This ensures we never vote for a block whose ancestry we cannot verify.
                return false;
            }
        };

        // 3. Check if justify_qc.view >= locked_qc.view (liveness condition)
        //    This is the standard HotStuff rule that allows progress even when
        //    the block doesn't directly extend the locked block.
        if let Some(ref justify_qc) = block_node.justify_qc {
            if justify_qc.view >= locked.view {
                return true;
            }
        }

        // 4. Walk ancestors until genesis or until we find locked_qc.block_id.
        let locked_block_id = &locked.block_id;
        let mut current = block_node;
        loop {
            if &current.id == locked_block_id {
                return true;
            }
            let parent_id = match &current.parent_id {
                Some(pid) => pid,
                None => break,
            };
            current = match self.blocks.get(parent_id) {
                Some(node) => node,
                None => break,
            };
        }

        // If we walked the chain and didn't find the locked block, and the
        // justify_qc.view was not >= locked_qc.view, this block conflicts
        // with our lock; do not vote.
        false
    }
}