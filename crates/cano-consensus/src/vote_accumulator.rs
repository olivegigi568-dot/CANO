//! Vote accumulator for HotStuff-like QC formation.
//!
//! This module provides a `VoteAccumulator` that:
//! - Tracks votes keyed by (view, block_id)
//! - Knows which validators have voted for each (view, block_id) pair
//! - Emits a `QuorumCertificate` when a quorum is reached
//!
//! # Design Note
//!
//! The accumulator is generic over `BlockIdT` to support different block
//! identifier types. The canonical type in cano-consensus is `[u8; 32]`.
//!
//! No cryptographic verification is performed in this module; that will be
//! added in future tasks.

use std::collections::{HashMap, HashSet};

use crate::ids::ValidatorId;
use crate::qc::{QcValidationError, QuorumCertificate};
use crate::validator_set::ConsensusValidatorSet;

/// Internal key for vote accumulation, representing (view, block_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VoteKey<BlockIdT> {
    view: u64,
    block_id: BlockIdT,
}

/// Accumulates votes for HotStuff-like QC formation.
///
/// This struct tracks votes keyed by (view, block_id) and knows when to
/// emit a `QuorumCertificate` based on the validator set's quorum threshold.
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
///
/// # Example
///
/// ```ignore
/// let mut acc = VoteAccumulator::new();
/// acc.on_vote(&validators, ValidatorId(0), view, &block_id)?;
/// acc.on_vote(&validators, ValidatorId(1), view, &block_id)?;
/// acc.on_vote(&validators, ValidatorId(2), view, &block_id)?;
/// if let Some(qc) = acc.maybe_qc_for(&validators, view, &block_id)? {
///     // QC is formed!
/// }
/// ```
#[derive(Debug)]
pub struct VoteAccumulator<BlockIdT> {
    /// Map from (view, block_id) to set of validators who have voted.
    entries: HashMap<VoteKey<BlockIdT>, HashSet<ValidatorId>>,
}

impl<BlockIdT> Default for VoteAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<BlockIdT> VoteAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new empty `VoteAccumulator`.
    pub fn new() -> Self {
        VoteAccumulator {
            entries: HashMap::new(),
        }
    }

    /// Ingest a single vote.
    ///
    /// Returns `Ok(true)` if this vote is new for this (view, block_id) pair,
    /// `Ok(false)` if it was a duplicate from the same validator.
    ///
    /// # Errors
    ///
    /// Returns `Err(QcValidationError::NonMemberSigner)` if the voter is not
    /// in the validator set.
    ///
    /// # Arguments
    ///
    /// - `validators`: The validator set to check membership against
    /// - `voter`: The validator who cast the vote
    /// - `view`: The view/round number of the vote
    /// - `block_id`: The block being voted for
    pub fn on_vote(
        &mut self,
        validators: &ConsensusValidatorSet,
        voter: ValidatorId,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<bool, QcValidationError> {
        // Reject non-members early.
        if !validators.contains(voter) {
            return Err(QcValidationError::NonMemberSigner(voter));
        }

        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };

        let entry = self.entries.entry(key).or_default();
        // Returns true if the voter was newly inserted, false if already present
        Ok(entry.insert(voter))
    }

    /// Attempts to form a QC for the given (view, block_id) pair.
    ///
    /// Returns `Ok(Some(qc))` if signers reach quorum; otherwise `Ok(None)`.
    ///
    /// This does *not* remove the entry; call `remove_entry` if you want to
    /// clean up after QC formation.
    ///
    /// # Errors
    ///
    /// Returns an error if the QC validation fails (e.g., non-member signers
    /// or duplicate signers, though duplicates should not occur if votes were
    /// ingested correctly).
    pub fn maybe_qc_for(
        &self,
        validators: &ConsensusValidatorSet,
        view: u64,
        block_id: &BlockIdT,
    ) -> Result<Option<QuorumCertificate<BlockIdT>>, QcValidationError> {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };

        let signers = match self.entries.get(&key) {
            Some(s) => s,
            None => return Ok(None),
        };

        let ids: Vec<ValidatorId> = signers.iter().copied().collect();
        let qc = QuorumCertificate::new(block_id.clone(), view, ids);

        // Reuse QC's validate() logic, which checks quorum, duplicates, non-members.
        match qc.validate(validators) {
            Ok(()) => Ok(Some(qc)),
            Err(QcValidationError::InsufficientQuorum { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Clear state for a given (view, block_id) once QC is formed.
    ///
    /// This is optional but can help reduce memory usage after a QC has been
    /// successfully formed.
    pub fn remove_entry(&mut self, view: u64, block_id: &BlockIdT) {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };
        self.entries.remove(&key);
    }

    /// Returns the number of votes currently accumulated for a given (view, block_id).
    ///
    /// Returns 0 if no votes have been received for this pair.
    pub fn vote_count(&self, view: u64, block_id: &BlockIdT) -> usize {
        let key = VoteKey {
            view,
            block_id: block_id.clone(),
        };
        self.entries.get(&key).map(|s| s.len()).unwrap_or(0)
    }
}
