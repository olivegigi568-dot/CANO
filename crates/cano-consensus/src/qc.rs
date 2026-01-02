//! Quorum Certificate (QC) abstraction for consensus.
//!
//! This module provides a logical representation of a Quorum Certificate that
//! attests to a block/proposal having received votes from a quorum of validators.
//!
//! # Design Note
//!
//! This is a purely logical QC abstraction for T52. It provides:
//! - A generic `QuorumCertificate<BlockIdT>` that references a block
//! - Logical validation against a `ConsensusValidatorSet` (membership + quorum)
//!
//! No cryptographic verification is performed in this module; that will be
//! added in future tasks.

use std::collections::HashSet;

use crate::ids::ValidatorId;
use crate::validator_set::ConsensusValidatorSet;

/// A Quorum Certificate attesting to a block having received sufficient votes.
///
/// This struct represents the logical components of a QC:
/// - The block/proposal it attests to
/// - The view/round at which it was formed
/// - The set of validators whose votes are included
///
/// The `BlockIdT` generic allows this to work with different block identifier types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate<BlockIdT> {
    /// Identifier of the block/proposal this QC attests to.
    pub block_id: BlockIdT,
    /// View / round / height at which this QC was formed.
    pub view: u64,
    /// Validators whose votes are included in this QC.
    pub signers: Vec<ValidatorId>,

    // Future: cryptographic material (aggregated signature, suite_id, etc.)
    // For now we keep this purely logical.
}

/// Errors that can occur during logical QC validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QcValidationError {
    /// A signer is not in the validator set.
    NonMemberSigner(ValidatorId),
    /// Duplicate signer detected in the QC.
    DuplicateSigner(ValidatorId),
    /// Total voting power of signers is below 2/3 threshold.
    InsufficientQuorum {
        /// The accumulated voting power of the signers.
        accumulated_vp: u64,
        /// The required voting power for a valid quorum.
        required_vp: u64,
    },
}

impl<BlockIdT: Clone> QuorumCertificate<BlockIdT> {
    /// Create a new `QuorumCertificate` from a block id, view, and signers.
    pub fn new(block_id: BlockIdT, view: u64, signers: Vec<ValidatorId>) -> Self {
        QuorumCertificate {
            block_id,
            view,
            signers,
        }
    }

    /// Validate the QC against a validator set.
    ///
    /// This performs logical validation only (no cryptographic checks):
    /// 1. All signers must be members of the validator set
    /// 2. No duplicate signers are allowed
    /// 3. The accumulated voting power must meet the 2/3 threshold
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A signer is not a member of the validator set (`NonMemberSigner`)
    /// - A signer appears more than once (`DuplicateSigner`)
    /// - The total voting power is below the 2/3 threshold (`InsufficientQuorum`)
    pub fn validate(&self, validators: &ConsensusValidatorSet) -> Result<(), QcValidationError> {
        let mut seen = HashSet::new();
        let mut acc_vp: u64 = 0;

        for id in &self.signers {
            // Check membership
            if !validators.contains(*id) {
                return Err(QcValidationError::NonMemberSigner(*id));
            }

            // Check for duplicates
            if !seen.insert(*id) {
                return Err(QcValidationError::DuplicateSigner(*id));
            }

            // Accumulate voting power
            if let Some(idx) = validators.index_of(*id) {
                let entry = validators.get(idx).expect("index_of should be valid");
                acc_vp = acc_vp.saturating_add(entry.voting_power);
            }
        }

        // Check quorum threshold
        let required = validators.two_thirds_vp();
        if acc_vp < required {
            return Err(QcValidationError::InsufficientQuorum {
                accumulated_vp: acc_vp,
                required_vp: required,
            });
        }

        Ok(())
    }
}
