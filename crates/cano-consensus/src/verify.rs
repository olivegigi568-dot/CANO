//! Consensus verification interface.
//!
//! This module defines the `ConsensusVerifier` trait and related types for
//! verifying consensus messages (votes and proposals). It provides:
//!
//! - `VerificationError`: Error type for verification failures
//! - `ConsensusVerifier`: Trait for signature verification
//! - `NoopConsensusVerifier`: Default implementation that accepts everything

use crate::ids::ValidatorId;
use cano_wire::consensus::{BlockProposal, Vote};

/// Errors that can occur during consensus message verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// The signature is invalid.
    InvalidSignature,
    /// The validator's public key is not in the registry.
    MissingKey(ValidatorId),
    /// Other verification error.
    Other(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidSignature => write!(f, "invalid signature"),
            VerificationError::MissingKey(id) => {
                write!(f, "missing public key for validator {:?}", id)
            }
            VerificationError::Other(s) => write!(f, "verification error: {}", s),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Trait for verifying consensus messages.
///
/// Implementors of this trait provide cryptographic verification of votes
/// and proposals. The verifier is called by the consensus driver before
/// processing incoming messages.
///
/// # Design Notes
///
/// - This trait does not use `ValidatorPublicKey` yet; that will be added
///   when real PQ signature verification is implemented.
/// - The trait is `Send + Sync` to allow sharing across threads.
pub trait ConsensusVerifier: Send + Sync + std::fmt::Debug {
    /// Verify a vote from a validator.
    ///
    /// Returns `Ok(())` if the vote is valid, or an error describing why
    /// verification failed.
    fn verify_vote(&self, validator: ValidatorId, vote: &Vote) -> Result<(), VerificationError>;

    /// Verify a block proposal from a validator.
    ///
    /// Returns `Ok(())` if the proposal is valid, or an error describing why
    /// verification failed.
    fn verify_proposal(
        &self,
        validator: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<(), VerificationError>;
}

/// A no-op verifier that accepts all messages.
///
/// This is the default verifier used in tests and until real cryptographic
/// verification is wired in. It always returns `Ok(())` for both votes
/// and proposals.
#[derive(Debug, Default, Clone)]
pub struct NoopConsensusVerifier;

impl ConsensusVerifier for NoopConsensusVerifier {
    fn verify_vote(&self, _validator: ValidatorId, _vote: &Vote) -> Result<(), VerificationError> {
        Ok(())
    }

    fn verify_proposal(
        &self,
        _validator: ValidatorId,
        _proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        Ok(())
    }
}