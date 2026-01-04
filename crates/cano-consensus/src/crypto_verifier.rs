//! Crypto-backed consensus verification.
//!
//! This module provides `CryptoConsensusVerifier`, a `ConsensusVerifier` implementation
//! that uses a `ValidatorKeyRegistry` to look up public keys and a `ConsensusSigVerifier`
//! backend to verify signatures.
//!
//! # Design
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                    CryptoConsensusVerifier                    │
//! │  ┌──────────────────────┐   ┌────────────────────────────────┐│
//! │  │ ValidatorKeyRegistry │   │ Arc<dyn ConsensusSigVerifier> ││
//! │  │   (ValidatorId →     │   │   (Verify signatures)          ││
//! │  │    ValidatorPublicKey)│   └────────────────────────────────┘│
//! │  └──────────────────────┘                                     │
//! └───────────────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;

use cano_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use cano_wire::consensus::{BlockProposal, Vote};

use crate::ids::{ValidatorId, ValidatorPublicKey};
use crate::key_registry::ValidatorKeyRegistry;
use crate::verify::{ConsensusVerifier, VerificationError};

/// A `ConsensusVerifier` that uses a `ValidatorKeyRegistry` plus a
/// `ConsensusSigVerifier` implementation from `cano-crypto`.
///
/// This struct bridges the typed world of `cano-consensus` (with `ValidatorId`,
/// `ValidatorPublicKey`, `ValidatorKeyRegistry`) with the algorithm-agnostic
/// `ConsensusSigVerifier` trait in `cano-crypto`.
pub struct CryptoConsensusVerifier {
    registry: ValidatorKeyRegistry,
    backend: Arc<dyn ConsensusSigVerifier>,
}

impl std::fmt::Debug for CryptoConsensusVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoConsensusVerifier")
            .field("registry", &self.registry)
            .field("backend", &"<ConsensusSigVerifier>")
            .finish()
    }
}

impl CryptoConsensusVerifier {
    /// Create a new `CryptoConsensusVerifier`.
    ///
    /// # Arguments
    ///
    /// * `registry` - The validator key registry for looking up public keys.
    /// * `backend` - The signature verification backend.
    pub fn new(registry: ValidatorKeyRegistry, backend: Arc<dyn ConsensusSigVerifier>) -> Self {
        CryptoConsensusVerifier { registry, backend }
    }

    /// Look up the public key for a validator.
    fn key_for(&self, validator: ValidatorId) -> Result<&ValidatorPublicKey, VerificationError> {
        self.registry
            .get(&validator)
            .ok_or_else(|| VerificationError::MissingKey(validator))
    }
}

/// Map a `ConsensusSigError` to a `VerificationError`.
fn map_sig_error(err: ConsensusSigError) -> VerificationError {
    match err {
        ConsensusSigError::MissingKey(id) => VerificationError::MissingKey(ValidatorId::new(id)),
        ConsensusSigError::MalformedSignature | ConsensusSigError::InvalidSignature => {
            VerificationError::InvalidSignature
        }
        ConsensusSigError::Other(msg) => VerificationError::Other(msg),
    }
}

impl ConsensusVerifier for CryptoConsensusVerifier {
    fn verify_vote(&self, from: ValidatorId, vote: &Vote) -> Result<(), VerificationError> {
        let pk = self.key_for(from)?;
        let preimage = vote.signing_preimage();

        self.backend
            .verify_vote(from.as_u64(), &pk.0, &preimage, &vote.signature)
            .map_err(map_sig_error)
    }

    fn verify_proposal(
        &self,
        from: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        let pk = self.key_for(from)?;
        let preimage = proposal.signing_preimage();

        self.backend
            .verify_proposal(from.as_u64(), &pk.0, &preimage, &proposal.signature)
            .map_err(map_sig_error)
    }
}
