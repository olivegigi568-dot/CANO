//! Consensus signature verification interface.
//!
//! This module defines an algorithm-agnostic interface for verifying consensus
//! signatures. It is designed to be PQC-friendly and does not assume any specific
//! signature algorithm.
//!
//! # Design Notes
//!
//! - This module is verification-only; signing is handled separately.
//! - Uses primitive types (`u64`, `&[u8]`) to avoid circular dependencies with
//!   `cano-consensus` where `ValidatorId` and `ValidatorPublicKey` are defined.
//! - The actual integration with typed IDs happens in `cano-consensus`'s
//!   `CryptoConsensusVerifier`.

use std::fmt;

/// Error type for consensus signature verification.
#[derive(Debug)]
pub enum ConsensusSigError {
    /// Key for this validator is missing in the registry / config.
    MissingKey(u64),
    /// Signature bytes are malformed (length, encoding, etc.).
    MalformedSignature,
    /// Signature verification failed.
    InvalidSignature,
    /// Any other backend-specific error.
    Other(String),
}

impl fmt::Display for ConsensusSigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusSigError::MissingKey(id) => {
                write!(f, "missing consensus key for validator {}", id)
            }
            ConsensusSigError::MalformedSignature => write!(f, "malformed consensus signature"),
            ConsensusSigError::InvalidSignature => write!(f, "invalid consensus signature"),
            ConsensusSigError::Other(msg) => write!(f, "consensus signature error: {}", msg),
        }
    }
}

impl std::error::Error for ConsensusSigError {}

/// Trait for consensus signature verification.
///
/// This intentionally does **not** assume any specific algorithm.
/// Implementations may be PQC, classical, or purely test-only.
///
/// # Type Notes
///
/// - `validator_id` is a `u64` (the raw value from `ValidatorId`).
/// - `pk` is a byte slice representing the validator's consensus public key.
/// - `preimage` is produced by `Vote::signing_preimage()` or `BlockProposal::signing_preimage()`.
/// - `signature` is the raw signature bytes carried on the wire.
pub trait ConsensusSigVerifier: Send + Sync {
    /// Verify a vote signature for this validator.
    ///
    /// `validator_id` is the validator's raw ID (from `ValidatorId::as_u64()`).
    /// `pk` is the validator's consensus public key bytes.
    /// `preimage` is produced by `Vote::signing_preimage()`.
    /// `signature` is the raw signature bytes carried on the wire.
    fn verify_vote(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError>;

    /// Verify a block proposal signature for this validator.
    ///
    /// `preimage` is produced by `BlockProposal::signing_preimage()`.
    fn verify_proposal(
        &self,
        validator_id: u64,
        pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    /// A test-only "toy" verifier using SHA3-256.
    ///
    /// This verifier expects signatures to be:
    /// `signature = SHA3-256(pk || preimage)`
    ///
    /// **NOT FOR PRODUCTION** - this is only for testing the verification pipeline.
    pub struct TestHashConsensusSigVerifier;

    impl TestHashConsensusSigVerifier {
        /// Create a test signature for the given public key and preimage.
        ///
        /// `sig = SHA3-256(pk || preimage)`
        pub fn sign(pk: &[u8], preimage: &[u8]) -> Vec<u8> {
            let mut hasher = Sha3_256::new();
            hasher.update(pk);
            hasher.update(preimage);
            hasher.finalize().to_vec()
        }
    }

    impl ConsensusSigVerifier for TestHashConsensusSigVerifier {
        fn verify_vote(
            &self,
            _validator_id: u64,
            pk: &[u8],
            preimage: &[u8],
            signature: &[u8],
        ) -> Result<(), ConsensusSigError> {
            let expected = Self::sign(pk, preimage);
            if signature == expected.as_slice() {
                Ok(())
            } else {
                Err(ConsensusSigError::InvalidSignature)
            }
        }

        fn verify_proposal(
            &self,
            _validator_id: u64,
            pk: &[u8],
            preimage: &[u8],
            signature: &[u8],
        ) -> Result<(), ConsensusSigError> {
            // Same verification logic for proposals
            let expected = Self::sign(pk, preimage);
            if signature == expected.as_slice() {
                Ok(())
            } else {
                Err(ConsensusSigError::InvalidSignature)
            }
        }
    }

    #[test]
    fn test_hash_verifier_accepts_valid_signature() {
        let verifier = TestHashConsensusSigVerifier;
        let pk = b"test-public-key";
        let preimage = b"test-preimage-data";
        let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

        let result = verifier.verify_vote(1, pk, preimage, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hash_verifier_rejects_invalid_signature() {
        let verifier = TestHashConsensusSigVerifier;
        let pk = b"test-public-key";
        let preimage = b"test-preimage-data";
        let mut signature = TestHashConsensusSigVerifier::sign(pk, preimage);
        // Tamper with the signature
        signature[0] ^= 0xff;

        let result = verifier.verify_vote(1, pk, preimage, &signature);
        assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
    }

    #[test]
    fn test_hash_verifier_rejects_wrong_key() {
        let verifier = TestHashConsensusSigVerifier;
        let pk = b"test-public-key";
        let wrong_pk = b"wrong-public-key";
        let preimage = b"test-preimage-data";
        let signature = TestHashConsensusSigVerifier::sign(pk, preimage);

        // Verify with wrong key
        let result = verifier.verify_vote(1, wrong_pk, preimage, &signature);
        assert!(matches!(result, Err(ConsensusSigError::InvalidSignature)));
    }

    #[test]
    fn test_consensus_sig_error_display() {
        let e1 = ConsensusSigError::MissingKey(42);
        assert!(format!("{}", e1).contains("42"));

        let e2 = ConsensusSigError::MalformedSignature;
        assert!(format!("{}", e2).contains("malformed"));

        let e3 = ConsensusSigError::InvalidSignature;
        assert!(format!("{}", e3).contains("invalid"));

        let e4 = ConsensusSigError::Other("custom error".to_string());
        assert!(format!("{}", e4).contains("custom error"));
    }
}
