//! Tests for `CryptoConsensusVerifier`.
//!
//! These tests verify that the `CryptoConsensusVerifier` correctly:
//! - Accepts valid vote and proposal signatures
//! - Rejects tampered signatures
//! - Rejects messages from validators not in the registry
//!
//! The tests use a simple hash-based "toy" signature scheme for testing purposes.
//! This is NOT a real signature scheme and should NOT be used in production.

use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use cano_consensus::verify::{ConsensusVerifier, VerificationError};
use cano_consensus::{
    CryptoConsensusVerifier, ValidatorId, ValidatorKeyRegistry, ValidatorPublicKey,
};
use cano_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use cano_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Test-only signature implementation
// ============================================================================

/// A test-only "toy" verifier using SHA3-256.
///
/// This verifier expects signatures to be:
/// `signature = SHA3-256(pk || preimage)`
///
/// **NOT FOR PRODUCTION** - this is only for testing the verification pipeline.
struct TestHashConsensusSigVerifier;

impl TestHashConsensusSigVerifier {
    /// Create a test signature for the given public key and preimage.
    ///
    /// `sig = SHA3-256(pk || preimage)`
    fn sign(pk: &[u8], preimage: &[u8]) -> Vec<u8> {
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
        let expected = Self::sign(pk, preimage);
        if signature == expected.as_slice() {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }
}

// ============================================================================
// Test helpers
// ============================================================================

/// Helper to create a Vote with a given signature.
fn make_vote_with_sig(height: u64, round: u64, signature: Vec<u8>) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        reserved: 0,
        signature,
    }
}

/// Helper to create a BlockProposal with a given signature.
fn make_proposal_with_sig(height: u64, round: u64, signature: Vec<u8>) -> BlockProposal {
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
        signature,
    }
}

/// Helper to sign a Vote using the test hash scheme.
fn sign_vote(pk: &[u8], vote: &Vote) -> Vec<u8> {
    let preimage = vote.signing_preimage();
    TestHashConsensusSigVerifier::sign(pk, &preimage)
}

/// Helper to sign a BlockProposal using the test hash scheme.
fn sign_proposal(pk: &[u8], proposal: &BlockProposal) -> Vec<u8> {
    let preimage = proposal.signing_preimage();
    TestHashConsensusSigVerifier::sign(pk, &preimage)
}

/// Build a simple registry with one validator.
fn build_registry_with_one_validator(id: u64, pk_bytes: Vec<u8>) -> ValidatorKeyRegistry {
    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(id), ValidatorPublicKey(pk_bytes));
    registry
}

// ============================================================================
// Vote verification tests
// ============================================================================

/// Test that CryptoConsensusVerifier accepts a valid vote signature.
#[test]
fn crypto_verifier_accepts_valid_vote_signature() {
    // Setup
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create a vote (without signature first to get preimage)
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    
    // Sign the vote
    vote.signature = sign_vote(&pk_bytes, &vote);

    // Verify
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that CryptoConsensusVerifier rejects a tampered vote signature.
#[test]
fn crypto_verifier_rejects_tampered_vote_signature() {
    // Setup
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create and sign a vote
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes, &vote);
    
    // Tamper with the signature
    vote.signature[0] ^= 0xff;

    // Verify should fail
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );
}

/// Test that CryptoConsensusVerifier rejects a vote from a validator not in the registry.
#[test]
fn crypto_verifier_rejects_missing_key() {
    // Setup - registry only has validator 1
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create a vote
    let vote = make_vote_with_sig(10, 5, vec![0u8; 32]);

    // Verify from validator 999 (not in registry)
    let result = verifier.verify_vote(ValidatorId::new(999), &vote);
    assert!(
        matches!(result, Err(VerificationError::MissingKey(_))),
        "Expected MissingKey, got {:?}",
        result
    );
}

// ============================================================================
// Proposal verification tests
// ============================================================================

/// Test that CryptoConsensusVerifier accepts a valid proposal signature.
#[test]
fn crypto_verifier_accepts_valid_proposal_signature() {
    // Setup
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create a proposal (without signature first to get preimage)
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    
    // Sign the proposal
    proposal.signature = sign_proposal(&pk_bytes, &proposal);

    // Verify
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
}

/// Test that CryptoConsensusVerifier rejects a tampered proposal signature.
#[test]
fn crypto_verifier_rejects_tampered_proposal_signature() {
    // Setup
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create and sign a proposal
    let mut proposal = make_proposal_with_sig(10, 5, vec![]);
    proposal.signature = sign_proposal(&pk_bytes, &proposal);
    
    // Tamper with the signature
    proposal.signature[0] ^= 0xff;

    // Verify should fail
    let result = verifier.verify_proposal(ValidatorId::new(1), &proposal);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );
}

/// Test that CryptoConsensusVerifier rejects a proposal from a validator not in the registry.
#[test]
fn crypto_verifier_rejects_missing_key_for_proposal() {
    // Setup - registry only has validator 1
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create a proposal
    let proposal = make_proposal_with_sig(10, 5, vec![0u8; 32]);

    // Verify from validator 999 (not in registry)
    let result = verifier.verify_proposal(ValidatorId::new(999), &proposal);
    assert!(
        matches!(result, Err(VerificationError::MissingKey(_))),
        "Expected MissingKey, got {:?}",
        result
    );
}

// ============================================================================
// Edge case tests
// ============================================================================

/// Test that signature verification fails when using the wrong public key.
#[test]
fn crypto_verifier_rejects_vote_signed_with_wrong_key() {
    // Setup
    let pk_bytes_1 = b"validator-1-public-key".to_vec();
    let pk_bytes_2 = b"validator-2-public-key".to_vec();
    
    // Registry has validator 1 with pk_bytes_1
    let registry = build_registry_with_one_validator(1, pk_bytes_1.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create a vote and sign it with the WRONG key (pk_bytes_2)
    let mut vote = make_vote_with_sig(10, 5, vec![]);
    vote.signature = sign_vote(&pk_bytes_2, &vote);

    // Verify should fail because the signature was made with a different key
    let result = verifier.verify_vote(ValidatorId::new(1), &vote);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature, got {:?}",
        result
    );
}

/// Test that different votes produce different signatures.
#[test]
fn crypto_verifier_signatures_are_vote_specific() {
    let pk_bytes = b"test-validator-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes.clone());
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create two different votes
    let mut vote1 = make_vote_with_sig(10, 5, vec![]);
    let mut vote2 = make_vote_with_sig(20, 10, vec![]);
    
    // Sign both votes
    vote1.signature = sign_vote(&pk_bytes, &vote1);
    vote2.signature = sign_vote(&pk_bytes, &vote2);

    // Signatures should be different
    assert_ne!(vote1.signature, vote2.signature);

    // Using vote1's signature for vote2 should fail
    let vote2_with_wrong_sig = make_vote_with_sig(20, 10, vote1.signature.clone());
    let result = verifier.verify_vote(ValidatorId::new(1), &vote2_with_wrong_sig);
    assert!(
        matches!(result, Err(VerificationError::InvalidSignature)),
        "Expected InvalidSignature when using wrong vote's signature"
    );
}

/// Test that CryptoConsensusVerifier is Debug.
#[test]
fn crypto_verifier_is_debug() {
    let pk_bytes = b"test-public-key".to_vec();
    let registry = build_registry_with_one_validator(1, pk_bytes);
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );
    
    let debug_str = format!("{:?}", verifier);
    assert!(debug_str.contains("CryptoConsensusVerifier"));
}

/// Test that CryptoConsensusVerifier can work with multiple validators.
#[test]
fn crypto_verifier_with_multiple_validators() {
    // Setup registry with multiple validators
    let pk1 = b"validator-1-pk".to_vec();
    let pk2 = b"validator-2-pk".to_vec();
    let pk3 = b"validator-3-pk".to_vec();
    
    let mut registry = ValidatorKeyRegistry::new();
    registry.insert(ValidatorId::new(1), ValidatorPublicKey(pk1.clone()));
    registry.insert(ValidatorId::new(2), ValidatorPublicKey(pk2.clone()));
    registry.insert(ValidatorId::new(3), ValidatorPublicKey(pk3.clone()));
    
    let verifier = CryptoConsensusVerifier::new(
        registry,
        Arc::new(TestHashConsensusSigVerifier),
    );

    // Create votes from each validator
    let mut vote1 = make_vote_with_sig(10, 0, vec![]);
    let mut vote2 = make_vote_with_sig(10, 0, vec![]);
    let mut vote3 = make_vote_with_sig(10, 0, vec![]);
    
    vote1.signature = sign_vote(&pk1, &vote1);
    vote2.signature = sign_vote(&pk2, &vote2);
    vote3.signature = sign_vote(&pk3, &vote3);

    // All should verify correctly
    assert!(verifier.verify_vote(ValidatorId::new(1), &vote1).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(2), &vote2).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(3), &vote3).is_ok());
    
    // Cross-verification should fail
    assert!(verifier.verify_vote(ValidatorId::new(2), &vote1).is_err());
    assert!(verifier.verify_vote(ValidatorId::new(1), &vote2).is_err());
}
