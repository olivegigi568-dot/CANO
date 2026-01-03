//! Tests for the ConsensusVerifier trait and NoopConsensusVerifier.
//!
//! These tests verify:
//! - NoopConsensusVerifier always returns Ok(())
//! - The trait can be implemented correctly

use cano_consensus::verify::{ConsensusVerifier, NoopConsensusVerifier, VerificationError};
use cano_consensus::ValidatorId;
use cano_wire::consensus::{BlockHeader, BlockProposal, Vote};

/// Create a dummy Vote for testing.
fn make_dummy_vote(height: u64, round: u64) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        reserved: 0,
        signature: vec![],
    }
}

/// Create a dummy BlockProposal for testing.
fn make_dummy_proposal(height: u64, round: u64) -> BlockProposal {
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
    }
}

/// Test that NoopConsensusVerifier always accepts votes.
#[test]
fn noop_verifier_accepts_all_votes() {
    let verifier = NoopConsensusVerifier::default();

    // Create different votes
    let vote1 = make_dummy_vote(1, 0);
    let vote2 = make_dummy_vote(100, 50);
    let vote3 = make_dummy_vote(u64::MAX, u64::MAX);

    // All should be accepted
    assert!(verifier.verify_vote(ValidatorId::new(1), &vote1).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(2), &vote2).is_ok());
    assert!(verifier.verify_vote(ValidatorId::new(999), &vote3).is_ok());
}

/// Test that NoopConsensusVerifier always accepts proposals.
#[test]
fn noop_verifier_accepts_all_proposals() {
    let verifier = NoopConsensusVerifier::default();

    // Create different proposals
    let proposal1 = make_dummy_proposal(1, 0);
    let proposal2 = make_dummy_proposal(100, 50);
    let proposal3 = make_dummy_proposal(u64::MAX, u64::MAX);

    // All should be accepted
    assert!(verifier
        .verify_proposal(ValidatorId::new(1), &proposal1)
        .is_ok());
    assert!(verifier
        .verify_proposal(ValidatorId::new(2), &proposal2)
        .is_ok());
    assert!(verifier
        .verify_proposal(ValidatorId::new(999), &proposal3)
        .is_ok());
}

/// Test that NoopConsensusVerifier can be created with new() and default().
#[test]
fn noop_verifier_creation() {
    // Both should work and behave the same
    let v1 = NoopConsensusVerifier;
    let v2 = NoopConsensusVerifier::default();

    let vote = make_dummy_vote(1, 0);
    let validator = ValidatorId::new(42);

    assert!(v1.verify_vote(validator, &vote).is_ok());
    assert!(v2.verify_vote(validator, &vote).is_ok());
}

/// Test that NoopConsensusVerifier is Debug.
#[test]
fn noop_verifier_is_debug() {
    let verifier = NoopConsensusVerifier::default();
    let debug_str = format!("{:?}", verifier);
    assert!(debug_str.contains("NoopConsensusVerifier"));
}

/// Test that NoopConsensusVerifier is Clone.
#[test]
fn noop_verifier_is_clone() {
    let verifier = NoopConsensusVerifier::default();
    let cloned = verifier.clone();

    let vote = make_dummy_vote(1, 0);
    let validator = ValidatorId::new(42);

    assert!(cloned.verify_vote(validator, &vote).is_ok());
}

/// Test VerificationError variants.
#[test]
fn verification_error_variants() {
    // Test InvalidSignature
    let err1 = VerificationError::InvalidSignature;
    let s1 = format!("{}", err1);
    assert!(s1.contains("invalid signature"));

    // Test MissingKey
    let err2 = VerificationError::MissingKey(ValidatorId::new(42));
    let s2 = format!("{}", err2);
    assert!(s2.contains("missing"));

    // Test Other
    let err3 = VerificationError::Other("custom error".to_string());
    let s3 = format!("{}", err3);
    assert!(s3.contains("custom error"));
}

/// Test that VerificationError implements Debug, Clone, PartialEq, Eq.
#[test]
fn verification_error_traits() {
    let err1 = VerificationError::InvalidSignature;
    let err2 = VerificationError::InvalidSignature;
    let err3 = VerificationError::MissingKey(ValidatorId::new(1));

    // PartialEq and Eq
    assert_eq!(err1, err2);
    assert_ne!(err1, err3);

    // Clone
    let err_clone = err1.clone();
    assert_eq!(err1, err_clone);

    // Debug
    let debug_str = format!("{:?}", err1);
    assert!(debug_str.contains("InvalidSignature"));
}