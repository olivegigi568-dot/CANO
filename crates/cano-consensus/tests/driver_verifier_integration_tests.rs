//! Integration tests for the HotStuffDriver with verifier integration.
//!
//! These tests verify:
//! - The driver uses the verifier to verify incoming messages
//! - Messages that fail verification are rejected
//! - The rejected_invalid_signatures counter is incremented
//! - NoopConsensusVerifier behaves like no verifier attached

use std::sync::Arc;

use cano_consensus::verify::{ConsensusVerifier, NoopConsensusVerifier, VerificationError};
use cano_consensus::{
    ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver, HotStuffState,
    MockConsensusNetwork, ValidatorId,
};
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

/// A verifier that rejects all messages.
#[derive(Debug, Default, Clone)]
struct RejectAllVerifier;

impl ConsensusVerifier for RejectAllVerifier {
    fn verify_vote(&self, _validator: ValidatorId, _vote: &Vote) -> Result<(), VerificationError> {
        Err(VerificationError::InvalidSignature)
    }

    fn verify_proposal(
        &self,
        _validator: ValidatorId,
        _proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        Err(VerificationError::InvalidSignature)
    }
}

/// Test that the driver drops votes when the verifier rejects them.
#[test]
fn driver_drops_votes_when_verifier_rejects() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new(engine).with_verifier(Arc::new(RejectAllVerifier));
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send a vote
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote { from: 42, vote };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Vote should be rejected due to invalid signature
    assert_eq!(driver.rejected_invalid_signatures(), 1);
    // Vote should NOT be counted as received
    assert_eq!(driver.votes_received(), 0);
    // No actions should be returned
    assert!(actions.is_empty());
}

/// Test that the driver drops proposals when the verifier rejects them.
#[test]
fn driver_drops_proposals_when_verifier_rejects() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new(engine).with_verifier(Arc::new(RejectAllVerifier));
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send a proposal
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: 99,
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Proposal should be rejected due to invalid signature
    assert_eq!(driver.rejected_invalid_signatures(), 1);
    // Proposal should NOT be counted as received
    assert_eq!(driver.proposals_received(), 0);
    // No actions should be returned
    assert!(actions.is_empty());
}

/// Test that the driver with NoopConsensusVerifier behaves like before.
#[test]
fn driver_with_noop_verifier_behaves_like_before() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new(engine).with_verifier(Arc::new(NoopConsensusVerifier::default()));
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send a vote
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote {
        from: 42,
        vote: vote.clone(),
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // With NoopConsensusVerifier, the vote should be accepted
    assert_eq!(driver.rejected_invalid_signatures(), 0);
    assert_eq!(driver.votes_received(), 1);
    assert!(!actions.is_empty());

    // Send a proposal
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: 99,
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // With NoopConsensusVerifier, the proposal should be accepted
    assert_eq!(driver.rejected_invalid_signatures(), 0);
    assert_eq!(driver.proposals_received(), 1);
    assert!(!actions.is_empty());
}

/// Test that the driver without a verifier accepts all messages (default behavior).
#[test]
fn driver_without_verifier_accepts_all() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send a vote
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote { from: 42, vote };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Without a verifier, the vote should be accepted
    assert_eq!(driver.rejected_invalid_signatures(), 0);
    assert_eq!(driver.votes_received(), 1);
    assert!(!actions.is_empty());

    // Send a proposal
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: 99,
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Without a verifier, the proposal should be accepted
    assert_eq!(driver.rejected_invalid_signatures(), 0);
    assert_eq!(driver.proposals_received(), 1);
    assert!(!actions.is_empty());
}

/// Test that multiple rejected messages increment the counter correctly.
#[test]
fn driver_counts_multiple_rejections() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new(engine).with_verifier(Arc::new(RejectAllVerifier));
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send multiple votes
    for i in 0..5 {
        let vote = make_dummy_vote(1, i);
        let event = ConsensusNetworkEvent::IncomingVote {
            from: i,
            vote,
        };
        let _ = driver.step(&mut net, Some(event)).unwrap();
    }

    // Send multiple proposals
    for i in 0..3 {
        let proposal = make_dummy_proposal(1, i);
        let event = ConsensusNetworkEvent::IncomingProposal {
            from: i + 100,
            proposal,
        };
        let _ = driver.step(&mut net, Some(event)).unwrap();
    }

    // All should be rejected
    assert_eq!(driver.rejected_invalid_signatures(), 8);
    assert_eq!(driver.votes_received(), 0);
    assert_eq!(driver.proposals_received(), 0);
}

/// Test the with_verifier builder pattern.
#[test]
fn driver_with_verifier_builder_pattern() {
    let engine = HotStuffState::new_at_height(1);

    // Test that with_verifier returns self for chaining
    let driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine)
        .with_verifier(Arc::new(NoopConsensusVerifier::default()));

    // Verify the driver is usable
    assert_eq!(driver.votes_received(), 0);
    assert_eq!(driver.rejected_invalid_signatures(), 0);
}

/// A verifier that accepts votes but rejects proposals.
#[derive(Debug, Default, Clone)]
struct AcceptVotesRejectProposals;

impl ConsensusVerifier for AcceptVotesRejectProposals {
    fn verify_vote(&self, _validator: ValidatorId, _vote: &Vote) -> Result<(), VerificationError> {
        Ok(())
    }

    fn verify_proposal(
        &self,
        _validator: ValidatorId,
        _proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        Err(VerificationError::InvalidSignature)
    }
}

/// Test that the verifier can selectively accept/reject messages.
#[test]
fn driver_verifier_selective_accept_reject() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new(engine).with_verifier(Arc::new(AcceptVotesRejectProposals));
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Send a vote - should be accepted
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote { from: 42, vote };
    let _ = driver.step(&mut net, Some(event)).unwrap();

    assert_eq!(driver.votes_received(), 1);
    assert_eq!(driver.rejected_invalid_signatures(), 0);

    // Send a proposal - should be rejected
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: 99,
        proposal,
    };
    let _ = driver.step(&mut net, Some(event)).unwrap();

    assert_eq!(driver.proposals_received(), 0);
    assert_eq!(driver.rejected_invalid_signatures(), 1);
}