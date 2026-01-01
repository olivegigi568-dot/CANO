//! Integration tests for the single-node simulation harness.
//!
//! These tests verify that `SingleNodeSim` correctly routes events through
//! the driver and applies actions back to the network:
//! - Events in → driver → actions → network is coherent and testable.

use cano_consensus::{
    ConsensusNetworkEvent, HotStuffDriver, HotStuffState, MockConsensusNetwork, SingleNodeSim,
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

/// Test that SingleNodeSim routes a vote event through the driver.
///
/// Outline:
/// 1. Create a MockConsensusNetwork<u64>
/// 2. Push a ConsensusNetworkEvent::IncomingVote into net.inbound
/// 3. Create a HotStuffDriver over a HotStuffState engine
/// 4. Wrap into SingleNodeSim
/// 5. Call step_once()
/// 6. Assert the driver recorded that it received 1 vote
#[test]
fn single_node_sim_routes_vote_via_driver() {
    // 1. Create a MockConsensusNetwork<u64>
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // 2. Push an IncomingVote into net.inbound
    let dummy_vote = make_dummy_vote(1, 0);
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: 1,
        vote: dummy_vote.clone(),
    });

    // 3. Create a HotStuffDriver over a HotStuffState engine
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::new(engine);

    // 4. Wrap into SingleNodeSim
    let mut sim = SingleNodeSim::new(net, driver);

    // 5. Call step_once()
    sim.step_once().unwrap();

    // 6. Assert the driver recorded that it received 1 vote
    assert_eq!(sim.driver.votes_received(), 1);
    assert_eq!(sim.driver.proposals_received(), 0);
}

/// Test that SingleNodeSim routes a proposal event through the driver.
///
/// Outline:
/// 1. Create a MockConsensusNetwork<u64>
/// 2. Push a ConsensusNetworkEvent::IncomingProposal into net.inbound
/// 3. Create a HotStuffDriver over a HotStuffState engine
/// 4. Wrap into SingleNodeSim
/// 5. Call step_once()
/// 6. Assert the driver recorded that it received 1 proposal
#[test]
fn single_node_sim_routes_proposal_via_driver() {
    // 1. Create a MockConsensusNetwork<u64>
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // 2. Push an IncomingProposal into net.inbound
    let dummy_proposal = make_dummy_proposal(1, 0);
    net.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 42,
            proposal: dummy_proposal.clone(),
        });

    // 3. Create a HotStuffDriver over a HotStuffState engine
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::new(engine);

    // 4. Wrap into SingleNodeSim
    let mut sim = SingleNodeSim::new(net, driver);

    // 5. Call step_once()
    sim.step_once().unwrap();

    // 6. Assert the driver recorded that it received 1 proposal
    assert_eq!(sim.driver.votes_received(), 0);
    assert_eq!(sim.driver.proposals_received(), 1);
}

/// Test that SingleNodeSim with no events is a no-op.
///
/// Outline:
/// 1. Start with an empty MockConsensusNetwork (no inbound events)
/// 2. Call step_once() a few times
/// 3. Assert that the driver's counters did not change
/// 4. Assert that no outbound actions were applied (outbound logs remain empty)
#[test]
fn single_node_sim_no_event_is_noop() {
    // 1. Create an empty MockConsensusNetwork<u64>
    let net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // 2. Create a HotStuffDriver over a HotStuffState engine
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::new(engine);

    // 3. Wrap into SingleNodeSim
    let mut sim = SingleNodeSim::new(net, driver);

    // 4. Call step_once() a few times to verify it doesn't change state
    const ITERATIONS: usize = 5;
    for _ in 0..ITERATIONS {
        sim.step_once().unwrap();
    }

    // 5. Assert that the driver's counters did not change
    assert_eq!(sim.driver.votes_received(), 0);
    assert_eq!(sim.driver.proposals_received(), 0);

    // 6. Assert that no outbound actions were applied (outbound logs remain empty)
    assert!(sim.net.outbound.is_empty());
    assert!(sim.net.outbound_proposals.is_empty());
}

/// Test that SingleNodeSim processes multiple events in sequence.
#[test]
fn single_node_sim_processes_multiple_events_in_sequence() {
    // Create a MockConsensusNetwork<u64> with multiple events
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Enqueue multiple events (3 votes + 1 proposal = 4 total)
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: 1,
        vote: make_dummy_vote(1, 0),
    });
    net.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 2,
            proposal: make_dummy_proposal(1, 0),
        });
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: 3,
        vote: make_dummy_vote(1, 1),
    });
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: 4,
        vote: make_dummy_vote(2, 0),
    });

    let num_events = net.inbound.len();

    // Create driver and sim
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::new(engine);
    let mut sim = SingleNodeSim::new(net, driver);

    // Process all events by calling step_once() for each enqueued event
    for _ in 0..num_events {
        sim.step_once().unwrap();
    }

    // Verify counters
    assert_eq!(sim.driver.votes_received(), 3);
    assert_eq!(sim.driver.proposals_received(), 1);
}

// ============================================================================
// Validator Set Enforcement Tests (T51)
// ============================================================================

/// Test that SingleNodeSim with ValidatorContext rejects votes from unknown validators.
///
/// Scenario:
/// 1. Create a ConsensusValidatorSet with one validator: ValidatorId(1).
/// 2. Build HotStuffDriver with ValidatorContext of that set.
/// 3. Create a MockConsensusNetwork<ValidatorId>.
/// 4. Enqueue an IncomingVote from ValidatorId(2) with a Vote.
/// 5. Run step_once().
/// 6. Assert that:
///    - The engine's "accepted vote" counter did not increase.
///    - The driver's "rejected votes" counter increased.
#[test]
fn single_node_sim_rejects_vote_from_unknown_validator() {
    use cano_consensus::{ConsensusValidatorSet, ValidatorContext, ValidatorId, ValidatorSetEntry};

    // Create a validator set with only validator 1
    let validators = vec![ValidatorSetEntry {
        id: ValidatorId::new(1),
        voting_power: 10,
    }];
    let set = ConsensusValidatorSet::new(validators).expect("should succeed");
    let ctx = ValidatorContext::new(set);

    // Create a MockConsensusNetwork<ValidatorId>
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Enqueue an IncomingVote from an unknown validator (ValidatorId(2))
    let vote = make_dummy_vote(1, 0);
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(2), // Not in validator set
        vote,
    });

    // Create driver with validator context
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::with_validators(engine, ctx);
    let mut sim = SingleNodeSim::new(net, driver);

    // Run step_once()
    sim.step_once().unwrap();

    // Assert vote was rejected, not accepted
    assert_eq!(
        sim.driver.votes_received(),
        0,
        "Vote from unknown validator should not be accepted"
    );
    assert_eq!(
        sim.driver.rejected_votes(),
        1,
        "Vote from unknown validator should be rejected"
    );
}

/// Test that SingleNodeSim with ValidatorContext accepts votes from known validators.
#[test]
fn single_node_sim_accepts_vote_from_known_validator() {
    use cano_consensus::{ConsensusValidatorSet, ValidatorContext, ValidatorId, ValidatorSetEntry};

    // Create a validator set with validator 1 and 2
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 20,
        },
    ];
    let set = ConsensusValidatorSet::new(validators).expect("should succeed");
    let ctx = ValidatorContext::new(set);

    // Create a MockConsensusNetwork<ValidatorId>
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Enqueue an IncomingVote from a known validator (ValidatorId(1))
    let vote = make_dummy_vote(1, 0);
    net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(1), // In validator set
        vote,
    });

    // Create driver with validator context
    let engine = HotStuffState::new_at_height(1);
    let driver = HotStuffDriver::with_validators(engine, ctx);
    let mut sim = SingleNodeSim::new(net, driver);

    // Run step_once()
    sim.step_once().unwrap();

    // Assert vote was accepted
    assert_eq!(
        sim.driver.votes_received(),
        1,
        "Vote from known validator should be accepted"
    );
    assert_eq!(
        sim.driver.rejected_votes(),
        0,
        "Vote from known validator should not be rejected"
    );
}