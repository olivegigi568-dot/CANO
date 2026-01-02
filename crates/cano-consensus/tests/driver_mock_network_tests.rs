//! Integration tests for the consensus engine driver with MockConsensusNetwork.
//!
//! These tests verify the wiring of:
//! `MockConsensusNetwork` → `ConsensusEngineDriver` → `ConsensusEngineAction`

use cano_consensus::{
    ConsensusEngineAction, ConsensusEngineDriver, ConsensusNetwork, ConsensusNetworkEvent,
    HotStuffDriver, HotStuffState, MockConsensusNetwork,
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

/// Test that the driver receives a vote event via MockConsensusNetwork.
///
/// This test validates the wiring:
/// 1. Push an `IncomingVote` into the mock network's inbound queue
/// 2. Poll the event using `try_recv_one()`
/// 3. Pass the event to the driver's `step()` method
/// 4. Verify the driver sees the event (updates internal counter)
/// 5. Verify `step()` returns `Ok(...)` without panicking
#[test]
fn driver_receives_vote_event_via_mock_network() {
    // 1. Construct a MockConsensusNetwork<u64>
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // 2. Push an IncomingVote into the inbound queue
    let vote = make_dummy_vote(1, 0);
    net.enqueue_event(ConsensusNetworkEvent::IncomingVote {
        from: 1,
        vote: vote.clone(),
    });

    // 3. Construct a HotStuffDriver wrapping a HotStuffState
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // 4. Poll the event and pass to driver
    let maybe_event = net.try_recv_one().unwrap();
    assert!(maybe_event.is_some());

    let actions = driver.step(&mut net, maybe_event).unwrap();

    // 5. Assert the driver processed the event
    assert_eq!(driver.votes_received(), 1);
    assert_eq!(driver.proposals_received(), 0);

    // 6. Assert actions were returned
    assert!(!actions.is_empty());
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that the driver receives a proposal event via MockConsensusNetwork.
///
/// Same idea as the vote test, but with IncomingProposal and a dummy BlockProposal.
#[test]
fn driver_receives_proposal_event_via_mock_network() {
    // 1. Construct a MockConsensusNetwork<u64>
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // 2. Push an IncomingProposal into the inbound queue
    let proposal = make_dummy_proposal(5, 2);
    net.enqueue_event(ConsensusNetworkEvent::IncomingProposal {
        from: 42,
        proposal: proposal.clone(),
    });

    // 3. Construct a HotStuffDriver wrapping a HotStuffState
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // 4. Poll the event and pass to driver
    let maybe_event = net.try_recv_one().unwrap();
    assert!(maybe_event.is_some());

    let actions = driver.step(&mut net, maybe_event).unwrap();

    // 5. Assert the driver processed the event
    assert_eq!(driver.votes_received(), 0);
    assert_eq!(driver.proposals_received(), 1);

    // 6. Assert actions were returned
    assert!(!actions.is_empty());
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that the driver correctly handles an empty network (no events).
#[test]
fn driver_handles_empty_network() {
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // Poll the empty network
    let maybe_event = net.try_recv_one().unwrap();
    assert!(maybe_event.is_none());

    // Step with no event
    let actions = driver.step(&mut net, maybe_event).unwrap();

    // No events processed, no counters updated
    assert_eq!(driver.votes_received(), 0);
    assert_eq!(driver.proposals_received(), 0);
    assert!(actions.is_empty());
}

/// Test the full driver loop: enqueue multiple events and process them in order.
#[test]
fn driver_processes_multiple_events_in_order() {
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Enqueue multiple events
    net.enqueue_event(ConsensusNetworkEvent::IncomingVote {
        from: 1,
        vote: make_dummy_vote(1, 0),
    });
    net.enqueue_event(ConsensusNetworkEvent::IncomingProposal {
        from: 2,
        proposal: make_dummy_proposal(1, 0),
    });
    net.enqueue_event(ConsensusNetworkEvent::IncomingVote {
        from: 3,
        vote: make_dummy_vote(1, 1),
    });
    net.enqueue_event(ConsensusNetworkEvent::IncomingVote {
        from: 4,
        vote: make_dummy_vote(1, 2),
    });

    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // Process all events
    while let Ok(Some(event)) = net.try_recv_one() {
        let _ = driver.step(&mut net, Some(event)).unwrap();
    }

    // Verify all events were processed
    assert_eq!(driver.votes_received(), 3);
    assert_eq!(driver.proposals_received(), 1);
}

/// Test that the driver can be used with the pattern described in the documentation.
#[test]
fn driver_follows_documented_usage_pattern() {
    let mut net: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Enqueue some events
    net.enqueue_event(ConsensusNetworkEvent::IncomingVote {
        from: 1,
        vote: make_dummy_vote(1, 0),
    });
    net.enqueue_event(ConsensusNetworkEvent::IncomingProposal {
        from: 2,
        proposal: make_dummy_proposal(2, 0),
    });

    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // Simulate the documented usage pattern for 2 iterations
    for _ in 0..2 {
        // 1. Poll the network for events
        let maybe_event = net.try_recv_one().unwrap();

        // 2. Step the consensus engine
        let actions = driver.step(&mut net, maybe_event).unwrap();

        // 3. Apply actions to the network (in a real scenario)
        for action in actions {
            match action {
                ConsensusEngineAction::BroadcastProposal(p) => {
                    net.broadcast_proposal(&p).unwrap();
                }
                ConsensusEngineAction::BroadcastVote(v) => {
                    net.broadcast_vote(&v).unwrap();
                }
                ConsensusEngineAction::SendVoteTo { to, vote } => {
                    net.send_vote_to(to, &vote).unwrap();
                }
                ConsensusEngineAction::Noop => {
                    // No network action needed
                }
            }
        }
    }

    // Verify events were processed
    assert_eq!(driver.votes_received(), 1);
    assert_eq!(driver.proposals_received(), 1);
}