//! Integration tests for the multi-node simulation harness.
//!
//! These tests verify that `MultiNodeSim` correctly wires multiple nodes together:
//! - Broadcasts and sends are delivered to the appropriate other nodes' inbound queues.
//! - No real network or cano-node is used.

use cano_consensus::{
    ConsensusEngineAction, ConsensusEngineDriver, ConsensusNetworkEvent, MockConsensusNetwork,
    MultiNodeSim, NetworkError,
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

// ============================================================================
// Test driver that records events and produces actions
// ============================================================================

/// A simple test driver that:
/// - Records received votes and proposals
/// - Produces configurable actions when processing events
#[derive(Debug, Default)]
struct TestDriver {
    /// Number of votes received
    votes_received: u64,
    /// Number of proposals received
    proposals_received: u64,
    /// Action to produce on IncomingProposal (if Some)
    on_proposal_action: Option<TestAction>,
    /// Action to produce on IncomingVote (if Some)
    on_vote_action: Option<TestAction>,
}

/// Actions that the test driver can produce.
#[derive(Debug, Clone)]
enum TestAction {
    /// Broadcast a vote
    BroadcastVote(Vote),
    /// Broadcast a proposal
    BroadcastProposal(BlockProposal),
    /// Send a vote to a specific target
    SendVoteTo { to: u64, vote: Vote },
}

impl TestDriver {
    fn new() -> Self {
        TestDriver::default()
    }

    fn with_on_proposal_action(mut self, action: TestAction) -> Self {
        self.on_proposal_action = Some(action);
        self
    }

    fn with_on_vote_action(mut self, action: TestAction) -> Self {
        self.on_vote_action = Some(action);
        self
    }
}

impl ConsensusEngineDriver<MockConsensusNetwork<u64>> for TestDriver {
    fn step(
        &mut self,
        _net: &mut MockConsensusNetwork<u64>,
        maybe_event: Option<ConsensusNetworkEvent<u64>>,
    ) -> Result<Vec<ConsensusEngineAction<u64>>, NetworkError> {
        let mut actions = Vec::new();

        if let Some(event) = maybe_event {
            match event {
                ConsensusNetworkEvent::IncomingVote { .. } => {
                    self.votes_received += 1;
                    if let Some(ref test_action) = self.on_vote_action {
                        actions.push(convert_test_action(test_action));
                    } else {
                        actions.push(ConsensusEngineAction::Noop);
                    }
                }
                ConsensusNetworkEvent::IncomingProposal { .. } => {
                    self.proposals_received += 1;
                    if let Some(ref test_action) = self.on_proposal_action {
                        actions.push(convert_test_action(test_action));
                    } else {
                        actions.push(ConsensusEngineAction::Noop);
                    }
                }
            }
        }

        Ok(actions)
    }
}

fn convert_test_action(test_action: &TestAction) -> ConsensusEngineAction<u64> {
    match test_action {
        TestAction::BroadcastVote(vote) => ConsensusEngineAction::BroadcastVote(vote.clone()),
        TestAction::BroadcastProposal(proposal) => {
            ConsensusEngineAction::BroadcastProposal(proposal.clone())
        }
        TestAction::SendVoteTo { to, vote } => ConsensusEngineAction::SendVoteTo {
            to: *to,
            vote: vote.clone(),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that a broadcast proposal from one node propagates to all other nodes.
///
/// Scenario:
/// - 3 nodes with ids 1, 2, 3
/// - Node 1 receives an IncomingProposal and broadcasts a vote in response
/// - After step_once(), nodes 2 and 3 should have IncomingVote in their inbound queues
#[test]
fn multi_node_sim_broadcast_propagates_to_all_others() {
    // Create 3 nodes with drivers
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert an IncomingProposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
        from: 1,
        proposal: dummy_proposal,
    });

    // Create drivers: node 1 will broadcast a vote when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(dummy_vote));
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2), (3u64, net3, driver3)];
    let mut sim = MultiNodeSim::new(nodes);

    // Run one step
    sim.step_once().unwrap();

    // After step, node 1's driver should have processed 1 proposal
    assert_eq!(sim.drivers.get(&1).unwrap().proposals_received, 1);

    // Nodes 2 and 3 should have an IncomingVote in their inbound queues (from the broadcast)
    assert_eq!(sim.nets.get(&2).unwrap().inbound.len(), 1);
    assert_eq!(sim.nets.get(&3).unwrap().inbound.len(), 1);

    // Verify it's a vote from node 1
    let event2 = sim.nets.get(&2).unwrap().inbound.front().unwrap();
    match event2 {
        ConsensusNetworkEvent::IncomingVote { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingVote"),
    }

    let event3 = sim.nets.get(&3).unwrap().inbound.front().unwrap();
    match event3 {
        ConsensusNetworkEvent::IncomingVote { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingVote"),
    }

    // Node 1 should NOT have received the vote (no self-delivery)
    assert!(sim.nets.get(&1).unwrap().inbound.is_empty());
}

/// Test that SendVoteTo delivers to a single target only.
///
/// Scenario:
/// - 3 nodes with ids 1, 2, 3
/// - Node 1 receives a proposal and sends a vote to node 2 only
/// - After step_once(), only node 2 should have the vote in its inbound queue
#[test]
fn multi_node_sim_send_vote_to_delivers_to_single_target() {
    // Create 3 nodes with drivers
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert an IncomingProposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
        from: 1,
        proposal: dummy_proposal,
    });

    // Create drivers: node 1 will send a vote to node 2 when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 =
        TestDriver::new().with_on_proposal_action(TestAction::SendVoteTo { to: 2, vote: dummy_vote });
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2), (3u64, net3, driver3)];
    let mut sim = MultiNodeSim::new(nodes);

    // Run one step
    sim.step_once().unwrap();

    // After step, node 1's driver should have processed 1 proposal
    assert_eq!(sim.drivers.get(&1).unwrap().proposals_received, 1);

    // Node 2 should have received the vote
    assert_eq!(sim.nets.get(&2).unwrap().inbound.len(), 1);

    // Verify it's a vote from node 1
    let event2 = sim.nets.get(&2).unwrap().inbound.front().unwrap();
    match event2 {
        ConsensusNetworkEvent::IncomingVote { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingVote"),
    }

    // Node 3 should NOT have received the vote (targeted send)
    assert!(sim.nets.get(&3).unwrap().inbound.is_empty());

    // Node 1 should NOT have received the vote
    assert!(sim.nets.get(&1).unwrap().inbound.is_empty());
}

/// Test that step_once with no events is a no-op.
///
/// Scenario:
/// - 3 nodes with empty inbound queues
/// - Call step_once() multiple times
/// - Verify no counters changed and no errors raised
#[test]
fn multi_node_sim_no_events_is_noop() {
    // Create 3 nodes with empty networks
    let net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    let driver1 = TestDriver::new();
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2), (3u64, net3, driver3)];
    let mut sim = MultiNodeSim::new(nodes);

    // Run multiple steps
    const ITERATIONS: usize = 5;
    for _ in 0..ITERATIONS {
        sim.step_once().unwrap();
    }

    // Verify no events were received by any driver
    for id in [1u64, 2u64, 3u64] {
        assert_eq!(sim.drivers.get(&id).unwrap().votes_received, 0);
        assert_eq!(sim.drivers.get(&id).unwrap().proposals_received, 0);
    }

    // Verify no messages in any inbound queue
    for id in [1u64, 2u64, 3u64] {
        assert!(sim.nets.get(&id).unwrap().inbound.is_empty());
    }
}

/// Test that broadcast proposal propagates to all other nodes.
///
/// Scenario:
/// - 3 nodes with ids 1, 2, 3
/// - Node 1 receives a vote and broadcasts a proposal in response
/// - After step_once(), nodes 2 and 3 should have IncomingProposal in their inbound queues
#[test]
fn multi_node_sim_broadcast_proposal_propagates_to_all_others() {
    // Create 3 nodes with drivers
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert an IncomingVote into node 1's inbound queue
    let dummy_vote = make_dummy_vote(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: 99,
        vote: dummy_vote,
    });

    // Create drivers: node 1 will broadcast a proposal when it sees a vote
    let dummy_proposal = make_dummy_proposal(1, 0);
    let driver1 =
        TestDriver::new().with_on_vote_action(TestAction::BroadcastProposal(dummy_proposal));
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2), (3u64, net3, driver3)];
    let mut sim = MultiNodeSim::new(nodes);

    // Run one step
    sim.step_once().unwrap();

    // After step, node 1's driver should have processed 1 vote
    assert_eq!(sim.drivers.get(&1).unwrap().votes_received, 1);

    // Nodes 2 and 3 should have an IncomingProposal in their inbound queues
    assert_eq!(sim.nets.get(&2).unwrap().inbound.len(), 1);
    assert_eq!(sim.nets.get(&3).unwrap().inbound.len(), 1);

    // Verify it's a proposal from node 1
    let event2 = sim.nets.get(&2).unwrap().inbound.front().unwrap();
    match event2 {
        ConsensusNetworkEvent::IncomingProposal { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingProposal"),
    }

    let event3 = sim.nets.get(&3).unwrap().inbound.front().unwrap();
    match event3 {
        ConsensusNetworkEvent::IncomingProposal { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingProposal"),
    }

    // Node 1 should NOT have received the proposal (no self-delivery)
    assert!(sim.nets.get(&1).unwrap().inbound.is_empty());
}

/// Test multi-step simulation: messages propagate across multiple steps.
///
/// Scenario:
/// - 3 nodes with ids 1, 2, 3
/// - Node 1 broadcasts a vote initially
/// - On receiving a vote, nodes 2 and 3 broadcast votes back
/// - After 2 steps, verify the multi-hop propagation
#[test]
fn multi_node_sim_multi_step_propagation() {
    // Create 3 nodes with drivers
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert an IncomingProposal into node 1's inbound queue to trigger a vote broadcast
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
        from: 1,
        proposal: dummy_proposal,
    });

    // Create drivers:
    // - Node 1: broadcasts a vote when it sees a proposal
    // - Nodes 2 & 3: broadcast a vote when they see a vote
    let vote1 = make_dummy_vote(1, 0);
    let vote2 = make_dummy_vote(2, 0);
    let vote3 = make_dummy_vote(3, 0);

    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(vote1));
    let driver2 = TestDriver::new().with_on_vote_action(TestAction::BroadcastVote(vote2));
    let driver3 = TestDriver::new().with_on_vote_action(TestAction::BroadcastVote(vote3));

    // Create the simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2), (3u64, net3, driver3)];
    let mut sim = MultiNodeSim::new(nodes);

    // Step 1: Node 1 processes proposal, broadcasts vote to nodes 2 and 3
    sim.step_once().unwrap();

    assert_eq!(sim.drivers.get(&1).unwrap().proposals_received, 1);
    assert_eq!(sim.nets.get(&2).unwrap().inbound.len(), 1);
    assert_eq!(sim.nets.get(&3).unwrap().inbound.len(), 1);

    // Step 2: Nodes 2 and 3 process the vote and broadcast their own votes
    sim.step_once().unwrap();

    assert_eq!(sim.drivers.get(&2).unwrap().votes_received, 1);
    assert_eq!(sim.drivers.get(&3).unwrap().votes_received, 1);

    // After step 2, each node should have received votes from the other two:
    // - Node 1 should have votes from 2 and 3
    // - Node 2 should have vote from 3 (already processed vote from 1)
    // - Node 3 should have vote from 2 (already processed vote from 1)
    assert_eq!(sim.nets.get(&1).unwrap().inbound.len(), 2);
    assert_eq!(sim.nets.get(&2).unwrap().inbound.len(), 1);
    assert_eq!(sim.nets.get(&3).unwrap().inbound.len(), 1);
}