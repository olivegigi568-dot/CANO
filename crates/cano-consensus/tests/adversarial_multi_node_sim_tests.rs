//! Integration tests for the adversarial multi-node simulation harness.
//!
//! These tests verify that `AdversarialMultiNodeSim` correctly applies fault injection:
//! - Partition-based message dropping
//! - Probability-based message dropping
//! - Message duplication

use cano_consensus::{
    AdversarialMultiNodeSim, ConsensusEngineAction, ConsensusEngineDriver, ConsensusNetworkEvent,
    MockConsensusNetwork, MultiNodeSim, NetworkError, PartitionConfig,
};
use cano_wire::consensus::{BlockHeader, BlockProposal, Vote};
use rand::rngs::StdRng;
use rand::SeedableRng;

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
        signature: vec![],
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
#[allow(dead_code)]
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

    #[allow(dead_code)]
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

/// Test that partitions block messages from specific source to specific destination.
///
/// Scenario:
/// - 3 nodes: 1, 2, 3
/// - Node 1 receives a proposal and broadcasts a vote
/// - Partition blocks messages from node 1 to node 2
/// - After step_once(), node 3 should receive the vote, node 2 should NOT
#[test]
fn adversarial_sim_respects_partitions() {
    let mut rng = StdRng::seed_from_u64(42);

    // Create 3 nodes
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert a proposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 1,
            proposal: dummy_proposal,
        });

    // Create drivers: node 1 broadcasts a vote when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(dummy_vote));
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the base simulation
    let nodes = vec![
        (1u64, net1, driver1),
        (2u64, net2, driver2),
        (3u64, net3, driver3),
    ];
    let inner_sim = MultiNodeSim::new(nodes);

    // Wrap with adversarial harness
    let mut sim = AdversarialMultiNodeSim::new(inner_sim);

    // Set drop and dup probabilities to 0 for deterministic behavior
    sim.set_drop_prob(0.0);
    sim.set_dup_prob(0.0);

    // Block messages from node 1 to node 2
    sim.partitions_mut().block(1, 2);

    // Run one step
    sim.step_once(&mut rng).unwrap();

    // After step, node 1's driver should have processed 1 proposal
    assert_eq!(sim.inner().drivers.get(&1).unwrap().proposals_received, 1);

    // Node 3 should have received the vote (not partitioned)
    assert_eq!(sim.inner().nets.get(&3).unwrap().inbound.len(), 1);
    let event3 = sim.inner().nets.get(&3).unwrap().inbound.front().unwrap();
    match event3 {
        ConsensusNetworkEvent::IncomingVote { from, .. } => {
            assert_eq!(*from, 1);
        }
        _ => panic!("Expected IncomingVote"),
    }

    // Node 2 should NOT have received the vote (partitioned)
    assert!(
        sim.inner().nets.get(&2).unwrap().inbound.is_empty(),
        "Node 2 should not receive messages from node 1 due to partition"
    );

    // Node 1 should NOT have received the vote (no self-delivery)
    assert!(sim.inner().nets.get(&1).unwrap().inbound.is_empty());
}

/// Test that drop_prob = 1.0 drops all messages.
///
/// Scenario:
/// - 2 nodes: 1, 2
/// - Node 1 receives a proposal and broadcasts a vote
/// - drop_prob = 1.0
/// - After step_once(), node 2 should NOT receive any messages
#[test]
fn adversarial_sim_drops_messages_with_probability_one() {
    let mut rng = StdRng::seed_from_u64(42);

    // Create 2 nodes
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert a proposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 1,
            proposal: dummy_proposal,
        });

    // Create drivers: node 1 broadcasts a vote when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(dummy_vote));
    let driver2 = TestDriver::new();

    // Create the base simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2)];
    let inner_sim = MultiNodeSim::new(nodes);

    // Wrap with adversarial harness
    let mut sim = AdversarialMultiNodeSim::new(inner_sim);

    // Set drop probability to 1.0 (drop everything)
    sim.set_drop_prob(1.0);
    sim.set_dup_prob(0.0);

    // Run a few steps
    for _ in 0..5 {
        sim.step_once(&mut rng).unwrap();
    }

    // Node 1's driver should have processed 1 proposal
    assert_eq!(sim.inner().drivers.get(&1).unwrap().proposals_received, 1);

    // Node 2 should NOT have received any messages (all dropped)
    assert!(
        sim.inner().nets.get(&2).unwrap().inbound.is_empty(),
        "Node 2 should not receive any messages when drop_prob = 1.0"
    );

    // Node 2's driver should have processed 0 votes
    assert_eq!(sim.inner().drivers.get(&2).unwrap().votes_received, 0);
}

/// Test that dup_prob = 1.0 duplicates all messages.
///
/// Scenario:
/// - 2 nodes: 1, 2
/// - Node 1 receives a proposal and broadcasts a vote
/// - dup_prob = 1.0
/// - After step_once(), node 2 should receive at least 2 copies of the vote
#[test]
fn adversarial_sim_duplicates_messages_with_probability_one() {
    let mut rng = StdRng::seed_from_u64(42);

    // Create 2 nodes
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert a proposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 1,
            proposal: dummy_proposal,
        });

    // Create drivers: node 1 broadcasts a vote when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(dummy_vote));
    let driver2 = TestDriver::new();

    // Create the base simulation
    let nodes = vec![(1u64, net1, driver1), (2u64, net2, driver2)];
    let inner_sim = MultiNodeSim::new(nodes);

    // Wrap with adversarial harness
    let mut sim = AdversarialMultiNodeSim::new(inner_sim);

    // Set drop probability to 0.0, dup probability to 1.0 (duplicate everything)
    sim.set_drop_prob(0.0);
    sim.set_dup_prob(1.0);

    // Run one step
    sim.step_once(&mut rng).unwrap();

    // Node 1's driver should have processed 1 proposal
    assert_eq!(sim.inner().drivers.get(&1).unwrap().proposals_received, 1);

    // Node 2 should have received at least 2 copies of the vote (original + duplicate)
    assert!(
        sim.inner().nets.get(&2).unwrap().inbound.len() >= 2,
        "Node 2 should receive at least 2 copies of the vote when dup_prob = 1.0, got {}",
        sim.inner().nets.get(&2).unwrap().inbound.len()
    );

    // Both messages should be IncomingVote from node 1
    for event in sim.inner().nets.get(&2).unwrap().inbound.iter() {
        match event {
            ConsensusNetworkEvent::IncomingVote { from, .. } => {
                assert_eq!(*from, 1);
            }
            _ => panic!("Expected IncomingVote"),
        }
    }
}

/// Test that partition config methods work correctly.
#[test]
fn partition_config_methods() {
    let mut config: PartitionConfig<u64> = PartitionConfig::default();

    // Initially empty
    assert!(!config.is_blocked(1, 2));
    assert!(!config.is_blocked(2, 1));

    // Block 1 -> 2
    config.block(1, 2);
    assert!(config.is_blocked(1, 2));
    assert!(!config.is_blocked(2, 1)); // Direction matters

    // Block 2 -> 1 as well
    config.block(2, 1);
    assert!(config.is_blocked(1, 2));
    assert!(config.is_blocked(2, 1));

    // Unblock 1 -> 2
    config.unblock(1, 2);
    assert!(!config.is_blocked(1, 2));
    assert!(config.is_blocked(2, 1)); // 2 -> 1 still blocked
}

/// Test that no faults (drop_prob=0, dup_prob=0, no partitions) behaves like normal MultiNodeSim.
#[test]
fn adversarial_sim_no_faults_behaves_like_normal() {
    let mut rng = StdRng::seed_from_u64(42);

    // Create 3 nodes
    let mut net1: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<u64> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<u64> = MockConsensusNetwork::new();

    // Insert a proposal into node 1's inbound queue
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound
        .push_back(ConsensusNetworkEvent::IncomingProposal {
            from: 1,
            proposal: dummy_proposal,
        });

    // Create drivers: node 1 broadcasts a vote when it sees a proposal
    let dummy_vote = make_dummy_vote(1, 0);
    let driver1 = TestDriver::new().with_on_proposal_action(TestAction::BroadcastVote(dummy_vote));
    let driver2 = TestDriver::new();
    let driver3 = TestDriver::new();

    // Create the base simulation
    let nodes = vec![
        (1u64, net1, driver1),
        (2u64, net2, driver2),
        (3u64, net3, driver3),
    ];
    let inner_sim = MultiNodeSim::new(nodes);

    // Wrap with adversarial harness with no faults
    let mut sim = AdversarialMultiNodeSim::new(inner_sim);
    sim.set_drop_prob(0.0);
    sim.set_dup_prob(0.0);
    // No partitions

    // Run one step
    sim.step_once(&mut rng).unwrap();

    // Node 1 processed the proposal
    assert_eq!(sim.inner().drivers.get(&1).unwrap().proposals_received, 1);

    // Both nodes 2 and 3 should have received exactly 1 vote each
    assert_eq!(sim.inner().nets.get(&2).unwrap().inbound.len(), 1);
    assert_eq!(sim.inner().nets.get(&3).unwrap().inbound.len(), 1);

    // Node 1 should NOT have received the vote (no self-delivery)
    assert!(sim.inner().nets.get(&1).unwrap().inbound.is_empty());
}