//! Integration tests for the multi-node simulation harness.
//!
//! These tests verify that `MultiNodeSim` correctly wires multiple nodes together:
//! - Broadcasts and sends are delivered to the appropriate other nodes' inbound queues.
//! - No real network or cano-node is used.
//!
//! Additionally, T49 identity consistency tests verify that:
//! - The network-level `from` field matches the consensus-level validator identity
//! - When using `ValidatorId` as the network Id type, identity is consistently tracked

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

// ============================================================================
// Identity Consistency Tests (T49)
// ============================================================================

/// Test that when using ValidatorId as the network Id type, the `from` field
/// in ConsensusNetworkEvent matches the node's own ValidatorId for honest nodes.
///
/// Scenario:
/// - 3 nodes with ValidatorId(1), ValidatorId(2), ValidatorId(3)
/// - Node 1 receives a proposal and broadcasts a vote
/// - Verify the vote's embedded from matches the node's ValidatorId
#[test]
fn multi_node_sim_validator_ids_match_network_ids() {
    use cano_consensus::ValidatorId;

    // Create 3 nodes with ValidatorId as the network Id type
    let mut net1: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    let val1 = ValidatorId::new(1);
    let val2 = ValidatorId::new(2);
    let val3 = ValidatorId::new(3);

    // Insert an IncomingProposal into node 1's inbound queue
    // For honest nodes, the `from` should match the actual sender's ValidatorId
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
        from: val2, // Proposal from validator 2
        proposal: dummy_proposal.clone(),
    });

    // Create a driver for ValidatorId
    let driver1 = ValidatorIdTestDriver::new(val1);
    let driver2 = ValidatorIdTestDriver::new(val2);
    let driver3 = ValidatorIdTestDriver::new(val3);

    // Create the simulation with ValidatorId as the Id type
    let nodes = vec![
        (val1, net1, driver1),
        (val2, net2, driver2),
        (val3, net3, driver3),
    ];
    let mut sim = MultiNodeSim::new(nodes);

    // Run one step
    sim.step_once().unwrap();

    // After step, node 1's driver should have processed 1 proposal
    assert_eq!(sim.drivers.get(&val1).unwrap().proposals_received, 1);

    // Nodes 2 and 3 should have received the vote from node 1
    assert_eq!(sim.nets.get(&val2).unwrap().inbound.len(), 1);
    assert_eq!(sim.nets.get(&val3).unwrap().inbound.len(), 1);

    // Verify the vote came from node 1 (ValidatorId(1))
    let event2 = sim.nets.get(&val2).unwrap().inbound.front().unwrap();
    match event2 {
        ConsensusNetworkEvent::IncomingVote { from, vote } => {
            // The `from` field should be ValidatorId(1) - the sender
            assert_eq!(*from, val1, "vote 'from' should match sender's ValidatorId");
            // The vote's validator_index is a u16 in the wire format,
            // but we can verify it was set to match the sender's id (at least conceptually)
            // For this test, we configured the driver to emit votes with matching index
            assert_eq!(
                vote.validator_index as u64,
                val1.as_u64(),
                "vote.validator_index should match the ValidatorId"
            );
        }
        _ => panic!("Expected IncomingVote"),
    }

    let event3 = sim.nets.get(&val3).unwrap().inbound.front().unwrap();
    match event3 {
        ConsensusNetworkEvent::IncomingVote { from, vote } => {
            assert_eq!(*from, val1, "vote 'from' should match sender's ValidatorId");
            assert_eq!(
                vote.validator_index as u64,
                val1.as_u64(),
                "vote.validator_index should match the ValidatorId"
            );
        }
        _ => panic!("Expected IncomingVote"),
    }
}

/// Test that ConsensusEngineAction::BroadcastVote produced by a driver
/// results in votes where the validator_index matches the node's own ValidatorId.
#[test]
fn multi_node_sim_broadcast_vote_validator_index_matches_sender_id() {
    use cano_consensus::ValidatorId;

    let mut net1: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    let val1 = ValidatorId::new(42);
    let val2 = ValidatorId::new(99);

    // Insert a proposal to trigger node 1 to broadcast a vote
    let dummy_proposal = make_dummy_proposal(1, 0);
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
        from: val2,
        proposal: dummy_proposal,
    });

    // Create drivers that emit votes with validator_index matching their own ValidatorId
    let driver1 = ValidatorIdTestDriver::new(val1);
    let driver2 = ValidatorIdTestDriver::new(val2);

    let nodes = vec![(val1, net1, driver1), (val2, net2, driver2)];
    let mut sim = MultiNodeSim::new(nodes);

    sim.step_once().unwrap();

    // Node 2 should have received a vote from node 1
    assert_eq!(sim.nets.get(&val2).unwrap().inbound.len(), 1);

    let event = sim.nets.get(&val2).unwrap().inbound.front().unwrap();
    if let ConsensusNetworkEvent::IncomingVote { from, vote } = event {
        assert_eq!(*from, val1);
        assert_eq!(
            vote.validator_index as u64,
            val1.as_u64(),
            "validator_index should equal the sender's ValidatorId"
        );
    } else {
        panic!("Expected IncomingVote");
    }
}

/// Test that IncomingVote events maintain identity consistency:
/// when we enqueue a vote with a specific `from` and `vote.validator_index`,
/// they should match for honest nodes.
#[test]
fn multi_node_sim_incoming_vote_identity_consistency() {
    use cano_consensus::ValidatorId;

    let mut net1: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    let val1 = ValidatorId::new(1);
    let val2 = ValidatorId::new(2);

    // Create a vote where validator_index matches the sender's id
    let mut vote = make_dummy_vote(1, 0);
    vote.validator_index = val2.as_u64() as u16; // Vote from validator 2

    // Enqueue with matching from
    net1.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: val2,
        vote: vote.clone(),
    });

    let driver1 = ValidatorIdTestDriver::new(val1);

    let nodes = vec![(val1, net1, driver1)];
    let mut sim = MultiNodeSim::new(nodes);

    // The simulation receives the event
    sim.step_once().unwrap();

    // Verify the driver received exactly 1 vote
    assert_eq!(sim.drivers.get(&val1).unwrap().votes_received, 1);

    // Verify the last received vote had matching from and validator_index
    let last_from = sim.drivers.get(&val1).unwrap().last_vote_from;
    let last_index = sim.drivers.get(&val1).unwrap().last_vote_validator_index;

    assert_eq!(last_from, Some(val2), "last_vote_from should be val2");
    assert_eq!(
        last_index,
        Some(val2.as_u64() as u16),
        "last_vote_validator_index should equal val2's id"
    );

    // The key invariant: from.as_u64() == vote.validator_index for honest nodes
    assert_eq!(
        last_from.unwrap().as_u64(),
        last_index.unwrap() as u64,
        "from and validator_index should match for honest nodes"
    );
}

// ============================================================================
// ValidatorIdTestDriver - A driver that works with ValidatorId
// ============================================================================

/// A test driver that uses `ValidatorId` as the network Id type.
/// It broadcasts votes with `validator_index` set to match its own `ValidatorId`.
#[derive(Debug, Default)]
struct ValidatorIdTestDriver {
    /// This driver's own ValidatorId
    own_id: cano_consensus::ValidatorId,
    /// Number of votes received
    votes_received: u64,
    /// Number of proposals received
    proposals_received: u64,
    /// Last vote's `from` field
    last_vote_from: Option<cano_consensus::ValidatorId>,
    /// Last vote's `validator_index` field
    last_vote_validator_index: Option<u16>,
}

impl ValidatorIdTestDriver {
    fn new(own_id: cano_consensus::ValidatorId) -> Self {
        ValidatorIdTestDriver {
            own_id,
            votes_received: 0,
            proposals_received: 0,
            last_vote_from: None,
            last_vote_validator_index: None,
        }
    }
}

impl ConsensusEngineDriver<MockConsensusNetwork<cano_consensus::ValidatorId>>
    for ValidatorIdTestDriver
{
    fn step(
        &mut self,
        _net: &mut MockConsensusNetwork<cano_consensus::ValidatorId>,
        maybe_event: Option<ConsensusNetworkEvent<cano_consensus::ValidatorId>>,
    ) -> Result<Vec<ConsensusEngineAction<cano_consensus::ValidatorId>>, NetworkError> {
        let mut actions = Vec::new();

        if let Some(event) = maybe_event {
            match event {
                ConsensusNetworkEvent::IncomingVote { from, vote } => {
                    self.votes_received += 1;
                    self.last_vote_from = Some(from);
                    self.last_vote_validator_index = Some(vote.validator_index);
                    actions.push(ConsensusEngineAction::Noop);
                }
                ConsensusNetworkEvent::IncomingProposal { .. } => {
                    self.proposals_received += 1;
                    // Create a vote with validator_index matching our own ValidatorId
                    let vote = Vote {
                        version: 1,
                        chain_id: 1,
                        height: 1,
                        round: 0,
                        step: 0,
                        block_id: [0u8; 32],
                        validator_index: self.own_id.as_u64() as u16,
                        reserved: 0,
                        signature: vec![],
                    };
                    actions.push(ConsensusEngineAction::BroadcastVote(vote));
                }
            }
        }

        Ok(actions)
    }
}

// ============================================================================
// Validator Set Enforcement Tests (T51)
// ============================================================================

/// Test that MultiNodeSim with ValidatorContext rejects votes from non-member nodes.
///
/// Scenario:
/// - Build a ConsensusValidatorSet with nodes 1, 2, 3.
/// - Add a 4th node with id 999 as a "byzantine" node that sends votes,
///   but do not include it in the validator set used by the drivers.
/// - Run MultiNodeSim for a few steps with that byzantine node broadcasting votes.
/// - Assert that honest nodes' drivers do not count those votes as valid.
#[test]
fn multi_node_sim_ignores_votes_from_non_members() {
    use cano_consensus::{
        ConsensusNetworkEvent,
        ConsensusValidatorSet, HotStuffDriver, HotStuffState, MockConsensusNetwork,
        MultiNodeSim, ValidatorContext, ValidatorId, ValidatorSetEntry,
    };

    // Create a validator set with nodes 1, 2, 3 (NOT 999)
    let validators = vec![
        ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
        ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
        ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
    ];
    let validator_set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Create networks and drivers for honest nodes (1, 2, 3)
    let net1: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net2: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    let ctx1 = ValidatorContext::new(validator_set.clone());
    let ctx2 = ValidatorContext::new(validator_set.clone());
    let ctx3 = ValidatorContext::new(validator_set.clone());

    let driver1: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx1);
    let driver2: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx2);
    let driver3: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx3);

    // Create the simulation with honest nodes
    let nodes = vec![
        (ValidatorId::new(1), net1, driver1),
        (ValidatorId::new(2), net2, driver2),
        (ValidatorId::new(3), net3, driver3),
    ];
    let mut sim = MultiNodeSim::new(nodes);

    // Manually inject a vote from the byzantine node (999) into each honest node's inbound queue
    let byzantine_vote = Vote {
        version: 1,
        chain_id: 1,
        height: 1,
        round: 0,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 999, // Byzantine validator
        reserved: 0,
        signature: vec![],
    };

    // Inject byzantine votes into all honest nodes' networks
    for (_, net) in sim.nets.iter_mut() {
        net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
            from: ValidatorId::new(999), // Byzantine node
            vote: byzantine_vote.clone(),
        });
    }

    // Run a step to process the byzantine votes
    sim.step_once().unwrap();

    // Assert that honest nodes did not count the byzantine votes as valid
    for (id, driver) in sim.drivers.iter() {
        assert_eq!(
            driver.votes_received(),
            0,
            "Node {:?} should not accept votes from non-member 999",
            id
        );
        assert_eq!(
            driver.rejected_votes(),
            1,
            "Node {:?} should reject votes from non-member 999",
            id
        );
    }
}

/// Test that MultiNodeSim with ValidatorContext accepts votes from member nodes.
#[test]
fn multi_node_sim_accepts_votes_from_members() {
    use cano_consensus::{
        ConsensusNetworkEvent, ConsensusValidatorSet, HotStuffDriver, HotStuffState,
        MockConsensusNetwork, MultiNodeSim, ValidatorContext, ValidatorId, ValidatorSetEntry,
    };

    // Create a validator set with nodes 1, 2, 3
    let validators = vec![
        ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
        ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
        ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
    ];
    let validator_set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Create networks and drivers for honest nodes (1, 2, 3)
    let net1: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let mut net2: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let net3: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    let ctx1 = ValidatorContext::new(validator_set.clone());
    let ctx2 = ValidatorContext::new(validator_set.clone());
    let ctx3 = ValidatorContext::new(validator_set.clone());

    let driver1: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx1);
    let driver2: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx2);
    let driver3: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::with_validators(HotStuffState::new_at_height(1), ctx3);

    // Inject a vote from a valid member (node 1) into node 2's inbound queue
    let valid_vote = Vote {
        version: 1,
        chain_id: 1,
        height: 1,
        round: 0,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 1,
        reserved: 0,
        signature: vec![],
    };
    net2.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(1), // Valid member
        vote: valid_vote,
    });

    // Create the simulation with honest nodes
    let nodes = vec![
        (ValidatorId::new(1), net1, driver1),
        (ValidatorId::new(2), net2, driver2),
        (ValidatorId::new(3), net3, driver3),
    ];
    let mut sim = MultiNodeSim::new(nodes);

    // Run a step to process the vote
    sim.step_once().unwrap();

    // Assert that node 2 accepted the vote from node 1
    let driver2 = sim.drivers.get(&ValidatorId::new(2)).unwrap();
    assert_eq!(
        driver2.votes_received(),
        1,
        "Node 2 should accept votes from member node 1"
    );
    assert_eq!(
        driver2.rejected_votes(),
        0,
        "Node 2 should not reject votes from member node 1"
    );
}