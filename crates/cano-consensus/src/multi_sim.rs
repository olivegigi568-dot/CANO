//! Multi-node consensus simulation harness.
//!
//! This module provides a minimal harness for testing and simulating
//! multiple consensus nodes using `MockConsensusNetwork` and drivers
//! that implement `ConsensusEngineDriver`.
//!
//! # Usage
//!
//! ```no_run
//! use cano_consensus::{MockConsensusNetwork, HotStuffDriver, HotStuffState, MultiNodeSim};
//!
//! // Create nodes
//! let nodes = vec![
//!     (1u64, MockConsensusNetwork::new(), HotStuffDriver::new(HotStuffState::new_at_height(1))),
//!     (2u64, MockConsensusNetwork::new(), HotStuffDriver::new(HotStuffState::new_at_height(1))),
//!     (3u64, MockConsensusNetwork::new(), HotStuffDriver::new(HotStuffState::new_at_height(1))),
//! ];
//! let mut sim = MultiNodeSim::new(nodes);
//!
//! // Run a single iteration
//! sim.step_once().unwrap();
//! ```

use std::collections::HashMap;

use crate::driver::{ConsensusEngineAction, ConsensusEngineDriver};
use crate::network::{ConsensusNetwork, ConsensusNetworkEvent, MockConsensusNetwork, NetworkError};

/// A multi-node simulation harness that pairs multiple `MockConsensusNetwork`s
/// with their respective consensus engine drivers.
///
/// This struct holds:
/// - A map from node ID to `MockConsensusNetwork<Id>` – each node's "fake network"
/// - A map from node ID to driver `D` – each node's consensus engine driver
///
/// It provides a `step_once()` method to drive a single iteration of all nodes,
/// routing broadcast and send actions to the appropriate destination networks.
#[derive(Debug)]
pub struct MultiNodeSim<Id, D>
where
    Id: Copy + Eq + std::hash::Hash,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    /// Map from node id to its mock network.
    pub nets: HashMap<Id, MockConsensusNetwork<Id>>,

    /// Map from node id to its driver.
    pub drivers: HashMap<Id, D>,
}

impl<Id, D> MultiNodeSim<Id, D>
where
    Id: Copy + Eq + std::hash::Hash,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    /// Create a new `MultiNodeSim` with the given nodes.
    ///
    /// Each node is a tuple of (node ID, mock network, driver).
    pub fn new<I>(nodes: I) -> Self
    where
        I: IntoIterator<Item = (Id, MockConsensusNetwork<Id>, D)>,
    {
        let mut nets = HashMap::new();
        let mut drivers = HashMap::new();

        for (id, net, driver) in nodes {
            nets.insert(id, net);
            drivers.insert(id, driver);
        }

        MultiNodeSim { nets, drivers }
    }

    /// One multi-node step:
    /// - For each node:
    ///   - Non-blocking poll its local network for one event
    ///   - Call driver.step(...)
    /// - Route generated actions to target nodes' networks.
    pub fn step_once(&mut self) -> Result<(), NetworkError> {
        // 1. Collect events and actions for each node.
        // We'll store actions by source node Id so we can route them in phase 2.
        let mut all_actions: Vec<(Id, Vec<ConsensusEngineAction<Id>>)> = Vec::new();

        // We need node ids in a Vec to avoid borrow checker issues.
        let node_ids: Vec<Id> = self.nets.keys().copied().collect();

        for node_id in node_ids {
            let net = self
                .nets
                .get_mut(&node_id)
                .expect("network missing for node");
            let driver = self
                .drivers
                .get_mut(&node_id)
                .expect("driver missing for node");

            // Non-blocking poll local network.
            let maybe_event = net.try_recv_one()?;

            // Let the driver process it.
            let actions = driver.step(net, maybe_event)?;
            all_actions.push((node_id, actions));
        }

        // 2. Deliver actions to networks.
        for (from_id, actions) in all_actions {
            for action in actions {
                match action {
                    ConsensusEngineAction::BroadcastProposal(proposal) => {
                        for (&to_id, net) in self.nets.iter_mut() {
                            if to_id == from_id {
                                continue;
                            }
                            net.inbound.push_back(ConsensusNetworkEvent::IncomingProposal {
                                from: from_id,
                                proposal: proposal.clone(),
                            });
                        }
                    }
                    ConsensusEngineAction::BroadcastVote(vote) => {
                        for (&to_id, net) in self.nets.iter_mut() {
                            if to_id == from_id {
                                continue;
                            }
                            net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
                                from: from_id,
                                vote: vote.clone(),
                            });
                        }
                    }
                    ConsensusEngineAction::SendVoteTo { to, vote } => {
                        if let Some(net) = self.nets.get_mut(&to) {
                            net.inbound.push_back(ConsensusNetworkEvent::IncomingVote {
                                from: from_id,
                                vote,
                            });
                        }
                        // if target doesn't exist, silently drop for now (or log later).
                    }
                    ConsensusEngineAction::Noop => {
                        // nothing to deliver
                    }
                }
            }
        }

        Ok(())
    }
}