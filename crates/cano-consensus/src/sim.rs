//! Single-node consensus simulation harness.
//!
//! This module provides a minimal harness for testing and simulating
//! a single consensus node using `MockConsensusNetwork` and a driver
//! that implements `ConsensusEngineDriver`.
//!
//! # Usage
//!
//! ```ignore
//! use cano_consensus::{MockConsensusNetwork, HotStuffDriver, HotStuffState, SingleNodeSim};
//!
//! let net = MockConsensusNetwork::<u64>::new();
//! let driver = HotStuffDriver::new(HotStuffState::new_at_height(1));
//! let mut sim = SingleNodeSim::new(net, driver);
//!
//! // Run a single iteration
//! sim.step_once().unwrap();
//! ```

use crate::driver::{ConsensusEngineAction, ConsensusEngineDriver};
use crate::network::{ConsensusNetwork, MockConsensusNetwork, NetworkError};

/// A single-node simulation harness that pairs a `MockConsensusNetwork`
/// with a consensus engine driver.
///
/// This struct holds:
/// - A `MockConsensusNetwork<Id>` – our "fake network"
/// - A `D` implementing `ConsensusEngineDriver<MockConsensusNetwork<Id>>` – our driver
///
/// It provides a `step_once()` method to drive a single iteration of the
/// node loop, demonstrating that "events in → driver → actions → network"
/// is coherent and testable.
#[derive(Debug)]
pub struct SingleNodeSim<Id, D>
where
    Id: Clone,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    /// The mock consensus network.
    pub net: MockConsensusNetwork<Id>,
    /// The consensus engine driver.
    pub driver: D,
}

impl<Id, D> SingleNodeSim<Id, D>
where
    Id: Clone,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    /// Create a new `SingleNodeSim` with the given network and driver.
    pub fn new(net: MockConsensusNetwork<Id>, driver: D) -> Self {
        SingleNodeSim { net, driver }
    }

    /// One iteration of the single-node simulation:
    /// - Poll the network for a single event (non-blocking).
    /// - Ask the driver to process that event and produce actions.
    /// - Apply those actions back to the network.
    pub fn step_once(&mut self) -> Result<(), NetworkError> {
        // 1. Non-blocking poll
        let maybe_event = self.net.try_recv_one()?;

        // 2. Let the driver process the event
        let actions = self.driver.step(&mut self.net, maybe_event)?;

        // 3. Apply actions back to the network
        for action in actions {
            match action {
                ConsensusEngineAction::BroadcastProposal(proposal) => {
                    self.net.broadcast_proposal(&proposal)?;
                }
                ConsensusEngineAction::BroadcastVote(vote) => {
                    self.net.broadcast_vote(&vote)?;
                }
                ConsensusEngineAction::SendVoteTo { to, vote } => {
                    self.net.send_vote_to(to, &vote)?;
                }
                ConsensusEngineAction::Noop => {
                    // nothing to do
                }
            }
        }

        Ok(())
    }
}