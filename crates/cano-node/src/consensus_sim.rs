//! Node-side consensus simulation harness.
//!
//! This module provides `NodeConsensusSim`, a harness that pairs a real
//! `ConsensusNode` (with TCP + KEMTLS networking) with a `ConsensusEngineDriver`.
//!
//! This is the node-side analogue of `SingleNodeSim` from `cano-consensus`,
//! but uses real networking instead of `MockConsensusNetwork`.
//!
//! # Usage
//!
//! ```ignore
//! use cano_consensus::{HotStuffDriver, HotStuffState};
//! use cano_node::{ConsensusNode, NetService, NetServiceConfig, NodeConsensusSim};
//!
//! // Create NetService and ConsensusNode
//! let net_service = NetService::new(config)?;
//! let node = ConsensusNode::new(net_service);
//!
//! // Create driver
//! let engine = HotStuffState::new_at_height(1);
//! let driver = HotStuffDriver::new(engine);
//!
//! // Create simulation harness
//! let mut sim = NodeConsensusSim::new(node, driver);
//!
//! // Run iterations
//! loop {
//!     sim.step_once()?;
//! }
//! ```

use crate::consensus_net::ConsensusNetAdapter;
use crate::consensus_node::{ConsensusNode, ConsensusNodeError, NodeCommitInfo};

use cano_consensus::driver::DrainableCommitLog;
use cano_consensus::{
    ConsensusEngineAction, ConsensusEngineDriver, ConsensusNetwork, NetworkError,
};

// ============================================================================
// NodeConsensusSimError
// ============================================================================

/// Error type for `NodeConsensusSim` operations.
///
/// This error type wraps errors from both the networking layer (ConsensusNode)
/// and the consensus network trait operations.
#[derive(Debug)]
pub enum NodeConsensusSimError {
    /// Error from the underlying ConsensusNode/NetService.
    Net(ConsensusNodeError),
    /// Error from ConsensusNetwork trait operations.
    Network(NetworkError),
}

impl From<ConsensusNodeError> for NodeConsensusSimError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeConsensusSimError::Net(e)
    }
}

impl From<NetworkError> for NodeConsensusSimError {
    fn from(e: NetworkError) -> Self {
        NodeConsensusSimError::Network(e)
    }
}

impl std::fmt::Display for NodeConsensusSimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeConsensusSimError::Net(e) => write!(f, "net error: {:?}", e),
            NodeConsensusSimError::Network(e) => write!(f, "network error: {}", e),
        }
    }
}

impl std::error::Error for NodeConsensusSimError {}

// ============================================================================
// NodeConsensusSim
// ============================================================================

/// A node-side consensus simulation harness that pairs a real `ConsensusNode`
/// with a `ConsensusEngineDriver`.
///
/// This struct mirrors `SingleNodeSim` from `cano-consensus`, but uses real
/// TCP + KEMTLS networking via `ConsensusNode` and `ConsensusNetAdapter<'_>`.
///
/// # Type Parameter
///
/// - `D`: The consensus engine driver type (e.g., `HotStuffDriver<HotStuffState>`)
#[derive(Debug)]
pub struct NodeConsensusSim<D> {
    /// The consensus node with real networking.
    pub node: ConsensusNode,
    /// The consensus engine driver.
    pub driver: D,
}

impl<D> NodeConsensusSim<D> {
    /// Create a new `NodeConsensusSim` with the given node and driver.
    pub fn new(node: ConsensusNode, driver: D) -> Self {
        NodeConsensusSim { node, driver }
    }

    /// Access the underlying driver.
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// Mutably access the underlying driver.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }
}

impl<D> NodeConsensusSim<D>
where
    for<'a> D: ConsensusEngineDriver<ConsensusNetAdapter<'a>>,
{
    /// One iteration of the node-side consensus simulation.
    ///
    /// This method:
    /// 1. Advances the network (accept, ping-sweep, prune) via `step_network()`.
    /// 2. Constructs an ephemeral `ConsensusNetAdapter<'_>` over the live `PeerManager`.
    /// 3. Non-blockingly polls for a single consensus event via `try_recv_one()`.
    /// 4. Calls `driver.step()` to process the event and produce actions.
    /// 5. Applies the returned actions back to the network.
    ///
    /// # Errors
    ///
    /// Returns `NodeConsensusSimError::Net` if network operations fail.
    /// Returns `NodeConsensusSimError::Network` if consensus network operations fail.
    pub fn step_once(&mut self) -> Result<(), NodeConsensusSimError> {
        // 1. Advance network (accept, ping-sweep, prune).
        self.node.step_network()?;

        // 2. Construct an ephemeral adapter over the *live* PeerManager.
        //    All operations are done within this block to ensure the borrow
        //    of PeerManager is properly scoped.
        let result: Result<(), NodeConsensusSimError> = {
            let peers = self.node.net_service().peers();
            let mut adapter = ConsensusNetAdapter::new(peers);

            // 2a. Non-blocking poll for one event.
            // Use the ConsensusNetwork trait method which returns NetworkError
            let maybe_event = ConsensusNetwork::try_recv_one(&mut adapter)?;

            // 2b. Ask driver to process event.
            let actions = self.driver.step(&mut adapter, maybe_event)?;

            // 2c. Apply actions back onto the same adapter.
            // Use the ConsensusNetwork trait methods which return NetworkError
            for action in actions {
                match action {
                    ConsensusEngineAction::BroadcastProposal(proposal) => {
                        ConsensusNetwork::broadcast_proposal(&mut adapter, &proposal)?;
                    }
                    ConsensusEngineAction::BroadcastVote(vote) => {
                        ConsensusNetwork::broadcast_vote(&mut adapter, &vote)?;
                    }
                    ConsensusEngineAction::SendVoteTo { to, vote } => {
                        ConsensusNetwork::send_vote_to(&mut adapter, to, &vote)?;
                    }
                    ConsensusEngineAction::Noop => {
                        // nothing to do
                    }
                }
            }

            Ok(())
        };

        result
    }
}

// ============================================================================
// Commit notification methods for NodeConsensusSim
// ============================================================================

impl<D> NodeConsensusSim<D>
where
    D: DrainableCommitLog<[u8; 32]>,
{
    /// Drain all new commits known to the underlying consensus driver,
    /// and present them as node-level commit info.
    ///
    /// This method delegates to the driver's `drain_new_commits()` and converts
    /// each `CommittedEntry` to a `NodeCommitInfo`.
    ///
    /// # Returns
    ///
    /// A vector of `NodeCommitInfo` representing all new commits since the last
    /// time this method was called. Returns an empty vector if no new commits
    /// have occurred.
    pub fn drain_commits(&mut self) -> Vec<NodeCommitInfo<[u8; 32]>> {
        self.driver
            .drain_new_commits()
            .into_iter()
            .map(NodeCommitInfo::from)
            .collect()
    }
}