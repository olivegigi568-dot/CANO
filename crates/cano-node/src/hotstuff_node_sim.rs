//! Node-level HotStuff harness for multi-node simulations over real TCP.
//!
//! This module provides `NodeHotstuffHarness`, a harness that wires together:
//! - `NetService` (TCP + KEMTLS + PeerManager)
//! - `ConsensusNode` (owns NetService + PeerValidatorMap)
//! - `BasicHotStuffEngine` + `HotStuffDriver`
//! - `NodeConsensusSim<D>`
//!
//! This is a test-oriented harness for running multi-node HotStuff simulations
//! over real TCP sockets (loopback).
//!
//! # Usage
//!
//! ```ignore
//! use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
//! use cano_node::validator_config::NodeValidatorConfig;
//!
//! let cfg = NodeValidatorConfig { /* ... */ };
//! let mut harness = NodeHotstuffHarness::new_from_validator_config(&cfg)?;
//!
//! // Run simulation steps
//! for _ in 0..100 {
//!     harness.step_once()?;
//! }
//! ```

use crate::block_store::{BlockStore, BlockStoreError};
use crate::commit_index::{CommitIndex, CommitIndexError};
use crate::consensus_net::ConsensusNetAdapter;
use crate::consensus_node::{ConsensusNode, ConsensusNodeError, NodeCommitInfo, NodeCommittedBlock};
use crate::consensus_sim::{NodeConsensusSim, NodeConsensusSimError};
use crate::net_service::{NetService, NetServiceConfig, NetServiceError};
use crate::validator_config::NodeValidatorConfig;

use cano_consensus::basic_hotstuff_engine::BasicHotStuffEngine;
use cano_consensus::driver::{ConsensusEngineAction, HotStuffDriver, ValidatorContext};
use cano_consensus::ids::ValidatorId;
use cano_consensus::network::{ConsensusNetwork, ConsensusNetworkEvent};
use cano_consensus::pacemaker::{BasicTickPacemaker, Pacemaker, PacemakerConfig};
use cano_consensus::validator_set::ConsensusValidatorSet;
use cano_net::{ClientConnectionConfig, ServerConnectionConfig};

use std::io;
use std::time::Duration;

// ============================================================================
// Error types
// ============================================================================

/// Error type for `NodeHotstuffHarness` operations.
#[derive(Debug)]
pub enum NodeHotstuffHarnessError {
    /// Error from the underlying `NodeConsensusSim`.
    Sim(NodeConsensusSimError),
    /// Error from `NetService`.
    NetService(NetServiceError),
    /// Error from `ConsensusNode`.
    ConsensusNode(ConsensusNodeError),
    /// Error from commit index operations.
    CommitIndex(CommitIndexError<[u8; 32]>),
    /// Error from block store operations.
    BlockStore(BlockStoreError),
    /// I/O error.
    Io(io::Error),
    /// Configuration or setup error.
    Config(String),
    /// A block was committed in the commit index, but no proposal was found in the block store.
    MissingProposalForCommittedBlock {
        block_id: [u8; 32],
        height: u64,
    },
}

impl From<NodeConsensusSimError> for NodeHotstuffHarnessError {
    fn from(e: NodeConsensusSimError) -> Self {
        NodeHotstuffHarnessError::Sim(e)
    }
}

impl From<NetServiceError> for NodeHotstuffHarnessError {
    fn from(e: NetServiceError) -> Self {
        NodeHotstuffHarnessError::NetService(e)
    }
}

impl From<ConsensusNodeError> for NodeHotstuffHarnessError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeHotstuffHarnessError::ConsensusNode(e)
    }
}

impl From<io::Error> for NodeHotstuffHarnessError {
    fn from(e: io::Error) -> Self {
        NodeHotstuffHarnessError::Io(e)
    }
}

impl From<CommitIndexError<[u8; 32]>> for NodeHotstuffHarnessError {
    fn from(e: CommitIndexError<[u8; 32]>) -> Self {
        NodeHotstuffHarnessError::CommitIndex(e)
    }
}

impl From<BlockStoreError> for NodeHotstuffHarnessError {
    fn from(e: BlockStoreError) -> Self {
        NodeHotstuffHarnessError::BlockStore(e)
    }
}

impl std::fmt::Display for NodeHotstuffHarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeHotstuffHarnessError::Sim(e) => write!(f, "sim error: {}", e),
            NodeHotstuffHarnessError::NetService(e) => write!(f, "net service error: {:?}", e),
            NodeHotstuffHarnessError::ConsensusNode(e) => write!(f, "consensus node error: {:?}", e),
            NodeHotstuffHarnessError::CommitIndex(e) => write!(f, "commit index error: {}", e),
            NodeHotstuffHarnessError::BlockStore(e) => write!(f, "block store error: {}", e),
            NodeHotstuffHarnessError::Io(e) => write!(f, "io error: {}", e),
            NodeHotstuffHarnessError::Config(s) => write!(f, "config error: {}", s),
            NodeHotstuffHarnessError::MissingProposalForCommittedBlock { block_id, height } => {
                write!(
                    f,
                    "missing proposal for committed block at height {}: block_id={:?}",
                    height, block_id
                )
            }
        }
    }
}

impl std::error::Error for NodeHotstuffHarnessError {}

// ============================================================================
// NodeHotstuffHarness
// ============================================================================

/// A node-level HotStuff harness for multi-node simulations over real TCP.
///
/// This struct wraps:
/// - `NodeConsensusSim<HotStuffDriver<BasicHotStuffEngine<[u8; 32]>>>` which owns
///   the `ConsensusNode` (with real TCP networking) and the consensus driver
/// - `CommitIndex<[u8; 32]>` which tracks the canonical committed chain
/// - `BlockStore` which stores locally broadcast block proposals
///
/// The harness provides a simplified interface for:
/// - Creating nodes from `NodeValidatorConfig`
/// - Running simulation steps
/// - Accessing consensus state (committed blocks, etc.)
///
/// # Note
///
/// This is a test-only harness. The actual node-level wiring for production
/// will be done in a separate module.
#[derive(Debug)]
pub struct NodeHotstuffHarness {
    /// The local validator ID for this node.
    pub validator_id: ValidatorId,
    /// The underlying simulation harness.
    pub sim: NodeConsensusSim<HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]>>,
    /// The commit index tracking the canonical committed chain.
    commit_index: CommitIndex<[u8; 32]>,
    /// Local block store for proposals broadcast by this node.
    block_store: BlockStore,
    /// Height of the last commit exposed via `drain_committed_blocks()`.
    /// `None` means no commits have been drained yet.
    last_drained_height: Option<u64>,
    /// Pacemaker controlling proposal timing.
    pacemaker: BasicTickPacemaker,
}

impl NodeHotstuffHarness {
    /// Create a new `NodeHotstuffHarness` from configuration components.
    ///
    /// This constructor takes pre-built components:
    /// - `NetServiceConfig` for TCP networking
    /// - `ConsensusValidatorSet` for the consensus engine
    /// - Local validator ID
    ///
    /// # Arguments
    ///
    /// - `local_id`: The validator ID for this node
    /// - `net_cfg`: Network service configuration
    /// - `consensus_validators`: Validator set for consensus
    /// - `id_map`: Peer-to-validator identity mapping
    ///
    /// # Returns
    ///
    /// A new `NodeHotstuffHarness` or an error if setup fails.
    pub fn new(
        local_id: ValidatorId,
        net_cfg: NetServiceConfig,
        consensus_validators: ConsensusValidatorSet,
        id_map: crate::identity_map::PeerValidatorMap,
    ) -> Result<Self, NodeHotstuffHarnessError> {
        // 1. Create NetService.
        let net_service = NetService::new(net_cfg)?;

        // 2. Build BasicHotStuffEngine.
        let engine = BasicHotStuffEngine::<[u8; 32]>::new(local_id, consensus_validators.clone());

        // 3. Build ValidatorContext from consensus_validators.
        let vctx = ValidatorContext::new(consensus_validators);

        // 4. Wrap engine in HotStuffDriver.
        let driver = HotStuffDriver::with_validators(engine, vctx);

        // 5. Build ConsensusNode with NetService and PeerValidatorMap.
        let consensus_node = ConsensusNode::with_id_map(net_service, id_map);

        // 6. Build NodeConsensusSim from node + driver.
        let sim = NodeConsensusSim::new(consensus_node, driver);

        // 7. Initialize an empty commit index.
        let commit_index = CommitIndex::new();

        // 8. Initialize an empty block store.
        let block_store = BlockStore::new();

        // 9. Initialize the pacemaker with min_ticks_between_proposals = 1.
        // This means "at most one proposal per view per step_once() call".
        let pm_cfg = PacemakerConfig {
            min_ticks_between_proposals: 1,
        };
        let pacemaker = BasicTickPacemaker::new(pm_cfg);

        Ok(NodeHotstuffHarness {
            validator_id: local_id,
            sim,
            commit_index,
            block_store,
            last_drained_height: None,
            pacemaker,
        })
    }

    /// Create a new `NodeHotstuffHarness` from a `NodeValidatorConfig`.
    ///
    /// This is a convenience constructor that builds all necessary components
    /// from a validator configuration. It uses default values for:
    /// - Ping interval: 50ms
    /// - Liveness timeout: 60s
    /// - Max peers: 100
    ///
    /// # Arguments
    ///
    /// - `cfg`: The validator configuration
    /// - `client_cfg`: Client-side KEMTLS connection config
    /// - `server_cfg`: Server-side KEMTLS connection config
    ///
    /// # Returns
    ///
    /// A new `NodeHotstuffHarness` or an error if setup fails.
    pub fn new_from_validator_config(
        cfg: &NodeValidatorConfig,
        client_cfg: ClientConnectionConfig,
        server_cfg: ServerConnectionConfig,
    ) -> Result<Self, NodeHotstuffHarnessError> {
        // 1. Build NetServiceConfig + PeerValidatorMap from NodeValidatorConfig.
        let (net_cfg, id_map) = crate::validator_config::build_net_config_and_id_map_for_tests(
            cfg,
            client_cfg,
            server_cfg,
            Duration::from_millis(50),
            Duration::from_secs(60),
            100,
        );

        // 2. Build consensus-side validator set.
        let consensus_validators = cfg.build_consensus_validator_set_for_tests();

        // 3. Create the harness with the built components.
        Self::new(cfg.local.validator_id, net_cfg, consensus_validators, id_map)
    }

    /// One iteration of the node-side consensus simulation.
    ///
    /// This method:
    /// 1. Advances the network (accept, ping-sweep, prune) via `step_network()`
    /// 2. Polls for consensus events via `try_recv_one()`
    /// 3. Processes events through the `BasicHotStuffEngine` methods
    /// 4. Tries to propose if this node is the leader and pacemaker allows
    /// 5. Applies resulting actions back to the network
    /// 6. Drains new commits and applies them to the commit index
    ///
    /// This is a HotStuff-specific step function that directly drives the
    /// `BasicHotStuffEngine` for proposal generation, vote processing, and
    /// QC formation.
    pub fn step_once(&mut self) -> Result<(), NodeHotstuffHarnessError> {
        use crate::peer::PeerId;

        // 1. Advance network (accept, ping-sweep, prune).
        self.sim.node.step_network()?;

        // 2. Process pending network events.
        // We process multiple events per step to ensure responsiveness.
        // Run all iterations to ensure we don't miss any messages.
        for _ in 0..10 {
            let peers = self.sim.node.net_service().peers();
            let mut adapter = ConsensusNetAdapter::new(peers);

            // Non-blocking poll for one event.
            let maybe_event: Option<ConsensusNetworkEvent<PeerId>> =
                ConsensusNetwork::try_recv_one(&mut adapter)
                    .map_err(|e| NodeHotstuffHarnessError::Config(format!("network error: {}", e)))?;

            if let Some(event) = maybe_event {
                // Convert PeerId to ValidatorId for the engine
                match event {
                    ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                        // Store the incoming proposal in the block store (idempotent).
                        // This ensures that followers have proposals available for
                        // committed blocks proposed by other validators.
                        self.block_store.insert(proposal.clone())?;

                        // Look up the ValidatorId for this peer
                        let from_validator = self.sim.node.get_validator_for_peer(&from)
                            .unwrap_or(ValidatorId::new(from.0));

                        // Process the proposal through the engine
                        let action = self.sim.driver.engine_mut()
                            .on_proposal_event(from_validator, &proposal);

                        // Apply any resulting action
                        if let Some(action) = action {
                            self.apply_action(action)?;
                        }
                    }
                    ConsensusNetworkEvent::IncomingVote { from, vote } => {
                        // Look up the ValidatorId for this peer
                        let from_validator = self.sim.node.get_validator_for_peer(&from)
                            .unwrap_or(ValidatorId::new(from.0));

                        // Process the vote through the engine
                        let result = self.sim.driver.engine_mut()
                            .on_vote_event(from_validator, &vote);

                        // If a QC was formed, notify the pacemaker
                        if let Ok(Some(qc)) = result {
                            self.pacemaker.on_qc(qc.view);
                        }
                    }
                }
            }
            // Continue all iterations to ensure we process all pending messages.
            // With non-blocking I/O, messages may arrive at any time.
        }

        // 3. Consult the pacemaker to decide if we should try to propose.
        // Get the current view from the engine.
        let engine_view = self.sim.driver.engine().current_view();
        let should_try = self.pacemaker.on_tick(engine_view);

        // 4. Try to propose if the pacemaker allows and we are the leader.
        // Note: try_propose() internally checks if we're the leader for the current view.
        if should_try {
            for action in self.sim.driver.engine_mut().try_propose() {
                self.apply_action(action)?;
            }
        }

        // 5. Drain new commits and apply to commit index.
        let new_commits: Vec<NodeCommitInfo<[u8; 32]>> = self.sim.drain_commits();
        if !new_commits.is_empty() {
            self.commit_index.apply_commits(new_commits)?;
        }

        Ok(())
    }

    /// Apply a consensus engine action to the network.
    ///
    /// When a `BroadcastProposal` action is received, the proposal is:
    /// 1. Stored in the local `BlockStore` for later retrieval
    /// 2. Broadcast to all connected peers
    ///
    /// This ensures that locally proposed blocks are available for:
    /// - Commit index lookups
    /// - State machine replay
    /// - Debugging and inspection
    fn apply_action(
        &mut self,
        action: ConsensusEngineAction<ValidatorId>,
    ) -> Result<(), NodeHotstuffHarnessError> {
        use crate::peer::PeerId;

        let peers = self.sim.node.net_service().peers();
        let mut adapter = ConsensusNetAdapter::new(peers);

        match action {
            ConsensusEngineAction::BroadcastProposal(proposal) => {
                // Store the proposal in our local block store before broadcasting.
                // This ensures we have a copy of all proposals we create.
                let _block_id = self.block_store.store_proposal(&proposal);

                ConsensusNetwork::broadcast_proposal(&mut adapter, &proposal)
                    .map_err(|e| NodeHotstuffHarnessError::Config(format!("broadcast proposal error: {}", e)))?;
            }
            ConsensusEngineAction::BroadcastVote(vote) => {
                ConsensusNetwork::broadcast_vote(&mut adapter, &vote)
                    .map_err(|e| NodeHotstuffHarnessError::Config(format!("broadcast vote error: {}", e)))?;
            }
            ConsensusEngineAction::SendVoteTo { to, vote } => {
                // Convert ValidatorId to PeerId
                // For now, use a simple mapping: ValidatorId(n) -> PeerId(n)
                let peer_id = PeerId(to.0);
                ConsensusNetwork::send_vote_to(&mut adapter, peer_id, &vote)
                    .map_err(|e| NodeHotstuffHarnessError::Config(format!("send vote error: {}", e)))?;
            }
            ConsensusEngineAction::Noop => {
                // Nothing to do
            }
        }

        Ok(())
    }

    /// Get the local address the node is listening on.
    ///
    /// Useful for tests that bind to port 0 and need the actual assigned port.
    ///
    /// Note: This requires mutable access because the underlying `ConsensusNode`
    /// API uses mutable references for accessing `NetService`.
    pub fn local_addr(&mut self) -> io::Result<std::net::SocketAddr> {
        self.sim.node.net_service().local_addr()
    }

    /// Get the committed block ID, if any.
    ///
    /// Returns the block ID of the most recently committed block, or `None`
    /// if no block has been committed yet.
    pub fn committed_block(&self) -> Option<&[u8; 32]> {
        self.sim.driver.engine().committed_block()
    }

    /// Get the current view of the consensus engine.
    pub fn current_view(&self) -> u64 {
        self.sim.driver.engine().current_view()
    }

    /// Check if this node is the leader for the current view.
    pub fn is_leader_for_current_view(&self) -> bool {
        self.sim.driver.engine().is_leader_for_current_view()
    }

    /// Get the number of connected peers.
    pub fn peer_count(&mut self) -> usize {
        self.sim.node.net_service().peers().len()
    }

    /// Access the underlying driver for advanced inspection.
    pub fn driver(&self) -> &HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]> {
        &self.sim.driver
    }

    /// Mutably access the underlying driver.
    pub fn driver_mut(&mut self) -> &mut HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]> {
        &mut self.sim.driver
    }

    /// Drain all new committed blocks known to this node's HotStuff driver.
    ///
    /// This method returns all commits that have occurred since the last call
    /// to `drain_commits()`, and marks them as consumed. Subsequent calls will
    /// only return commits that occurred after the previous call.
    ///
    /// # Returns
    ///
    /// A vector of `NodeCommitInfo` representing all new commits. Returns an
    /// empty vector if no new commits have occurred.
    pub fn drain_commits(&mut self) -> Vec<NodeCommitInfo<[u8; 32]>> {
        self.sim.drain_commits()
    }

    /// Returns the current committed tip from the commit index, if any.
    ///
    /// This reflects the highest committed block tracked by the node's commit index.
    pub fn commit_tip(&self) -> Option<&NodeCommitInfo<[u8; 32]>> {
        self.commit_index.tip()
    }

    /// Returns the current committed height from the commit index, if any.
    ///
    /// This is the height of the highest committed block tracked by the node.
    pub fn committed_height(&self) -> Option<u64> {
        self.commit_index.tip().map(|c| c.height)
    }

    /// Returns the number of committed blocks tracked by the commit index.
    pub fn commit_count(&self) -> usize {
        self.commit_index.len()
    }

    // ========================================================================
    // BlockStore accessors
    // ========================================================================

    /// Access the block store.
    ///
    /// Returns a reference to the local block store containing all
    /// proposals that have been broadcast by this node.
    pub fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    /// Mutably access the block store.
    ///
    /// Allows direct manipulation of the block store, such as clearing
    /// old proposals or adding proposals received from other sources.
    pub fn block_store_mut(&mut self) -> &mut BlockStore {
        &mut self.block_store
    }

    /// Get the number of proposals stored in the block store.
    ///
    /// This reflects the number of proposals that have been broadcast
    /// by this node (and stored locally).
    pub fn block_store_count(&self) -> usize {
        self.block_store.len()
    }

    /// Retrieve a stored block from the block store by its block ID.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The block ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the stored `StoredBlock`, or `None` if not found.
    pub fn get_proposal(&self, block_id: &[u8; 32]) -> Option<&crate::block_store::StoredBlock> {
        self.block_store.get(block_id)
    }

    // ========================================================================
    // Draining committed blocks
    // ========================================================================

    /// Drain newly committed blocks (height > last_drained_height) in ascending
    /// height order. Each block is returned exactly once.
    ///
    /// Returns an empty `Vec` if there are no new commits.
    ///
    /// # Errors
    ///
    /// Returns `NodeHotstuffHarnessError::MissingProposalForCommittedBlock` if a
    /// committed block's proposal is not found in the block store. This should not
    /// happen in normal operation.
    pub fn drain_committed_blocks(&mut self) -> Result<Vec<NodeCommittedBlock<[u8; 32]>>, NodeHotstuffHarnessError> {
        let mut result = Vec::new();
        let last = self.last_drained_height;

        let mut max_seen = last;

        for (height, info) in self.commit_index.iter_by_height() {
            // Skip heights that have already been drained
            if let Some(last_h) = last {
                if *height <= last_h {
                    continue;
                }
            }

            let block_id = info.block_id;
            let stored = self
                .block_store
                .get(&block_id)
                .ok_or(NodeHotstuffHarnessError::MissingProposalForCommittedBlock {
                    block_id,
                    height: *height,
                })?;

            // Clone the Arc handle only, not the full proposal
            let proposal_arc = stored.proposal.clone();

            let committed = NodeCommittedBlock {
                block_id,
                view: info.view,
                height: info.height,
                proposal: proposal_arc,
            };
            result.push(committed);

            max_seen = Some(max_seen.map_or(*height, |curr| curr.max(*height)));
        }

        // Update the drain cursor
        if let Some(max_h) = max_seen {
            self.last_drained_height = Some(max_h);
        }

        Ok(result)
    }

    // ========================================================================
    // Pruning
    // ========================================================================

    /// Prune internal commit index and block store below the given height.
    ///
    /// Safe to call after the ledger has applied all commits up to at least `min_height`.
    pub fn prune_below_height(&mut self, min_height: u64) {
        self.commit_index.prune_below(min_height);
        self.block_store.prune_below(min_height);
    }
}