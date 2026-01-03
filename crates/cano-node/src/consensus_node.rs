//! Consensus node integration for the cano post-quantum blockchain.
//!
//! This module provides `ConsensusNode`, a thin wrapper that owns `NetService`
//! and creates ephemeral `ConsensusNetAdapter` views over its `PeerManager`
//! whenever needed.
//!
//! # Design
//!
//! `ConsensusNode` owns only `NetService`. The `with_consensus_network` method
//! creates a temporary, borrowing `ConsensusNetAdapter<'_>` inside the method.
//! This guarantees that `NetService` and the adapter always see the same
//! `PeerManager` instance—no cloning, no `Arc`.
//!
//! We are not yet embedding the real consensus engine here; this is a
//! networking + trait glue skeleton.
//!
//! # Identity Mapping
//!
//! `ConsensusNode` also holds a `PeerValidatorMap` that tracks the relationship
//! between transport-level `PeerId`s and consensus-level `ValidatorId`s.
//! This mapping is not yet enforced at runtime, but provides a place for future
//! tasks to add cryptographic verification.

use crate::consensus_net::ConsensusNetAdapter;
use crate::identity_map::PeerValidatorMap;
use crate::net_service::{NetService, NetServiceError};
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;

use cano_consensus::hotstuff_state_engine::CommittedEntry;
use cano_consensus::{ConsensusNetwork, ConsensusNetworkEvent, NetworkError, ValidatorId};
use cano_wire::consensus::BlockProposal;

// ============================================================================
// NodeCommitInfo
// ============================================================================

/// Minimal node-level view of a committed consensus block.
///
/// This struct provides a thin wrapper around the consensus `CommittedEntry`,
/// exposing commit information to callers at the node level.
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. The canonical type is `[u8; 32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCommitInfo<BlockIdT> {
    /// The block identifier that was committed.
    pub block_id: BlockIdT,
    /// The view at which the block was proposed.
    pub view: u64,
    /// The height of the block in the chain from genesis.
    pub height: u64,
}

impl<BlockIdT: Clone> From<CommittedEntry<BlockIdT>> for NodeCommitInfo<BlockIdT> {
    fn from(entry: CommittedEntry<BlockIdT>) -> Self {
        NodeCommitInfo {
            block_id: entry.block_id,
            view: entry.view,
            height: entry.height,
        }
    }
}

// ============================================================================
// NodeCommittedBlock
// ============================================================================

/// A committed block record that pairs commit metadata with the corresponding proposal.
///
/// This struct provides a node-friendly view of a committed block, combining:
/// - Commit metadata from `NodeCommitInfo` (block_id, view, height)
/// - The corresponding `BlockProposal` from the block store
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. The canonical type is `[u8; 32]`.
#[derive(Clone, Debug)]
pub struct NodeCommittedBlock<BlockIdT> {
    /// The block identifier that was committed.
    pub block_id: BlockIdT,
    /// The view at which the block was proposed.
    pub view: u64,
    /// The height of the block in the chain from genesis.
    pub height: u64,
    /// The block proposal associated with this committed block.
    pub proposal: BlockProposal,
}

// ============================================================================
// ConsensusNodeError
// ============================================================================

/// Error type for `ConsensusNode` operations.
#[derive(Debug)]
pub enum ConsensusNodeError {
    /// Error from the underlying NetService.
    Net(NetServiceError),
    /// Error from the ConsensusNetwork trait operations.
    ConsensusNetwork(NetworkError),
}

impl From<NetServiceError> for ConsensusNodeError {
    fn from(e: NetServiceError) -> Self {
        ConsensusNodeError::Net(e)
    }
}

impl From<NetworkError> for ConsensusNodeError {
    fn from(e: NetworkError) -> Self {
        ConsensusNodeError::ConsensusNetwork(e)
    }
}

// ============================================================================
// ConsensusNode
// ============================================================================

/// A consensus node that owns a `NetService` and provides ephemeral
/// `ConsensusNetwork` views over its `PeerManager`.
///
/// This struct does NOT handle the full consensus engine logic yet.
/// It only provides a networking + trait glue skeleton.
///
/// The `id_map` field holds a `PeerValidatorMap` that tracks the relationship
/// between transport-level `PeerId`s and consensus-level `ValidatorId`s.
/// This mapping is not yet enforced at runtime; it exists so we can make the
/// binding explicit and testable.
#[derive(Debug)]
pub struct ConsensusNode {
    net_service: NetService,
    id_map: PeerValidatorMap,
}

impl ConsensusNode {
    /// Create a new `ConsensusNode` with the given `NetService`.
    pub fn new(net_service: NetService) -> Self {
        ConsensusNode {
            net_service,
            id_map: PeerValidatorMap::new(),
        }
    }

    /// Create a new `ConsensusNode` with the given `NetService` and `PeerValidatorMap`.
    ///
    /// This constructor allows tests to pre-populate the identity mapping.
    pub fn with_id_map(net_service: NetService, id_map: PeerValidatorMap) -> Self {
        ConsensusNode { net_service, id_map }
    }

    /// Access the underlying `NetService` for low-level control or tests.
    pub fn net_service(&mut self) -> &mut NetService {
        &mut self.net_service
    }

    /// Access the identity map for reading or modification.
    pub fn id_map(&self) -> &PeerValidatorMap {
        &self.id_map
    }

    /// Mutably access the identity map.
    pub fn id_map_mut(&mut self) -> &mut PeerValidatorMap {
        &mut self.id_map
    }

    /// Register a mapping from a `PeerId` to a `ValidatorId`.
    ///
    /// This is a convenience method for `id_map_mut().insert(...)`.
    pub fn register_peer_validator(&mut self, peer: PeerId, validator: ValidatorId) {
        self.id_map.insert(peer, validator);
    }

    /// Look up the `ValidatorId` for a given `PeerId`.
    ///
    /// This is a convenience method for `id_map().get(...)`.
    pub fn get_validator_for_peer(&self, peer: &PeerId) -> Option<ValidatorId> {
        self.id_map.get(peer)
    }

    /// Run one network step (accept, ping-sweep, prune).
    ///
    /// This does not yet invoke the consensus engine; it just advances
    /// the networking state.
    pub fn step_network(&mut self) -> Result<(), ConsensusNodeError> {
        self.net_service.step().map_err(ConsensusNodeError::Net)
    }

    /// Execute a closure with a `ConsensusNetwork` view over the live `PeerManager`.
    ///
    /// This constructs an ephemeral `ConsensusNetAdapter<'_>` borrowing
    /// the `PeerManager` from `NetService`; no cloning and no split-brain.
    pub fn with_consensus_network<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut dyn ConsensusNetwork<Id = PeerId>) -> R,
    {
        let peers: &mut PeerManager = self.net_service.peers();
        let mut adapter = ConsensusNetAdapter::new(peers);
        f(&mut adapter)
    }

    /// Run one network step and non-blockingly poll for a single consensus event.
    ///
    /// This is the first shape of a real node loop primitive:
    /// ```ignore
    /// loop {
    ///     if let Some(evt) = node.step_and_try_recv_event()? {
    ///         // pass evt to consensus engine (future task)
    ///     }
    ///     // do other work, timers, etc.
    /// }
    /// ```
    ///
    /// Returns:
    /// - `Ok(Some(event))` if a consensus event is available
    /// - `Ok(None)` if no event is currently available
    /// - `Err(ConsensusNodeError)` on errors
    pub fn step_and_try_recv_event(
        &mut self,
    ) -> Result<Option<ConsensusNetworkEvent<PeerId>>, ConsensusNodeError> {
        self.step_network()?;

        self.with_consensus_network(|net| net.try_recv_one())
            .map_err(ConsensusNodeError::from)
    }
}