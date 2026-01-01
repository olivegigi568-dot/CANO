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

use crate::consensus_net::ConsensusNetAdapter;
use crate::net_service::{NetService, NetServiceError};
use crate::peer::PeerId;
use crate::peer_manager::PeerManager;

use cano_consensus::{ConsensusNetwork, NetworkError};

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
#[derive(Debug)]
pub struct ConsensusNode {
    net_service: NetService,
}

impl ConsensusNode {
    /// Create a new `ConsensusNode` with the given `NetService`.
    pub fn new(net_service: NetService) -> Self {
        ConsensusNode { net_service }
    }

    /// Access the underlying `NetService` for low-level control or tests.
    pub fn net_service(&mut self) -> &mut NetService {
        &mut self.net_service
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
}