//! Network service for managing TCP connections with secure channels.
//!
//! This module provides `NetService`, a minimal, blocking network service that:
//! - Owns a `PeerManager`
//! - Listens on a TCP port for inbound connections
//! - Can dial configured outbound peers
//! - Wraps all connections in `SecureChannel` and `Peer`
//!
//! This is a "synchronous skeleton" that will be refined later.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use crate::peer::PeerId;
use crate::peer_manager::{PeerManager, PeerManagerError};
use crate::secure_channel::ChannelError;

use cano_net::{ClientConnectionConfig, ServerConnectionConfig};

// ============================================================================
// NetServiceError
// ============================================================================

/// Error type for `NetService` operations.
#[derive(Debug)]
pub enum NetServiceError {
    /// I/O error (TCP operations).
    Io(io::Error),
    /// Channel error (crypto/protocol).
    Channel(ChannelError),
    /// PeerManager error.
    PeerManager(PeerManagerError),
    /// The service has reached its configured max_peers limit.
    PeerLimitReached { max: usize },
}

impl From<io::Error> for NetServiceError {
    fn from(e: io::Error) -> Self {
        NetServiceError::Io(e)
    }
}

impl From<ChannelError> for NetServiceError {
    fn from(e: ChannelError) -> Self {
        NetServiceError::Channel(e)
    }
}

impl From<PeerManagerError> for NetServiceError {
    fn from(e: PeerManagerError) -> Self {
        NetServiceError::PeerManager(e)
    }
}

// ============================================================================
// NetServiceConfig
// ============================================================================

/// Configuration for the network service.
#[derive(Debug, Clone)]
pub struct NetServiceConfig {
    /// Address to bind for inbound connections, e.g. "127.0.0.1:9000".
    pub listen_addr: SocketAddr,

    /// Outbound peers to dial on startup.
    pub outbound_peers: Vec<(PeerId, SocketAddr)>,

    /// Client-side connection config for KEMTLS.
    pub client_cfg: ClientConnectionConfig,

    /// Server-side connection config for KEMTLS.
    pub server_cfg: ServerConnectionConfig,

    /// Maximum number of peers this service will track at once.
    /// If the limit is reached, new inbound connections are rejected.
    pub max_peers: usize,
}

// ============================================================================
// NetService
// ============================================================================

/// A minimal, blocking network service.
///
/// `NetService` owns a `PeerManager` and provides methods for:
/// - Accepting incoming peers
/// - Establishing outbound peers
/// - Accessing the underlying `PeerManager`
///
/// The listener is set to non-blocking mode so that `accept_one()` can return
/// immediately if no connection is pending.
#[derive(Debug)]
pub struct NetService {
    listener: TcpListener,
    peers: PeerManager,
    cfg: NetServiceConfig,
    /// Counter for generating peer IDs for inbound connections.
    next_inbound_id: u64,
}

impl NetService {
    /// Create a new `NetService` bound to the configured listen address.
    ///
    /// # Errors
    ///
    /// Returns `NetServiceError::Io` if binding or socket configuration fails.
    pub fn new(cfg: NetServiceConfig) -> Result<Self, NetServiceError> {
        let listener = TcpListener::bind(cfg.listen_addr)?;
        listener.set_nonblocking(true)?;

        Ok(NetService {
            listener,
            peers: PeerManager::new(),
            cfg,
            next_inbound_id: 1,
        })
    }

    /// Get the local address the service is listening on.
    ///
    /// This is useful for tests that bind to port 0 and need to know
    /// the actual assigned port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Access the inner `PeerManager` (for higher-level adapters).
    pub fn peers(&mut self) -> &mut PeerManager {
        &mut self.peers
    }

    // Note: consensus_adapter() is omitted for now because PeerManager is not Clone.
    // The adapter can be wired externally by accessing peers() and constructing
    // ConsensusNetAdapter externally. This keeps the design simple and avoids
    // ownership issues.

    /// Try to accept at most one inbound connection.
    ///
    /// Returns `Ok(Some(peer_id))` if a new peer was added, `Ok(None)` if no
    /// connection was ready (non-blocking).
    ///
    /// # Connection Limit
    ///
    /// If the current number of peers has reached `max_peers`, this method
    /// returns `Err(NetServiceError::PeerLimitReached { .. })` immediately
    /// without accepting new sockets.
    ///
    /// # Errors
    ///
    /// Returns `NetServiceError` if the accept or handshake fails, or if the
    /// peer limit has been reached.
    pub fn accept_one(&mut self) -> Result<Option<PeerId>, NetServiceError> {
        // Enforce connection limit before accepting a new socket.
        if self.peers.len() >= self.cfg.max_peers {
            return Err(NetServiceError::PeerLimitReached {
                max: self.cfg.max_peers,
            });
        }

        match self.listener.accept() {
            Ok((stream, _addr)) => {
                stream.set_nodelay(true)?;
                // Set to blocking for KEMTLS handshake
                stream.set_nonblocking(false)?;

                // Generate a peer ID based on current counter.
                // Later this will be derived from validator identity / handshake.
                let new_id = PeerId(self.next_inbound_id);
                self.next_inbound_id += 1;

                // Use PeerManager's add_inbound_peer which handles SecureChannel creation
                self.peers
                    .add_inbound_peer(new_id, stream, self.cfg.server_cfg.clone())?;

                Ok(Some(new_id))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(NetServiceError::Io(e)),
        }
    }

    /// Dial all outbound peers from config.
    ///
    /// This is a blocking call that connects to each configured outbound peer.
    ///
    /// # Errors
    ///
    /// Returns `NetServiceError` if any connection fails.
    pub fn connect_outbound_from_config(&mut self) -> Result<(), NetServiceError> {
        for (peer_id, addr) in &self.cfg.outbound_peers {
            let addr_str = addr.to_string();
            self.peers
                .add_outbound_peer(*peer_id, &addr_str, self.cfg.client_cfg.clone())?;
        }
        Ok(())
    }

    /// Perform a single network service step.
    ///
    /// Currently this:
    /// - Accepts at most one inbound connection
    ///
    /// Note: If the peer limit is reached, this method continues normally
    /// (the limit is an expected operational state, not an error).
    ///
    /// Future extensions: poll peers, send pings, etc.
    ///
    /// # Errors
    ///
    /// Returns `NetServiceError` if any operation fails (excluding peer limit).
    pub fn step(&mut self) -> Result<(), NetServiceError> {
        // Accept inbound if any.
        // PeerLimitReached is an expected state, not an error for step().
        match self.accept_one() {
            Ok(_) => {}
            Err(NetServiceError::PeerLimitReached { .. }) => {
                // At capacity - this is fine, continue operating.
            }
            Err(e) => return Err(e),
        }
        // Future: we could do more here (poll peers, send pings, etc.)
        Ok(())
    }

    /// Returns true if the given peer is considered live within the given timeout.
    ///
    /// This delegates to `PeerManager::is_peer_live`, which checks if the peer
    /// has responded to a ping within the specified timeout duration.
    ///
    /// # Errors
    ///
    /// Returns `NetServiceError::PeerManager` if the peer is not found.
    pub fn is_peer_live(&self, id: PeerId, timeout: Duration) -> Result<bool, NetServiceError> {
        Ok(self.peers.is_peer_live(id, timeout)?)
    }
}