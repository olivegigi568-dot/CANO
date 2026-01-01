//! Validator configuration for the cano-node.
//!
//! This module provides configuration structures for validators:
//! - `LocalValidatorConfig`: Configuration for this node's local validator identity
//! - `RemoteValidatorConfig`: Configuration for a remote validator peer
//! - `NodeValidatorConfig`: Combined configuration for a node's validator setup
//!
//! # Design Note
//!
//! For T50, this is a pure in-memory config used in tests and future wiring.
//! We are NOT yet:
//! - Parsing TOML/JSON from disk
//! - Verifying signatures
//! - Adding CLI support
//!
//! The `validator_id` here is the consensus-level identity (`ValidatorId`).
//! `PeerId` will be derived deterministically from `remotes` when wiring
//! `NetServiceConfig` and `PeerValidatorMap`.

use std::net::SocketAddr;
use std::time::Duration;

use cano_consensus::ValidatorId;
use cano_net::{ClientConnectionConfig, ServerConnectionConfig};

use crate::identity_map::PeerValidatorMap;
use crate::net_service::NetServiceConfig;
use crate::peer::PeerId;

/// Configuration for this node's local validator identity.
#[derive(Debug, Clone)]
pub struct LocalValidatorConfig {
    /// The consensus-level identity for this validator.
    pub validator_id: ValidatorId,
    /// The network address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
}

/// Configuration for a remote validator peer.
#[derive(Debug, Clone)]
pub struct RemoteValidatorConfig {
    /// The consensus-level identity for this remote validator.
    pub validator_id: ValidatorId,
    /// The network address of this remote validator.
    pub addr: SocketAddr,
}

/// Combined configuration for a node's validator setup.
///
/// This structure expresses:
/// - Local validator ID for this node
/// - Its listening address
/// - Peer validators and their addresses
#[derive(Debug, Clone)]
pub struct NodeValidatorConfig {
    /// Configuration for this node's local validator.
    pub local: LocalValidatorConfig,
    /// Configuration for remote validator peers.
    pub remotes: Vec<RemoteValidatorConfig>,
}

/// Deterministically constructs a `NetServiceConfig` and `PeerValidatorMap`
/// from a `NodeValidatorConfig`.
///
/// This is a test-only helper function that:
/// - Assigns `PeerId(1)`, `PeerId(2)`, ... to remotes in the given order
/// - Uses `NodeValidatorConfig.local.listen_addr` as `listen_addr`
/// - Uses the provided crypto configs and network parameters
///
/// # Arguments
///
/// * `cfg` - The validator configuration
/// * `client_cfg` - Client-side KEMTLS connection config
/// * `server_cfg` - Server-side KEMTLS connection config
/// * `ping_interval` - How often to send Ping to peers
/// * `liveness_timeout` - How long without Pong before peer is considered dead
/// * `max_peers` - Maximum number of peers
///
/// # Returns
///
/// A tuple of `(NetServiceConfig, PeerValidatorMap)` that are aligned:
/// - `NetServiceConfig.outbound_peers` contains `(PeerId(i+1), addr)` for each remote
/// - `PeerValidatorMap` maps `PeerId(i+1)` to the corresponding `ValidatorId`
///
/// # Example
///
/// ```ignore
/// use cano_node::validator_config::*;
/// use cano_consensus::ValidatorId;
///
/// let cfg = NodeValidatorConfig {
///     local: LocalValidatorConfig {
///         validator_id: ValidatorId::new(1),
///         listen_addr: "127.0.0.1:9000".parse().unwrap(),
///     },
///     remotes: vec![
///         RemoteValidatorConfig {
///             validator_id: ValidatorId::new(2),
///             addr: "127.0.0.1:9001".parse().unwrap(),
///         },
///     ],
/// };
///
/// let (net_cfg, id_map) = build_net_config_and_id_map_for_tests(
///     &cfg,
///     client_cfg,
///     server_cfg,
///     Duration::from_secs(5),
///     Duration::from_secs(30),
///     100,
/// );
///
/// // PeerId(1) -> ValidatorId(2) for the first remote
/// assert_eq!(id_map.get(&PeerId(1)), Some(ValidatorId::new(2)));
/// ```
pub fn build_net_config_and_id_map_for_tests(
    cfg: &NodeValidatorConfig,
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
    ping_interval: Duration,
    liveness_timeout: Duration,
    max_peers: usize,
) -> (NetServiceConfig, PeerValidatorMap) {
    let mut outbound_peers = Vec::new();
    let mut id_map = PeerValidatorMap::new();

    for (i, remote) in cfg.remotes.iter().enumerate() {
        // Assign PeerId(1), PeerId(2), ... to remotes in order
        let peer_id = PeerId((i + 1) as u64);
        outbound_peers.push((peer_id, remote.addr));
        id_map.insert(peer_id, remote.validator_id);
    }

    let net_cfg = NetServiceConfig {
        listen_addr: cfg.local.listen_addr,
        outbound_peers,
        client_cfg,
        server_cfg,
        max_peers,
        ping_interval,
        liveness_timeout,
    };

    (net_cfg, id_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_validator_config_creation() {
        let config = LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
        };

        assert_eq!(config.validator_id, ValidatorId::new(1));
        assert_eq!(config.listen_addr.port(), 9000);
    }

    #[test]
    fn remote_validator_config_creation() {
        let config = RemoteValidatorConfig {
            validator_id: ValidatorId::new(2),
            addr: "127.0.0.1:9001".parse().unwrap(),
        };

        assert_eq!(config.validator_id, ValidatorId::new(2));
        assert_eq!(config.addr.port(), 9001);
    }

    #[test]
    fn node_validator_config_creation() {
        let config = NodeValidatorConfig {
            local: LocalValidatorConfig {
                validator_id: ValidatorId::new(1),
                listen_addr: "127.0.0.1:9000".parse().unwrap(),
            },
            remotes: vec![
                RemoteValidatorConfig {
                    validator_id: ValidatorId::new(2),
                    addr: "127.0.0.1:9001".parse().unwrap(),
                },
                RemoteValidatorConfig {
                    validator_id: ValidatorId::new(3),
                    addr: "127.0.0.1:9002".parse().unwrap(),
                },
            ],
        };

        assert_eq!(config.local.validator_id, ValidatorId::new(1));
        assert_eq!(config.remotes.len(), 2);
        assert_eq!(config.remotes[0].validator_id, ValidatorId::new(2));
        assert_eq!(config.remotes[1].validator_id, ValidatorId::new(3));
    }
}
