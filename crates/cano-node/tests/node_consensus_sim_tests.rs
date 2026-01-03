//! Integration tests for the node-side consensus simulation harness.
//!
//! These tests verify that `NodeConsensusSim` correctly routes events through
//! the driver and applies actions back to the network using real TCP + KEMTLS
//! networking via `ConsensusNode`.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_consensus::{ConsensusNetwork, HotStuffDriver, HotStuffState};
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::consensus_net::ConsensusNetAdapter;
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_node::{ConsensusNode, NetService, NetServiceConfig, NodeConsensusSim};
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (copied from other test files to keep tests self-contained)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let xor_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ xor_byte).collect();
        let tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let (ciphertext, tag_slice) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 1);
        let expected_tag = ciphertext.iter().fold(0u8, |acc, &b| acc ^ b);
        if tag_slice[0] != expected_tag {
            return Err(CryptoError::InvalidCiphertext);
        }
        let xor_byte = key.first().copied().unwrap_or(0);
        let plaintext: Vec<u8> = ciphertext.iter().map(|b| b ^ xor_byte).collect();
        Ok(plaintext)
    }
}

fn make_test_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> StaticCryptoProvider {
    StaticCryptoProvider::new()
        .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
        .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
        .with_signature_suite(Arc::new(DummySig::new(sig_suite_id)))
}

fn make_test_delegation_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_pk: Vec<u8>,
    leaf_kem_suite_id: u8,
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id,
        leaf_kem_pk,
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

// ============================================================================
// Helper to create test client and server configurations
// ============================================================================

struct TestSetup {
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
}

fn create_test_setup() -> TestSetup {
    let kem_suite_id: u8 = 1;
    let aead_suite_id: u8 = 2;
    let sig_suite_id: u8 = 3;

    let provider = Arc::new(make_test_provider(
        kem_suite_id,
        aead_suite_id,
        sig_suite_id,
    ));

    let mut validator_id = [0u8; 32];
    validator_id[0..6].copy_from_slice(b"val-42");

    let mut root_key_id = [0u8; 32];
    root_key_id[0..8].copy_from_slice(b"root-key");

    let server_kem_pk: Vec<u8> = (0..32).collect();
    let server_kem_sk: Vec<u8> = (0..32).map(|x| x ^ 0xFF).collect();

    let cert = make_test_delegation_cert(
        validator_id,
        root_key_id,
        server_kem_pk.clone(),
        kem_suite_id,
        sig_suite_id,
    );

    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);

    let root_network_pk: Vec<u8> = vec![0u8; 32];

    let mut client_random = [0u8; 32];
    client_random[0..6].copy_from_slice(b"client");

    let mut server_random = [0u8; 32];
    server_random[0..6].copy_from_slice(b"server");

    let client_handshake_cfg = ClientHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        peer_root_network_pk: root_network_pk.clone(),
    };

    let server_handshake_cfg = ServerHandshakeConfig {
        kem_suite_id,
        aead_suite_id,
        crypto: provider.clone(),
        local_root_network_pk: root_network_pk,
        local_delegation_cert: cert_bytes,
        local_kem_sk: server_kem_sk,
    };

    let client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random,
        validator_id,
        peer_kem_pk: server_kem_pk,
    };

    let server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random,
    };

    TestSetup {
        client_cfg,
        server_cfg,
    }
}

// ============================================================================
// Helper functions to create dummy consensus messages
// ============================================================================

/// Create a dummy Vote with deterministic values for testing.
fn make_dummy_vote() -> Vote {
    let mut block_id = [0u8; 32];
    block_id[0..8].copy_from_slice(b"block-id");

    Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0, // Prevote
        block_id,
        validator_index: 7,
        reserved: 0,
        signature: vec![0xAA; 64], // Dummy signature
    }
}

/// Create a dummy BlockProposal with deterministic values for testing.
fn make_dummy_block_proposal() -> BlockProposal {
    let mut parent_block_id = [0u8; 32];
    parent_block_id[0..6].copy_from_slice(b"parent");

    let mut payload_hash = [0u8; 32];
    payload_hash[0..7].copy_from_slice(b"payload");

    let header = BlockHeader {
        version: 1,
        chain_id: 42,
        height: 101,
        round: 3,
        parent_block_id,
        payload_hash,
        proposer_index: 2,
        reserved: 0,
        tx_count: 1,
        timestamp: 1700000000,
    };

    // Create a small dummy QC
    let mut qc_block_id = [0u8; 32];
    qc_block_id[0..5].copy_from_slice(b"qc-id");

    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 2,
        step: 1, // Precommit
        block_id: qc_block_id,
        signer_bitmap: vec![0xFF, 0x0F], // Dummy bitmap
        signatures: vec![vec![0xBB; 64]], // One dummy signature
    };

    // One dummy tx blob
    let txs = vec![vec![0x01, 0x02, 0x03, 0x04]];

    BlockProposal {
        header,
        qc: Some(qc),
        txs,
        signature: vec![],
    }
}

// ============================================================================
// NodeConsensusSim Tests
// ============================================================================

/// Test that NodeConsensusSim processes a vote event.
///
/// This test:
/// 1. Sets up a server-side ConsensusNode wrapped in NodeConsensusSim with HotStuffDriver.
/// 2. On the client side, uses PeerManager + ConsensusNetAdapter to connect and send a vote.
/// 3. Runs the simulation loop via step_once() until the vote is received.
/// 4. Asserts the driver recorded at least one vote.
#[test]
fn node_consensus_sim_processes_vote_event() {
    use std::sync::mpsc;

    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create the dummy vote to send
    let dummy_vote = make_dummy_vote();

    // Create NetServiceConfig for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 4,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and wrap in ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");
    let node = ConsensusNode::new(net_service);

    // Create HotStuffDriver with HotStuffState engine
    let engine = HotStuffState::new_at_height(1);
    let driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // Wrap into NodeConsensusSim
    let mut sim = NodeConsensusSim::new(node, driver);

    // Use a channel to signal when the server is ready
    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    // Use a channel to signal when the vote has been sent
    let (vote_sent_tx, vote_sent_rx) = mpsc::channel::<()>();

    // Server thread: run simulation loop
    let server_handle = thread::spawn(move || {
        // Step until we have a connection
        for _ in 0..1000 {
            sim.step_once().expect("step_once failed");
            if sim.node.net_service().peers().len() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(
            sim.node.net_service().peers().len() > 0,
            "No peer connected to server"
        );

        // Signal that server is ready
        server_ready_tx
            .send(())
            .expect("failed to send server ready signal");

        // Wait for the vote to be sent
        vote_sent_rx
            .recv()
            .expect("failed to receive vote sent signal");

        // Now run the simulation loop until we receive the vote
        for _ in 0..100 {
            sim.step_once().expect("step_once failed");
            if sim.driver.votes_received() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // Return the driver's votes_received count
        sim.driver.votes_received()
    });

    // Client side: Connect via PeerManager and send vote via ConsensusNetAdapter
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Wait for server to be ready
    server_ready_rx
        .recv()
        .expect("failed to receive server ready signal");

    // Send the vote via ConsensusNetAdapter
    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_vote(&dummy_vote)
            .expect("client broadcast_vote failed");
    }

    // Signal that the vote has been sent
    vote_sent_tx
        .send(())
        .expect("failed to send vote sent signal");

    // Wait for server to complete
    let votes_received = server_handle.join().expect("server thread panicked");

    // Assert the driver received at least one vote
    assert!(
        votes_received >= 1,
        "expected at least 1 vote received, got {}",
        votes_received
    );
}

/// Test that NodeConsensusSim processes a block proposal event.
///
/// This test:
/// 1. Sets up a server-side ConsensusNode wrapped in NodeConsensusSim with HotStuffDriver.
/// 2. On the client side, uses PeerManager + ConsensusNetAdapter to connect and send a proposal.
/// 3. Runs the simulation loop via step_once() until the proposal is received.
/// 4. Asserts the driver recorded at least one proposal.
#[test]
fn node_consensus_sim_processes_block_proposal_event() {
    use std::sync::mpsc;

    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create the dummy proposal to send
    let dummy_proposal = make_dummy_block_proposal();

    // Create NetServiceConfig for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 4,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and wrap in ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");
    let node = ConsensusNode::new(net_service);

    // Create HotStuffDriver with HotStuffState engine
    let engine = HotStuffState::new_at_height(1);
    let driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new(engine);

    // Wrap into NodeConsensusSim
    let mut sim = NodeConsensusSim::new(node, driver);

    // Use a channel to signal when the server is ready
    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    // Use a channel to signal when the proposal has been sent
    let (proposal_sent_tx, proposal_sent_rx) = mpsc::channel::<()>();

    // Server thread: run simulation loop
    let server_handle = thread::spawn(move || {
        // Step until we have a connection
        for _ in 0..1000 {
            sim.step_once().expect("step_once failed");
            if sim.node.net_service().peers().len() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(
            sim.node.net_service().peers().len() > 0,
            "No peer connected to server"
        );

        // Signal that server is ready
        server_ready_tx
            .send(())
            .expect("failed to send server ready signal");

        // Wait for the proposal to be sent
        proposal_sent_rx
            .recv()
            .expect("failed to receive proposal sent signal");

        // Now run the simulation loop until we receive the proposal
        for _ in 0..100 {
            sim.step_once().expect("step_once failed");
            if sim.driver.proposals_received() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // Return the driver's proposals_received count
        sim.driver.proposals_received()
    });

    // Client side: Connect via PeerManager and send proposal via ConsensusNetAdapter
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Wait for server to be ready
    server_ready_rx
        .recv()
        .expect("failed to receive server ready signal");

    // Send the proposal via ConsensusNetAdapter
    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_proposal(&dummy_proposal)
            .expect("client broadcast_proposal failed");
    }

    // Signal that the proposal has been sent
    proposal_sent_tx
        .send(())
        .expect("failed to send proposal sent signal");

    // Wait for server to complete
    let proposals_received = server_handle.join().expect("server thread panicked");

    // Assert the driver received at least one proposal
    assert!(
        proposals_received >= 1,
        "expected at least 1 proposal received, got {}",
        proposals_received
    );
}

// ============================================================================
// Identity Plumbing Tests (T49)
// ============================================================================

/// Test that PeerValidatorMap correctly maps PeerId to ValidatorId.
///
/// This test verifies that:
/// - The mapping can be pre-populated
/// - The mapping can be queried after setup
#[test]
fn peer_validator_map_basic_mapping() {
    use cano_consensus::ValidatorId;
    use cano_node::identity_map::PeerValidatorMap;
    use cano_node::peer::PeerId;

    let mut map = PeerValidatorMap::new();

    // Set up a mapping for two nodes
    let peer1 = PeerId(100);
    let peer2 = PeerId(200);
    let val1 = ValidatorId::new(1);
    let val2 = ValidatorId::new(2);

    map.insert(peer1, val1);
    map.insert(peer2, val2);

    // Verify the mapping
    assert_eq!(map.get(&peer1), Some(val1));
    assert_eq!(map.get(&peer2), Some(val2));
    assert_eq!(map.get(&PeerId(999)), None);
}

/// Test that ConsensusNode can be created with a pre-populated PeerValidatorMap.
#[test]
fn consensus_node_with_id_map_constructor() {
    use cano_consensus::ValidatorId;
    use cano_node::identity_map::PeerValidatorMap;
    use cano_node::peer::PeerId;
    use std::net::SocketAddr;

    let setup = create_test_setup();

    // Create a pre-populated identity map
    let mut id_map = PeerValidatorMap::new();
    id_map.insert(PeerId(100), ValidatorId::new(1));
    id_map.insert(PeerId(200), ValidatorId::new(2));

    // Create NetServiceConfig
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: setup.client_cfg,
        server_cfg: setup.server_cfg,
        max_peers: 4,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and ConsensusNode with pre-populated id_map
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let node = ConsensusNode::with_id_map(net_service, id_map);

    // Verify the mapping is accessible
    assert_eq!(
        node.get_validator_for_peer(&PeerId(100)),
        Some(ValidatorId::new(1))
    );
    assert_eq!(
        node.get_validator_for_peer(&PeerId(200)),
        Some(ValidatorId::new(2))
    );
    assert_eq!(node.get_validator_for_peer(&PeerId(999)), None);
}

/// Test that ConsensusNode can register peer-validator mappings dynamically.
#[test]
fn consensus_node_register_peer_validator() {
    use cano_consensus::ValidatorId;
    use cano_node::peer::PeerId;
    use std::net::SocketAddr;

    let setup = create_test_setup();

    // Create NetServiceConfig
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: setup.client_cfg,
        server_cfg: setup.server_cfg,
        max_peers: 4,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let mut node = ConsensusNode::new(net_service);

    // Verify no mapping initially
    assert_eq!(node.get_validator_for_peer(&PeerId(100)), None);

    // Register a mapping dynamically
    node.register_peer_validator(PeerId(100), ValidatorId::new(42));

    // Verify the mapping is now present
    assert_eq!(
        node.get_validator_for_peer(&PeerId(100)),
        Some(ValidatorId::new(42))
    );
}

/// Test that when processing an IncomingVote event, we can look up the ValidatorId
/// for the sender's PeerId using the identity map.
///
/// This test verifies the identity plumbing is in place and usable, even though
/// runtime enforcement is not yet implemented.
#[test]
fn consensus_node_identity_map_lookup_on_incoming_vote() {
    use cano_consensus::ValidatorId;
    use cano_node::peer::PeerId;
    use std::net::SocketAddr;
    use std::sync::mpsc;

    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create a vote to send
    let mut vote = make_dummy_vote();
    // Set validator_index to match the ValidatorId we'll map to the client peer
    vote.validator_index = 42;

    // Note: The actual PeerId is assigned by the server when it accepts the connection.
    // In a real scenario, we'd populate this mapping during handshake or from config.
    // For this test, we register the mapping after the connection is established.

    // Create NetServiceConfig for the server side
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 4,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");

    // We use a default map here; in a real scenario, we'd populate it during handshake
    let mut node = ConsensusNode::new(net_service);

    // Use channels to coordinate
    let (server_ready_tx, server_ready_rx) = mpsc::channel::<PeerId>();
    let (vote_sent_tx, vote_sent_rx) = mpsc::channel::<()>();

    // Server thread
    let server_handle = thread::spawn(move || {
        // Step until we have a connection
        let mut connected_peer: Option<PeerId> = None;
        for _ in 0..1000 {
            node.step_network().expect("step_network failed");
            if node.net_service().peers().len() > 0 {
                // Get the connected peer's ID
                let peers: Vec<PeerId> = node
                    .net_service()
                    .peers()
                    .iter_ids()
                    .collect();
                if !peers.is_empty() {
                    connected_peer = Some(peers[0]);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        let peer_id = connected_peer.expect("No peer connected");

        // Now register the peer-validator mapping
        // This simulates what would happen after a verified handshake
        node.register_peer_validator(peer_id, ValidatorId::new(42));

        // Signal that server is ready, sending the peer_id
        server_ready_tx
            .send(peer_id)
            .expect("failed to send server ready signal");

        // Wait for the vote to be sent
        vote_sent_rx
            .recv()
            .expect("failed to receive vote sent signal");

        // Process incoming events until we receive the vote
        for _ in 0..100 {
            if let Ok(Some(event)) = node.step_and_try_recv_event() {
                if let cano_consensus::ConsensusNetworkEvent::IncomingVote { from, vote: v } = event
                {
                    // Look up the ValidatorId for the sender
                    let validator_id = node.get_validator_for_peer(&from);

                    // Return the info for assertion
                    return (
                        from,
                        validator_id,
                        v.validator_index,
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        panic!("Did not receive vote event");
    });

    // Client side
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Wait for server to be ready and get the peer_id it assigned to us
    let _ = server_ready_rx
        .recv()
        .expect("failed to receive server ready signal");

    // Send the vote
    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_vote(&vote).expect("client broadcast_vote failed");
    }

    // Signal that the vote has been sent
    vote_sent_tx
        .send(())
        .expect("failed to send vote sent signal");

    // Wait for server to complete and get the results
    let (from_peer, mapped_validator, vote_validator_index) =
        server_handle.join().expect("server thread panicked");

    // Verify the identity mapping is correct
    assert!(
        mapped_validator.is_some(),
        "Expected ValidatorId to be mapped for peer {:?}",
        from_peer
    );

    let mapped_val = mapped_validator.unwrap();
    assert_eq!(
        mapped_val,
        ValidatorId::new(42),
        "Mapped ValidatorId should be 42"
    );

    // The vote's validator_index should match the mapped ValidatorId
    assert_eq!(
        vote_validator_index as u64,
        mapped_val.as_u64(),
        "vote.validator_index should match the mapped ValidatorId"
    );
}