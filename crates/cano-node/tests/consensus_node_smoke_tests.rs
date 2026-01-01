//! Integration tests for ConsensusNode.
//!
//! These tests verify that ConsensusNode can:
//! - Run the network service
//! - Accept a peer
//! - Use `with_consensus_network` to send/receive consensus messages via the
//!   ConsensusNetwork trait, over real encrypted TCP.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_consensus::{ConsensusNetwork, ConsensusNetworkEvent};
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::consensus_net::ConsensusNetAdapter;
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_node::{ConsensusNode, NetService, NetServiceConfig};
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
    }
}

// ============================================================================
// ConsensusNode Smoke Tests
// ============================================================================

/// Test that ConsensusNode can receive a vote event via the ConsensusNetwork trait.
///
/// This test:
/// 1. Starts a server-side NetService wrapped in ConsensusNode.
/// 2. On the client side, uses PeerManager + ConsensusNetAdapter to connect and send a vote.
/// 3. On the server side, uses `with_consensus_network` to receive the vote.
/// 4. Asserts the received event is `ConsensusNetworkEvent::IncomingVote`.
#[test]
fn consensus_node_receives_vote_event_via_trait() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create the dummy vote to send
    let dummy_vote = make_dummy_vote();
    let expected_vote = dummy_vote.clone();

    // Create NetServiceConfig for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 100,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and wrap in ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");
    let mut node = ConsensusNode::new(net_service);

    // Server thread: step network and receive vote via with_consensus_network
    let server_handle = thread::spawn(move || {
        // First, step network until we have a connection
        for _ in 0..1000 {
            node.step_network().expect("step_network failed");
            if node.net_service().peers().len() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(
            node.net_service().peers().len() > 0,
            "No peer connected to server"
        );

        // Now receive the vote via with_consensus_network
        let mut received_event = None;
        for _ in 0..1000 {
            let result: Result<ConsensusNetworkEvent<PeerId>, _> =
                node.with_consensus_network(|net| net.recv_one());

            match result {
                Ok(evt) => {
                    received_event = Some(evt);
                    break;
                }
                Err(_) => {
                    // No message yet, step and try again
                    node.step_network().expect("step_network failed");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }

        received_event.expect("Failed to receive vote event")
    });

    // Client side: Connect via PeerManager and send vote via ConsensusNetAdapter
    // First, bind a TcpListener so the client can connect
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Create a ConsensusNetAdapter (borrowing) and use it via the trait
    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_vote(&dummy_vote)
            .expect("client broadcast_vote failed");
    }

    // Wait for server to receive
    let event = server_handle.join().expect("server thread panicked");

    // Assert we received the expected event
    match event {
        ConsensusNetworkEvent::IncomingVote { from, vote } => {
            assert_eq!(from, PeerId(1)); // Server assigns PeerId(1) to first inbound peer
            assert_eq!(vote, expected_vote);
        }
        other => panic!("expected IncomingVote, got {:?}", other),
    }
}

/// Test that ConsensusNode can receive a block proposal event via the ConsensusNetwork trait.
///
/// This test:
/// 1. Starts a server-side NetService wrapped in ConsensusNode.
/// 2. On the client side, uses PeerManager + ConsensusNetAdapter to connect and send a proposal.
/// 3. On the server side, uses `with_consensus_network` to receive the proposal.
/// 4. Asserts the received event is `ConsensusNetworkEvent::IncomingProposal`.
#[test]
fn consensus_node_receives_block_proposal_event_via_trait() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create the dummy proposal to send
    let dummy_proposal = make_dummy_block_proposal();
    let expected_proposal = dummy_proposal.clone();

    // Create NetServiceConfig for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 100,
        ping_interval: Duration::from_millis(50),
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService and wrap in ConsensusNode
    let net_service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = net_service.local_addr().expect("local_addr failed");
    let mut node = ConsensusNode::new(net_service);

    // Server thread: step network and receive proposal via with_consensus_network
    let server_handle = thread::spawn(move || {
        // First, step network until we have a connection
        for _ in 0..1000 {
            node.step_network().expect("step_network failed");
            if node.net_service().peers().len() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        assert!(
            node.net_service().peers().len() > 0,
            "No peer connected to server"
        );

        // Now receive the proposal via with_consensus_network
        let mut received_event = None;
        for _ in 0..1000 {
            let result: Result<ConsensusNetworkEvent<PeerId>, _> =
                node.with_consensus_network(|net| net.recv_one());

            match result {
                Ok(evt) => {
                    received_event = Some(evt);
                    break;
                }
                Err(_) => {
                    // No message yet, step and try again
                    node.step_network().expect("step_network failed");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }

        received_event.expect("Failed to receive proposal event")
    });

    // Client side: Connect via PeerManager and send proposal via ConsensusNetAdapter
    let mut client_peers = PeerManager::new();
    client_peers
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Create a ConsensusNetAdapter (borrowing) and use it via the trait
    {
        let mut adapter = ConsensusNetAdapter::new(&mut client_peers);
        let net: &mut dyn ConsensusNetwork<Id = PeerId> = &mut adapter;
        net.broadcast_proposal(&dummy_proposal)
            .expect("client broadcast_proposal failed");
    }

    // Wait for server to receive
    let event = server_handle.join().expect("server thread panicked");

    // Assert we received the expected event
    match event {
        ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
            assert_eq!(from, PeerId(1)); // Server assigns PeerId(1) to first inbound peer
            assert_eq!(proposal, expected_proposal);
        }
        other => panic!("expected IncomingProposal, got {:?}", other),
    }
}