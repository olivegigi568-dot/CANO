//! Integration tests for ConsensusNetAdapter over real TCP sockets.
//!
//! These tests exercise the ConsensusNetAdapter's ability to:
//!  - Broadcast and receive votes
//!  - Broadcast and receive block proposals
//!  - Translate NetMessage into ConsensusNetEvent

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::consensus_net::{ConsensusNetAdapter, ConsensusNetEvent};
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (copied from peer_manager_consensus_roundtrip_tests.rs to keep tests self-contained)
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
// ConsensusNetAdapter Roundtrip Tests
// ============================================================================

#[test]
fn broadcast_vote_roundtrip_to_single_peer() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Create the dummy vote to send
    let dummy_vote = make_dummy_vote();
    let expected_vote = dummy_vote.clone();

    // Server thread
    let server_handle = thread::spawn(move || {
        // Accept a single connection
        let (stream, _peer_addr) = listener.accept().expect("accept failed");

        // Create a PeerManager and add the inbound peer
        let mut peers = PeerManager::new();
        peers
            .add_inbound_peer(PeerId(1), stream, server_cfg)
            .expect("add_inbound_peer failed");

        // Wrap in ConsensusNetAdapter (borrowing)
        let mut adapter = ConsensusNetAdapter::new(&mut peers);

        // Receive a vote via recv_one()
        let event = adapter.recv_one().expect("server recv_one failed");

        // Assert we received the expected event
        match event {
            ConsensusNetEvent::IncomingVote { from, vote } => {
                assert_eq!(from, PeerId(1));
                vote
            }
            other => panic!("expected IncomingVote, got {:?}", other),
        }
    });

    // Client side
    let mut peers = PeerManager::new();
    peers
        .add_outbound_peer(PeerId(2), &addr_str, client_cfg)
        .expect("add_outbound_peer failed");

    // Wrap in ConsensusNetAdapter (borrowing)
    let mut adapter = ConsensusNetAdapter::new(&mut peers);

    // Broadcast the vote
    adapter
        .broadcast_vote(&dummy_vote)
        .expect("client broadcast_vote failed");

    // Join server thread and verify vote
    let received_vote = server_handle.join().expect("server thread panicked");
    assert_eq!(received_vote, expected_vote);
}

#[test]
fn broadcast_block_proposal_to_multiple_peers() {
    use std::sync::mpsc;

    let setup1 = create_test_setup();
    let setup2 = create_test_setup();

    // Bind two TcpListeners on OS-assigned ports
    let listener1 = TcpListener::bind("127.0.0.1:0").expect("bind1 failed");
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind2 failed");
    let addr1 = listener1.local_addr().expect("local_addr1 failed");
    let addr2 = listener2.local_addr().expect("local_addr2 failed");
    let addr_str1 = addr1.to_string();
    let addr_str2 = addr2.to_string();

    let server_cfg1 = setup1.server_cfg;
    let server_cfg2 = setup2.server_cfg;
    let client_cfg1 = setup1.client_cfg;
    let client_cfg2 = setup2.client_cfg;

    // Create the dummy proposal to send
    let dummy_proposal = make_dummy_block_proposal();
    let expected_proposal = dummy_proposal.clone();

    // Use channels to collect what each server received
    let (tx1, rx1) = mpsc::channel::<(PeerId, BlockProposal)>();
    let (tx2, rx2) = mpsc::channel::<(PeerId, BlockProposal)>();

    // Server thread 1: accepts connection, receives BlockProposal via ConsensusNetAdapter
    let server1_handle = thread::spawn(move || {
        let (stream, _) = listener1.accept().expect("accept1 failed");
        let mut peers = PeerManager::new();
        peers
            .add_inbound_peer(PeerId(10), stream, server_cfg1)
            .expect("add_inbound_peer1 failed");

        // Wrap in ConsensusNetAdapter (borrowing)
        let mut adapter = ConsensusNetAdapter::new(&mut peers);

        // Receive a proposal via recv_one()
        let event = adapter.recv_one().expect("server1 recv_one failed");

        // Extract and send the proposal
        match event {
            ConsensusNetEvent::IncomingProposal { from, proposal } => {
                tx1.send((from, proposal)).expect("send to channel1 failed");
            }
            other => panic!("expected IncomingProposal, got {:?}", other),
        }
    });

    // Server thread 2: accepts connection, receives BlockProposal via ConsensusNetAdapter
    let server2_handle = thread::spawn(move || {
        let (stream, _) = listener2.accept().expect("accept2 failed");
        let mut peers = PeerManager::new();
        peers
            .add_inbound_peer(PeerId(11), stream, server_cfg2)
            .expect("add_inbound_peer2 failed");

        // Wrap in ConsensusNetAdapter (borrowing)
        let mut adapter = ConsensusNetAdapter::new(&mut peers);

        // Receive a proposal via recv_one()
        let event = adapter.recv_one().expect("server2 recv_one failed");

        // Extract and send the proposal
        match event {
            ConsensusNetEvent::IncomingProposal { from, proposal } => {
                tx2.send((from, proposal)).expect("send to channel2 failed");
            }
            other => panic!("expected IncomingProposal, got {:?}", other),
        }
    });

    // Client: Create a PeerManager with two outbound peers
    let mut peers = PeerManager::new();
    peers
        .add_outbound_peer(PeerId(1), &addr_str1, client_cfg1)
        .expect("add_outbound_peer1 failed");
    peers
        .add_outbound_peer(PeerId(2), &addr_str2, client_cfg2)
        .expect("add_outbound_peer2 failed");

    assert_eq!(peers.len(), 2);

    // Wrap in ConsensusNetAdapter (borrowing)
    let mut adapter = ConsensusNetAdapter::new(&mut peers);

    // Broadcast the BlockProposal to all peers
    adapter
        .broadcast_proposal(&dummy_proposal)
        .expect("client broadcast_proposal failed");

    // Wait for server threads to finish
    server1_handle.join().expect("server1 thread panicked");
    server2_handle.join().expect("server2 thread panicked");

    // Verify both servers received the same BlockProposal
    let (from1, proposal1) = rx1.recv().expect("recv from channel1 failed");
    let (from2, proposal2) = rx2.recv().expect("recv from channel2 failed");

    // Check that proposals match
    assert_eq!(proposal1, expected_proposal);
    assert_eq!(proposal2, expected_proposal);

    // Check that `from` is one of the expected peer IDs
    assert_eq!(from1, PeerId(10));
    assert_eq!(from2, PeerId(11));
}