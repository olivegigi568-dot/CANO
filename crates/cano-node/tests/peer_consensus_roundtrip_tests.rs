//! Integration tests for Peer wire encoding/decoding of consensus messages over SecureChannel.
//!
//! These tests exercise the full path for consensus-plane messages:
//!  - TcpListener + TcpStream
//!  - SecureChannel::{connect, from_accepted}
//!  - Peer::{send_msg, recv_msg}
//!  - NetMessage::ConsensusVote and NetMessage::BlockProposal

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::{Peer, PeerId};
use cano_node::secure_channel::SecureChannel;
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use cano_wire::io::WireEncode;
use cano_wire::net::{NetMessage, NetworkDelegationCert};

// ============================================================================
// Dummy Implementations for Testing
// (copied from peer_wire_roundtrip_tests.rs to keep tests self-contained)
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
// Peer Consensus Roundtrip Tests
// ============================================================================

#[test]
fn peer_single_consensus_vote_roundtrip() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread: accept + SecureChannel::from_accepted + Peer::recv_msg
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");

        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        // Receive a ConsensusVote message from client
        let msg = peer.recv_msg().expect("server recv_msg failed");
        match msg {
            NetMessage::ConsensusVote(vote) => vote,
            other => panic!("expected ConsensusVote, got {:?}", other),
        }
    });

    // Client side: connect + send vote
    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut peer = Peer::new(PeerId(2), channel);

    // Build a small dummy Vote
    let vote = make_dummy_vote();

    let msg = NetMessage::ConsensusVote(vote.clone());
    peer.send_msg(&msg).expect("client send_msg failed");

    // Join server thread and verify vote
    let received_vote = server_handle.join().expect("server thread panicked");
    assert_eq!(received_vote, vote);
}

#[test]
fn peer_single_block_proposal_roundtrip() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");

        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(10), channel);

        // Receive a BlockProposal message from client
        let msg = peer.recv_msg().expect("server recv_msg failed");
        match msg {
            NetMessage::BlockProposal(bp) => bp,
            other => panic!("expected BlockProposal, got {:?}", other),
        }
    });

    // Client side: connect + send block proposal
    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut peer = Peer::new(PeerId(20), channel);

    // Build a small dummy BlockProposal
    let proposal = make_dummy_block_proposal();

    let msg = NetMessage::BlockProposal(proposal.clone());
    peer.send_msg(&msg).expect("client send_msg failed");

    // Join server thread and verify proposal
    let received = server_handle.join().expect("server thread panicked");
    assert_eq!(received, proposal);
}