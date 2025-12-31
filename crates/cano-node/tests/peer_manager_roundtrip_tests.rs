//! Integration tests for PeerManager over real TCP sockets.
//!
//! These tests exercise the full path:
//!  - TcpListener + TcpStream
//!  - PeerManager::{add_outbound_peer, add_inbound_peer}
//!  - PeerManager::{send_to, broadcast, recv_from_any}
//!  - Real wire messages from cano-wire::net

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_wire::io::WireEncode;
use cano_wire::net::{NetMessage, NetworkDelegationCert};

// ============================================================================
// Dummy Implementations for Testing (same as in peer_wire_roundtrip_tests)
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
// PeerManager Roundtrip Tests
// ============================================================================

#[test]
fn peer_manager_single_peer_send_receive() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread
    let server_handle = thread::spawn(move || {
        // Accept a single connection
        let (stream, _peer_addr) = listener.accept().expect("accept failed");

        // Create a PeerManager and add the inbound peer
        let mut mgr = PeerManager::new();
        mgr.add_inbound_peer(PeerId(1), stream, server_cfg)
            .expect("add_inbound_peer failed");

        assert_eq!(mgr.len(), 1);
        assert!(!mgr.is_empty());

        // Receive a Ping message from client via recv_from_any
        let (recv_id, msg) = mgr.recv_from_any().expect("server recv_from_any failed");
        assert_eq!(recv_id, PeerId(1));
        assert_eq!(msg, NetMessage::Ping(123));

        // Send a Pong response back
        mgr.send_to(PeerId(1), &NetMessage::Pong(123))
            .expect("server send_to failed");
    });

    // Client thread (inline)
    let mut mgr = PeerManager::new();
    mgr.add_outbound_peer(PeerId(2), &addr_str, client_cfg)
        .expect("add_outbound_peer failed");

    assert_eq!(mgr.len(), 1);
    assert!(!mgr.is_empty());

    // Send a Ping message to server
    mgr.send_to(PeerId(2), &NetMessage::Ping(123))
        .expect("client send_to failed");

    // Receive Pong response from server
    let (recv_id, msg) = mgr.recv_from_any().expect("client recv_from_any failed");
    assert_eq!(recv_id, PeerId(2));
    assert_eq!(msg, NetMessage::Pong(123));

    // Wait for server thread to finish
    server_handle.join().expect("server thread panicked");
}

#[test]
fn peer_manager_multiple_peers_broadcast() {
    // This test sets up two separate client-server pairs to simulate multiple peers.
    // Each client connects to its own server listener and they communicate via PeerManager.
    //
    // The test focuses on the broadcast functionality: we send a Ping via broadcast,
    // and verify each server receives it. Each server sends back a Pong.
    // We then read the two Pong responses from the client's PeerManager.
    //
    // Because recv_from_any() is blocking and iterates in HashMap order, we read
    // from each peer individually using send_to/recv (via recv_from_any which has
    // only one peer active at a time effectively).

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

    // Use channels to collect what each server received
    let (tx1, rx1) = mpsc::channel::<NetMessage>();
    let (tx2, rx2) = mpsc::channel::<NetMessage>();

    // Server thread 1: accepts connection, receives Ping, sends Pong
    let server1_handle = thread::spawn(move || {
        let (stream, _) = listener1.accept().expect("accept1 failed");
        let mut mgr = PeerManager::new();
        mgr.add_inbound_peer(PeerId(10), stream, server_cfg1)
            .expect("add_inbound_peer1 failed");

        // Receive a Ping message
        let (recv_id, msg) = mgr.recv_from_any().expect("server1 recv_from_any failed");
        assert_eq!(recv_id, PeerId(10));

        // Report what we received
        tx1.send(msg.clone()).expect("send to channel failed");

        // Send a Pong back
        if let NetMessage::Ping(nonce) = msg {
            mgr.send_to(PeerId(10), &NetMessage::Pong(nonce))
                .expect("server1 send_to failed");
        }
    });

    // Server thread 2: accepts connection, receives Ping, sends Pong
    let server2_handle = thread::spawn(move || {
        let (stream, _) = listener2.accept().expect("accept2 failed");
        let mut mgr = PeerManager::new();
        mgr.add_inbound_peer(PeerId(11), stream, server_cfg2)
            .expect("add_inbound_peer2 failed");

        // Receive a Ping message
        let (recv_id, msg) = mgr.recv_from_any().expect("server2 recv_from_any failed");
        assert_eq!(recv_id, PeerId(11));

        // Report what we received
        tx2.send(msg.clone()).expect("send to channel failed");

        // Send a Pong back
        if let NetMessage::Ping(nonce) = msg {
            mgr.send_to(PeerId(11), &NetMessage::Pong(nonce))
                .expect("server2 send_to failed");
        }
    });

    // Client: Create a PeerManager with two outbound peers
    let mut mgr = PeerManager::new();
    mgr.add_outbound_peer(PeerId(1), &addr_str1, client_cfg1)
        .expect("add_outbound_peer1 failed");
    mgr.add_outbound_peer(PeerId(2), &addr_str2, client_cfg2)
        .expect("add_outbound_peer2 failed");

    assert_eq!(mgr.len(), 2);
    assert!(!mgr.is_empty());

    // Broadcast a Ping to all peers
    mgr.broadcast(&NetMessage::Ping(42))
        .expect("client broadcast failed");

    // Wait for server threads to finish and verify they received the broadcast
    server1_handle.join().expect("server1 thread panicked");
    server2_handle.join().expect("server2 thread panicked");

    // Verify both servers received the same Ping(42)
    let msg1 = rx1.recv().expect("recv from channel1 failed");
    let msg2 = rx2.recv().expect("recv from channel2 failed");
    assert_eq!(msg1, NetMessage::Ping(42));
    assert_eq!(msg2, NetMessage::Ping(42));

    // Note: We could also receive the Pong responses from the client side,
    // but that would require waiting for both servers to complete. Since
    // we've already verified broadcast works (both servers got Ping(42)),
    // the test is complete.
}

#[test]
fn peer_manager_peer_exists_error() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread (just accept)
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept failed");
        let mut mgr = PeerManager::new();
        mgr.add_inbound_peer(PeerId(1), stream, server_cfg)
            .expect("add_inbound_peer failed");

        // Receive something from client to keep connection alive
        let _ = mgr.recv_from_any();
    });

    // Client
    let mut mgr = PeerManager::new();
    mgr.add_outbound_peer(PeerId(1), &addr_str, client_cfg.clone())
        .expect("add_outbound_peer failed");

    // Try to add another peer with the same ID – should fail
    let setup2 = create_test_setup();
    let result = mgr.add_outbound_peer(PeerId(1), &addr_str, setup2.client_cfg);
    assert!(matches!(
        result,
        Err(cano_node::peer_manager::PeerManagerError::PeerExists(PeerId(1)))
    ));

    // Send something to keep server alive
    mgr.send_to(PeerId(1), &NetMessage::Ping(1)).ok();

    server_handle.join().expect("server thread panicked");
}

#[test]
fn peer_manager_peer_not_found_error() {
    let mut mgr = PeerManager::new();

    // Try to send to a non-existent peer
    let result = mgr.send_to(PeerId(999), &NetMessage::Ping(1));
    assert!(matches!(
        result,
        Err(cano_node::peer_manager::PeerManagerError::PeerNotFound(PeerId(999)))
    ));
}