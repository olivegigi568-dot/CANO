//! Integration tests for Peer ping/pong liveness over SecureChannel.
//!
//! These tests exercise the ping/pong liveness mechanism:
//!  - Peer::{send_ping, handle_incoming_ping, handle_incoming_pong, is_live}
//!  - PeerManager::{broadcast_ping, ping_peer, is_peer_live}

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::{Peer, PeerId};
use cano_node::peer_manager::PeerManager;
use cano_node::secure_channel::SecureChannel;
use cano_wire::io::WireEncode;
use cano_wire::net::{NetMessage, NetworkDelegationCert};

// ============================================================================
// Dummy Implementations for Testing (same as in other test files)
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
// Peer Liveness Ping/Pong Tests
// ============================================================================

/// Test 3.1: peer_ping_pong_roundtrip_updates_liveness
///
/// Set up a client and server Peer pair over real TCP using SecureChannel helpers.
/// Client calls send_ping(42).
/// Server receives NetMessage::Ping(42), calls handle_incoming_ping(42) and sends back Pong.
/// Client receives NetMessage::Pong(42), calls handle_incoming_pong(42).
/// Assert that client_peer.is_live(Duration::from_secs(1)) is true.
/// Also assert that before any pong, is_live is false.
#[test]
fn peer_ping_pong_roundtrip_updates_liveness() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread: accepts connection, receives Ping, sends Pong
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        assert!(peer.is_established());

        // Receive a Ping message from client
        let incoming = peer.recv_msg().expect("server recv_msg failed");
        match incoming {
            NetMessage::Ping(nonce) => {
                assert_eq!(nonce, 42);
                // Handle incoming ping and send pong
                peer.handle_incoming_ping(nonce)
                    .expect("handle_incoming_ping failed");
            }
            _ => panic!("expected Ping, got {:?}", incoming),
        }
    });

    // Client: connect, verify is_live is false before pong, send ping, recv pong, verify is_live
    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut client_peer = Peer::new(PeerId(2), channel);

    assert!(client_peer.is_established());

    // Before any pong, is_live should be false
    assert!(
        !client_peer.is_live(Duration::from_secs(1)),
        "is_live should be false before any pong"
    );

    // Send a Ping with nonce 42
    client_peer.send_ping(42).expect("send_ping failed");

    // Verify last_ping is set
    assert!(
        client_peer.last_ping().is_some(),
        "last_ping should be set after send_ping"
    );

    // Receive Pong response from server
    let response = client_peer.recv_msg().expect("client recv_msg failed");
    match response {
        NetMessage::Pong(nonce) => {
            assert_eq!(nonce, 42);
            // Handle incoming pong to update liveness
            client_peer.handle_incoming_pong(nonce);
        }
        _ => panic!("expected Pong, got {:?}", response),
    }

    // After handling pong, is_live should be true
    assert!(
        client_peer.is_live(Duration::from_secs(1)),
        "is_live should be true after receiving pong"
    );

    // Verify last_pong is set
    assert!(
        client_peer.last_pong().is_some(),
        "last_pong should be set after handle_incoming_pong"
    );

    // Wait for server thread to finish
    server_handle.join().expect("server thread panicked");
}

/// Test 3.2: peer_manager_broadcast_ping_and_pong_liveness
///
/// Use PeerManager with a single peer to verify broadcast_ping works.
/// This avoids the complexity of recv_from_any with multiple peers.
/// Call broadcast_ping(nonce) from client side.
/// Drive the ping/pong roundtrip by reading frames and calling handle_incoming_ping/pong.
/// Assert that the peer's is_live(Duration::from_secs(..)) returns true afterwards.
#[test]
fn peer_manager_broadcast_ping_and_pong_liveness() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread: accepts connection, receives Ping, sends Pong
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        // Receive a Ping message from client (sent via broadcast_ping)
        let incoming = peer.recv_msg().expect("server recv_msg failed");
        match incoming {
            NetMessage::Ping(nonce) => {
                assert_eq!(nonce, 99);
                // Handle incoming ping and send pong
                peer.handle_incoming_ping(nonce)
                    .expect("handle_incoming_ping failed");
            }
            _ => panic!("expected Ping, got {:?}", incoming),
        }
    });

    // Client: Create a PeerManager with one outbound peer
    let mut mgr = PeerManager::new();
    mgr.add_outbound_peer(PeerId(1), &addr_str, client_cfg)
        .expect("add_outbound_peer failed");

    assert_eq!(mgr.len(), 1);

    // Before any pong, peer should not be live
    assert!(
        !mgr.is_peer_live(PeerId(1), Duration::from_secs(1))
            .expect("is_peer_live failed"),
        "peer 1 should not be live before pong"
    );

    // Broadcast a Ping to all peers with nonce 99
    mgr.broadcast_ping(99).expect("broadcast_ping failed");

    // Wait for server thread to finish sending pong
    server_handle.join().expect("server thread panicked");

    // Receive Pong from peer
    let (recv_id, msg) = mgr.recv_from_any().expect("recv_from_any failed");
    assert_eq!(recv_id, PeerId(1));

    if let NetMessage::Pong(nonce) = msg {
        assert_eq!(nonce, 99);
        let peer = mgr.get_peer_mut(PeerId(1)).expect("peer not found");
        peer.handle_incoming_pong(nonce);
    } else {
        panic!("expected Pong, got {:?}", msg);
    }

    // After handling pong, peer should be live
    assert!(
        mgr.is_peer_live(PeerId(1), Duration::from_secs(1))
            .expect("is_peer_live failed"),
        "peer 1 should be live after pong"
    );
}

/// Test 3.3: peer_is_not_live_after_timeout
///
/// For a single Peer, simulate that last_pong was set some time ago (> timeout).
/// Assert is_live(timeout) returns false.
///
/// Since we can't easily manipulate Instant directly, we use a test helper to
/// set the timestamp to an older time.
#[test]
fn peer_is_not_live_after_timeout() {
    use std::sync::mpsc;

    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Bind a TcpListener on an OS-assigned port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Channel to coordinate server shutdown
    let (client_done_tx, client_done_rx) = mpsc::channel::<()>();

    // Server thread: accepts connection, receives Ping, sends Pong, waits for client signal
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        // Receive a Ping message from client
        let incoming = peer.recv_msg().expect("server recv_msg failed");
        if let NetMessage::Ping(nonce) = incoming {
            peer.handle_incoming_ping(nonce)
                .expect("handle_incoming_ping failed");
        }

        // Wait for client to signal it's done reading
        client_done_rx.recv().ok();
    });

    // Client
    let channel = SecureChannel::connect(&addr_str, client_cfg).expect("client connect failed");
    let mut client_peer = Peer::new(PeerId(2), channel);

    // Send a Ping
    client_peer.send_ping(42).expect("send_ping failed");

    // Receive Pong
    let response = client_peer.recv_msg().expect("client recv_msg failed");
    if let NetMessage::Pong(nonce) = response {
        client_peer.handle_incoming_pong(nonce);
    }

    // Signal server that client is done reading
    client_done_tx.send(()).ok();

    // Immediately after pong, is_live should be true with a reasonable timeout
    assert!(
        client_peer.is_live(Duration::from_secs(1)),
        "is_live should be true immediately after pong"
    );

    // Now simulate timeout by setting last_pong to an older time
    // We use the test helper set_last_pong_for_test
    let old_time = Instant::now() - Duration::from_secs(5);
    client_peer.set_last_pong_for_test(Some(old_time));

    // With a 1-second timeout, is_live should now be false
    assert!(
        !client_peer.is_live(Duration::from_secs(1)),
        "is_live should be false after timeout"
    );

    // With a 10-second timeout, is_live should still be true (5 < 10)
    assert!(
        client_peer.is_live(Duration::from_secs(10)),
        "is_live should be true with longer timeout"
    );

    // Wait for server thread to finish
    server_handle.join().expect("server thread panicked");
}

/// Additional test: ping_peer sends ping to a single peer
#[test]
fn peer_manager_ping_peer_single() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
    let addr = listener.local_addr().expect("local_addr failed");
    let addr_str = addr.to_string();

    // Server thread
    let server_handle = thread::spawn(move || {
        let (stream, _peer_addr) = listener.accept().expect("accept failed");
        let channel =
            SecureChannel::from_accepted(stream, server_cfg).expect("server from_accepted failed");
        let mut peer = Peer::new(PeerId(1), channel);

        // Receive a Ping message from client
        let incoming = peer.recv_msg().expect("server recv_msg failed");
        match incoming {
            NetMessage::Ping(nonce) => {
                assert_eq!(nonce, 123);
                peer.handle_incoming_ping(nonce)
                    .expect("handle_incoming_ping failed");
            }
            _ => panic!("expected Ping, got {:?}", incoming),
        }
    });

    // Client: Create a PeerManager with one outbound peer
    let mut mgr = PeerManager::new();
    mgr.add_outbound_peer(PeerId(1), &addr_str, client_cfg)
        .expect("add_outbound_peer failed");

    // Send a Ping to the single peer
    mgr.ping_peer(PeerId(1), 123).expect("ping_peer failed");

    // Receive Pong response
    let (recv_id, msg) = mgr.recv_from_any().expect("recv_from_any failed");
    assert_eq!(recv_id, PeerId(1));

    if let NetMessage::Pong(nonce) = msg {
        assert_eq!(nonce, 123);
        let peer = mgr.get_peer_mut(PeerId(1)).expect("peer not found");
        peer.handle_incoming_pong(nonce);
    } else {
        panic!("expected Pong, got {:?}", msg);
    }

    // Verify peer is live
    assert!(
        mgr.is_peer_live(PeerId(1), Duration::from_secs(1))
            .expect("is_peer_live failed"),
        "peer should be live after pong"
    );

    server_handle.join().expect("server thread panicked");
}

/// Test: ping_peer returns PeerNotFound for unknown peer
#[test]
fn peer_manager_ping_peer_not_found() {
    let mut mgr = PeerManager::new();

    // Try to ping a non-existent peer
    let result = mgr.ping_peer(PeerId(999), 1);
    assert!(matches!(
        result,
        Err(cano_node::peer_manager::PeerManagerError::PeerNotFound(PeerId(999)))
    ));
}