//! Integration tests for NetService connection limits and liveness.
//!
//! These tests exercise:
//!  - NetService's max_peers limit enforcement
//!  - NetService's is_peer_live delegation to PeerManager

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_node::{NetService, NetServiceConfig, NetServiceError};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing (same as in net_service_smoke_tests.rs)
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
// Connection Limit Tests
// ============================================================================

/// Test that NetService respects the max_peers limit.
///
/// Verifies:
/// 1. First inbound connection is accepted when under limit.
/// 2. Second inbound connection is rejected with PeerLimitReached error.
/// 3. Peer count remains at the limit.
#[test]
fn net_service_respects_max_peers_limit() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create NetServiceConfig with max_peers = 1
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 1, // Limit to exactly 1 peer
    };

    // Create NetService
    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Server thread: accept the first connection, then verify limit is enforced
    let server_handle = thread::spawn(move || {
        // Accept first connection
        for _ in 0..1000 {
            match service.accept_one() {
                Ok(Some(peer_id)) => {
                    assert_eq!(peer_id, PeerId(1));
                    assert_eq!(service.peers().len(), 1);
                    return service;
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("First accept_one failed unexpectedly: {:?}", e),
            }
        }
        panic!("Timeout waiting for first inbound connection");
    });

    // Client 1: connect to server
    let mut client1_mgr = PeerManager::new();
    client1_mgr
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg.clone())
        .expect("client1 add_outbound_peer failed");

    assert_eq!(client1_mgr.len(), 1);

    // Wait for server to accept first connection
    let mut service = server_handle.join().expect("server thread panicked");
    assert_eq!(service.peers().len(), 1);

    // Now the server is at its max_peers limit (1).
    // Attempting to accept another connection should return PeerLimitReached.

    // Immediately check that accept_one returns PeerLimitReached
    // (before any second client tries to connect).
    match service.accept_one() {
        Err(NetServiceError::PeerLimitReached { max }) => {
            assert_eq!(max, 1);
        }
        other => panic!(
            "Expected PeerLimitReached error, got: {:?}",
            other
        ),
    }

    // Verify peer count is still 1
    assert_eq!(service.peers().len(), 1);
}

/// Test that is_peer_live correctly delegates to PeerManager.
///
/// Verifies:
/// 1. Initially peer is NOT live (no pong received).
/// 2. After setting last_pong via test helper, peer IS live.
/// 3. After setting an old timestamp, peer is NOT live.
#[test]
fn net_service_is_peer_live_delegates_to_peer_manager() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create NetServiceConfig for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 100,
    };

    // Create NetService
    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Server thread: accept one connection
    let server_handle = thread::spawn(move || {
        for _ in 0..1000 {
            match service.accept_one() {
                Ok(Some(peer_id)) => {
                    assert_eq!(peer_id, PeerId(1));
                    return service;
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("accept_one failed: {:?}", e),
            }
        }
        panic!("Timeout waiting for inbound connection");
    });

    // Client connects
    let mut client_mgr = PeerManager::new();
    client_mgr
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Wait for server to accept
    let mut service = server_handle.join().expect("server thread panicked");

    let peer_id = PeerId(1);
    let timeout = Duration::from_secs(1);

    // 1. Initially, peer should NOT be live (no pong received yet)
    let live_initial = service
        .is_peer_live(peer_id, timeout)
        .expect("is_peer_live failed");
    assert!(!live_initial, "Peer should not be live initially (no pong)");

    // 2. Set last_pong to now via test helper, peer should be live
    {
        let peer = service
            .peers()
            .get_peer_mut(peer_id)
            .expect("peer not found");
        peer.set_last_pong_for_test(Some(Instant::now()));
    }

    let live_after_pong = service
        .is_peer_live(peer_id, timeout)
        .expect("is_peer_live failed");
    assert!(live_after_pong, "Peer should be live after recent pong");

    // 3. Set last_pong to an old timestamp (5 seconds ago), peer should NOT be live
    //    with a 1 second timeout.
    {
        let peer = service
            .peers()
            .get_peer_mut(peer_id)
            .expect("peer not found");
        let old_time = Instant::now() - Duration::from_secs(5);
        peer.set_last_pong_for_test(Some(old_time));
    }

    let live_after_old_pong = service
        .is_peer_live(peer_id, timeout)
        .expect("is_peer_live failed");
    assert!(
        !live_after_old_pong,
        "Peer should not be live after old pong timestamp"
    );
}
