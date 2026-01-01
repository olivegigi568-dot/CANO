//! Integration tests for NetService ping sweep and dead peer pruning.
//!
//! These tests exercise:
//!  - Periodic ping broadcasting based on ping_interval
//!  - Dead peer pruning based on liveness_timeout

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::peer::PeerId;
use cano_node::peer_manager::PeerManager;
use cano_node::{NetService, NetServiceConfig};
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
// Ping Sweep Tests
// ============================================================================

/// Test 5.1: net_service_broadcasts_ping_on_interval
///
/// Verifies that NetService broadcasts Ping messages to all peers when
/// step() is called after the ping_interval has elapsed.
#[test]
fn net_service_broadcasts_ping_on_interval() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create NetServiceConfig with a short ping interval
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 10,
        ping_interval: Duration::from_millis(10),
        // Large liveness_timeout to avoid pruning during this test
        liveness_timeout: Duration::from_secs(60),
    };

    // Create NetService (server side)
    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Track ping count on client side
    let client_handle = thread::spawn(move || {
        // Connect as a client
        let mut client_mgr = PeerManager::new();
        client_mgr
            .add_outbound_peer(PeerId(1), &actual_addr.to_string(), client_cfg)
            .expect("client add_outbound_peer failed");

        // Wait for pings and count them
        let mut ping_count = 0;
        let start = Instant::now();
        let timeout = Duration::from_millis(200);

        while start.elapsed() < timeout {
            // Try to receive a message (non-blocking would be nice, but we use a timeout)
            match client_mgr.recv_from_any() {
                Ok((_, NetMessage::Ping(_))) => {
                    ping_count += 1;
                    // We've received at least one ping, that's what we need to verify
                    if ping_count >= 1 {
                        break;
                    }
                }
                Ok((_, _other)) => {
                    // Other message types, continue waiting
                }
                Err(_) => {
                    // No data ready or error, sleep briefly
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }

        (client_mgr, ping_count)
    });

    // Server side: accept connection and call step() repeatedly
    let start = Instant::now();
    let timeout = Duration::from_millis(200);
    let mut accepted = false;

    while start.elapsed() < timeout {
        service.step().expect("step failed");

        if !accepted && service.peers().len() > 0 {
            accepted = true;
        }

        thread::sleep(Duration::from_millis(5));
    }

    // Wait for client thread
    let (_client_mgr, ping_count) = client_handle.join().expect("client thread panicked");

    // Verify that at least one Ping was received
    assert!(
        accepted,
        "Server should have accepted a connection"
    );
    assert!(
        ping_count >= 1,
        "Client should have received at least one Ping, got {}",
        ping_count
    );
}

/// Test 5.2: net_service_prunes_dead_peers_after_timeout
///
/// Verifies that NetService removes peers that haven't responded to pings
/// within the liveness_timeout after the grace period.
#[test]
fn net_service_prunes_dead_peers_after_timeout() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create NetServiceConfig with a short liveness_timeout
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
        max_peers: 10,
        ping_interval: Duration::from_millis(10),
        // Short liveness_timeout for testing pruning
        liveness_timeout: Duration::from_millis(50),
    };

    // Create NetService (server side)
    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Start client 1 in a thread (we need server to accept)
    let actual_addr_clone = actual_addr;
    let client_cfg_clone = client_cfg.clone();
    let client1_handle = thread::spawn(move || {
        let mut mgr = PeerManager::new();
        mgr.add_outbound_peer(PeerId(1), &actual_addr_clone.to_string(), client_cfg_clone)
            .expect("client1 add_outbound_peer failed");
        mgr
    });

    // Accept first client
    let mut accepted_count = 0;
    for _ in 0..1000 {
        match service.accept_one() {
            Ok(Some(_peer_id)) => {
                accepted_count += 1;
                break;
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept_one failed: {:?}", e),
        }
    }
    assert_eq!(accepted_count, 1, "Should have accepted 1 client");
    let _client_mgr1 = client1_handle.join().expect("client1 thread panicked");

    // Start client 2 in a thread
    let actual_addr_clone2 = actual_addr;
    let client2_handle = thread::spawn(move || {
        let mut mgr = PeerManager::new();
        mgr.add_outbound_peer(PeerId(2), &actual_addr_clone2.to_string(), client_cfg)
            .expect("client2 add_outbound_peer failed");
        mgr
    });

    // Accept second client
    for _ in 0..1000 {
        match service.accept_one() {
            Ok(Some(_peer_id)) => {
                accepted_count += 1;
                break;
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept_one failed: {:?}", e),
        }
    }
    assert_eq!(accepted_count, 2, "Should have accepted 2 clients");
    let _client_mgr2 = client2_handle.join().expect("client2 thread panicked");

    // Verify we have 2 peers
    assert_eq!(service.peers().len(), 2, "Should have 2 peers initially");

    // For peer B (PeerId(2)): leave last_pong as None so it's considered dead
    // (it's already None by default)

    // Wait for the liveness_timeout grace period to pass
    // The grace period is based on created_at, so we need to wait
    thread::sleep(Duration::from_millis(100)); // > liveness_timeout (50ms)

    // For peer A (PeerId(1)): set last_pong to "recent" AFTER the sleep
    // so it's considered live when step() is called
    {
        let peer_a = service
            .peers()
            .get_peer_mut(PeerId(1))
            .expect("peer 1 not found");
        peer_a.set_last_pong_for_test(Some(Instant::now()));
    }

    // Call step() to trigger pruning
    service.step().expect("step failed");

    // Verify peer A is still present (is_live returns true)
    assert!(
        service.peers().get_peer(PeerId(1)).is_some(),
        "Peer A should still be present"
    );

    // Verify peer B has been removed (is_live returns false)
    assert!(
        service.peers().get_peer(PeerId(2)).is_none(),
        "Peer B should have been pruned"
    );

    // Final verification: only 1 peer remains
    assert_eq!(service.peers().len(), 1, "Should have 1 peer after pruning");
}