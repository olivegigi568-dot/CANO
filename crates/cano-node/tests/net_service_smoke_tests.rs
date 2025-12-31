//! Integration tests for NetService.
//!
//! These tests exercise the full path:
//!  - NetService binding and accepting connections
//!  - NetService connecting to outbound peers
//!  - PeerManager integration

use std::sync::Arc;
use std::thread;

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
// Dummy Implementations for Testing (same as in other tests)
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
// NetService Smoke Tests
// ============================================================================

/// Test that NetService can accept an inbound peer connection.
#[test]
fn net_service_accepts_inbound_peer() {
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
    };

    // Create NetService
    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Server thread: run accept_one in a loop until we get a peer
    let server_handle = thread::spawn(move || {
        // Try accept_one until we get a peer (with a timeout via loop limit)
        for _ in 0..1000 {
            match service.accept_one() {
                Ok(Some(peer_id)) => {
                    // Got a peer!
                    assert_eq!(service.peers().len(), 1);
                    return (service, peer_id);
                }
                Ok(None) => {
                    // No connection yet, sleep briefly and try again
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("accept_one failed: {:?}", e),
            }
        }
        panic!("Timeout waiting for inbound connection");
    });

    // Client side: use PeerManager to connect
    let mut client_mgr = PeerManager::new();
    client_mgr
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    assert_eq!(client_mgr.len(), 1);

    // Wait for server to accept
    let (mut service, peer_id) = server_handle.join().expect("server thread panicked");

    // Verify we got a peer ID
    assert_eq!(peer_id, PeerId(1));
    assert_eq!(service.peers().len(), 1);

    // Optionally verify communication works by exchanging a ping/pong
    // Client sends ping
    client_mgr
        .send_to(PeerId(100), &NetMessage::Ping(42))
        .expect("client send_to failed");

    // Server receives and responds
    let (recv_id, msg) = service
        .peers()
        .recv_from_any()
        .expect("server recv_from_any failed");
    assert_eq!(recv_id, PeerId(1));
    assert_eq!(msg, NetMessage::Ping(42));

    service
        .peers()
        .send_to(PeerId(1), &NetMessage::Pong(42))
        .expect("server send_to failed");

    // Client receives pong
    let (recv_id, msg) = client_mgr
        .recv_from_any()
        .expect("client recv_from_any failed");
    assert_eq!(recv_id, PeerId(100));
    assert_eq!(msg, NetMessage::Pong(42));
}

/// Test that NetService can connect to outbound peers from config.
#[test]
fn net_service_connects_outbound_peers_from_config() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Side A: Start a NetService as a listener (the "server" that will accept)
    let listen_addr_a = "127.0.0.1:0".parse().unwrap();
    let service_cfg_a = NetServiceConfig {
        listen_addr: listen_addr_a,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg: server_cfg.clone(),
    };

    let mut service_a = NetService::new(service_cfg_a).expect("NetService::new for A failed");
    let actual_addr_a = service_a.local_addr().expect("local_addr failed for A");

    // Server A thread: accept the incoming connection
    let server_handle = thread::spawn(move || {
        // Try accept_one until we get a peer
        for _ in 0..1000 {
            match service_a.accept_one() {
                Ok(Some(peer_id)) => {
                    assert_eq!(service_a.peers().len(), 1);
                    return (service_a, peer_id);
                }
                Ok(None) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("accept_one failed: {:?}", e),
            }
        }
        panic!("Timeout waiting for inbound connection on A");
    });

    // Side B: Create a NetService with outbound_peers configured
    let listen_addr_b = "127.0.0.1:0".parse().unwrap();
    let service_cfg_b = NetServiceConfig {
        listen_addr: listen_addr_b,
        outbound_peers: vec![(PeerId(1), actual_addr_a)],
        client_cfg,
        server_cfg,
    };

    let mut service_b = NetService::new(service_cfg_b).expect("NetService::new for B failed");

    // B connects to all outbound peers
    service_b
        .connect_outbound_from_config()
        .expect("connect_outbound_from_config failed");

    // Verify B now has one peer
    assert_eq!(service_b.peers().len(), 1);

    // Wait for A to accept
    let (mut service_a, peer_id) = server_handle.join().expect("server thread panicked");

    // Verify A also has one peer
    assert_eq!(peer_id, PeerId(1));
    assert_eq!(service_a.peers().len(), 1);

    // Verify connectivity by exchanging a ping/pong
    // B sends ping to its peer (PeerId(1))
    service_b
        .peers()
        .send_to(PeerId(1), &NetMessage::Ping(999))
        .expect("B send_to failed");

    // A receives the ping
    let (recv_id, msg) = service_a
        .peers()
        .recv_from_any()
        .expect("A recv_from_any failed");
    assert_eq!(recv_id, PeerId(1));
    assert_eq!(msg, NetMessage::Ping(999));

    // A sends pong back
    service_a
        .peers()
        .send_to(PeerId(1), &NetMessage::Pong(999))
        .expect("A send_to failed");

    // B receives pong
    let (recv_id, msg) = service_b
        .peers()
        .recv_from_any()
        .expect("B recv_from_any failed");
    assert_eq!(recv_id, PeerId(1));
    assert_eq!(msg, NetMessage::Pong(999));
}

/// Test that NetService::step() accepts inbound connections.
#[test]
fn net_service_step_accepts_connection() {
    let setup = create_test_setup();
    let server_cfg = setup.server_cfg;
    let client_cfg = setup.client_cfg;

    // Create NetService for the server side
    let listen_addr = "127.0.0.1:0".parse().unwrap();
    let service_cfg = NetServiceConfig {
        listen_addr,
        outbound_peers: vec![],
        client_cfg: client_cfg.clone(),
        server_cfg,
    };

    let mut service = NetService::new(service_cfg).expect("NetService::new failed");
    let actual_addr = service.local_addr().expect("local_addr failed");

    // Server thread: call step() in a loop
    let server_handle = thread::spawn(move || {
        for _ in 0..1000 {
            service.step().expect("step failed");
            if service.peers().len() > 0 {
                return service;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("Timeout waiting for connection via step()");
    });

    // Client side: connect
    let mut client_mgr = PeerManager::new();
    client_mgr
        .add_outbound_peer(PeerId(100), &actual_addr.to_string(), client_cfg)
        .expect("client add_outbound_peer failed");

    // Wait for server
    let mut service = server_handle.join().expect("server thread panicked");
    assert_eq!(service.peers().len(), 1);
}
