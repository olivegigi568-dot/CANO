//! Two-node TCP HotStuff + ledger convergence integration tests.
//!
//! These tests verify that two nodes running over real TCP can:
//! - Reach commits when communicating
//! - Converge on the same ledger tip height
//! - Agree on block_ids at each height
//!
//! This is Task T69 in the Canonot workspace.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_ledger::InMemoryLedger;
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
use cano_node::ledger_bridge::InMemoryNodeLedgerHarness;
use cano_node::peer::PeerId;
use cano_node::validator_config::{LocalValidatorConfig, NodeValidatorConfig, RemoteValidatorConfig};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (These are test-only implementations copied from other test files in the
// repository. They provide no real cryptographic security and must NEVER be
// used in production.)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets for testing.
/// This implementation is NOT cryptographically secure.
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

/// A DummySig that always verifies successfully.
/// This implementation is NOT cryptographically secure - for testing only.
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

/// A DummyAead that XORs with a single-byte key.
/// WARNING: This provides NO cryptographic security - for testing only!
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
// Helper: two-node validator configs
// ============================================================================

/// Construct symmetric two-node validator configurations.
///
/// Both nodes use port 0 (OS-assigned) for their listen addresses.
/// The remote addresses are placeholders; they must be updated after
/// discovering actual ports from the harnesses.
fn make_two_node_configs() -> (NodeValidatorConfig, NodeValidatorConfig) {
    let v0 = ValidatorId(0);
    let v1 = ValidatorId(1);

    let addr0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    let cfg0 = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: v0,
            listen_addr: addr0,
        },
        remotes: vec![RemoteValidatorConfig {
            validator_id: v1,
            addr: addr1,
        }],
    };

    let cfg1 = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: v1,
            listen_addr: addr1,
        },
        remotes: vec![RemoteValidatorConfig {
            validator_id: v0,
            addr: addr0,
        }],
    };

    (cfg0, cfg1)
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Test that two nodes over real TCP converge on the same ledger tip height.
///
/// This test:
/// 1. Creates both nodes with port 0 (OS assigns ports)
/// 2. Gets their actual addresses after creation
/// 3. Uses threading to establish connections (server accepts while client connects)
/// 4. Wraps each node in an InMemoryNodeLedgerHarness
/// 5. Drives both harnesses for a bounded number of steps
/// 6. Asserts that both ledgers have at least one committed block
/// 7. Asserts that both ledgers converge on the same tip height
#[test]
fn two_nodes_converge_on_same_ledger_tip_height() {
    eprintln!("[DEBUG] Starting two_nodes_converge_on_same_ledger_tip_height");
    let (cfg0, cfg1) = make_two_node_configs();
    let setup0 = create_test_setup();
    let setup1 = create_test_setup();

    // 1. Create both nodes (they each use port 0, so OS assigns free ports).
    eprintln!("[DEBUG] Creating node0...");
    let mut node0 = NodeHotstuffHarness::new_from_validator_config(
        &cfg0,
        setup0.client_cfg.clone(),
        setup0.server_cfg.clone(),
    )
    .expect("failed to create node0");
    eprintln!("[DEBUG] node0 created");

    eprintln!("[DEBUG] Creating node1...");
    let mut node1 = NodeHotstuffHarness::new_from_validator_config(
        &cfg1,
        setup1.client_cfg.clone(),
        setup1.server_cfg.clone(),
    )
    .expect("failed to create node1");
    eprintln!("[DEBUG] node1 created");

    // 2. Get their actual addresses.
    let addr1_actual = node1.local_addr().expect("node1 local_addr failed");
    let addr1_str = addr1_actual.to_string();
    let client_cfg_for_thread = setup0.client_cfg.clone();
    eprintln!("[DEBUG] node1 listening at: {}", addr1_str);

    // 3. Use threading to establish connection.
    // Node1 is the server (acceptor), node0 is the client (connector).
    // The KEMTLS handshake is synchronous and requires both sides to be active.

    // Spawn a thread to have node1 accept the incoming connection.
    eprintln!("[DEBUG] Spawning accept thread...");
    let accept_handle = thread::spawn(move || {
        for i in 0..1000 {
            match node1.sim.node.net_service().accept_one() {
                Ok(Some(_peer_id)) => {
                    eprintln!("[DEBUG] node1 accepted connection at iteration {}", i);
                    return node1;
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("node1 accept_one failed: {:?}", e),
            }
        }
        panic!("Timeout waiting for node1 to accept connection");
    });

    // Node0 connects to node1.
    eprintln!("[DEBUG] node0 connecting to node1...");
    node0
        .sim
        .node
        .net_service()
        .peers()
        .add_outbound_peer(PeerId(1), &addr1_str, client_cfg_for_thread)
        .expect("node0 failed to connect to node1");
    eprintln!("[DEBUG] node0 connected to node1");

    // Wait for accept thread to complete.
    eprintln!("[DEBUG] Waiting for accept thread...");
    let node1 = accept_handle.join().expect("accept thread panicked");
    eprintln!("[DEBUG] Accept thread completed");

    // Verify both nodes have a peer connection.
    assert!(
        node0.peer_count() >= 1,
        "node0 should have at least 1 peer, got {}",
        node0.peer_count()
    );
    eprintln!("[DEBUG] node0 peer_count: {}", node0.peer_count());

    // 4. Wrap each node in an InMemoryNodeLedgerHarness.
    let ledger0 = InMemoryLedger::<[u8; 32]>::new();
    let ledger1 = InMemoryLedger::<[u8; 32]>::new();

    let mut h0 = InMemoryNodeLedgerHarness::new(node0, ledger0);
    let mut h1 = InMemoryNodeLedgerHarness::new(node1, ledger1);

    // 5. Drive both harnesses for a bounded number of steps.
    const MAX_STEPS: usize = 400;

    eprintln!("[DEBUG] Starting simulation loop (up to {} steps)...", MAX_STEPS);
    for i in 0..MAX_STEPS {
        if i % 100 == 0 {
            eprintln!(
                "[DEBUG] Step {}: tip0={:?}, tip1={:?}, h0.commits={}, h1.commits={}",
                i,
                h0.ledger().tip_height(),
                h1.ledger().tip_height(),
                h0.node().commit_count(),
                h1.node().commit_count(),
            );
        }
        h0.step_once().expect("h0.step_once failed");
        h1.step_once().expect("h1.step_once failed");
    }
    eprintln!("[DEBUG] Simulation loop completed");

    let tip0 = h0.ledger().tip_height();
    let tip1 = h1.ledger().tip_height();

    eprintln!("[DEBUG] Final tip0: {:?}, tip1: {:?}", tip0, tip1);

    let tip0 = tip0.expect("node0 ledger had no commits");
    let tip1 = tip1.expect("node1 ledger had no commits");

    // 6. Assert both ledgers have converged on the same tip height.
    assert_eq!(tip0, tip1, "ledgers diverged in tip height");

    // Optional: they should have the same number of applied blocks.
    assert_eq!(h0.ledger().len(), h1.ledger().len());
}

/// Test that two nodes over real TCP match block_ids at each height.
///
/// This test strengthens the convergence assertion by comparing block_id
/// for each committed height up to the tip.
#[test]
fn two_nodes_ledgers_match_block_ids_by_height() {
    let (cfg0, cfg1) = make_two_node_configs();
    let setup0 = create_test_setup();
    let setup1 = create_test_setup();

    // 1. Create both nodes.
    let mut node0 = NodeHotstuffHarness::new_from_validator_config(
        &cfg0,
        setup0.client_cfg.clone(),
        setup0.server_cfg.clone(),
    )
    .expect("failed to create node0");

    let mut node1 = NodeHotstuffHarness::new_from_validator_config(
        &cfg1,
        setup1.client_cfg.clone(),
        setup1.server_cfg.clone(),
    )
    .expect("failed to create node1");

    // 2. Get address and establish connection using threading.
    let addr1_actual = node1.local_addr().expect("node1 local_addr failed");
    let addr1_str = addr1_actual.to_string();
    let client_cfg_for_thread = setup0.client_cfg.clone();

    let accept_handle = thread::spawn(move || {
        for _ in 0..1000 {
            match node1.sim.node.net_service().accept_one() {
                Ok(Some(_peer_id)) => {
                    return node1;
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("node1 accept_one failed: {:?}", e),
            }
        }
        panic!("Timeout waiting for node1 to accept connection");
    });

    node0
        .sim
        .node
        .net_service()
        .peers()
        .add_outbound_peer(PeerId(1), &addr1_str, client_cfg_for_thread)
        .expect("node0 failed to connect to node1");

    let node1 = accept_handle.join().expect("accept thread panicked");

    // 3. Wrap in ledger harnesses.
    let ledger0 = InMemoryLedger::<[u8; 32]>::new();
    let ledger1 = InMemoryLedger::<[u8; 32]>::new();

    let mut h0 = InMemoryNodeLedgerHarness::new(node0, ledger0);
    let mut h1 = InMemoryNodeLedgerHarness::new(node1, ledger1);

    // 4. Drive both harnesses.
    const MAX_STEPS: usize = 400;
    for _ in 0..MAX_STEPS {
        h0.step_once().expect("h0.step_once failed");
        h1.step_once().expect("h1.step_once failed");
    }

    let ledger0 = h0.ledger();
    let ledger1 = h1.ledger();

    let tip0 = ledger0.tip_height().expect("node0 ledger had no commits");
    let tip1 = ledger1.tip_height().expect("node1 ledger had no commits");
    assert_eq!(tip0, tip1, "tip heights differ");

    // 5. Compare block_id at each height up to the tip.
    // If chain starts at height 1 rather than 0, we use the minimum height
    // from both ledgers.
    let min_height = ledger0
        .iter()
        .map(|(h, _)| *h)
        .min()
        .expect("ledger0 is empty");

    for height in min_height..=tip0 {
        let b0 = ledger0
            .get(height)
            .unwrap_or_else(|| panic!("node0 missing height {}", height));
        let b1 = ledger1
            .get(height)
            .unwrap_or_else(|| panic!("node1 missing height {}", height));

        assert_eq!(
            b0.block_id, b1.block_id,
            "block_id mismatch at height {}",
            height
        );
    }
}
