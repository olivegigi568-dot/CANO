//! Integration tests for node-level pruning.
//!
//! These tests verify that:
//! - Pruning below a given height doesn't break ledger progression
//! - Pruning doesn't affect the ledger's visibility of blocks at or above the prune height
//! - Pruning is safe to call repeatedly

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_ledger::InMemoryLedger;
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
use cano_node::ledger_bridge::InMemoryNodeLedgerHarness;
use cano_node::validator_config::{LocalValidatorConfig, NodeValidatorConfig};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (These are test-only implementations copied from other test files in the
// repository. They provide no real cryptographic security and must NEVER be
// used in production.)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets for testing.
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
// Helper: configs for a single node
// ============================================================================

/// Create a single-node validator configuration.
fn make_single_node_config() -> NodeValidatorConfig {
    NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: vec![],
        },
        remotes: vec![],
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Test that pruning below a given height preserves ledger progress.
///
/// Scenario:
/// 1. Build a single-node harness with InMemoryNodeLedgerHarness
/// 2. Drive step_once() enough to get some commits (tip height ≥ 3)
/// 3. Read the current tip_height from the ledger
/// 4. Call prune_below_height(tip_height.saturating_sub(1)) on the harness
/// 5. Continue driving step_once() for more iterations
/// 6. Assert:
///    - Ledger still has a monotonically increasing tip_height
///    - No panics or errors occur
///    - The ledger's existing entries at and above the prune height are still accessible
#[test]
fn pruning_below_height_preserves_ledger_progress() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive until we get a few commits.
    const MAX_STEPS_INITIAL: usize = 500;
    for _ in 0..MAX_STEPS_INITIAL {
        harness.step_once().expect("step_once failed (initial)");
        if let Some(tip) = harness.ledger().tip_height() {
            if tip >= 3 {
                break;
            }
        }
    }

    let tip_before = harness
        .ledger()
        .tip_height()
        .expect("no commits before pruning");

    // Prune below tip_before - 1 (keeping at least the last two heights).
    let prune_height = tip_before.saturating_sub(1);
    harness.prune_below_height(prune_height);

    // Drive again.
    const MAX_STEPS_AFTER: usize = 200;
    for _ in 0..MAX_STEPS_AFTER {
        harness.step_once().expect("step_once failed (after prune)");
    }

    let tip_after = harness
        .ledger()
        .tip_height()
        .expect("no commits after pruning");

    assert!(
        tip_after >= tip_before,
        "tip height regressed after pruning: before={}, after={}",
        tip_before,
        tip_after
    );

    // Make sure the commit at prune_height is still visible in the ledger.
    let _ = harness
        .ledger()
        .get(prune_height)
        .expect("missing commit at prune_height after pruning");
}

/// Test that pruning the node's internal structures doesn't affect existing ledger entries.
///
/// The ledger stores its own copy of committed block info, independent of the node's
/// commit index and block store. After pruning, ledger entries should remain intact.
#[test]
fn pruning_doesnt_affect_ledger_entries() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive until we have several commits
    for _ in 0..300 {
        harness.step_once().expect("step_once failed");
        if let Some(tip) = harness.ledger().tip_height() {
            if tip >= 5 {
                break;
            }
        }
    }

    // Record ledger state before pruning
    let ledger_len_before = harness.ledger().len();
    let tip_before = harness.ledger().tip_height();

    // Prune at height 3
    harness.prune_below_height(3);

    // Ledger entries should be unchanged (ledger stores its own copy)
    let ledger_len_after = harness.ledger().len();
    let tip_after = harness.ledger().tip_height();

    assert_eq!(
        ledger_len_before, ledger_len_after,
        "ledger length should not change after pruning node structures"
    );
    assert_eq!(
        tip_before, tip_after,
        "ledger tip should not change after pruning node structures"
    );

    // All ledger entries should still be accessible
    for (height, info) in harness.ledger().iter() {
        assert_eq!(info.height, *height);
    }
}

/// Test that pruning multiple times is safe and idempotent.
#[test]
fn pruning_multiple_times_is_safe() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive until we have some commits
    for _ in 0..200 {
        harness.step_once().expect("step_once failed");
        if let Some(tip) = harness.ledger().tip_height() {
            if tip >= 3 {
                break;
            }
        }
    }

    // Prune multiple times at the same height
    harness.prune_below_height(2);
    harness.prune_below_height(2);
    harness.prune_below_height(2);

    // Should still work
    for _ in 0..50 {
        harness.step_once().expect("step_once failed after multiple prunes");
    }

    // Ledger should still be valid
    assert!(harness.ledger().tip_height().is_some());
}

/// Test that pruning with increasing heights works correctly.
#[test]
fn pruning_with_increasing_heights() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive until we have some commits
    for _ in 0..300 {
        harness.step_once().expect("step_once failed");
        if let Some(tip) = harness.ledger().tip_height() {
            if tip >= 5 {
                break;
            }
        }
    }

    let initial_tip = harness.ledger().tip_height().unwrap_or(0);

    // Prune with increasing heights
    harness.prune_below_height(1);
    harness.prune_below_height(2);
    harness.prune_below_height(3);

    // Drive some more
    for _ in 0..100 {
        harness.step_once().expect("step_once failed");
    }

    // Tip should not have regressed
    let final_tip = harness.ledger().tip_height().unwrap_or(0);
    assert!(
        final_tip >= initial_tip,
        "tip regressed: initial={}, final={}",
        initial_tip,
        final_tip
    );
}

/// Test that pruning at height 0 is a no-op and doesn't break anything.
#[test]
fn pruning_at_zero_is_noop() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive until we have some commits
    for _ in 0..200 {
        harness.step_once().expect("step_once failed");
        if let Some(tip) = harness.ledger().tip_height() {
            if tip >= 2 {
                break;
            }
        }
    }

    let tip_before = harness.ledger().tip_height();
    let node_commit_count_before = harness.node().commit_count();
    let node_block_count_before = harness.node().block_store_count();

    // Prune at height 0 (should be a no-op)
    harness.prune_below_height(0);

    // Everything should be unchanged
    assert_eq!(harness.ledger().tip_height(), tip_before);
    assert_eq!(harness.node().commit_count(), node_commit_count_before);
    assert_eq!(harness.node().block_store_count(), node_block_count_before);
}