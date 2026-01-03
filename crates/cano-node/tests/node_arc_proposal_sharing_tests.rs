//! Tests for Arc<BlockProposal> sharing between BlockStore and InMemoryLedger.
//!
//! These tests verify that:
//! - BlockStore and InMemoryLedger share the same `Arc<BlockProposal>` instances
//! - No additional `BlockProposal` clones occur during the commit flow
//! - `Arc::ptr_eq` confirms pointer equality between stored and ledger proposals

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
// Helper: configs for a small cluster
// ============================================================================

/// Create a single-node validator configuration.
fn make_single_node_config() -> NodeValidatorConfig {
    NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        },
        remotes: vec![],
    }
}

// ============================================================================
// Arc Sharing Tests
// ============================================================================

/// Test that committed blocks share the same `Arc<BlockProposal>` between
/// the BlockStore and the InMemoryLedger.
///
/// This verifies that:
/// 1. When a block is committed, the proposal Arc in the ledger is the same
///    as the Arc in the block store (pointer equality via `Arc::ptr_eq`).
/// 2. No additional BlockProposal clones occur during the commit flow.
#[test]
fn committed_blocks_share_proposal_arc_between_block_store_and_ledger() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node harness");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive the node until it has at least one commit.
    const MAX_STEPS: usize = 400;
    for _ in 0..MAX_STEPS {
        harness.step_once().expect("step_once failed");
        if harness.ledger().tip_height().is_some() {
            break;
        }
    }

    let tip = harness
        .ledger()
        .tip_height()
        .expect("ledger had no commits after max steps");

    // For each height up to tip, the proposal Arc in the ledger should
    // be pointer-equal to the proposal Arc in the block store.
    let node = harness.node();
    let store = node.block_store();
    let ledger = harness.ledger();

    for (height, info) in ledger.iter() {
        assert!(*height <= tip);

        let stored = store
            .get(&info.block_id)
            .unwrap_or_else(|| panic!("missing stored block for height {}", height));

        // Both sides now hold Arc<BlockProposal>. They should point to the same allocation.
        assert!(
            Arc::ptr_eq(&stored.proposal, &info.proposal),
            "proposal Arc not shared between block store and ledger at height {}",
            height
        );
    }
}

/// Test that multiple ledger entries from consecutive commits all share
/// their respective Arc<BlockProposal> with the BlockStore.
#[test]
fn multiple_committed_blocks_all_share_arc_with_store() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let node = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create node harness");
    let ledger = InMemoryLedger::<[u8; 32]>::new();

    let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);

    // Drive the node until we have multiple commits
    const MAX_STEPS: usize = 500;
    let target_commits = 3;

    for _ in 0..MAX_STEPS {
        harness.step_once().expect("step_once failed");
        if harness.ledger().len() >= target_commits {
            break;
        }
    }

    let ledger_len = harness.ledger().len();
    assert!(
        ledger_len >= 1,
        "expected at least 1 commit, got {}",
        ledger_len
    );

    let node = harness.node();
    let store = node.block_store();
    let ledger = harness.ledger();

    let mut checked = 0;
    for (_height, info) in ledger.iter() {
        let stored = store
            .get(&info.block_id)
            .expect("block store missing proposal");

        // Verify Arc pointer equality
        assert!(
            Arc::ptr_eq(&stored.proposal, &info.proposal),
            "Arc not shared at block_id {:?}",
            info.block_id
        );
        checked += 1;
    }

    assert!(checked >= 1, "no blocks were checked");
}
