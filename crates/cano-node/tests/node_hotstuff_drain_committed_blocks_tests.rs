//! Integration tests for `drain_committed_blocks()` in `NodeHotstuffHarness`.
//!
//! These tests verify that:
//! - `drain_committed_blocks()` returns an empty Vec initially
//! - Each committed block is returned exactly once (handle-once semantics)
//! - The returned proposals match those in the block store

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
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
// Integration Tests
// ============================================================================

/// Test that `drain_committed_blocks()` returns an empty Vec initially.
///
/// Scenario:
/// 1. Build a single-node harness
/// 2. Call `drain_committed_blocks()` immediately
/// 3. Assert that it returns an empty Vec
#[test]
fn drain_committed_blocks_is_initially_empty() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create harness");

    // Call drain_committed_blocks immediately (before any steps)
    let drained = harness.drain_committed_blocks().expect("drain failed");
    assert!(
        drained.is_empty(),
        "Expected empty drain initially, got {} blocks",
        drained.len()
    );
}

/// Test that `drain_committed_blocks()` returns each commit exactly once.
///
/// Scenario:
/// 1. Build a single-node harness
/// 2. Step until we see some commits
/// 3. First drain should return the commits in ascending height order
/// 4. Second drain (without more steps) should return empty
#[test]
fn drain_committed_blocks_returns_commits_once() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create harness");

    // Step the harness until we observe a commit
    for _ in 0..200 {
        harness.step_once().expect("step_once failed");
        if harness.committed_height().is_some() {
            break;
        }
    }

    // First drain: should return the commits
    let first = harness.drain_committed_blocks().expect("drain failed");
    assert!(
        !first.is_empty(),
        "Expected at least one committed block after stepping"
    );

    // Verify heights are in ascending order
    let first_heights: Vec<u64> = first.iter().map(|c| c.height).collect();
    assert!(
        first_heights.windows(2).all(|w| w[0] <= w[1]),
        "Heights should be in ascending order: {:?}",
        first_heights
    );

    // Second drain (without more steps): should be empty
    let second = harness.drain_committed_blocks().expect("drain failed");
    assert!(
        second.is_empty(),
        "Second drain should see no new commits, got {} blocks",
        second.len()
    );
}

/// Test that drained proposals match those in the block store.
///
/// Scenario:
/// 1. Build a single-node harness
/// 2. Step until we see commits
/// 3. Drain committed blocks
/// 4. For each drained block, verify the proposal matches the block store
#[test]
fn drain_committed_blocks_yields_proposals_matching_store() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create harness");

    // Step the harness until we observe a commit
    for _ in 0..200 {
        harness.step_once().expect("step_once failed");
        if harness.committed_height().is_some() {
            break;
        }
    }

    // Drain committed blocks
    let drained = harness.drain_committed_blocks().expect("drain failed");

    // Verify that each drained block's proposal matches the block store
    let store = harness.block_store();
    for c in &drained {
        let stored = store.get(&c.block_id).expect("missing proposal in store");
        // Compare the dereferenced Arc values (both are Arc<BlockProposal>)
        assert_eq!(
            *stored.proposal, *c.proposal,
            "Proposal mismatch for block at height {}",
            c.height
        );
    }
}

/// Test that subsequent drains return new commits after more steps.
///
/// Scenario:
/// 1. Build a single-node harness
/// 2. Step until we see commits, then drain
/// 3. Step some more
/// 4. Drain again - should return only the new commits
#[test]
fn drain_committed_blocks_returns_only_new_commits() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create harness");

    // Step the harness until we observe a commit
    for _ in 0..200 {
        harness.step_once().expect("step_once failed");
        if harness.committed_height().is_some() {
            break;
        }
    }

    // First drain
    let first = harness.drain_committed_blocks().expect("drain failed");
    let first_max_height = first.iter().map(|c| c.height).max();

    // Continue stepping to potentially get more commits
    let initial_commit_count = harness.commit_count();
    for _ in 0..100 {
        harness.step_once().expect("step_once failed");
    }

    // Second drain should only contain blocks with height > first_max_height
    let second = harness.drain_committed_blocks().expect("drain failed");

    // All heights in second drain should be greater than first_max_height (if any)
    if let Some(max_h) = first_max_height {
        for c in &second {
            assert!(
                c.height > max_h,
                "Second drain should only have heights > {}, got {}",
                max_h,
                c.height
            );
        }
    }

    // If we got more commits, second should not be empty
    if harness.commit_count() > initial_commit_count {
        assert!(
            !second.is_empty(),
            "Expected new commits in second drain after more steps"
        );
    }
}