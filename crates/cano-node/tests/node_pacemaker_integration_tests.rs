//! Integration tests for pacemaker behavior in NodeHotstuffHarness.
//!
//! These tests verify that:
//! - The pacemaker correctly gates proposal timing
//! - Only one proposal per view is allowed
//! - Commits still happen with pacemaker-gated proposals (liveness preserved)

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
// (copied from other test files to keep tests self-contained)
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
// Pacemaker Integration Tests
// ============================================================================

/// Test that the pacemaker does not allow more than one proposal per view.
///
/// In a single-node setup, the node is always leader. The pacemaker should
/// ensure that only one proposal is generated per view. We track this by
/// observing the block_store_count() after each view.
///
/// With min_ticks_between_proposals = 1, the pacemaker will allow one proposal
/// on the first tick of each view, and subsequent ticks in the same view
/// should NOT trigger additional proposals.
#[test]
fn node_pacemaker_does_not_propose_twice_in_same_view() {
    let setup = create_test_setup();

    // Create a single-node configuration
    let cfg = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: vec![],
        },
        remotes: vec![],
    };

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("Failed to create harness");

    // In a single-node setup with no remotes:
    // - The node is always leader
    // - With min_ticks_between_proposals = 1, proposals are allowed on first tick
    // - The single node immediately forms QCs (since it has 100% voting power)
    // - View advances after each proposal + QC formation

    // Run the harness for multiple steps and count proposals
    // Since views advance rapidly in single-node mode, we'll verify that
    // the number of proposals equals the number of views we've seen.

    for _ in 0..50 {
        harness.step_once().expect("step_once failed");
    }

    let current_view = harness.current_view();
    let block_store_count = harness.block_store_count();

    // In a single-node setup:
    // - Each view produces exactly one proposal
    // - The view advances immediately after proposal + self-vote forms QC
    // - So block_store_count should equal the number of views we've gone through
    // - current_view represents the NEXT view to propose in

    // The block_store_count should be approximately equal to current_view
    // (one proposal per view that has completed)
    // Allow some tolerance for timing edge cases
    assert!(
        block_store_count as u64 <= current_view + 1,
        "Expected at most one proposal per view, but got {} proposals for {} views",
        block_store_count,
        current_view
    );

    // Also verify that the proposals are for different views by checking heights
    // (in BasicHotStuffEngine, height == view for proposals)
    let mut seen_heights = std::collections::HashSet::new();
    for (_block_id, stored) in harness.block_store().iter() {
        let height = stored.proposal.header.height;
        let was_new = seen_heights.insert(height);
        assert!(
            was_new,
            "Found duplicate proposal at height/view {}, pacemaker should prevent this",
            height
        );
    }
}

/// Test that commits still happen with pacemaker-gated proposals.
///
/// This test ensures that the pacemaker doesn't starve the leader and
/// liveness is preserved in a single-node setup.
#[test]
fn node_pacemaker_still_commits_in_single_node_setup() {
    let setup = create_test_setup();

    // Create a single-node configuration
    let cfg = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: vec![],
        },
        remotes: vec![],
    };

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("Failed to create harness");

    // Run the harness for many steps
    for _ in 0..100 {
        harness.step_once().expect("step_once failed");
    }

    // Verify that commits happened
    let commit_count = harness.commit_count();
    assert!(
        commit_count > 0,
        "Expected at least one commit with pacemaker-gated proposals, but got {}",
        commit_count
    );

    // Verify that committed height has advanced
    let committed_height = harness.committed_height();
    assert!(
        committed_height.is_some(),
        "Expected committed_height to be set after {} steps",
        100
    );

    let height = committed_height.unwrap();
    assert!(
        height >= 1,
        "Expected committed height >= 1, got {}",
        height
    );
}

/// Test that a single-node harness advances views with the pacemaker.
///
/// This verifies the basic integration: pacemaker allows proposals,
/// views advance, and the system makes progress.
#[test]
fn node_pacemaker_allows_view_advancement() {
    let setup = create_test_setup();

    let cfg = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            consensus_pk: vec![],
        },
        remotes: vec![],
    };

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("Failed to create harness");

    let initial_view = harness.current_view();
    assert_eq!(initial_view, 0, "Expected initial view to be 0");

    // Run several steps
    for _ in 0..20 {
        harness.step_once().expect("step_once failed");
    }

    let final_view = harness.current_view();
    assert!(
        final_view > initial_view,
        "Expected view to advance from {} but got {}",
        initial_view,
        final_view
    );
}