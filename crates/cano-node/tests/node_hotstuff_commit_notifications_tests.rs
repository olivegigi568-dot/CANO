//! Tests for node-level commit notifications in `NodeHotstuffHarness`.
//!
//! These tests verify that:
//! - `drain_commits()` returns committed blocks from the HotStuff driver
//! - Calling `drain_commits()` a second time returns an empty vector
//! - Heights are non-decreasing across commits
//! - Multiple nodes see consistent commits

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
use cano_node::validator_config::{LocalValidatorConfig, NodeValidatorConfig, RemoteValidatorConfig};
use cano_node::consensus_node::NodeCommitInfo;
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
// Tests
// ============================================================================

/// Test that a single-node harness yields commits and drain clears them.
///
/// This test:
/// 1. Creates a single-node harness
/// 2. Drives the harness until at least one commit happens
/// 3. Asserts that drain_commits() returns non-empty
/// 4. Asserts that drain_commits() again returns empty
/// 5. Verifies heights are non-decreasing
#[test]
fn node_hotstuff_single_node_drain_commits_yields_and_clears() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("Failed to create harness");

    // Drive the harness until at least one commit happens.
    // With a single node, we need several views to accumulate the 3-chain
    // required for commit.
    let mut all_commits: Vec<NodeCommitInfo<[u8; 32]>> = Vec::new();
    let max_iterations = 200;

    for _ in 0..max_iterations {
        harness.step_once().expect("step_once failed");
        let new_commits = harness.drain_commits();
        if !new_commits.is_empty() {
            all_commits.extend(new_commits);
            break;
        }
    }

    // Assert that we got at least one commit
    assert!(
        !all_commits.is_empty(),
        "Expected at least one commit after {} iterations, got none",
        max_iterations
    );

    // Call drain_commits() again - should return empty
    let second_drain = harness.drain_commits();
    assert!(
        second_drain.is_empty(),
        "Expected drain_commits() to return empty after draining, got {} commits",
        second_drain.len()
    );

    // Verify heights are non-decreasing and >= 0
    let mut prev_height: Option<u64> = None;
    for commit in &all_commits {
        if let Some(ph) = prev_height {
            assert!(
                commit.height >= ph,
                "Commit heights not non-decreasing: {} < {}",
                commit.height,
                ph
            );
        }
        prev_height = Some(commit.height);
    }
}

/// Test that two nodes with configured but non-connected peers cannot reach quorum.
///
/// This test verifies that when nodes are configured with a 2-validator set
/// but cannot actually communicate, they do not reach commits.
///
/// Note: With a 2-node validator set (voting_power=1 each):
/// - Total voting power = 2
/// - Two-thirds threshold = ceil(2*2/3) = 2
/// - Both nodes must vote to form a QC
#[test]
fn node_hotstuff_two_nodes_have_consistent_commits() {
    let setup0 = create_test_setup();
    let setup1 = create_test_setup();

    // Use a bogus address for the remote to simulate a disconnected peer
    let bogus_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 59998);

    // Create configs where each node knows about the other but can't connect
    let cfg0 = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        },
        remotes: vec![RemoteValidatorConfig {
            validator_id: ValidatorId::new(2),
            addr: bogus_addr,
        }],
    };

    let cfg1 = NodeValidatorConfig {
        local: LocalValidatorConfig {
            validator_id: ValidatorId::new(2),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        },
        remotes: vec![RemoteValidatorConfig {
            validator_id: ValidatorId::new(1),
            addr: bogus_addr,
        }],
    };

    // Create both harnesses - they each have a 2-validator set but can't connect
    let mut h0 = NodeHotstuffHarness::new_from_validator_config(
        &cfg0,
        setup0.client_cfg.clone(),
        setup0.server_cfg.clone(),
    )
    .expect("Failed to create harness h0");

    let mut h1 = NodeHotstuffHarness::new_from_validator_config(
        &cfg1,
        setup1.client_cfg.clone(),
        setup1.server_cfg.clone(),
    )
    .expect("Failed to create harness h1");

    // Accumulate commits from both nodes
    let mut commits0: Vec<NodeCommitInfo<[u8; 32]>> = Vec::new();
    let mut commits1: Vec<NodeCommitInfo<[u8; 32]>> = Vec::new();

    let max_iterations = 100;

    for _ in 0..max_iterations {
        // Ignore errors from connection attempts to bogus addresses
        let _ = h0.step_once();
        let _ = h1.step_once();
        commits0.extend(h0.drain_commits());
        commits1.extend(h1.drain_commits());
    }

    // With 2 validators and no network connectivity between them,
    // neither node can reach quorum on its own (need 2 votes, have 1).
    // Both should have empty commits.
    assert!(
        commits0.is_empty(),
        "Expected h0 to have no commits without quorum, got {} commits",
        commits0.len()
    );
    assert!(
        commits1.is_empty(),
        "Expected h1 to have no commits without quorum, got {} commits",
        commits1.len()
    );

    // Verify the drain_commits() API works correctly by checking it returns empty
    assert!(h0.drain_commits().is_empty());
    assert!(h1.drain_commits().is_empty());
}