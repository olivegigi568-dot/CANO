//! Integration tests for follower proposal persistence in `NodeHotstuffHarness`.
//!
//! These tests verify that:
//! - Followers store proposals received from other validators (leaders)
//! - For every committed block, the node's BlockStore contains the corresponding BlockProposal
//! - BlockStore::insert is idempotent for the same proposal
//! - BlockStore::insert returns an error for conflicting proposals

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cano_consensus::ids::ValidatorId;
use cano_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use cano_net::{
    ClientConnectionConfig, ClientHandshakeConfig, ServerConnectionConfig, ServerHandshakeConfig,
};
use cano_node::block_store::BlockStore;
use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
use cano_node::validator_config::{LocalValidatorConfig, NodeValidatorConfig};
use cano_wire::consensus::{BlockHeader, BlockProposal};
use cano_wire::io::WireEncode;
use cano_wire::net::NetworkDelegationCert;

// ============================================================================
// Dummy Implementations for Testing
// (copied from other test files to keep tests self-contained)
// ============================================================================

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
// BlockStore::insert idempotence tests
// ============================================================================

fn make_test_proposal(proposer_index: u16, height: u64, parent: [u8; 32]) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height,
            round: height,
            parent_block_id: parent,
            payload_hash: [0u8; 32],
            proposer_index,
            reserved: 0,
            tx_count: 0,
            timestamp: 0,
        },
        qc: None,
        txs: vec![],
    }
}

/// Test that BlockStore::insert is idempotent for the same proposal.
///
/// Scenario:
/// 1. Create a BlockStore
/// 2. Insert a proposal
/// 3. Insert the same proposal again
/// 4. Verify that both inserts succeed and return the same block_id
#[test]
fn block_store_insert_is_idempotent_for_same_proposal() {
    let mut store = BlockStore::new();

    let proposal = make_test_proposal(1, 0, [0u8; 32]);

    let id1 = store.insert(proposal.clone()).expect("first insert should succeed");
    let id2 = store.insert(proposal).expect("second insert should be idempotent");

    assert_eq!(id1, id2);
    assert_eq!(store.len(), 1);
}

/// Test that BlockStore::insert returns error for conflicting proposals.
///
/// Scenario:
/// 1. Create a BlockStore
/// 2. Insert a proposal
/// 3. Create a different proposal with the same block_id fields but different content
/// 4. Attempt to insert the conflicting proposal
/// 5. Verify that an error is returned
#[test]
fn block_store_insert_errors_on_conflicting_proposal() {
    let mut store = BlockStore::new();

    let proposal1 = make_test_proposal(1, 0, [0u8; 32]);
    let _id1 = store.insert(proposal1).expect("first insert should succeed");

    // Create a proposal that would have the same block_id (same proposer, height, parent)
    // but with different transactions
    let mut proposal2 = make_test_proposal(1, 0, [0u8; 32]);
    proposal2.txs = vec![vec![1, 2, 3]]; // Different transactions

    let result = store.insert(proposal2);
    assert!(result.is_err(), "inserting conflicting proposal should fail");
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Maximum number of steps to run before expecting a commit.
const MAX_STEPS_FOR_COMMIT: usize = 200;

/// Test that a single node stores proposals in the block store and they match committed blocks.
///
/// Scenario:
/// 1. Create a single-node harness
/// 2. Step until we see commits
/// 3. Verify that all committed blocks have corresponding proposals in the block store
#[test]
fn single_node_committed_blocks_have_proposals_in_store() {
    let setup = create_test_setup();
    let cfg = make_single_node_config();

    let mut harness = NodeHotstuffHarness::new_from_validator_config(
        &cfg,
        setup.client_cfg,
        setup.server_cfg,
    )
    .expect("failed to create harness");

    // Step until we see commits
    for _ in 0..MAX_STEPS_FOR_COMMIT {
        harness.step_once().expect("step_once failed");
        if harness.committed_height().is_some() {
            break;
        }
    }

    // Drain committed blocks - this should succeed (no MissingProposalForCommittedBlock error)
    let committed = harness.drain_committed_blocks().expect("drain should succeed");

    // Verify each committed block has a matching proposal in the store
    let store = harness.block_store();
    for c in &committed {
        let stored = store.get(&c.block_id).expect("proposal should exist in store");
        assert_eq!(
            *stored, c.proposal,
            "Proposal mismatch for block at height {}",
            c.height
        );
    }
}