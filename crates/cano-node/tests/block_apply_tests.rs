use std::sync::Arc;

use cano_node::{Node, NodeError};
use cano_consensus::{ValidatorInfo, ValidatorSet, HotStuffState, BlockVerifyConfig, VoteDecision, ConsensusNodeError, ConsensusVerifyError};
use cano_wire::consensus::{BlockHeader, BlockProposal};
use cano_wire::tx::{Transaction, TxAccountMeta};
use cano_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use cano_wire::io::WireEncode;
use cano_ledger::{AccountStore, InMemoryAccountStore};
use cano_types::{AccountId, KeysetAccount, Hash32};
use cano_system::keyset_program::KEYSET_PROGRAM_ID;
use cano_serde::StateDecode;
use cano_crypto::{CryptoProvider, SignatureSuite, KemSuite, AeadSuite, CryptoError};

fn dummy_account_id(b: u8) -> AccountId {
    [b; 32]
}

/// A dummy SignatureSuite that always verifies successfully.
struct AcceptAllSignatureSuite;

impl SignatureSuite for AcceptAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        0
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A CryptoProvider for tests that returns AcceptAllSignatureSuite for suite_id 1.
struct TestCryptoProvider {
    sig_suite: AcceptAllSignatureSuite,
}

impl TestCryptoProvider {
    fn new() -> Self {
        Self {
            sig_suite: AcceptAllSignatureSuite,
        }
    }
}

impl CryptoProvider for TestCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        if suite_id == 1 {
            Some(&self.sig_suite)
        } else {
            None
        }
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn AeadSuite> {
        None
    }
}

fn test_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(TestCryptoProvider::new())
}

fn small_validator_set() -> ValidatorSet {
    ValidatorSet {
        validators: vec![
            ValidatorInfo {
                validator_id: 0,
                suite_id: 1,
                consensus_pk: vec![0],
                voting_power: 1,
            },
        ],
        qc_threshold: 1,
    }
}

fn build_keyset_create_tx(target_id: AccountId) -> Transaction {
    let entries = vec![
        WireKeyEntry {
            suite_id: 1,
            weight: 100,
            pubkey_bytes: vec![1, 2, 3],
        },
    ];

    let call = CreateKeysetCall {
        version: 1,
        target_id,
        threshold: 50,
        entries,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_KEYSET_CREATE);

    let accounts = vec![
        TxAccountMeta {
            account_id: target_id,
            flags: 0b0000_0011, // signer + writable
            access_hint: 0,
            reserved0: [0u8; 2],
        },
    ];

    // No auths for keyset creation: the keyset account doesn't exist yet,
    // so authentication against it is impossible. verify_transaction_auth
    // returns Ok when auths is empty.
    let auths = Vec::new();

    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts,
        program_id: KEYSET_PROGRAM_ID,
        call_data,
        auths,
    }
}

fn build_proposal_with_txs(txs: &[Transaction]) -> BlockProposal {
    // Encode each tx into a blob.
    let mut tx_blobs = Vec::with_capacity(txs.len());
    for tx in txs {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        tx_blobs.push(buf);
    }

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: tx_blobs.len() as u32,
            timestamp: 1234567890,
        },
        qc: None,
        txs: tx_blobs,
        signature: vec![],
    }
}

#[test]
fn node_applies_block_and_executes_transactions() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    let keyset_id = dummy_account_id(0xEE);
    let tx = build_keyset_create_tx(keyset_id);
    let proposal = build_proposal_with_txs(&[tx]);

    let outcome = node
        .apply_block(&mut store, &proposal)
        .expect("block apply should succeed");

    assert_eq!(outcome.height, 10);
    assert_eq!(outcome.round, 0);
    assert_eq!(outcome.block_id, [0xAB; 32]);
    assert!(outcome.exec_result.all_succeeded());
    assert!(matches!(outcome.vote_decision, VoteDecision::ShouldVote { height: 10, round: 0 }));

    // Check that the keyset account was created.
    let stored = store.get(&keyset_id).expect("keyset account should exist");
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode KeysetAccount");
    assert!(slice.is_empty());
    assert_eq!(decoded.entries.len(), 1);
}

#[test]
fn node_rejects_block_when_tx_count_exceeds_max() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    // Very small max_tx_count to trigger overflow
    let cfg = BlockVerifyConfig { max_tx_count: 1 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create proposal with 2 txs, exceeding max_tx_count of 1
    let keyset_id1 = dummy_account_id(0xA1);
    let keyset_id2 = dummy_account_id(0xA2);
    let tx1 = build_keyset_create_tx(keyset_id1);
    let tx2 = build_keyset_create_tx(keyset_id2);
    let proposal = build_proposal_with_txs(&[tx1, tx2]);

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with consensus verification error for TxCountOverflow
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Consensus(ConsensusNodeError::Verify(ConsensusVerifyError::TxCountOverflow)) => {
            // expected
        }
        other => panic!("expected TxCountOverflow error, got {:?}", other),
    }

    // Ensure store was not modified
    assert!(store.get(&keyset_id1).is_none());
    assert!(store.get(&keyset_id2).is_none());
}

#[test]
fn node_rejects_block_with_malformed_tx_blob() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create a proposal with a malformed tx blob
    let malformed_blob = vec![0xFF, 0xFF, 0xFF]; // garbage bytes

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 1,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![malformed_blob],
        signature: vec![],
    };

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with wire decoding error
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Wire(msg) => {
            assert!(msg.contains("failed to decode transaction"), "expected decode failure, got: {}", msg);
        }
        other => panic!("expected Wire error, got {:?}", other),
    }
}

#[test]
fn node_rejects_block_with_extra_bytes_after_tx() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create a valid tx, then append extra bytes
    let keyset_id = dummy_account_id(0xEE);
    let tx = build_keyset_create_tx(keyset_id);
    let mut blob = Vec::new();
    tx.encode(&mut blob);
    blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra bytes

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 1,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![blob],
        signature: vec![],
    };

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with wire decoding error about extra bytes
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Wire(msg) => {
            assert!(msg.contains("extra bytes"), "expected extra bytes error, got: {}", msg);
        }
        other => panic!("expected Wire error, got {:?}", other),
    }
}