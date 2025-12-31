use std::sync::Arc;

use cano_runtime::{BlockExecutor, TxApplyResult};
use cano_types::{AccountId, KeysetAccount};
use cano_wire::tx::{Transaction, TxAccountMeta};
use cano_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use cano_wire::io::WireEncode;
use cano_system::keyset_program::KEYSET_PROGRAM_ID;
use cano_system::validator_program::VALIDATOR_PROGRAM_ID;
use cano_ledger::{AccountStore, InMemoryAccountStore};
use cano_serde::StateDecode;
use cano_crypto::{CryptoProvider, SignatureSuite, KemSuite, AeadSuite, CryptoError};
use cano_types::Hash32;

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
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

fn empty_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(TestCryptoProvider::new())
}

/// Build a minimal Transaction targeting KEYSET_PROGRAM_ID with one auth referencing
/// a keyset account that will be created.
///
/// In this test, we rely on AcceptAllSignatureSuite to accept any signature bytes.
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

    // accounts[0] will be the keyset account id referenced by TxAuth.account_index = 0.
    let accounts = vec![
        TxAccountMeta {
            account_id: target_id,
            flags: 0b0000_0011, // signer + writable (advisory)
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

/// Build a deliberately invalid validator transaction with an invalid opcode.
fn build_invalid_validator_tx() -> Transaction {
    let accounts = Vec::new();

    let call_data = vec![0xFF]; // invalid opcode for ValidatorProgram

    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x02),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts,
        program_id: VALIDATOR_PROGRAM_ID,
        call_data,
        // No auths needed: this tx is designed to fail due to invalid opcode,
        // not authentication. verify_transaction_auth returns Ok when auths is empty.
        auths: Vec::new(),
    }
}

#[test]
fn block_executor_applies_multiple_txs_and_reports_results() {
    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let executor: BlockExecutor<InMemoryAccountStore> = BlockExecutor::new();

    let keyset_id = dummy_account_id(0xEE);
    let tx1 = build_keyset_create_tx(keyset_id);
    let tx2 = build_invalid_validator_tx();

    let result = executor.execute_block(&mut store, crypto, &[tx1, tx2]);

    assert_eq!(result.tx_results.len(), 2);
    assert!(matches!(result.tx_results[0], TxApplyResult::Success));
    assert!(matches!(result.tx_results[1], TxApplyResult::Failed(_)));
    assert!(!result.all_succeeded());

    // Check that state from the successful tx is present.
    let stored = store.get(&keyset_id).expect("keyset account must exist");
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode KeysetAccount");
    assert!(slice.is_empty());
    assert_eq!(decoded.entries.len(), 1);
}

#[test]
fn block_executor_all_successes_sets_all_succeeded_true() {
    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let executor: BlockExecutor<InMemoryAccountStore> = BlockExecutor::new();

    let keyset_id1 = dummy_account_id(0xA1);
    let keyset_id2 = dummy_account_id(0xA2);

    let tx1 = build_keyset_create_tx(keyset_id1);
    let tx2 = build_keyset_create_tx(keyset_id2);

    let result = executor.execute_block(&mut store, crypto, &[tx1, tx2]);

    assert_eq!(result.tx_results.len(), 2);
    assert!(result.all_succeeded());
    assert!(matches!(result.tx_results[0], TxApplyResult::Success));
    assert!(matches!(result.tx_results[1], TxApplyResult::Success));

    assert!(store.get(&keyset_id1).is_some());
    assert!(store.get(&keyset_id2).is_some());
}