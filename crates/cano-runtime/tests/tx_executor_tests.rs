use std::sync::Arc;

use cano_runtime::TxExecutor;
use cano_types::{AccountId, ProgramId, KeysetAccount, Hash32};
use cano_wire::tx::{Transaction, TxAccountMeta};
use cano_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use cano_wire::io::WireEncode;
use cano_system::keyset_program::KEYSET_PROGRAM_ID;
use cano_ledger::{AccountStore, InMemoryAccountStore, ExecutionError};
use cano_serde::StateDecode;
use cano_crypto::{CryptoProvider, SignatureSuite, KemSuite, AeadSuite, CryptoError};

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn dummy_program_id(byte: u8) -> ProgramId {
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

    // No auths for this test as the keyset doesn't exist yet.
    // verify_transaction_auth returns Ok if auths is empty.
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

#[test]
fn executor_runs_keyset_create_end_to_end() {
    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let executor: TxExecutor<InMemoryAccountStore> = TxExecutor::new();

    let keyset_id = dummy_account_id(0xEE);
    let tx = build_keyset_create_tx(keyset_id);

    executor.execute_transaction(&mut store, crypto, &tx).expect("execute_transaction should succeed");

    // Check that the keyset account now exists and decodes correctly.
    let stored = store.get(&keyset_id).expect("keyset account should exist");
    assert_eq!(stored.id, keyset_id);
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode keyset account");
    assert!(slice.is_empty());

    assert_eq!(decoded.threshold, 50);
    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(decoded.entries[0].suite_id, 1);
    assert_eq!(decoded.entries[0].weight, 100);
    assert_eq!(decoded.entries[0].pubkey_bytes, vec![1, 2, 3]);
}

#[test]
fn executor_unknown_program_id_fails() {
    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let executor: TxExecutor<InMemoryAccountStore> = TxExecutor::new();

    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(),
        program_id: dummy_program_id(0xFF), // unknown
        call_data: Vec::new(),
        auths: Vec::new(),
    };

    let err = executor.execute_transaction(&mut store, crypto, &tx).expect_err("must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("unknown program_id"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}