use std::sync::Arc;

use cano_crypto::{CryptoError, CryptoProvider, SignatureSuite};
use cano_ledger::auth::verify_transaction_auth;
use cano_ledger::{Account, ExecutionError, InMemoryAccountStore, AccountStore};
use cano_serde::StateEncode;
use cano_types::{AccountId, Hash32, KeysetAccount, KeysetEntry, ProgramId};
use cano_wire::tx::{Transaction, TxAccountMeta, TxAuth};

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn dummy_program_id(byte: u8) -> ProgramId {
    [byte; 32]
}

/// A dummy SignatureSuite that always returns Ok(()).
struct AcceptAllSignatureSuite;

impl SignatureSuite for AcceptAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        0 // Variable/unknown
    }

    fn signature_len(&self) -> usize {
        0 // Variable/unknown
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A dummy SignatureSuite that always returns an error.
struct RejectAllSignatureSuite;

impl SignatureSuite for RejectAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        2
    }

    fn public_key_len(&self) -> usize {
        0
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidSignature)
    }
}

/// A CryptoProvider that returns AcceptAllSignatureSuite for suite_id 1,
/// RejectAllSignatureSuite for suite_id 2, and None for others.
struct TestCryptoProvider {
    accept_suite: AcceptAllSignatureSuite,
    reject_suite: RejectAllSignatureSuite,
}

impl TestCryptoProvider {
    fn new() -> Self {
        Self {
            accept_suite: AcceptAllSignatureSuite,
            reject_suite: RejectAllSignatureSuite,
        }
    }
}

impl CryptoProvider for TestCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        match suite_id {
            1 => Some(&self.accept_suite),
            2 => Some(&self.reject_suite),
            _ => None,
        }
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::AeadSuite> {
        None
    }
}

fn make_keyset_account(suite_id: u8, pubkey_bytes: Vec<u8>) -> KeysetAccount {
    // In test code, we expect small pubkey_bytes that fit in u16.
    assert!(pubkey_bytes.len() <= u16::MAX as usize, "pubkey_bytes too large for test");
    let pubkey_len = pubkey_bytes.len() as u16;
    let entry = KeysetEntry {
        suite_id,
        weight: 1,
        reserved0: [0u8; 1],
        pubkey_len,
        pubkey_bytes,
    };
    KeysetAccount {
        version: 1,
        reserved0: [0u8; 3],
        threshold: 1,
        entry_count: 1, // matches entries.len() below
        reserved1: [0u8; 4],
        entries: vec![entry],
    }
}

fn make_transaction(
    accounts: Vec<TxAccountMeta>,
    auths: Vec<TxAuth>,
) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000,
        accounts,
        program_id: dummy_program_id(0x99),
        call_data: Vec::new(),
        auths,
    }
}

#[test]
fn verify_transaction_auth_success_with_keyset_account() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with one entry (suite_id 1).
    let keyset = make_keyset_account(1, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    // Build a Transaction with one account meta and one auth.
    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA, 0xBB],
        }],
    );

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let result = verify_transaction_auth(&mut store, crypto, &tx);
    assert!(result.is_ok());
}

#[test]
fn verify_transaction_auth_empty_auths_succeeds() {
    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let tx = make_transaction(Vec::new(), Vec::new());

    let result = verify_transaction_auth(&mut store, crypto, &tx);
    assert!(result.is_ok());
}

#[test]
fn verify_transaction_auth_fails_on_bad_index() {
    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let tx = make_transaction(
        Vec::new(), // No accounts
        vec![TxAuth {
            account_index: 0, // Invalid, no accounts
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::InvalidCallData(msg) => assert!(msg.contains("account_index")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_missing_keyset() {
    let keyset_id = dummy_account_id(0xAA);
    let mut store = InMemoryAccountStore::new();
    // Do NOT add any account to the store

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::AccountNotFound => {}
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_wrong_suite_id() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 1
    let keyset = make_keyset_account(1, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    // Auth uses suite_id 99 which doesn't match the keyset entry (suite_id 1)
    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 99, // Not in keyset
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::InvalidCallData(msg) => assert!(msg.contains("suite_id")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_unknown_suite() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 99 (which the CryptoProvider doesn't support)
    let keyset = make_keyset_account(99, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 99, // Keyset has this, but CryptoProvider doesn't
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(msg) => assert!(msg.contains("suite")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_fails_on_invalid_signature() {
    let keyset_id = dummy_account_id(0xAA);

    // Build a KeysetAccount with suite_id 2 (RejectAllSignatureSuite)
    let keyset = make_keyset_account(2, vec![0x01, 0x02, 0x03]);

    let mut data = Vec::new();
    keyset.encode_state(&mut data);

    let mut store = InMemoryAccountStore::new();
    let account = Account::new(keyset_id, dummy_program_id(0x4B), 0, data);
    store.put(account).unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![TxAccountMeta {
        account_id: keyset_id,
        flags: 0b0000_0001,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let tx = make_transaction(
        accounts,
        vec![TxAuth {
            account_index: 0,
            suite_id: 2, // Uses RejectAllSignatureSuite
            reserved: 0,
            signature: vec![0xAA],
        }],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(msg) => assert!(msg.contains("verification")),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn verify_transaction_auth_multiple_auths_all_succeed() {
    let keyset_id1 = dummy_account_id(0xAA);
    let keyset_id2 = dummy_account_id(0xBB);

    // Build two KeysetAccounts
    let keyset1 = make_keyset_account(1, vec![0x01, 0x02, 0x03]);
    let keyset2 = make_keyset_account(1, vec![0x04, 0x05, 0x06]);

    let mut data1 = Vec::new();
    keyset1.encode_state(&mut data1);
    let mut data2 = Vec::new();
    keyset2.encode_state(&mut data2);

    let mut store = InMemoryAccountStore::new();
    store
        .put(Account::new(keyset_id1, dummy_program_id(0x4B), 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, dummy_program_id(0x4B), 0, data2))
        .unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![
        TxAccountMeta {
            account_id: keyset_id1,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
        TxAccountMeta {
            account_id: keyset_id2,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
    ];

    let tx = make_transaction(
        accounts,
        vec![
            TxAuth {
                account_index: 0,
                suite_id: 1,
                reserved: 0,
                signature: vec![0xAA],
            },
            TxAuth {
                account_index: 1,
                suite_id: 1,
                reserved: 0,
                signature: vec![0xBB],
            },
        ],
    );

    let result = verify_transaction_auth(&mut store, crypto, &tx);
    assert!(result.is_ok());
}

#[test]
fn verify_transaction_auth_multiple_auths_one_fails() {
    let keyset_id1 = dummy_account_id(0xAA);
    let keyset_id2 = dummy_account_id(0xBB);

    // keyset1 uses suite_id 1 (AcceptAll), keyset2 uses suite_id 2 (RejectAll)
    let keyset1 = make_keyset_account(1, vec![0x01, 0x02, 0x03]);
    let keyset2 = make_keyset_account(2, vec![0x04, 0x05, 0x06]);

    let mut data1 = Vec::new();
    keyset1.encode_state(&mut data1);
    let mut data2 = Vec::new();
    keyset2.encode_state(&mut data2);

    let mut store = InMemoryAccountStore::new();
    store
        .put(Account::new(keyset_id1, dummy_program_id(0x4B), 0, data1))
        .unwrap();
    store
        .put(Account::new(keyset_id2, dummy_program_id(0x4B), 0, data2))
        .unwrap();

    let crypto = Arc::new(TestCryptoProvider::new()) as Arc<dyn CryptoProvider>;

    let accounts = vec![
        TxAccountMeta {
            account_id: keyset_id1,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
        TxAccountMeta {
            account_id: keyset_id2,
            flags: 0b0000_0001,
            access_hint: 0,
            reserved0: [0u8; 2],
        },
    ];

    let tx = make_transaction(
        accounts,
        vec![
            TxAuth {
                account_index: 0,
                suite_id: 1, // Will succeed
                reserved: 0,
                signature: vec![0xAA],
            },
            TxAuth {
                account_index: 1,
                suite_id: 2, // Will fail
                reserved: 0,
                signature: vec![0xBB],
            },
        ],
    );

    let err = verify_transaction_auth(&mut store, crypto, &tx).expect_err("should fail");
    match err {
        ExecutionError::CryptoError(_) => {}
        other => panic!("unexpected error: {:?}", other),
    }
}