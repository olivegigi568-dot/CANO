use std::sync::Arc;

use cano_system::KeysetProgram;
use cano_system::keyset_program::KEYSET_PROGRAM_ID;
use cano_types::{AccountId, ProgramId, KeysetAccount};
use cano_wire::tx::Transaction;
use cano_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use cano_wire::io::WireEncode;
use cano_ledger::{InMemoryAccountStore, ExecutionContext, AccountStore, Program};
use cano_serde::StateDecode;
use cano_crypto::{CryptoProvider, StaticCryptoProvider};
use cano_ledger::ExecutionError;

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn empty_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(StaticCryptoProvider::new())
}

fn base_tx(program_id: ProgramId, call_data: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(),
        program_id,
        call_data,
        auths: Vec::new(),
    }
}

#[test]
fn keyset_create_creates_account() {
    let keyset_id = dummy_account_id(0xEE);

    let entries = vec![
        WireKeyEntry {
            suite_id: 0x01,
            weight: 100,
            pubkey_bytes: vec![1, 2, 3],
        },
        WireKeyEntry {
            suite_id: 0x02,
            weight: 50,
            pubkey_bytes: vec![4, 5],
        },
    ];

    let call = CreateKeysetCall {
        version: 1,
        target_id: keyset_id,
        threshold: 120,
        entries,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_KEYSET_CREATE);

    let tx = base_tx(KEYSET_PROGRAM_ID, call_data);

    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    let program = KeysetProgram::new();
    program.execute(&mut ctx, &tx).expect("execute ok");

    let stored = store.get(&keyset_id).expect("keyset account");
    assert_eq!(stored.id, keyset_id);
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode KeysetAccount");
    assert!(slice.is_empty());

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.threshold, 120);
    assert_eq!(decoded.entries.len(), 2);
    assert_eq!(decoded.entries[0].suite_id, 0x01);
    assert_eq!(decoded.entries[0].weight, 100);
    assert_eq!(decoded.entries[0].pubkey_bytes, vec![1, 2, 3]);
    assert_eq!(decoded.entries[1].suite_id, 0x02);
    assert_eq!(decoded.entries[1].weight, 50);
    assert_eq!(decoded.entries[1].pubkey_bytes, vec![4, 5]);
}

#[test]
fn keyset_create_fails_if_exists() {
    let keyset_id = dummy_account_id(0xEF);

    let entries = vec![
        WireKeyEntry {
            suite_id: 0x01,
            weight: 10,
            pubkey_bytes: vec![9],
        },
    ];

    let call = CreateKeysetCall {
        version: 1,
        target_id: keyset_id,
        threshold: 10,
        entries,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let tx = base_tx(KEYSET_PROGRAM_ID, call_data);

    let mut store = InMemoryAccountStore::new();
    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    let program = KeysetProgram::new();

    // First execution: ok.
    program.execute(&mut ctx, &tx).expect("first create ok");

    // Second execution: must fail.
    let err = program.execute(&mut ctx, &tx).expect_err("second create must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("keyset account already exists"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}