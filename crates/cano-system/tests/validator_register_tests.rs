use std::sync::Arc;

use cano_system::ValidatorProgram;
use cano_types::{AccountId, ValidatorRecord, ValidatorStatus};
use cano_wire::tx::{Transaction, TxAccountMeta};
use cano_wire::validator::RegisterValidatorCall;
use cano_wire::io::WireEncode;
use cano_serde::StateDecode;
use cano_ledger::{AccountStore, InMemoryAccountStore, ExecutionContext, ExecutionError, Program};
use cano_crypto::CryptoProvider;

// Dummy CryptoProvider for tests; we don't use crypto here.
struct DummyCryptoProvider;

impl CryptoProvider for DummyCryptoProvider {
    fn signature_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::SignatureSuite> {
        None
    }
    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::KemSuite> {
        None
    }
    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::AeadSuite> {
        None
    }
}

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

#[test]
fn register_validator_creates_validator_record_account() {
    let validator_id = dummy_account_id(0xAA);
    let owner_keyset_id = dummy_account_id(0xBB);

    // Build RegisterValidatorCall.
    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0x11, 0x22, 0x33],
        network_suite_id: 0x02,
        network_pk: vec![0x44, 0x55],
        stake: 1_000_000,
    };

    // Encode call_data.
    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    // Build a Transaction targeting VALIDATOR_PROGRAM_ID.
    let validator_program = ValidatorProgram::new();
    let program_id = ValidatorProgram::id();

    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 42,
        fee_limit: 1_000_000,
        accounts: vec![
            TxAccountMeta {
                account_id: validator_id,
                flags: 0b0000_0011, // signer + writable (advisory only for now)
                access_hint: 0b0000_0011,
                reserved0: [0u8; 2],
            }
        ],
        program_id,
        call_data,
        auths: Vec::new(), // auths not used yet
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    // Execute program.
    validator_program.execute(&mut ctx, &tx).expect("execute should succeed");

    // Check that the validator account exists and decodes correctly.
    let stored = store.get(&validator_id).expect("validator account created");
    assert_eq!(stored.id, validator_id);
    assert_eq!(stored.header.owner, program_id);

    let mut slice: &[u8] = &stored.data;
    let decoded = ValidatorRecord::decode_state(&mut slice).expect("decode ValidatorRecord");
    assert!(slice.is_empty());

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.status, ValidatorStatus::Active);
    assert_eq!(decoded.owner_keyset_id, owner_keyset_id);
    assert_eq!(decoded.consensus_suite_id, 0x01);
    assert_eq!(decoded.consensus_pk, vec![0x11, 0x22, 0x33]);
    assert_eq!(decoded.network_suite_id, 0x02);
    assert_eq!(decoded.network_pk, vec![0x44, 0x55]);
    assert_eq!(decoded.stake, 1_000_000);
    assert_eq!(decoded.last_slash_height, 0);
    assert!(decoded.ext_bytes.is_empty());
}

#[test]
fn register_validator_fails_if_already_exists() {
    let validator_id = dummy_account_id(0xCC);
    let owner_keyset_id = dummy_account_id(0xDD);

    let call = RegisterValidatorCall {
        version: 1,
        validator_id,
        owner_keyset_id,
        consensus_suite_id: 0x01,
        consensus_pk: vec![0xAA],
        network_suite_id: 0x02,
        network_pk: vec![0xBB],
        stake: 10,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);

    let program_id = ValidatorProgram::id();
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000,
        accounts: vec![
            TxAccountMeta {
                account_id: validator_id,
                flags: 0b0000_0011,
                access_hint: 0b0000_0011,
                reserved0: [0u8; 2],
            }
        ],
        program_id,
        call_data,
        auths: Vec::new(),
    };

    let mut store = InMemoryAccountStore::new();
    let crypto = Arc::new(DummyCryptoProvider) as Arc<dyn CryptoProvider>;
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    let program = ValidatorProgram::new();

    // First registration should succeed.
    program.execute(&mut ctx, &tx).expect("first register ok");

    // Second registration should fail with ProgramError.
    let err = program.execute(&mut ctx, &tx).expect_err("second register must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("validator already exists"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}