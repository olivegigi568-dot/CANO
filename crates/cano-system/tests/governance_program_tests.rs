use std::sync::Arc;

use cano_system::GovernanceProgram;
use cano_system::governance_program::{
    GOVERNANCE_PROGRAM_ID,
    SUITE_REGISTRY_ACCOUNT_ID,
    PARAM_REGISTRY_ACCOUNT_ID,
    LAUNCH_CHECKLIST_ACCOUNT_ID,
};
use cano_types::{
    AccountId, ProgramId, Hash32,
    SuiteEntry, SuiteRegistry, SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus,
    ParamRegistry, MainnetStatus,
    LaunchChecklist,
};
use cano_wire::tx::Transaction;
use cano_wire::gov::{
    OP_GOV_UPDATE_SUITE_STATUS,
    OP_GOV_UPDATE_PARAM_REGISTRY,
    OP_GOV_UPDATE_LAUNCH_CHECKLIST,
    OP_GOV_SET_MAINNET_STATUS,
    GovUpdateSuiteStatusCall,
    GovUpdateParamRegistryCall,
    GovUpdateLaunchChecklistCall,
    GovSetMainnetStatusCall,
};
use cano_wire::io::WireEncode;
use cano_serde::StateEncode;
use cano_serde::StateDecode;
use cano_ledger::{Account, AccountStore, InMemoryAccountStore, ExecutionContext, Program};
use cano_crypto::{CryptoProvider, StaticCryptoProvider};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

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
        accounts: Vec::new(), // not enforced yet
        program_id,
        call_data,
        auths: Vec::new(),
    }
}

#[test]
fn gov_update_suite_status_updates_entry() {
    // Prepare a SuiteRegistry account with two entries.
    let e1 = SuiteEntry {
        suite_id: 0x01,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let e2 = SuiteEntry {
        suite_id: 0x02,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let registry = SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 2,
        reserved1: 0,
        suites: vec![e1, e2],
    };

    let mut data = Vec::new();
    registry.encode_state(&mut data);

    let suite_account = Account::new(SUITE_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = InMemoryAccountStore::new();
    store.put(suite_account).unwrap();

    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);

    let program = GovernanceProgram::new();

    // Build call to set suite_id 0x01 to Disabled (2).
    let call = GovUpdateSuiteStatusCall {
        version: 1,
        suite_id: 0x01,
        new_status: 2, // Disabled
        proposal_id: 42,
        eta_height: 1000,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_SUITE_STATUS);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    program.execute(&mut ctx, &tx).expect("execute ok");

    // Re-read SuiteRegistry and assert change.
    let stored = store.get(&SUITE_REGISTRY_ACCOUNT_ID).expect("suite registry exists");
    let mut slice: &[u8] = &stored.data;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert!(slice.is_empty());
    assert_eq!(decoded.suites.len(), 2);
    let s1 = &decoded.suites[0];
    let s2 = &decoded.suites[1];
    assert_eq!(s1.suite_id, 0x01);
    assert_eq!(s1.status, SuiteStatus::Disabled);
    assert_eq!(s2.status, SuiteStatus::Active);
}

#[test]
fn gov_update_param_registry_changes_slash_params() {
    // Prepare ParamRegistry account.
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 10,
        slash_bps_precommit: 20,
        reporter_reward_bps: 5,
        reserved1: 0,
    };

    let mut data = Vec::new();
    params.encode_state(&mut data);
    let param_account = Account::new(PARAM_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = InMemoryAccountStore::new();
    store.put(param_account).unwrap();

    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);
    let program = GovernanceProgram::new();

    let call = GovUpdateParamRegistryCall {
        version: 1,
        proposal_id: 7,
        eta_height: 2000,
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 50,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_PARAM_REGISTRY);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    program.execute(&mut ctx, &tx).expect("execute ok");

    let stored = store.get(&PARAM_REGISTRY_ACCOUNT_ID).expect("params account");
    let mut slice: &[u8] = &stored.data;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert!(slice.is_empty());
    assert_eq!(decoded.slash_bps_prevote, 100);
    assert_eq!(decoded.slash_bps_precommit, 200);
    assert_eq!(decoded.reporter_reward_bps, 50);
    assert_eq!(decoded.mainnet_status, MainnetStatus::PreGenesis);
}

#[test]
fn gov_update_launch_checklist_roundtrip() {
    // Prepare LaunchChecklist account with defaults.
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: false,
        testnet_ok: false,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: false,
        proto_audit_ok: false,
        spec_ok: false,
        reserved1: 0,
        devnet_report_hash: zero_hash(),
        testnet_report_hash: zero_hash(),
        perf_report_hash: zero_hash(),
        adversarial_report_hash: zero_hash(),
        crypto_audit_hash: zero_hash(),
        proto_audit_hash: zero_hash(),
        spec_hash: zero_hash(),
    };

    let mut data = Vec::new();
    checklist.encode_state(&mut data);
    let checklist_account = Account::new(LAUNCH_CHECKLIST_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = InMemoryAccountStore::new();
    store.put(checklist_account).unwrap();

    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);
    let program = GovernanceProgram::new();

    let call = GovUpdateLaunchChecklistCall {
        version: 1,
        proposal_id: 9,
        eta_height: 3000,
        devnet_ok: true,
        testnet_ok: true,
        perf_ok: true,
        adversarial_ok: false,
        crypto_audit_ok: true,
        proto_audit_ok: false,
        spec_ok: true,
        devnet_report_hash: [1u8; 32],
        testnet_report_hash: [2u8; 32],
        perf_report_hash: [3u8; 32],
        adversarial_report_hash: [4u8; 32],
        crypto_audit_hash: [5u8; 32],
        proto_audit_hash: [6u8; 32],
        spec_hash: [7u8; 32],
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_LAUNCH_CHECKLIST);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    program.execute(&mut ctx, &tx).expect("execute ok");

    let stored = store.get(&LAUNCH_CHECKLIST_ACCOUNT_ID).expect("checklist account");
    let mut slice: &[u8] = &stored.data;
    let decoded = LaunchChecklist::decode_state(&mut slice).expect("decode");
    assert!(slice.is_empty());

    assert!(decoded.devnet_ok);
    assert!(decoded.testnet_ok);
    assert!(decoded.perf_ok);
    assert!(!decoded.adversarial_ok);
    assert!(decoded.crypto_audit_ok);
    assert!(!decoded.proto_audit_ok);
    assert!(decoded.spec_ok);

    assert_eq!(decoded.devnet_report_hash, [1u8; 32]);
    assert_eq!(decoded.testnet_report_hash, [2u8; 32]);
    assert_eq!(decoded.perf_report_hash, [3u8; 32]);
    assert_eq!(decoded.adversarial_report_hash, [4u8; 32]);
    assert_eq!(decoded.crypto_audit_hash, [5u8; 32]);
    assert_eq!(decoded.proto_audit_hash, [6u8; 32]);
    assert_eq!(decoded.spec_hash, [7u8; 32]);
}

#[test]
fn gov_set_mainnet_status_changes_status_only() {
    // Prepare ParamRegistry with PreGenesis.
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 10,
        slash_bps_precommit: 20,
        reporter_reward_bps: 5,
        reserved1: 0,
    };
    let mut data = Vec::new();
    params.encode_state(&mut data);
    let param_account = Account::new(PARAM_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = InMemoryAccountStore::new();
    store.put(param_account).unwrap();

    let crypto = empty_crypto();
    let mut ctx = ExecutionContext::new(&mut store, crypto);
    let program = GovernanceProgram::new();

    let call = GovSetMainnetStatusCall {
        version: 1,
        new_status: MainnetStatus::Ready,
        proposal_id: 11,
        eta_height: 4000,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_SET_MAINNET_STATUS);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    program.execute(&mut ctx, &tx).expect("execute ok");

    let stored = store.get(&PARAM_REGISTRY_ACCOUNT_ID).expect("params account");
    let mut slice: &[u8] = &stored.data;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert!(slice.is_empty());
    assert_eq!(decoded.mainnet_status, MainnetStatus::Ready);
    // Other fields unchanged.
    assert_eq!(decoded.slash_bps_prevote, 10);
    assert_eq!(decoded.slash_bps_precommit, 20);
    assert_eq!(decoded.reporter_reward_bps, 5);
}