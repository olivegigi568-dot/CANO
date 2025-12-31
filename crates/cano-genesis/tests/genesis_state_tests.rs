use cano_genesis::{
    write_genesis_suite_registry,
    write_genesis_param_registry,
    write_genesis_launch_checklist,
    write_genesis_state,
    write_full_genesis_state,
};
use cano_ledger::{InMemoryAccountStore, ExecutionError, AccountStore};
use cano_system::governance_program::{
    GOVERNANCE_PROGRAM_ID,
    SUITE_REGISTRY_ACCOUNT_ID,
    PARAM_REGISTRY_ACCOUNT_ID,
    LAUNCH_CHECKLIST_ACCOUNT_ID,
    SAFETY_COUNCIL_KEYSET_ACCOUNT_ID,
    SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS,
};
use cano_types::{
    SuiteRegistry,
    ParamRegistry,
    LaunchChecklist,
    MainnetStatus,
    SafetyCouncilKeyset,
    SafetyCouncilKeyAccount,
};
use cano_serde::StateDecode;

#[test]
fn write_genesis_state_populates_all_three_accounts() {
    let mut store = InMemoryAccountStore::new();

    write_genesis_state(&mut store).expect("write_genesis_state should succeed");

    // SuiteRegistry
    let suite_account = store.get(&SUITE_REGISTRY_ACCOUNT_ID).expect("SuiteRegistry account");
    assert_eq!(suite_account.header.owner, GOVERNANCE_PROGRAM_ID);
    let mut slice: &[u8] = &suite_account.data;
    let suite_reg = SuiteRegistry::decode_state(&mut slice).expect("decode SuiteRegistry");
    assert!(slice.is_empty());
    assert_eq!(suite_reg.suite_count as usize, suite_reg.suites.len());
    assert!(suite_reg.suites.len() >= 3);

    // ParamRegistry
    let param_account = store.get(&PARAM_REGISTRY_ACCOUNT_ID).expect("ParamRegistry account");
    assert_eq!(param_account.header.owner, GOVERNANCE_PROGRAM_ID);
    let mut slice: &[u8] = &param_account.data;
    let params = ParamRegistry::decode_state(&mut slice).expect("decode ParamRegistry");
    assert!(slice.is_empty());
    assert_eq!(params.version, 1);
    assert_eq!(params.mainnet_status, MainnetStatus::PreGenesis);

    // LaunchChecklist
    let checklist_account = store.get(&LAUNCH_CHECKLIST_ACCOUNT_ID).expect("LaunchChecklist account");
    assert_eq!(checklist_account.header.owner, GOVERNANCE_PROGRAM_ID);
    let mut slice: &[u8] = &checklist_account.data;
    let checklist = LaunchChecklist::decode_state(&mut slice).expect("decode LaunchChecklist");
    assert!(slice.is_empty());
    assert!(!checklist.devnet_ok);
    assert!(!checklist.testnet_ok);
    assert!(!checklist.perf_ok);
}

#[test]
fn write_genesis_state_fails_if_called_twice() {
    let mut store = InMemoryAccountStore::new();

    write_genesis_state(&mut store).expect("first write_genesis_state ok");

    let err = write_genesis_state(&mut store).expect_err("second write_genesis_state must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("genesis account already exists"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn individual_writers_fail_if_account_exists() {
    let mut store = InMemoryAccountStore::new();

    // Write SuiteRegistry twice.
    write_genesis_suite_registry(&mut store).expect("first suite ok");
    let err = write_genesis_suite_registry(&mut store).expect_err("second suite must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("SuiteRegistry"));
        }
        other => panic!("unexpected error: {:?}", other),
    }

    // We can still write ParamRegistry and LaunchChecklist separately on this partially populated store.
    write_genesis_param_registry(&mut store).expect("param ok");
    write_genesis_launch_checklist(&mut store).expect("checklist ok");
}

// ========== Safety Council Genesis Tests ==========

#[test]
fn write_genesis_safety_council_populates_keyset_and_members() {
    let mut store = InMemoryAccountStore::new();

    // Use the full writer to ensure everything is compatible.
    write_full_genesis_state(&mut store).expect("full genesis ok");

    // Keyset account
    let keyset_account = store
        .get(&SAFETY_COUNCIL_KEYSET_ACCOUNT_ID)
        .expect("SafetyCouncilKeyset account");
    assert_eq!(keyset_account.header.owner, GOVERNANCE_PROGRAM_ID);
    let mut slice: &[u8] = &keyset_account.data;
    let keyset = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode SafetyCouncilKeyset");
    assert!(slice.is_empty());
    // Check threshold and member count according to genesis_safety_council_keyset.
    assert_eq!(keyset.threshold, 5);
    assert_eq!(keyset.member_count, 7);
    assert_eq!(keyset.members.len(), 7);

    // Member accounts
    for id in SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS.iter() {
        let acc = store.get(id).expect("SafetyCouncil member account");
        assert_eq!(acc.header.owner, GOVERNANCE_PROGRAM_ID);

        let mut slice: &[u8] = &acc.data;
        let sc = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode SafetyCouncilKeyAccount");
        assert!(slice.is_empty());
        assert!(!sc.pk_bytes.is_empty());
    }
}

#[test]
fn write_genesis_safety_council_fails_if_called_twice() {
    let mut store = InMemoryAccountStore::new();

    write_full_genesis_state(&mut store).expect("first full genesis ok");

    let err = write_full_genesis_state(&mut store).expect_err("second full genesis must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("genesis account already exists"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn full_genesis_state_includes_all_accounts() {
    let mut store = InMemoryAccountStore::new();

    write_full_genesis_state(&mut store).expect("full genesis ok");

    // Verify all existing accounts are still written.
    assert!(store.get(&SUITE_REGISTRY_ACCOUNT_ID).is_some());
    assert!(store.get(&PARAM_REGISTRY_ACCOUNT_ID).is_some());
    assert!(store.get(&LAUNCH_CHECKLIST_ACCOUNT_ID).is_some());

    // Verify new Safety Council accounts.
    assert!(store.get(&SAFETY_COUNCIL_KEYSET_ACCOUNT_ID).is_some());
    for id in SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS.iter() {
        assert!(store.get(id).is_some());
    }
}