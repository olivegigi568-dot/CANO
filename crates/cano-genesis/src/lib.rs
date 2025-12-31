//! Genesis state initialization for cano post-quantum blockchain.
//!
//! This crate provides helpers to create and write the canonical genesis state
//! into any `AccountStore`.

use cano_types::{
    AccountId, ProgramId,
    SuiteRegistry,
    ParamRegistry,
    LaunchChecklist,
    MainnetStatus,
    SafetyCouncilKeyset,
    SafetyCouncilKeyAccount,
};
use cano_serde::StateEncode;
use cano_ledger::{Account, AccountStore, ExecutionError};
use cano_system::governance_program::{
    GOVERNANCE_PROGRAM_ID,
    SUITE_REGISTRY_ACCOUNT_ID,
    PARAM_REGISTRY_ACCOUNT_ID,
    LAUNCH_CHECKLIST_ACCOUNT_ID,
    SAFETY_COUNCIL_KEYSET_ACCOUNT_ID,
    SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS,
};

/// Build the canonical genesis `SuiteRegistry` value.
fn build_genesis_suite_registry() -> SuiteRegistry {
    cano_types::genesis_suite_registry()
}

/// Build the canonical genesis `ParamRegistry` value.
///
/// For now, we choose conservative placeholder parameters:
/// - mainnet_status = PreGenesis
/// - slash_bps_prevote, slash_bps_precommit, reporter_reward_bps set
///   to simple, non-zero defaults (can be adjusted later via governance).
fn build_genesis_param_registry() -> ParamRegistry {
    ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        // 1% slash for prevote equivocation, 100% for precommit QC-level,
        // 10% reporter reward — placeholder numbers, changeable via governance.
        slash_bps_prevote: 100,      // 1%
        slash_bps_precommit: 10_000, // 100%
        reporter_reward_bps: 1_000,  // 10%
        reserved1: 0,
    }
}

/// Build the canonical genesis `LaunchChecklist` value (all false, zero hashes).
fn build_genesis_launch_checklist() -> LaunchChecklist {
    LaunchChecklist {
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
        devnet_report_hash: [0u8; 32],
        testnet_report_hash: [0u8; 32],
        perf_report_hash: [0u8; 32],
        adversarial_report_hash: [0u8; 32],
        crypto_audit_hash: [0u8; 32],
        proto_audit_hash: [0u8; 32],
        spec_hash: [0u8; 32],
    }
}

/// Helper: write a single genesis account, erroring if it already exists.
fn put_genesis_account<S: AccountStore>(
    store: &mut S,
    id: AccountId,
    owner: ProgramId,
    data: Vec<u8>,
    exists_error: &'static str,
) -> Result<(), ExecutionError> {
    if store.get(&id).is_some() {
        return Err(ExecutionError::ProgramError(exists_error));
    }

    let account = Account::new(id, owner, 0, data);
    store.put(account)
}

/// Write the genesis `SuiteRegistry` account into the given store.
///
/// - AccountId: SUITE_REGISTRY_ACCOUNT_ID
/// - Owner: GOVERNANCE_PROGRAM_ID
pub fn write_genesis_suite_registry<S: AccountStore>(
    store: &mut S,
) -> Result<(), ExecutionError> {
    let value = build_genesis_suite_registry();
    let mut data = Vec::new();
    value.encode_state(&mut data);
    put_genesis_account(
        store,
        SUITE_REGISTRY_ACCOUNT_ID,
        GOVERNANCE_PROGRAM_ID,
        data,
        "genesis account already exists: SuiteRegistry",
    )
}

/// Write the genesis `ParamRegistry` account into the given store.
///
/// - AccountId: PARAM_REGISTRY_ACCOUNT_ID
/// - Owner: GOVERNANCE_PROGRAM_ID
pub fn write_genesis_param_registry<S: AccountStore>(
    store: &mut S,
) -> Result<(), ExecutionError> {
    let value = build_genesis_param_registry();
    let mut data = Vec::new();
    value.encode_state(&mut data);
    put_genesis_account(
        store,
        PARAM_REGISTRY_ACCOUNT_ID,
        GOVERNANCE_PROGRAM_ID,
        data,
        "genesis account already exists: ParamRegistry",
    )
}

/// Write the genesis `LaunchChecklist` account.
///
/// - AccountId: LAUNCH_CHECKLIST_ACCOUNT_ID
/// - Owner: GOVERNANCE_PROGRAM_ID
pub fn write_genesis_launch_checklist<S: AccountStore>(
    store: &mut S,
) -> Result<(), ExecutionError> {
    let value = build_genesis_launch_checklist();
    let mut data = Vec::new();
    value.encode_state(&mut data);
    put_genesis_account(
        store,
        LAUNCH_CHECKLIST_ACCOUNT_ID,
        GOVERNANCE_PROGRAM_ID,
        data,
        "genesis account already exists: LaunchChecklist",
    )
}

/// Write all core governance-related genesis accounts into the store.
///
/// This is idempotent only on an *empty* store; calling it twice will error.
pub fn write_genesis_state<S: AccountStore>(store: &mut S) -> Result<(), ExecutionError> {
    write_genesis_suite_registry(store)?;
    write_genesis_param_registry(store)?;
    write_genesis_launch_checklist(store)?;
    Ok(())
}

// ========== Safety Council Genesis ==========

/// Build the canonical genesis `SafetyCouncilKeyset` value.
fn build_genesis_safety_council_keyset() -> SafetyCouncilKeyset {
    cano_types::genesis_safety_council_keyset(&SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS)
}

/// Build the canonical genesis `SafetyCouncilKeyAccount` entries.
fn build_genesis_safety_council_accounts() -> Vec<SafetyCouncilKeyAccount> {
    cano_types::genesis_safety_council_accounts()
}

/// Write the SafetyCouncilKeyset account.
///
/// - AccountId: SAFETY_COUNCIL_KEYSET_ACCOUNT_ID
/// - Owner: GOVERNANCE_PROGRAM_ID
pub fn write_genesis_safety_council_keyset<S: AccountStore>(
    store: &mut S,
) -> Result<(), ExecutionError> {
    let value = build_genesis_safety_council_keyset();
    let mut data = Vec::new();
    value.encode_state(&mut data);
    put_genesis_account(
        store,
        SAFETY_COUNCIL_KEYSET_ACCOUNT_ID,
        GOVERNANCE_PROGRAM_ID,
        data,
        "genesis account already exists: SafetyCouncilKeyset",
    )
}

/// Write the 7 SafetyCouncilKeyAccount member accounts.
///
/// Uses SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS[0..7] as the account IDs, in the
/// same order as genesis_safety_council_accounts().
pub fn write_genesis_safety_council_members<S: AccountStore>(
    store: &mut S,
) -> Result<(), ExecutionError> {
    let members = build_genesis_safety_council_accounts();
    assert_eq!(members.len(), SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS.len());

    for (i, member) in members.into_iter().enumerate() {
        let mut data = Vec::new();
        member.encode_state(&mut data);
        put_genesis_account(
            store,
            SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS[i],
            GOVERNANCE_PROGRAM_ID,
            data,
            "genesis account already exists: SafetyCouncilKeyAccount",
        )?;
    }

    Ok(())
}

/// Write all genesis accounts including Safety Council state.
///
/// This calls `write_genesis_state` for core governance accounts plus
/// Safety Council keyset and member accounts.
pub fn write_full_genesis_state<S: AccountStore>(store: &mut S) -> Result<(), ExecutionError> {
    write_genesis_state(store)?; // existing suites + params + checklist
    write_genesis_safety_council_keyset(store)?;
    write_genesis_safety_council_members(store)?;
    Ok(())
}