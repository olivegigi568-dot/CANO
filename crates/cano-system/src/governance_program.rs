//! GovernanceProgram: mutates SuiteRegistry, ParamRegistry, and LaunchChecklist state
//! using governance call_data types from cano-wire::gov.
//!
//! No timelock/TA/SC enforcement yet; just parse → mutate → re-encode.

use cano_types::{
    AccountId, ProgramId,
    SuiteRegistry, SuiteStatus,
    ParamRegistry, LaunchChecklist,
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
use cano_wire::io::WireDecode;
use cano_serde::{StateEncode, StateDecode};
use cano_ledger::{AccountStore, ExecutionContext, ExecutionError, Program};

/// Hard-coded ProgramId for governance.
pub const GOVERNANCE_PROGRAM_ID: ProgramId = [0x47; 32]; // 'G'

/// Well-known system account IDs for core governance state.
pub const SUITE_REGISTRY_ACCOUNT_ID: AccountId = [0xA1; 32];
pub const PARAM_REGISTRY_ACCOUNT_ID: AccountId = [0xA2; 32];
pub const LAUNCH_CHECKLIST_ACCOUNT_ID: AccountId = [0xA3; 32];

/// Safety Council keyset and member account IDs for genesis.
/// These are well-known, fixed IDs; in a production deployment, the chain
/// operator would replace the dummy keys, not the IDs.
pub const SAFETY_COUNCIL_KEYSET_ACCOUNT_ID: AccountId = [0xB0; 32];

pub const SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS: [AccountId; 7] = [
    [0xB1; 32],
    [0xB2; 32],
    [0xB3; 32],
    [0xB4; 32],
    [0xB5; 32],
    [0xB6; 32],
    [0xB7; 32],
];

/// GovernanceProgram handles governance-related state mutations.
pub struct GovernanceProgram;

impl GovernanceProgram {
    pub fn new() -> Self {
        GovernanceProgram
    }

    pub fn id() -> ProgramId {
        GOVERNANCE_PROGRAM_ID
    }
}

impl Default for GovernanceProgram {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_err(label: &'static str) -> ExecutionError {
    ExecutionError::InvalidCallData(label)
}

impl<S: AccountStore> Program<S> for GovernanceProgram {
    fn id(&self) -> ProgramId {
        GOVERNANCE_PROGRAM_ID
    }

    fn execute(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError> {
        if tx.program_id != GOVERNANCE_PROGRAM_ID {
            return Err(ExecutionError::ProgramError("program_id mismatch for GovernanceProgram"));
        }
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_GOV_UPDATE_SUITE_STATUS => self.handle_update_suite_status(ctx, tx),
            OP_GOV_UPDATE_PARAM_REGISTRY => self.handle_update_param_registry(ctx, tx),
            OP_GOV_UPDATE_LAUNCH_CHECKLIST => self.handle_update_launch_checklist(ctx, tx),
            OP_GOV_SET_MAINNET_STATUS => self.handle_set_mainnet_status(ctx, tx),
            _ => Err(ExecutionError::ProgramError("unsupported governance opcode")),
        }
    }
}

impl GovernanceProgram {
    /// Handle GovUpdateSuiteStatusCall → SuiteRegistry
    fn handle_update_suite_status<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = GovUpdateSuiteStatusCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateSuiteStatusCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after GovUpdateSuiteStatusCall"));
        }

        // Load SuiteRegistry account.
        let mut account = ctx
            .store
            .get(&SUITE_REGISTRY_ACCOUNT_ID)
            .ok_or(ExecutionError::AccountNotFound)?;

        // Decode existing SuiteRegistry.
        let mut slice: &[u8] = &account.data;
        let mut registry = SuiteRegistry::decode_state(&mut slice)
            .map_err(|_| ExecutionError::SerializationError("decode SuiteRegistry"))?;
        if !slice.is_empty() {
            return Err(ExecutionError::SerializationError("trailing bytes in SuiteRegistry account"));
        }

        // Map new_status (u8) into SuiteStatus enum.
        let new_status = match call.new_status {
            0 => SuiteStatus::Active,
            1 => SuiteStatus::Legacy,
            2 => SuiteStatus::Disabled,
            _ => return Err(ExecutionError::InvalidCallData("invalid SuiteStatus")),
        };

        // Find suite entry by suite_id and update status.
        let mut updated = false;
        for entry in &mut registry.suites {
            if entry.suite_id == call.suite_id {
                entry.status = new_status;
                updated = true;
                break;
            }
        }

        if !updated {
            return Err(ExecutionError::InvalidCallData("suite_id not found in SuiteRegistry"));
        }

        // Re-encode and store back.
        let mut new_data = Vec::new();
        registry.encode_state(&mut new_data);
        account.data = new_data;
        ctx.store.put(account)?;

        Ok(())
    }

    /// Handle GovUpdateParamRegistryCall → ParamRegistry
    fn handle_update_param_registry<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = GovUpdateParamRegistryCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateParamRegistryCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after GovUpdateParamRegistryCall"));
        }

        let mut account = ctx
            .store
            .get(&PARAM_REGISTRY_ACCOUNT_ID)
            .ok_or(ExecutionError::AccountNotFound)?;

        let mut slice: &[u8] = &account.data;
        let mut params = ParamRegistry::decode_state(&mut slice)
            .map_err(|_| ExecutionError::SerializationError("decode ParamRegistry"))?;
        if !slice.is_empty() {
            return Err(ExecutionError::SerializationError("trailing bytes in ParamRegistry account"));
        }

        params.slash_bps_prevote = call.slash_bps_prevote;
        params.slash_bps_precommit = call.slash_bps_precommit;
        params.reporter_reward_bps = call.reporter_reward_bps;

        let mut new_data = Vec::new();
        params.encode_state(&mut new_data);
        account.data = new_data;
        ctx.store.put(account)?;

        Ok(())
    }

    /// Handle GovUpdateLaunchChecklistCall → LaunchChecklist
    fn handle_update_launch_checklist<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = GovUpdateLaunchChecklistCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovUpdateLaunchChecklistCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after GovUpdateLaunchChecklistCall"));
        }

        let mut account = ctx
            .store
            .get(&LAUNCH_CHECKLIST_ACCOUNT_ID)
            .ok_or(ExecutionError::AccountNotFound)?;

        let mut slice: &[u8] = &account.data;
        let mut checklist = LaunchChecklist::decode_state(&mut slice)
            .map_err(|_| ExecutionError::SerializationError("decode LaunchChecklist"))?;
        if !slice.is_empty() {
            return Err(ExecutionError::SerializationError("trailing bytes in LaunchChecklist account"));
        }

        // Update flags.
        checklist.devnet_ok = call.devnet_ok;
        checklist.testnet_ok = call.testnet_ok;
        checklist.perf_ok = call.perf_ok;
        checklist.adversarial_ok = call.adversarial_ok;
        checklist.crypto_audit_ok = call.crypto_audit_ok;
        checklist.proto_audit_ok = call.proto_audit_ok;
        checklist.spec_ok = call.spec_ok;

        // Update hashes.
        checklist.devnet_report_hash = call.devnet_report_hash;
        checklist.testnet_report_hash = call.testnet_report_hash;
        checklist.perf_report_hash = call.perf_report_hash;
        checklist.adversarial_report_hash = call.adversarial_report_hash;
        checklist.crypto_audit_hash = call.crypto_audit_hash;
        checklist.proto_audit_hash = call.proto_audit_hash;
        checklist.spec_hash = call.spec_hash;

        let mut new_data = Vec::new();
        checklist.encode_state(&mut new_data);
        account.data = new_data;
        ctx.store.put(account)?;

        Ok(())
    }

    /// Handle GovSetMainnetStatusCall → ParamRegistry
    fn handle_set_mainnet_status<S: AccountStore>(
        &self,
        ctx: &mut ExecutionContext<S>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = GovSetMainnetStatusCall::decode(&mut input)
            .map_err(|_| decode_err("invalid GovSetMainnetStatusCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after GovSetMainnetStatusCall"));
        }

        let mut account = ctx
            .store
            .get(&PARAM_REGISTRY_ACCOUNT_ID)
            .ok_or(ExecutionError::AccountNotFound)?;

        let mut slice: &[u8] = &account.data;
        let mut params = ParamRegistry::decode_state(&mut slice)
            .map_err(|_| ExecutionError::SerializationError("decode ParamRegistry"))?;
        if !slice.is_empty() {
            return Err(ExecutionError::SerializationError("trailing bytes in ParamRegistry account"));
        }

        params.mainnet_status = call.new_status;

        let mut new_data = Vec::new();
        params.encode_state(&mut new_data);
        account.data = new_data;
        ctx.store.put(account)?;

        Ok(())
    }
}