use cano_types::{AccountId, ProgramId, ValidatorRecord, ValidatorStatus};
use cano_wire::tx::Transaction;
use cano_wire::validator::{
    OP_REGISTER_VALIDATOR,
    RegisterValidatorCall,
};
use cano_wire::io::WireDecode;
use cano_serde::StateEncode;
use cano_ledger::{
    Account,
    AccountStore,
    ExecutionContext,
    ExecutionError,
    Program,
};

/// Hard-coded ProgramId for the validator system program (placeholder for now).
pub const VALIDATOR_PROGRAM_ID: ProgramId = [0x56; 32]; // 'V'

/// ValidatorProgram implements validator registration and, later, key rotation and slashing.
pub struct ValidatorProgram;

impl ValidatorProgram {
    pub fn new() -> Self {
        ValidatorProgram
    }

    pub fn id() -> ProgramId {
        VALIDATOR_PROGRAM_ID
    }
}

impl Default for ValidatorProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: AccountStore> Program<S> for ValidatorProgram {
    fn id(&self) -> ProgramId {
        VALIDATOR_PROGRAM_ID
    }

    fn execute(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError> {
        // Basic sanity: ensure the tx is actually targeting this program.
        if tx.program_id != VALIDATOR_PROGRAM_ID {
            return Err(ExecutionError::ProgramError("program_id mismatch for ValidatorProgram"));
        }

        // For now, we only support RegisterValidator (OP_REGISTER_VALIDATOR).
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_REGISTER_VALIDATOR => {
                self.handle_register(ctx, tx)
            }
            _ => Err(ExecutionError::ProgramError("unsupported validator opcode")),
        }
    }
}

impl ValidatorProgram {
    fn handle_register<S: AccountStore>(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError> {
        // Decode call_data into RegisterValidatorCall.
        let mut input: &[u8] = &tx.call_data;
        let call = RegisterValidatorCall::decode(&mut input)
            .map_err(|_| ExecutionError::InvalidCallData("invalid RegisterValidatorCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after RegisterValidatorCall"));
        }

        let validator_id: AccountId = call.validator_id;

        // Ensure validator account does not already exist.
        if ctx.store.get(&validator_id).is_some() {
            return Err(ExecutionError::ProgramError("validator already exists"));
        }

        // Build initial ValidatorRecord.
        let record = ValidatorRecord {
            version: 1,
            status: ValidatorStatus::Active, // may be tightened to Inactive + separate activation later
            reserved0: [0u8; 2],
            owner_keyset_id: call.owner_keyset_id,
            consensus_suite_id: call.consensus_suite_id,
            reserved1: [0u8; 3],
            consensus_pk: call.consensus_pk,
            network_suite_id: call.network_suite_id,
            reserved2: [0u8; 3],
            network_pk: call.network_pk,
            stake: call.stake,
            last_slash_height: 0,
            ext_bytes: Vec::new(),
        };

        // Encode state using cano-serde.
        let mut data = Vec::new();
        record.encode_state(&mut data);

        // Create and insert the account, owned by VALIDATOR_PROGRAM.
        let account = Account::new(validator_id, VALIDATOR_PROGRAM_ID, 0, data);
        ctx.store.put(account)?;

        Ok(())
    }
}