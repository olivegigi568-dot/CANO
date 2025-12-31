use cano_types::{ProgramId, KeysetAccount, KeysetEntry};
use cano_wire::tx::Transaction;
use cano_wire::keyset::{OP_KEYSET_CREATE, CreateKeysetCall};
use cano_wire::io::WireDecode;
use cano_serde::StateEncode;
use cano_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, Program};

/// Hard-coded ProgramId for the keyset system program.
pub const KEYSET_PROGRAM_ID: ProgramId = [0x4B; 32]; // 'K'

pub struct KeysetProgram;

impl KeysetProgram {
    pub fn new() -> Self {
        KeysetProgram
    }

    pub fn id() -> ProgramId {
        KEYSET_PROGRAM_ID
    }
}

impl Default for KeysetProgram {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_err(label: &'static str) -> ExecutionError {
    ExecutionError::InvalidCallData(label)
}

impl<S: AccountStore> Program<S> for KeysetProgram {
    fn id(&self) -> ProgramId {
        KEYSET_PROGRAM_ID
    }

    fn execute(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError> {
        if tx.program_id != KEYSET_PROGRAM_ID {
            return Err(ExecutionError::ProgramError("program_id mismatch for KeysetProgram"));
        }
        if tx.call_data.is_empty() {
            return Err(ExecutionError::InvalidCallData("empty call_data"));
        }

        match tx.call_data[0] {
            OP_KEYSET_CREATE => self.handle_create(ctx, tx),
            _ => Err(ExecutionError::ProgramError("unsupported keyset opcode")),
        }
    }
}

impl KeysetProgram {
    fn handle_create<S: AccountStore>(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError> {
        let mut input: &[u8] = &tx.call_data;
        let call = CreateKeysetCall::decode(&mut input)
            .map_err(|_| decode_err("invalid CreateKeysetCall"))?;
        if !input.is_empty() {
            return Err(ExecutionError::InvalidCallData("extra bytes after CreateKeysetCall"));
        }

        // Ensure account does not yet exist.
        if ctx.store.get(&call.target_id).is_some() {
            return Err(ExecutionError::ProgramError("keyset account already exists"));
        }

        // Build KeysetAccount from wire entries.
        let entries: Vec<KeysetEntry> = call.entries.iter().map(|e| KeysetEntry {
            suite_id: e.suite_id,
            weight: e.weight,
            reserved0: [0u8; 1],
            pubkey_len: e.pubkey_bytes.len() as u16,
            pubkey_bytes: e.pubkey_bytes.clone(),
        }).collect();

        // Optionally, we could check that sum(weights) >= threshold here.
        let account_state = KeysetAccount {
            version: call.version,
            reserved0: [0u8; 3],
            threshold: call.threshold,
            entry_count: entries.len() as u16,
            reserved1: [0u8; 4],
            entries,
        };

        // Encode and store.
        let mut data = Vec::new();
        account_state.encode_state(&mut data);

        let account = Account::new(call.target_id, KEYSET_PROGRAM_ID, 0, data);
        ctx.store.put(account)?;

        Ok(())
    }
}