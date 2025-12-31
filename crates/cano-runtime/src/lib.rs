use std::collections::HashMap;
use std::sync::Arc;

use cano_types::ProgramId;
use cano_wire::tx::Transaction;
use cano_crypto::CryptoProvider;
use cano_ledger::{AccountStore, ExecutionContext, ExecutionError, Program};
use cano_system::{
    KeysetProgram,
    ValidatorProgram,
    GovernanceProgram,
};
use cano_system::keyset_program::KEYSET_PROGRAM_ID;
use cano_system::validator_program::VALIDATOR_PROGRAM_ID;
use cano_system::governance_program::GOVERNANCE_PROGRAM_ID;

/// Result for a single transaction in a block.
#[derive(Debug, Clone)]
pub enum TxApplyResult {
    Success,
    Failed(ExecutionError),
}

/// Result of executing a block: one entry per transaction.
#[derive(Debug, Clone)]
pub struct BlockExecutionResult {
    pub tx_results: Vec<TxApplyResult>,
}

impl BlockExecutionResult {
    pub fn all_succeeded(&self) -> bool {
        self.tx_results.iter().all(|r| matches!(r, TxApplyResult::Success))
    }
}

/// Simple registry-based transaction executor.
///
/// - Holds one instance of each core system program.
/// - For each transaction:
///   - verifies auth using cano-ledger's verify_tx_auth(),
///   - dispatches to the program whose id matches tx.program_id.
pub struct TxExecutor<S: AccountStore> {
    programs: HashMap<ProgramId, Box<dyn Program<S>>>,
}

impl<S: AccountStore> TxExecutor<S> {
    /// Construct a new executor with the three core system programs registered.
    pub fn new() -> Self {
        let mut programs: HashMap<ProgramId, Box<dyn Program<S>>> = HashMap::new();
        programs.insert(KEYSET_PROGRAM_ID, Box::new(KeysetProgram::new()));
        programs.insert(VALIDATOR_PROGRAM_ID, Box::new(ValidatorProgram::new()));
        programs.insert(GOVERNANCE_PROGRAM_ID, Box::new(GovernanceProgram::new()));

        TxExecutor { programs }
    }

    /// Execute a single transaction:
    ///  - build an ExecutionContext over the given store + crypto provider,
    ///  - verify all TxAuth entries against on-chain keysets,
    ///  - dispatch to the appropriate program based on tx.program_id.
    pub fn execute_transaction(
        &self,
        store: &mut S,
        crypto: Arc<dyn CryptoProvider>,
        tx: &Transaction,
    ) -> Result<(), ExecutionError> {
        // Build the execution context.
        let mut ctx = ExecutionContext::new(store, crypto);

        // Verify transaction auth (tx.auths vs on-chain keysets).
        ctx.verify_tx_auth(tx)?;

        // Find the program for tx.program_id.
        let program = self
            .programs
            .get(&tx.program_id)
            .ok_or(ExecutionError::ProgramError("unknown program_id"))?;

        // Execute program logic.
        program.execute(&mut ctx, tx)
    }
}

impl<S: AccountStore> Default for TxExecutor<S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Block-level executor that uses a TxExecutor under the hood.
pub struct BlockExecutor<S: AccountStore> {
    tx_executor: TxExecutor<S>,
}

impl<S: AccountStore> BlockExecutor<S> {
    /// Construct a new BlockExecutor with the default TxExecutor.
    pub fn new() -> Self {
        BlockExecutor {
            tx_executor: TxExecutor::new(),
        }
    }

    /// Access the underlying TxExecutor (if needed by tests or higher layers).
    pub fn tx_executor(&self) -> &TxExecutor<S> {
        &self.tx_executor
    }

    /// Execute a sequence of transactions sequentially.
    ///
    /// Semantics:
    ///  - Txs are executed in the given order.
    ///  - For each tx:
    ///      * auth is verified via ctx.verify_tx_auth(),
    ///      * the appropriate program is executed,
    ///      * if it returns Ok(()) we record Success,
    ///        otherwise we record Failed(error).
    ///  - No rollback is performed; successful txs stay applied even if a later tx fails.
    ///
    /// This function is deterministic given the initial store and tx list.
    pub fn execute_block(
        &self,
        store: &mut S,
        crypto: Arc<dyn CryptoProvider>,
        txs: &[Transaction],
    ) -> BlockExecutionResult {
        let mut results = Vec::with_capacity(txs.len());

        for tx in txs {
            let result = self.tx_executor.execute_transaction(store, crypto.clone(), tx);
            match result {
                Ok(()) => results.push(TxApplyResult::Success),
                Err(e) => results.push(TxApplyResult::Failed(e)),
            }
        }

        BlockExecutionResult { tx_results: results }
    }
}

impl<S: AccountStore> Default for BlockExecutor<S> {
    fn default() -> Self {
        Self::new()
    }
}