use cano_types::ProgramId;
use cano_wire::tx::Transaction;
use crate::{ExecutionError, context::ExecutionContext};
use crate::store::AccountStore;

/// A system or user program that can be invoked by transactions.
/// Programs interpret Transaction.call_data and mutate accounts via the ExecutionContext.
pub trait Program<S: AccountStore> {
    /// ProgramId that owns the accounts this program is allowed to mutate.
    fn id(&self) -> ProgramId;

    /// Execute this program for a given transaction.
    ///
    /// - `ctx` provides access to accounts and crypto.
    /// - `tx` is the full transaction as decoded from the wire.
    ///
    /// For now, we do not split out "program accounts" subset; that will be derived from tx.accounts later.
    fn execute(&self, ctx: &mut ExecutionContext<S>, tx: &Transaction) -> Result<(), ExecutionError>;
}