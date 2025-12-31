use std::sync::Arc;
use cano_crypto::CryptoProvider;
use cano_wire::tx::Transaction;
use crate::auth::verify_transaction_auth;
use crate::store::AccountStore;
use crate::ExecutionError;

/// Execution context for a single transaction or block.
/// Provides access to accounts and to cryptographic suites.
pub struct ExecutionContext<'a, S: AccountStore> {
    pub store: &'a mut S,
    pub crypto: Arc<dyn CryptoProvider>,
}

impl<'a, S: AccountStore> ExecutionContext<'a, S> {
    pub fn new(store: &'a mut S, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self { store, crypto }
    }

    /// Verify all transaction auth entries against on-chain keyset accounts.
    pub fn verify_tx_auth(&mut self, tx: &Transaction) -> Result<(), ExecutionError> {
        verify_transaction_auth(self.store, self.crypto.clone(), tx)
    }
}