use std::collections::HashMap;
use cano_types::AccountId;
use crate::account::Account;
use crate::ExecutionError;

/// Abstract account storage used by the execution engine.
/// Implementations can be in-memory (for tests) or persistent (for nodes).
pub trait AccountStore {
    /// Fetch an account by its AccountId.
    fn get(&self, id: &AccountId) -> Option<Account>;

    /// Insert or replace an account.
    fn put(&mut self, account: Account) -> Result<(), ExecutionError>;

    /// Remove an account.
    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError>;
}

/// Simple in-memory HashMap-backed account store for tests and local execution.
pub struct InMemoryAccountStore {
    inner: HashMap<AccountId, Account>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }
}

impl Default for InMemoryAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountStore for InMemoryAccountStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.inner.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.inner.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.inner.remove(id);
        Ok(())
    }
}