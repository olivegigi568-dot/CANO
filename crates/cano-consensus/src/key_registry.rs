//! Validator key registry for mapping validator IDs to public keys.
//!
//! This module provides a registry that maps `ValidatorId` to `ValidatorPublicKey`.
//! It is used to look up public keys for signature verification during consensus.

use std::collections::HashMap;

use crate::ids::{ValidatorId, ValidatorPublicKey};

/// A registry mapping validator IDs to their public keys.
///
/// This struct provides a simple key-value store for looking up validator
/// public keys by their consensus identity. It is used during signature
/// verification to obtain the appropriate public key.
#[derive(Debug, Default, Clone)]
pub struct ValidatorKeyRegistry {
    inner: HashMap<ValidatorId, ValidatorPublicKey>,
}

impl ValidatorKeyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        ValidatorKeyRegistry {
            inner: HashMap::new(),
        }
    }

    /// Insert a validator's public key into the registry.
    ///
    /// Returns the previous public key if one was already present for this validator.
    pub fn insert(
        &mut self,
        id: ValidatorId,
        pk: ValidatorPublicKey,
    ) -> Option<ValidatorPublicKey> {
        self.inner.insert(id, pk)
    }

    /// Get a reference to a validator's public key.
    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorPublicKey> {
        self.inner.get(id)
    }

    /// Check if the registry contains a key for the given validator.
    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.inner.contains_key(id)
    }

    /// Returns the number of validators in the registry.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an iterator over all (ValidatorId, ValidatorPublicKey) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &ValidatorPublicKey)> {
        self.inner.iter()
    }
}