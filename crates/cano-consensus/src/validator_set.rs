//! Validator set abstraction for consensus.
//!
//! This module provides `ValidatorSetEntry` and `ConsensusValidatorSet` types for
//! representing the validator committee in the consensus layer.
//!
//! # Design Note
//!
//! This is a simplified validator set abstraction for T50. It provides:
//! - A canonical representation of the validator committee
//! - Simple helpers for index lookup, iteration, and total weight
//!
//! These types are distinct from the existing `ValidatorInfo` and `ValidatorSet` 
//! types in `lib.rs`, which are specifically designed for verification with 
//! cryptographic fields (consensus_pk, suite_id). The types in this module use
//! the canonical `ValidatorId` type and are intended for structural wiring.
//!
//! We are NOT yet:
//! - Parsing TOML/JSON from disk
//! - Verifying signatures
//! - Changing the actual consensus algorithm
//!
//! This is purely structural wiring.

use std::collections::HashMap;

use crate::ids::ValidatorId;

/// Information about a single validator in the consensus committee.
///
/// This is a minimal structure containing the validator's identity and voting power.
/// Future extensions may include cryptographic keys, suite IDs, etc.
///
/// Note: This type is distinct from the `ValidatorInfo` in `lib.rs`, which includes
/// cryptographic fields for verification purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSetEntry {
    /// The canonical validator identity.
    pub id: ValidatorId,
    /// Simple voting power for now; can be generalized later.
    pub voting_power: u64,
}

/// A set of validators that form the consensus committee.
///
/// `ConsensusValidatorSet` provides:
/// - Fast lookup by `ValidatorId`
/// - Iteration over all validators
/// - Total voting power calculation
///
/// # Invariants
///
/// - The validator set is non-empty.
/// - All `ValidatorId`s are unique.
/// - Total voting power is the sum of all individual voting powers (with saturation).
///
/// Note: This type is distinct from the `ValidatorSet` in `lib.rs`, which is
/// specifically designed for consensus verification with cryptographic fields.
#[derive(Debug, Clone)]
pub struct ConsensusValidatorSet {
    validators: Vec<ValidatorSetEntry>,
    index_by_id: HashMap<ValidatorId, usize>,
    total_voting_power: u64,
}

impl ConsensusValidatorSet {
    /// Create a new `ConsensusValidatorSet` from an iterator of `ValidatorSetEntry`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The iterator is empty (validator set must not be empty)
    /// - There are duplicate `ValidatorId`s
    pub fn new<I>(validators: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = ValidatorSetEntry>,
    {
        let mut vec = Vec::new();
        let mut index_by_id = HashMap::new();
        let mut total_vp = 0u64;

        for info in validators {
            if index_by_id.contains_key(&info.id) {
                return Err(format!("duplicate ValidatorId: {:?}", info.id));
            }
            let idx = vec.len();
            total_vp = total_vp.saturating_add(info.voting_power);
            index_by_id.insert(info.id, idx);
            vec.push(info);
        }

        if vec.is_empty() {
            return Err("validator set must not be empty".to_string());
        }

        Ok(ConsensusValidatorSet {
            validators: vec,
            index_by_id,
            total_voting_power: total_vp,
        })
    }

    /// Returns the number of validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if the validator set is empty.
    ///
    /// Note: This should always return `false` since the constructor
    /// enforces that the set is non-empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Returns the total voting power of all validators.
    pub fn total_voting_power(&self) -> u64 {
        self.total_voting_power
    }

    /// Get a validator by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get(&self, idx: usize) -> Option<&ValidatorSetEntry> {
        self.validators.get(idx)
    }

    /// Get the index of a validator by its `ValidatorId`.
    ///
    /// Returns `None` if the validator is not in the set.
    pub fn index_of(&self, id: ValidatorId) -> Option<usize> {
        self.index_by_id.get(&id).copied()
    }

    /// Check if a validator with the given `ValidatorId` is in the set.
    pub fn contains(&self, id: ValidatorId) -> bool {
        self.index_by_id.contains_key(&id)
    }

    /// Iterate over all validators in the set.
    pub fn iter(&self) -> impl Iterator<Item = &ValidatorSetEntry> {
        self.validators.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_set_basic_creation() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
        ];

        let set = ConsensusValidatorSet::new(validators).expect("should succeed");
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.total_voting_power(), 30);
    }

    #[test]
    fn validator_set_get_by_index() {
        let validators = vec![
            ValidatorSetEntry {
                id: ValidatorId::new(1),
                voting_power: 10,
            },
            ValidatorSetEntry {
                id: ValidatorId::new(2),
                voting_power: 20,
            },
        ];

        let set = ConsensusValidatorSet::new(validators).expect("should succeed");
        
        let v0 = set.get(0).expect("index 0 should exist");
        assert_eq!(v0.id, ValidatorId::new(1));
        assert_eq!(v0.voting_power, 10);

        let v1 = set.get(1).expect("index 1 should exist");
        assert_eq!(v1.id, ValidatorId::new(2));
        assert_eq!(v1.voting_power, 20);

        assert!(set.get(2).is_none());
    }
}