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

    /// Returns the classical `f` assuming `n = 3f + 1` type reasoning.
    ///
    /// This is a helper for tests and thresholds; we do not enforce that
    /// the set exactly satisfies 3f+1 for now.
    ///
    /// For n validators, returns floor((n - 1) / 3).
    pub fn f(&self) -> usize {
        let n = self.len();
        if n == 0 {
            return 0;
        }
        // integer floor of (n - 1)/3
        (n.saturating_sub(1)) / 3
    }

    /// Convenience: minimum number of validators for a "classic" quorum: 2f+1.
    pub fn quorum_size(&self) -> usize {
        let f = self.f();
        2 * f + 1
    }

    /// Minimum voting power required for a "2/3 total" quorum.
    ///
    /// Returns ceil(2 * total / 3).
    pub fn two_thirds_vp(&self) -> u64 {
        let total = self.total_voting_power();
        // ceil(2 * total / 3)
        (2 * total + 2) / 3
    }

    /// Checks if a set of validators (by id) reaches >= 2/3 of the total voting power.
    ///
    /// Unknown validator ids are ignored (treated as 0 weight).
    pub fn has_quorum<I>(&self, ids: I) -> bool
    where
        I: IntoIterator<Item = ValidatorId>,
    {
        let mut acc: u64 = 0;
        for id in ids {
            if let Some(idx) = self.index_of(id) {
                let entry = &self.validators[idx];
                acc = acc.saturating_add(entry.voting_power);
            }
            // Unknown id: ignore (treat as 0 weight)
        }
        acc >= self.two_thirds_vp()
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

    #[test]
    fn validator_set_f_calculation() {
        // n=1: f = (1-1)/3 = 0
        let set1 = ConsensusValidatorSet::new(vec![ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        }])
        .unwrap();
        assert_eq!(set1.f(), 0);

        // n=3: f = (3-1)/3 = 0  (floor)
        let set3 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
        ])
        .unwrap();
        assert_eq!(set3.f(), 0);

        // n=4: f = (4-1)/3 = 1
        let set4 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(4), voting_power: 10 },
        ])
        .unwrap();
        assert_eq!(set4.f(), 1);

        // n=7: f = (7-1)/3 = 2
        let set7 = ConsensusValidatorSet::new((1..=7).map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 10,
        }))
        .unwrap();
        assert_eq!(set7.f(), 2);
    }

    #[test]
    fn validator_set_quorum_size_calculation() {
        // n=4, f=1 => quorum_size = 2*1+1 = 3
        let set4 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(4), voting_power: 10 },
        ])
        .unwrap();
        assert_eq!(set4.quorum_size(), 3);

        // n=7, f=2 => quorum_size = 2*2+1 = 5
        let set7 = ConsensusValidatorSet::new((1..=7).map(|i| ValidatorSetEntry {
            id: ValidatorId::new(i),
            voting_power: 10,
        }))
        .unwrap();
        assert_eq!(set7.quorum_size(), 5);
    }

    #[test]
    fn validator_set_two_thirds_vp() {
        // total_power = 30, two_thirds = ceil(2*30/3) = ceil(60/3) = 20
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
        ])
        .unwrap();
        assert_eq!(set.total_voting_power(), 30);
        assert_eq!(set.two_thirds_vp(), 20);

        // total_power = 100, two_thirds = ceil(200/3) = 67
        let set100 = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 50 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 50 },
        ])
        .unwrap();
        assert_eq!(set100.total_voting_power(), 100);
        assert_eq!(set100.two_thirds_vp(), 67);
    }

    #[test]
    fn validator_set_has_quorum() {
        // 3 validators with power 10 each => total = 30, need >= 20 for quorum
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 10 },
        ])
        .unwrap();

        // Single validator (10) does not reach quorum (20)
        assert!(!set.has_quorum([ValidatorId::new(1)]));

        // Two validators (20) reaches quorum (20)
        assert!(set.has_quorum([ValidatorId::new(1), ValidatorId::new(2)]));

        // All three (30) reaches quorum
        assert!(set.has_quorum([ValidatorId::new(1), ValidatorId::new(2), ValidatorId::new(3)]));

        // Unknown validator is ignored
        assert!(!set.has_quorum([ValidatorId::new(999)]));

        // Unknown validator + one known (10) does not reach quorum
        assert!(!set.has_quorum([ValidatorId::new(1), ValidatorId::new(999)]));

        // Two known validators + one unknown reaches quorum
        assert!(set.has_quorum([ValidatorId::new(1), ValidatorId::new(2), ValidatorId::new(999)]));
    }

    #[test]
    fn validator_set_has_quorum_weighted() {
        // Weighted validators: 10 + 20 + 70 = 100, need >= 67 for quorum
        let set = ConsensusValidatorSet::new(vec![
            ValidatorSetEntry { id: ValidatorId::new(1), voting_power: 10 },
            ValidatorSetEntry { id: ValidatorId::new(2), voting_power: 20 },
            ValidatorSetEntry { id: ValidatorId::new(3), voting_power: 70 },
        ])
        .unwrap();

        // Validator 3 alone (70) reaches quorum (67)
        assert!(set.has_quorum([ValidatorId::new(3)]));

        // Validators 1+2 (30) does not reach quorum (67)
        assert!(!set.has_quorum([ValidatorId::new(1), ValidatorId::new(2)]));

        // Validators 2+3 (90) reaches quorum
        assert!(set.has_quorum([ValidatorId::new(2), ValidatorId::new(3)]));
    }
}