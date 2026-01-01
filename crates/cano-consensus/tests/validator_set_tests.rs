//! Tests for the `validator_set` module.
//!
//! These tests verify that:
//! - `ConsensusValidatorSet::new` rejects empty input
//! - `ConsensusValidatorSet::new` rejects duplicate `ValidatorId`s
//! - Index lookup and `contains` work correctly
//! - Total voting power sums correctly

use cano_consensus::{ConsensusValidatorSet, ValidatorId, ValidatorSetEntry};

/// Test that an empty validator set is rejected.
#[test]
fn validator_set_rejects_empty() {
    let validators: Vec<ValidatorSetEntry> = vec![];
    let result = ConsensusValidatorSet::new(validators);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("must not be empty"),
        "Expected 'must not be empty' error, got: {}",
        err
    );
}

/// Test that duplicate ValidatorIds are rejected.
#[test]
fn validator_set_rejects_duplicate_ids() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 20,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(1), // Duplicate
            voting_power: 30,
        },
    ];

    let result = ConsensusValidatorSet::new(validators);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("duplicate ValidatorId"),
        "Expected 'duplicate ValidatorId' error, got: {}",
        err
    );
}

/// Test that index_of and contains work correctly.
#[test]
fn validator_set_index_and_contains_work() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(10),
            voting_power: 100,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(20),
            voting_power: 200,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(30),
            voting_power: 300,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Test index_of
    assert_eq!(set.index_of(ValidatorId::new(10)), Some(0));
    assert_eq!(set.index_of(ValidatorId::new(20)), Some(1));
    assert_eq!(set.index_of(ValidatorId::new(30)), Some(2));
    assert_eq!(set.index_of(ValidatorId::new(99)), None);

    // Test contains
    assert!(set.contains(ValidatorId::new(10)));
    assert!(set.contains(ValidatorId::new(20)));
    assert!(set.contains(ValidatorId::new(30)));
    assert!(!set.contains(ValidatorId::new(99)));

    // Test get
    let v0 = set.get(0).expect("index 0 should exist");
    assert_eq!(v0.id, ValidatorId::new(10));
    
    let v2 = set.get(2).expect("index 2 should exist");
    assert_eq!(v2.id, ValidatorId::new(30));

    assert!(set.get(3).is_none());
}

/// Test that total voting power sums correctly.
#[test]
fn validator_set_total_voting_power_sums_correctly() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 100,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 200,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(3),
            voting_power: 300,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    assert_eq!(set.total_voting_power(), 600);
    assert_eq!(set.len(), 3);
}

/// Test that voting power saturates instead of overflowing.
#[test]
fn validator_set_total_voting_power_saturates_on_overflow() {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: u64::MAX,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 1,
        },
    ];

    let set = ConsensusValidatorSet::new(validators).expect("should succeed");

    // Should saturate to u64::MAX instead of panicking or overflowing
    assert_eq!(set.total_voting_power(), u64::MAX);
}

/// Test iteration over validators.
#[test]
fn validator_set_iter_works() {
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

    let collected: Vec<&ValidatorSetEntry> = set.iter().collect();
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].id, ValidatorId::new(1));
    assert_eq!(collected[1].id, ValidatorId::new(2));
}
