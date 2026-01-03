//! Tests for ValidatorKeyRegistry.
//!
//! These tests verify the basic functionality of the ValidatorKeyRegistry:
//! - Insert and get operations
//! - Overwriting returns the old key
//! - Iterator functionality
//! - Utility methods (len, is_empty, contains)

use cano_consensus::key_registry::ValidatorKeyRegistry;
use cano_consensus::{ValidatorId, ValidatorPublicKey};

/// Test that insert and get operations work correctly.
#[test]
fn registry_insert_and_get_works() {
    let mut reg = ValidatorKeyRegistry::new();

    // Initially empty
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);

    // Insert first validator
    let id1 = ValidatorId::new(1);
    let pk1 = ValidatorPublicKey(b"public-key-1".to_vec());
    let prev = reg.insert(id1, pk1.clone());
    assert!(prev.is_none());

    // Check get works
    let retrieved = reg.get(&id1);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), &pk1);

    // Check contains works
    assert!(reg.contains(&id1));
    assert!(!reg.contains(&ValidatorId::new(999)));

    // Check len and is_empty
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());

    // Insert more validators
    let id2 = ValidatorId::new(2);
    let pk2 = ValidatorPublicKey(b"public-key-2".to_vec());
    reg.insert(id2, pk2.clone());

    let id3 = ValidatorId::new(3);
    let pk3 = ValidatorPublicKey(b"public-key-3".to_vec());
    reg.insert(id3, pk3.clone());

    // Verify all are retrievable
    assert_eq!(reg.len(), 3);
    assert_eq!(reg.get(&id1).unwrap(), &pk1);
    assert_eq!(reg.get(&id2).unwrap(), &pk2);
    assert_eq!(reg.get(&id3).unwrap(), &pk3);
    assert!(reg.contains(&id1));
    assert!(reg.contains(&id2));
    assert!(reg.contains(&id3));
}

/// Test that inserting a key twice returns the old key.
#[test]
fn registry_overwrite_returns_old_key() {
    let mut reg = ValidatorKeyRegistry::new();

    let id = ValidatorId::new(42);
    let pk_old = ValidatorPublicKey(b"old-key".to_vec());
    let pk_new = ValidatorPublicKey(b"new-key".to_vec());

    // First insert returns None
    let prev1 = reg.insert(id, pk_old.clone());
    assert!(prev1.is_none());

    // Second insert returns the old key
    let prev2 = reg.insert(id, pk_new.clone());
    assert!(prev2.is_some());
    assert_eq!(prev2.unwrap(), pk_old);

    // The new key is now stored
    assert_eq!(reg.get(&id).unwrap(), &pk_new);

    // Length should still be 1 (same validator, updated key)
    assert_eq!(reg.len(), 1);
}

/// Test that iterating over the registry returns all entries.
#[test]
fn registry_iterates_all_entries() {
    let mut reg = ValidatorKeyRegistry::new();
    let n = 5;

    // Insert N entries
    for i in 0..n {
        let id = ValidatorId::new(i as u64);
        let pk = ValidatorPublicKey(format!("pk-{}", i).into_bytes());
        reg.insert(id, pk);
    }

    // Iterate and collect
    let entries: Vec<_> = reg.iter().collect();
    assert_eq!(entries.len(), n);

    // Verify all entries are present (order may vary due to HashMap)
    for i in 0..n {
        let id = ValidatorId::new(i as u64);
        let expected_pk = ValidatorPublicKey(format!("pk-{}", i).into_bytes());
        assert!(reg.contains(&id));
        assert_eq!(reg.get(&id).unwrap(), &expected_pk);
    }
}

/// Test that a new registry is empty.
#[test]
fn registry_new_is_empty() {
    let reg = ValidatorKeyRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    assert!(reg.get(&ValidatorId::new(1)).is_none());
    assert!(!reg.contains(&ValidatorId::new(1)));
    assert_eq!(reg.iter().count(), 0);
}

/// Test the Default implementation.
#[test]
fn registry_default_is_empty() {
    let reg = ValidatorKeyRegistry::default();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}
