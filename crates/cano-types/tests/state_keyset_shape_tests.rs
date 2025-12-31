use cano_types::{KeysetEntry, KeysetAccount};

#[test]
fn test_keyset_entry_clone() {
    let entry = KeysetEntry {
        suite_id: 0x01,
        weight: 100,
        reserved0: [0u8; 1],
        pubkey_len: 3,
        pubkey_bytes: vec![1, 2, 3],
    };

    let cloned = entry.clone();

    assert_eq!(cloned.suite_id, entry.suite_id);
    assert_eq!(cloned.weight, entry.weight);
    assert_eq!(cloned.reserved0, entry.reserved0);
    assert_eq!(cloned.pubkey_len, entry.pubkey_len);
    assert_eq!(cloned.pubkey_bytes, entry.pubkey_bytes);
    assert_eq!(cloned, entry);
}

#[test]
fn test_keyset_account_with_two_entries() {
    let entry1 = KeysetEntry {
        suite_id: 0x01,
        weight: 100,
        reserved0: [0u8; 1],
        pubkey_len: 3,
        pubkey_bytes: vec![1, 2, 3],
    };

    let entry2 = KeysetEntry {
        suite_id: 0x02,
        weight: 50,
        reserved0: [0u8; 1],
        pubkey_len: 2,
        pubkey_bytes: vec![4, 5],
    };

    let account = KeysetAccount {
        version: 1,
        reserved0: [0u8; 3],
        threshold: 120,
        entry_count: 2,
        reserved1: [0u8; 4],
        entries: vec![entry1.clone(), entry2.clone()],
    };

    assert_eq!(account.version, 1);
    assert_eq!(account.threshold, 120);
    assert_eq!(account.entry_count, 2);
    assert_eq!(account.entries.len(), 2);
    assert_eq!(account.entries[0], entry1);
    assert_eq!(account.entries[1], entry2);
}

#[test]
fn test_keyset_account_clone() {
    let entry = KeysetEntry {
        suite_id: 0x03,
        weight: 200,
        reserved0: [0x11],
        pubkey_len: 5,
        pubkey_bytes: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
    };

    let account = KeysetAccount {
        version: 2,
        reserved0: [0x01, 0x02, 0x03],
        threshold: 150,
        entry_count: 1,
        reserved1: [0x04, 0x05, 0x06, 0x07],
        entries: vec![entry],
    };

    let cloned = account.clone();

    assert_eq!(cloned.version, account.version);
    assert_eq!(cloned.reserved0, account.reserved0);
    assert_eq!(cloned.threshold, account.threshold);
    assert_eq!(cloned.entry_count, account.entry_count);
    assert_eq!(cloned.reserved1, account.reserved1);
    assert_eq!(cloned.entries, account.entries);
    assert_eq!(cloned, account);
}