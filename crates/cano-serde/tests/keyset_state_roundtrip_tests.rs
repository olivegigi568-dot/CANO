use cano_types::{KeysetEntry, KeysetAccount};
use cano_serde::{StateEncode, StateDecode};

#[test]
fn keyset_entry_roundtrip() {
    let entry = KeysetEntry {
        suite_id: 0x01,
        weight: 100,
        reserved0: [0u8; 1],
        pubkey_len: 3,
        pubkey_bytes: vec![1, 2, 3],
    };

    let mut buf = Vec::new();
    entry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeysetEntry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, entry);
    assert!(slice.is_empty());
}

#[test]
fn keyset_account_roundtrip_with_two_entries() {
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
        entries: vec![entry1, entry2],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn keyset_account_roundtrip_empty_entries() {
    let account = KeysetAccount {
        version: 1,
        reserved0: [0u8; 3],
        threshold: 0,
        entry_count: 0,
        reserved1: [0u8; 4],
        entries: Vec::new(),
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn keyset_account_roundtrip_large_pubkeys() {
    // Test with ML-DSA-like pubkeys
    let entry1 = KeysetEntry {
        suite_id: 0x01,
        weight: 200,
        reserved0: [0u8; 1],
        pubkey_len: 2592,
        pubkey_bytes: vec![0xAA; 2592],
    };

    let entry2 = KeysetEntry {
        suite_id: 0x02,
        weight: 100,
        reserved0: [0u8; 1],
        pubkey_len: 1952,
        pubkey_bytes: vec![0xBB; 1952],
    };

    let account = KeysetAccount {
        version: 1,
        reserved0: [0u8; 3],
        threshold: 250,
        entry_count: 2,
        reserved1: [0u8; 4],
        entries: vec![entry1, entry2],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn keyset_account_roundtrip_reserved_fields() {
    let entry = KeysetEntry {
        suite_id: 0xFF,
        weight: u16::MAX,
        reserved0: [0x11],
        pubkey_len: 5,
        pubkey_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };

    let account = KeysetAccount {
        version: 255,
        reserved0: [0x11, 0x22, 0x33],
        threshold: u16::MAX,
        entry_count: 1,
        reserved1: [0x44, 0x55, 0x66, 0x77],
        entries: vec![entry],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}