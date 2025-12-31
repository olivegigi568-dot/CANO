use cano_wire::keyset::{OP_KEYSET_CREATE, CreateKeysetCall, WireKeyEntry};
use cano_wire::io::{WireEncode, WireDecode};
use cano_types::AccountId;

fn dummy_account(id_byte: u8) -> AccountId {
    [id_byte; 32]
}

#[test]
fn wire_key_entry_roundtrip() {
    let entry = WireKeyEntry {
        suite_id: 0x01,
        weight: 100,
        pubkey_bytes: vec![1, 2, 3],
    };

    let mut buf = Vec::new();
    entry.encode(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = WireKeyEntry::decode(&mut slice).expect("decode");
    assert_eq!(decoded, entry);
    assert!(slice.is_empty());
}

#[test]
fn create_keyset_call_roundtrip() {
    let entries = vec![
        WireKeyEntry {
            suite_id: 0x01,
            weight: 100,
            pubkey_bytes: vec![1, 2, 3],
        },
        WireKeyEntry {
            suite_id: 0x02,
            weight: 50,
            pubkey_bytes: vec![4, 5],
        },
    ];

    let call = CreateKeysetCall {
        version: 1,
        target_id: dummy_account(0xEE),
        threshold: 120,
        entries,
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);

    // First byte should be op_code
    assert_eq!(buf[0], OP_KEYSET_CREATE);

    let mut slice: &[u8] = &buf;
    let decoded = CreateKeysetCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn create_keyset_call_empty_entries() {
    let call = CreateKeysetCall {
        version: 1,
        target_id: dummy_account(0xFF),
        threshold: 0,
        entries: Vec::new(),
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);

    assert_eq!(buf[0], OP_KEYSET_CREATE);

    let mut slice: &[u8] = &buf;
    let decoded = CreateKeysetCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn create_keyset_call_large_pubkeys() {
    let entries = vec![
        WireKeyEntry {
            suite_id: 0x01,
            weight: 200,
            pubkey_bytes: vec![0xAA; 2592],
        },
        WireKeyEntry {
            suite_id: 0x02,
            weight: 100,
            pubkey_bytes: vec![0xBB; 1952],
        },
    ];

    let call = CreateKeysetCall {
        version: 1,
        target_id: dummy_account(0xAB),
        threshold: 250,
        entries,
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);

    assert_eq!(buf[0], OP_KEYSET_CREATE);

    let mut slice: &[u8] = &buf;
    let decoded = CreateKeysetCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}