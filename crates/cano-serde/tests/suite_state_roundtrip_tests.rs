use cano_types::{SuiteEntry, SuiteRegistry, SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus, Hash32, genesis_suite_registry};
use cano_serde::{StateEncode, StateDecode};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

#[test]
fn suite_entry_roundtrip() {
    let entry = SuiteEntry {
        suite_id: 0x01,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };

    let mut buf = Vec::new();
    entry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteEntry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, entry);
    assert!(slice.is_empty());
}

#[test]
fn suite_entry_roundtrip_with_ext_bytes() {
    let entry = SuiteEntry {
        suite_id: 0x02,
        family: SuiteFamily::HashBased,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Experimental,
        status: SuiteStatus::Legacy,
        reserved0: [0x11, 0x22, 0x33],
        params_hash: [0xAB; 32],
        ext_len: 5,
        ext_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };

    let mut buf = Vec::new();
    entry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteEntry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, entry);
    assert!(slice.is_empty());
}

#[test]
fn suite_registry_roundtrip() {
    let entry = SuiteEntry {
        suite_id: 0x01,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let registry = SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 1,
        reserved1: 0,
        suites: vec![entry],
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

#[test]
fn suite_registry_roundtrip_multiple_entries() {
    let entry1 = SuiteEntry {
        suite_id: 0x01,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: [0x11; 32],
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let entry2 = SuiteEntry {
        suite_id: 0x02,
        family: SuiteFamily::HashBased,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Experimental,
        status: SuiteStatus::Legacy,
        reserved0: [0u8; 3],
        params_hash: [0x22; 32],
        ext_len: 3,
        ext_bytes: vec![0xAA, 0xBB, 0xCC],
    };
    let registry = SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 2,
        reserved1: 0,
        suites: vec![entry1, entry2],
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

#[test]
fn suite_registry_empty() {
    let registry = SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 0,
        reserved1: 0,
        suites: Vec::new(),
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

#[test]
fn genesis_suite_registry_roundtrip_works() {
    let registry = genesis_suite_registry();

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}