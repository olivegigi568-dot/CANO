use cano_ledger::{Account, InMemoryAccountStore, AccountStore};
use cano_types::{
    AccountId, ProgramId, SuiteEntry, SuiteRegistry,
    SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus, Hash32,
};
use cano_serde::{StateEncode, StateDecode};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn dummy_program_id(byte: u8) -> ProgramId {
    [byte; 32]
}

#[test]
fn suite_registry_account_roundtrip() {
    // Build a simple SuiteRegistry with one entry.
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

    // Encode via cano-serde.
    let mut data = Vec::new();
    registry.encode_state(&mut data);

    // Wrap into an Account and store in InMemoryAccountStore.
    let id = dummy_account_id(0xAA);
    let owner = dummy_program_id(0xBB);
    let account = Account::new(id, owner, 0, data);

    let mut store = InMemoryAccountStore::new();
    store.put(account.clone()).expect("put");

    // Fetch and decode back.
    let fetched = store.get(&id).expect("account exists");
    assert_eq!(fetched.id, id);
    assert_eq!(fetched.header.owner, owner);

    let mut slice: &[u8] = &fetched.data;
    let decoded = SuiteRegistry::decode_state(&mut slice).expect("decode");
    assert!(slice.is_empty());
    assert_eq!(decoded, registry);
}
