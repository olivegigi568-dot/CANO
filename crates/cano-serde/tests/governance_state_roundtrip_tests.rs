use cano_types::{
    AccountId, Hash32, MainnetStatus,
    SafetyCouncilKeyAccount, SafetyCouncilKeyset,
    LaunchChecklist, ParamRegistry,
};
use cano_serde::{StateEncode, StateDecode};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

fn test_member_id(n: u8) -> AccountId {
    [n; 32]
}

#[test]
fn safety_council_key_account_roundtrip() {
    let account = SafetyCouncilKeyAccount {
        version: 1,
        suite_id: 0x01,
        reserved0: [0u8; 2],
        pk_bytes: vec![0xAA; 100],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_key_account_large_pk() {
    // ML-DSA-65 pk is 2592 bytes
    let account = SafetyCouncilKeyAccount {
        version: 1,
        suite_id: 0x01,
        reserved0: [0u8; 2],
        pk_bytes: vec![0xBB; 2592],
    };

    let mut buf = Vec::new();
    account.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, account);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_keyset_roundtrip() {
    let keyset = SafetyCouncilKeyset {
        version: 1,
        threshold: 3,
        member_count: 5,
        reserved0: 0,
        members: vec![
            test_member_id(1),
            test_member_id(2),
            test_member_id(3),
            test_member_id(4),
            test_member_id(5),
        ],
    };

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());
}

#[test]
fn safety_council_keyset_empty() {
    let keyset = SafetyCouncilKeyset {
        version: 1,
        threshold: 0,
        member_count: 0,
        reserved0: 0,
        members: Vec::new(),
    };

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());
}

#[test]
fn launch_checklist_roundtrip() {
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: false,
        testnet_ok: false,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: false,
        proto_audit_ok: false,
        spec_ok: false,
        reserved1: 0,
        devnet_report_hash: zero_hash(),
        testnet_report_hash: zero_hash(),
        perf_report_hash: zero_hash(),
        adversarial_report_hash: zero_hash(),
        crypto_audit_hash: zero_hash(),
        proto_audit_hash: zero_hash(),
        spec_hash: zero_hash(),
    };

    let mut buf = Vec::new();
    checklist.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = LaunchChecklist::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, checklist);
    assert!(slice.is_empty());
}

#[test]
fn launch_checklist_roundtrip_all_ok() {
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: true,
        testnet_ok: true,
        perf_ok: true,
        adversarial_ok: true,
        crypto_audit_ok: true,
        proto_audit_ok: true,
        spec_ok: true,
        reserved1: 0,
        devnet_report_hash: [0x11; 32],
        testnet_report_hash: [0x22; 32],
        perf_report_hash: [0x33; 32],
        adversarial_report_hash: [0x44; 32],
        crypto_audit_hash: [0x55; 32],
        proto_audit_hash: [0x66; 32],
        spec_hash: [0x77; 32],
    };

    let mut buf = Vec::new();
    checklist.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = LaunchChecklist::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, checklist);
    assert!(slice.is_empty());
}

#[test]
fn param_registry_roundtrip() {
    let registry = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 10,
        reserved1: 0,
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

#[test]
fn param_registry_roundtrip_all_statuses() {
    let statuses = [
        MainnetStatus::PreGenesis,
        MainnetStatus::Ready,
        MainnetStatus::Activated,
    ];

    for status in statuses {
        let registry = ParamRegistry {
            version: 1,
            mainnet_status: status,
            reserved0: [0u8; 6],
            slash_bps_prevote: 500,
            slash_bps_precommit: 1000,
            reporter_reward_bps: 50,
            reserved1: 0,
        };

        let mut buf = Vec::new();
        registry.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, registry);
        assert!(slice.is_empty());
    }
}

#[test]
fn param_registry_max_values() {
    let registry = ParamRegistry {
        version: 255,
        mainnet_status: MainnetStatus::Activated,
        reserved0: [0xFF; 6],
        slash_bps_prevote: u16::MAX,
        slash_bps_precommit: u16::MAX,
        reporter_reward_bps: u16::MAX,
        reserved1: u16::MAX,
    };

    let mut buf = Vec::new();
    registry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = ParamRegistry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, registry);
    assert!(slice.is_empty());
}

// Genesis SafetyCouncil roundtrip tests

#[test]
fn genesis_safety_council_keyset_roundtrip() {
    let member_ids: [AccountId; 7] = [
        [0xB1; 32],
        [0xB2; 32],
        [0xB3; 32],
        [0xB4; 32],
        [0xB5; 32],
        [0xB6; 32],
        [0xB7; 32],
    ];

    let keyset = cano_types::genesis_safety_council_keyset(&member_ids);

    let mut buf = Vec::new();
    keyset.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = SafetyCouncilKeyset::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, keyset);
    assert!(slice.is_empty());

    // Verify expected values.
    assert_eq!(decoded.threshold, 5);
    assert_eq!(decoded.member_count, 7);
}

#[test]
fn genesis_safety_council_accounts_roundtrip() {
    let accounts = cano_types::genesis_safety_council_accounts();
    assert_eq!(accounts.len(), 7);

    for account in accounts {
        let mut buf = Vec::new();
        account.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = SafetyCouncilKeyAccount::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, account);
        assert!(slice.is_empty());

        // Verify expected values.
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.suite_id, 0x02); // SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024
        assert!(!decoded.pk_bytes.is_empty());
    }
}