use cano_types::{Role, SecurityCategory, RolePolicyEntry, KeyRolePolicy, genesis_key_role_policy};
use cano_serde::{StateEncode, StateDecode};

#[test]
fn role_policy_entry_roundtrip() {
    let entry = RolePolicyEntry {
        role_id: Role::ValidatorOwner,
        min_category: SecurityCategory::Cat3,
        allowed_tiers: 0x01,
        allow_legacy: 0,
        reserved0: [0u8; 4],
    };

    let mut buf = Vec::new();
    entry.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = RolePolicyEntry::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, entry);
    assert!(slice.is_empty());
}

#[test]
fn role_policy_entry_roundtrip_all_roles() {
    let roles = [
        Role::ValidatorOwner,
        Role::ValidatorConsensus,
        Role::ValidatorNetwork,
        Role::Governance,
        Role::BridgeOperator,
    ];

    for role in roles {
        let entry = RolePolicyEntry {
            role_id: role,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: 0x03,
            allow_legacy: 1,
            reserved0: [0x11, 0x22, 0x33, 0x44],
        };

        let mut buf = Vec::new();
        entry.encode_state(&mut buf);

        let mut slice: &[u8] = &buf;
        let decoded = RolePolicyEntry::decode_state(&mut slice).expect("decode");
        assert_eq!(decoded, entry);
        assert!(slice.is_empty());
    }
}

#[test]
fn key_role_policy_roundtrip() {
    let entry = RolePolicyEntry {
        role_id: Role::ValidatorOwner,
        min_category: SecurityCategory::Cat3,
        allowed_tiers: 0x01,
        allow_legacy: 0,
        reserved0: [0u8; 4],
    };
    let policy = KeyRolePolicy {
        version: 1,
        reserved0: [0u8; 3],
        role_count: 1,
        reserved1: 0,
        roles: vec![entry],
    };

    let mut buf = Vec::new();
    policy.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeyRolePolicy::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, policy);
    assert!(slice.is_empty());
}

#[test]
fn key_role_policy_roundtrip_multiple_roles() {
    let roles = vec![
        RolePolicyEntry {
            role_id: Role::ValidatorOwner,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: 0x01,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        RolePolicyEntry {
            role_id: Role::ValidatorConsensus,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: 0x01,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        RolePolicyEntry {
            role_id: Role::ValidatorNetwork,
            min_category: SecurityCategory::Cat1,
            allowed_tiers: 0x03,
            allow_legacy: 1,
            reserved0: [0u8; 4],
        },
        RolePolicyEntry {
            role_id: Role::Governance,
            min_category: SecurityCategory::Cat5,
            allowed_tiers: 0x01,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        RolePolicyEntry {
            role_id: Role::BridgeOperator,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: 0x01,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
    ];

    let policy = KeyRolePolicy {
        version: 1,
        reserved0: [0u8; 3],
        role_count: 5,
        reserved1: 0,
        roles,
    };

    let mut buf = Vec::new();
    policy.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeyRolePolicy::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, policy);
    assert!(slice.is_empty());
}

#[test]
fn key_role_policy_empty() {
    let policy = KeyRolePolicy {
        version: 1,
        reserved0: [0u8; 3],
        role_count: 0,
        reserved1: 0,
        roles: Vec::new(),
    };

    let mut buf = Vec::new();
    policy.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeyRolePolicy::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, policy);
    assert!(slice.is_empty());
}

#[test]
fn genesis_key_role_policy_roundtrip_works() {
    let policy = genesis_key_role_policy();

    let mut buf = Vec::new();
    policy.encode_state(&mut buf);

    let mut slice: &[u8] = &buf;
    let decoded = KeyRolePolicy::decode_state(&mut slice).expect("decode");
    assert_eq!(decoded, policy);
    assert!(slice.is_empty());
}