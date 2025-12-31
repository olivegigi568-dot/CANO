use cano_types::{
    genesis_safety_council_keyset,
    genesis_safety_council_accounts,
    SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
    AccountId,
};

fn test_member_ids() -> [AccountId; 7] {
    [
        [0xB1; 32],
        [0xB2; 32],
        [0xB3; 32],
        [0xB4; 32],
        [0xB5; 32],
        [0xB6; 32],
        [0xB7; 32],
    ]
}

#[test]
fn genesis_safety_council_keyset_shape_is_correct() {
    let member_ids = test_member_ids();
    let keyset = genesis_safety_council_keyset(&member_ids);

    // Version should be 1.
    assert_eq!(keyset.version, 1);

    // 5-of-7 threshold.
    assert_eq!(keyset.threshold, 5);
    assert_eq!(keyset.member_count, 7);

    // Should have 7 members.
    assert_eq!(keyset.members.len(), 7);

    // Members should match the input.
    for (i, id) in keyset.members.iter().enumerate() {
        assert_eq!(*id, member_ids[i]);
    }

    // Reserved should be 0.
    assert_eq!(keyset.reserved0, 0);
}

#[test]
fn genesis_safety_council_accounts_shape_is_correct() {
    let accounts = genesis_safety_council_accounts();

    // Should have 7 accounts.
    assert_eq!(accounts.len(), 7);

    for account in accounts {
        // Version should be 1.
        assert_eq!(account.version, 1);

        // Suite ID should be Cat-5 lattice (0x02).
        assert_eq!(account.suite_id, SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024);
        assert_eq!(account.suite_id, 0x02);

        // Reserved should be zeros.
        assert_eq!(account.reserved0, [0u8; 2]);

        // Public key should have non-zero length.
        assert!(!account.pk_bytes.is_empty());
    }
}