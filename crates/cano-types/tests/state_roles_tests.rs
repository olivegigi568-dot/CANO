use cano_types::{
    genesis_key_role_policy, Role, SecurityCategory,
    TIER_MASK_CORE, TIER_MASK_BOTH,
};

#[test]
fn genesis_key_role_policy_shape_is_correct() {
    let pol = genesis_key_role_policy();
    assert_eq!(pol.version, 1);
    assert_eq!(pol.role_count, 5);
    assert_eq!(pol.roles.len(), 5);
}

#[test]
fn genesis_key_role_policy_enforces_no_cat1_for_validators() {
    let pol = genesis_key_role_policy();

    let by_role = |r: Role| pol.roles.iter().find(|e| e.role_id == r).unwrap();

    // ValidatorConsensus must be Cat3+
    let vc = by_role(Role::ValidatorConsensus);
    assert!(vc.min_category as u8 >= SecurityCategory::Cat3 as u8);
    assert_eq!(vc.allowed_tiers, TIER_MASK_CORE);

    // ValidatorOwner must be Cat5
    let vo = by_role(Role::ValidatorOwner);
    assert_eq!(vo.min_category, SecurityCategory::Cat5);
    assert_eq!(vo.allowed_tiers, TIER_MASK_CORE);

    // ValidatorNetwork must be Cat3+
    let vn = by_role(Role::ValidatorNetwork);
    assert!(vn.min_category as u8 >= SecurityCategory::Cat3 as u8);
    assert_eq!(vn.allowed_tiers, TIER_MASK_BOTH);

    // Governance must be Cat5
    let gov = by_role(Role::Governance);
    assert_eq!(gov.min_category, SecurityCategory::Cat5);
    assert_eq!(gov.allowed_tiers, TIER_MASK_BOTH);

    // BridgeOperator must be Cat3+
    let br = by_role(Role::BridgeOperator);
    assert!(br.min_category as u8 >= SecurityCategory::Cat3 as u8);
    assert_eq!(br.allowed_tiers, TIER_MASK_CORE);
}

#[test]
fn genesis_key_role_policy_no_validator_role_allows_cat1() {
    let pol = genesis_key_role_policy();

    // Verify that no validator or governance role has min_category = Cat1
    let validator_gov_roles = [
        Role::ValidatorOwner,
        Role::ValidatorConsensus,
        Role::ValidatorNetwork,
        Role::Governance,
    ];

    for role in validator_gov_roles {
        let entry = pol.roles.iter().find(|e| e.role_id == role).unwrap();
        assert!(
            entry.min_category as u8 >= SecurityCategory::Cat3 as u8,
            "Role {:?} must require at least Cat3, but has {:?}",
            role,
            entry.min_category
        );
    }
}