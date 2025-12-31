use cano_types::{SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus, Role, MainnetStatus};

#[test]
fn test_suite_family_discriminants() {
    assert_eq!(SuiteFamily::Lattice as u8, 0x00);
    assert_eq!(SuiteFamily::HashBased as u8, 0x01);
    assert_eq!(SuiteFamily::CodeBased as u8, 0x02);
    assert_eq!(SuiteFamily::Isogeny as u8, 0x03);
    assert_eq!(SuiteFamily::Reserved as u8, 0xFF);
}

#[test]
fn test_security_category_discriminants() {
    assert_eq!(SecurityCategory::Cat1 as u8, 0x01);
    assert_eq!(SecurityCategory::Cat3 as u8, 0x03);
    assert_eq!(SecurityCategory::Cat5 as u8, 0x05);
}

#[test]
fn test_suite_tier_discriminants() {
    assert_eq!(SuiteTier::Core as u8, 0x00);
    assert_eq!(SuiteTier::Experimental as u8, 0x01);
}

#[test]
fn test_suite_status_discriminants() {
    assert_eq!(SuiteStatus::Active as u8, 0x00);
    assert_eq!(SuiteStatus::Legacy as u8, 0x01);
    assert_eq!(SuiteStatus::Disabled as u8, 0x02);
}

#[test]
fn test_role_discriminants() {
    assert_eq!(Role::ValidatorOwner as u8, 0x00);
    assert_eq!(Role::ValidatorConsensus as u8, 0x01);
    assert_eq!(Role::ValidatorNetwork as u8, 0x02);
    assert_eq!(Role::Governance as u8, 0x03);
    assert_eq!(Role::BridgeOperator as u8, 0x04);
}

#[test]
fn test_mainnet_status_discriminants() {
    assert_eq!(MainnetStatus::PreGenesis as u8, 0x00);
    assert_eq!(MainnetStatus::Ready as u8, 0x01);
    assert_eq!(MainnetStatus::Activated as u8, 0x02);
}