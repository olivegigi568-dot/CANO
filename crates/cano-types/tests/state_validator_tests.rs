use cano_types::{ValidatorStatus, ValidatorRecord};

#[test]
fn test_validator_status_discriminants() {
    assert_eq!(ValidatorStatus::Inactive as u8, 0);
    assert_eq!(ValidatorStatus::Active as u8, 1);
    assert_eq!(ValidatorStatus::Jailed as u8, 2);
    assert_eq!(ValidatorStatus::Exiting as u8, 3);
}

#[test]
fn test_validator_record_clone() {
    let record = ValidatorRecord {
        version: 1,
        status: ValidatorStatus::Active,
        reserved0: [0; 2],
        owner_keyset_id: [0x01; 32],
        consensus_suite_id: 0x01,
        reserved1: [0; 3],
        consensus_pk: vec![0xAA; 64],
        network_suite_id: 0x02,
        reserved2: [0; 3],
        network_pk: vec![0xBB; 32],
        stake: 1_000_000,
        last_slash_height: 0,
        ext_bytes: Vec::new(),
    };

    let cloned = record.clone();

    assert_eq!(cloned.version, record.version);
    assert_eq!(cloned.status, record.status);
    assert_eq!(cloned.owner_keyset_id, record.owner_keyset_id);
    assert_eq!(cloned.consensus_suite_id, record.consensus_suite_id);
    assert_eq!(cloned.consensus_pk, record.consensus_pk);
    assert_eq!(cloned.network_suite_id, record.network_suite_id);
    assert_eq!(cloned.network_pk, record.network_pk);
    assert_eq!(cloned.stake, record.stake);
    assert_eq!(cloned.last_slash_height, record.last_slash_height);
    assert_eq!(cloned, record);
}