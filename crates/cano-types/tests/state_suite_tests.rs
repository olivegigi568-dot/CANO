use cano_types::{
    genesis_suite_registry, SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus,
    SUITE_ID_LATTICE_L3_MLDSA65_MLKEM768, SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
    SUITE_ID_LATTICE_L1_MLDSA44_MLKEM768, SUITE_ID_HASH_L5_SLHDSA_S,
};

#[test]
fn genesis_suite_registry_shape_is_correct() {
    let reg = genesis_suite_registry();
    assert_eq!(reg.version, 1);
    assert_eq!(reg.suite_count, 4);
    assert_eq!(reg.suites.len(), 4);

    let by_id = |id: u8| reg.suites.iter().find(|s| s.suite_id == id).unwrap();

    let l3 = by_id(SUITE_ID_LATTICE_L3_MLDSA65_MLKEM768);
    assert_eq!(l3.family, SuiteFamily::Lattice);
    assert_eq!(l3.category, SecurityCategory::Cat3);
    assert_eq!(l3.tier, SuiteTier::Core);
    assert_eq!(l3.status, SuiteStatus::Active);

    let l5 = by_id(SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024);
    assert_eq!(l5.family, SuiteFamily::Lattice);
    assert_eq!(l5.category, SecurityCategory::Cat5);
    assert_eq!(l5.tier, SuiteTier::Core);
    assert_eq!(l5.status, SuiteStatus::Active);

    let l1 = by_id(SUITE_ID_LATTICE_L1_MLDSA44_MLKEM768);
    assert_eq!(l1.family, SuiteFamily::Lattice);
    assert_eq!(l1.category, SecurityCategory::Cat1);
    assert_eq!(l1.tier, SuiteTier::Experimental);
    assert_eq!(l1.status, SuiteStatus::Active);

    let h5 = by_id(SUITE_ID_HASH_L5_SLHDSA_S);
    assert_eq!(h5.family, SuiteFamily::HashBased);
    assert_eq!(h5.category, SecurityCategory::Cat5);
    assert_eq!(h5.tier, SuiteTier::Experimental);
    assert_eq!(h5.status, SuiteStatus::Active);
}

#[test]
fn suite_id_constants_are_unique() {
    let ids = [
        SUITE_ID_LATTICE_L3_MLDSA65_MLKEM768,
        SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
        SUITE_ID_LATTICE_L1_MLDSA44_MLKEM768,
        SUITE_ID_HASH_L5_SLHDSA_S,
    ];
    let mut sorted = ids.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "Suite IDs must be unique");
}