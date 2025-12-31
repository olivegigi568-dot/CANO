//! SuiteRegistry state types for cano.

use crate::primitives::{Hash32, SecurityCategory, SuiteFamily, SuiteStatus, SuiteTier};

// Canonical suite IDs for cano v1 genesis.
/// Lattice ML-DSA-65 / ML-KEM-768: Core, Cat-3
pub const SUITE_ID_LATTICE_L3_MLDSA65_MLKEM768: u8 = 0x01;

/// Lattice ML-DSA-87 / ML-KEM-1024: Core, Cat-5
pub const SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024: u8 = 0x02;

/// Lattice ML-DSA-44 / ML-KEM-768: Experimental, Cat-1 (non-core)
pub const SUITE_ID_LATTICE_L1_MLDSA44_MLKEM768: u8 = 0x03;

/// Hash-based SLH-DSA-S (SPHINCS+ small): Experimental, Cat-5
pub const SUITE_ID_HASH_L5_SLHDSA_S: u8 = 0x10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiteEntry {
    pub suite_id: u8,
    pub family: SuiteFamily,
    pub category: SecurityCategory,
    pub tier: SuiteTier,
    pub status: SuiteStatus,
    pub reserved0: [u8; 3],
    pub params_hash: Hash32,
    pub ext_len: u16,
    // For v1 we can keep ext_bytes empty in genesis, but type should support arbitrary future data.
    pub ext_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiteRegistry {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub suite_count: u16,
    pub reserved1: u16,
    pub suites: Vec<SuiteEntry>,
}

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

/// Canonical SuiteRegistry contents for cano v1 genesis.
///
/// Suites:
///   0x01: ML-DSA-65 / ML-KEM-768 (Lattice, Core, Cat3)
///   0x02: ML-DSA-87 / ML-KEM-1024 (Lattice, Core, Cat5)
///   0x03: ML-DSA-44 / ML-KEM-768 (Lattice, Experimental, Cat1)
///   0x10: SLH-DSA-S (hash-based, Experimental, Cat5)
pub fn genesis_suite_registry() -> SuiteRegistry {
    let s_l3 = SuiteEntry {
        suite_id: SUITE_ID_LATTICE_L3_MLDSA65_MLKEM768,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };

    let s_l5 = SuiteEntry {
        suite_id: SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };

    let s_l1 = SuiteEntry {
        suite_id: SUITE_ID_LATTICE_L1_MLDSA44_MLKEM768,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat1,
        tier: SuiteTier::Experimental,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };

    let s_hash = SuiteEntry {
        suite_id: SUITE_ID_HASH_L5_SLHDSA_S,
        family: SuiteFamily::HashBased,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Experimental,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };

    SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 4,
        reserved1: 0,
        suites: vec![s_l3, s_l5, s_l1, s_hash],
    }
}