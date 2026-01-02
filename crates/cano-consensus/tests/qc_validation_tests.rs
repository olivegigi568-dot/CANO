//! Tests for the `qc` module.
//!
//! These tests verify logical QC validation:
//! - Valid QC with sufficient quorum
//! - QC with non-member signers
//! - QC with duplicate signers
//! - QC with insufficient quorum

use cano_consensus::{
    ConsensusValidatorSet, QcValidationError, QuorumCertificate, ValidatorId, ValidatorSetEntry,
};

/// Helper to build a simple validator set with `num` validators, each with `vp` voting power.
/// Validator IDs are 0, 1, 2, ..., num-1.
fn make_simple_set(num: u64, vp: u64) -> ConsensusValidatorSet {
    let entries = (0..num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: vp,
        })
        .collect::<Vec<_>>();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Test that a QC with sufficient quorum (2/3+) is valid.
#[test]
fn qc_valid_with_two_thirds_quorum() {
    // 4 validators with voting power 1 each
    // total_vp = 4, two_thirds_vp = ceil(2*4/3) = ceil(8/3) = 3
    let set = make_simple_set(4, 1);

    // Use a simple [u8; 32] as the block id (canonical type in cano-consensus)
    let block_id: [u8; 32] = [0xAA; 32];

    // 3 signers with 3 voting power >= 3 required
    let qc = QuorumCertificate::new(
        block_id,
        10,
        vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
    );

    assert!(qc.validate(&set).is_ok());
}

/// Test that a QC with all validators is also valid.
#[test]
fn qc_valid_with_all_validators() {
    let set = make_simple_set(4, 1);
    let block_id: [u8; 32] = [0xBB; 32];

    let qc = QuorumCertificate::new(
        block_id,
        5,
        vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(3),
        ],
    );

    assert!(qc.validate(&set).is_ok());
}

/// Test that a QC rejects a non-member signer.
#[test]
fn qc_rejects_non_member_signer() {
    // Validators are 0, 1, 2
    let set = make_simple_set(3, 1);
    let block_id: [u8; 32] = [0xCC; 32];

    // Validator 99 is not in the set
    let qc = QuorumCertificate::new(block_id, 10, vec![ValidatorId(0), ValidatorId(99)]);

    let err = qc.validate(&set).unwrap_err();
    assert_eq!(err, QcValidationError::NonMemberSigner(ValidatorId(99)));
}

/// Test that a QC rejects a non-member signer even if enough valid signers present.
#[test]
fn qc_rejects_non_member_even_with_quorum() {
    // 4 validators with voting power 1 each, need 3 for quorum
    let set = make_simple_set(4, 1);
    let block_id: [u8; 32] = [0xDD; 32];

    // 3 valid signers + 1 invalid signer
    let qc = QuorumCertificate::new(
        block_id,
        10,
        vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(2),
            ValidatorId(100), // not in set
        ],
    );

    let err = qc.validate(&set).unwrap_err();
    assert_eq!(err, QcValidationError::NonMemberSigner(ValidatorId(100)));
}

/// Test that a QC rejects duplicate signers.
#[test]
fn qc_rejects_duplicate_signer() {
    let set = make_simple_set(3, 1);
    let block_id: [u8; 32] = [0xEE; 32];

    // Validator 0 appears twice
    let qc = QuorumCertificate::new(block_id, 10, vec![ValidatorId(0), ValidatorId(0)]);

    let err = qc.validate(&set).unwrap_err();
    assert_eq!(err, QcValidationError::DuplicateSigner(ValidatorId(0)));
}

/// Test that a QC rejects duplicate signers even if they would provide sufficient quorum.
#[test]
fn qc_rejects_duplicate_even_with_quorum() {
    // 4 validators with voting power 1 each, need 3 for quorum
    let set = make_simple_set(4, 1);
    let block_id: [u8; 32] = [0xFF; 32];

    // Validator 1 appears twice
    let qc = QuorumCertificate::new(
        block_id,
        10,
        vec![
            ValidatorId(0),
            ValidatorId(1),
            ValidatorId(1), // duplicate
            ValidatorId(2),
        ],
    );

    let err = qc.validate(&set).unwrap_err();
    assert_eq!(err, QcValidationError::DuplicateSigner(ValidatorId(1)));
}

/// Test that a QC rejects insufficient quorum.
#[test]
fn qc_rejects_insufficient_quorum() {
    // 4 validators with voting power 1 each
    // total_vp = 4, two_thirds_vp = ceil(2*4/3) = 3
    let set = make_simple_set(4, 1);
    let block_id: [u8; 32] = [0x11; 32];

    // Only 2 signers with 2 voting power < 3 required
    let qc = QuorumCertificate::new(block_id, 10, vec![ValidatorId(0), ValidatorId(1)]);

    let err = qc.validate(&set).unwrap_err();
    match err {
        QcValidationError::InsufficientQuorum {
            accumulated_vp,
            required_vp,
        } => {
            assert_eq!(accumulated_vp, 2);
            assert_eq!(required_vp, 3);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

/// Test that a QC with zero signers is rejected.
#[test]
fn qc_rejects_empty_signers() {
    let set = make_simple_set(4, 1);
    let block_id: [u8; 32] = [0x22; 32];

    let qc: QuorumCertificate<[u8; 32]> = QuorumCertificate::new(block_id, 10, vec![]);

    let err = qc.validate(&set).unwrap_err();
    match err {
        QcValidationError::InsufficientQuorum {
            accumulated_vp,
            required_vp,
        } => {
            assert_eq!(accumulated_vp, 0);
            assert_eq!(required_vp, 3);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

/// Test that a QC with a single signer is rejected when insufficient.
#[test]
fn qc_rejects_single_signer_insufficient() {
    // 3 validators with voting power 10 each
    // total_vp = 30, two_thirds_vp = ceil(60/3) = 20
    let set = make_simple_set(3, 10);
    let block_id: [u8; 32] = [0x33; 32];

    // Single signer with 10 voting power < 20 required
    let qc = QuorumCertificate::new(block_id, 10, vec![ValidatorId(0)]);

    let err = qc.validate(&set).unwrap_err();
    match err {
        QcValidationError::InsufficientQuorum {
            accumulated_vp,
            required_vp,
        } => {
            assert_eq!(accumulated_vp, 10);
            assert_eq!(required_vp, 20);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

/// Test that weighted voting power is correctly accumulated.
#[test]
fn qc_weighted_voting_power() {
    // 3 validators with different voting powers: 10, 20, 70 = 100 total
    // two_thirds_vp = ceil(200/3) = 67
    let entries = vec![
        ValidatorSetEntry {
            id: ValidatorId(0),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId(1),
            voting_power: 20,
        },
        ValidatorSetEntry {
            id: ValidatorId(2),
            voting_power: 70,
        },
    ];
    let set = ConsensusValidatorSet::new(entries).expect("valid set");
    let block_id: [u8; 32] = [0x44; 32];

    // Validator 2 alone (70) reaches quorum (67)
    let qc1 = QuorumCertificate::new(block_id, 10, vec![ValidatorId(2)]);
    assert!(qc1.validate(&set).is_ok());

    // Validators 0+1 (30) does not reach quorum (67)
    let qc2 = QuorumCertificate::new(block_id, 10, vec![ValidatorId(0), ValidatorId(1)]);
    let err = qc2.validate(&set).unwrap_err();
    match err {
        QcValidationError::InsufficientQuorum {
            accumulated_vp,
            required_vp,
        } => {
            assert_eq!(accumulated_vp, 30);
            assert_eq!(required_vp, 67);
        }
        other => panic!("unexpected error: {:?}", other),
    }

    // Validators 1+2 (90) reaches quorum
    let qc3 = QuorumCertificate::new(block_id, 10, vec![ValidatorId(1), ValidatorId(2)]);
    assert!(qc3.validate(&set).is_ok());
}

/// Test that QC fields are accessible.
#[test]
fn qc_fields_accessible() {
    let block_id: [u8; 32] = [0x55; 32];
    let signers = vec![ValidatorId(1), ValidatorId(2)];

    let qc = QuorumCertificate::new(block_id, 42, signers.clone());

    assert_eq!(qc.block_id, block_id);
    assert_eq!(qc.view, 42);
    assert_eq!(qc.signers, signers);
}

/// Test that QuorumCertificate implements Clone and PartialEq correctly.
#[test]
fn qc_clone_and_eq() {
    let block_id: [u8; 32] = [0x66; 32];
    let qc1 = QuorumCertificate::new(block_id, 100, vec![ValidatorId(1)]);
    let qc2 = qc1.clone();

    assert_eq!(qc1, qc2);

    let qc3 = QuorumCertificate::new(block_id, 101, vec![ValidatorId(1)]);
    assert_ne!(qc1, qc3);
}
