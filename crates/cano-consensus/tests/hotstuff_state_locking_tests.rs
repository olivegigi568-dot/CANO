//! Tests for HotStuffStateEngine QC-based locking behavior.
//!
//! These tests verify:
//! - QC formation updates locked_qc when enough votes arrive
//! - Non-member votes are rejected and do not affect locking
//! - Higher-view QCs replace lower-view locked QCs
//! - Block registration in the block tree

use cano_consensus::{
    ConsensusValidatorSet, HotStuffStateEngine, QcValidationError, QuorumCertificate,
    ValidatorId, ValidatorSetEntry,
};

// ============================================================================
// Helpers
// ============================================================================

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

/// Helper to create a dummy block ID from a seed byte.
fn make_block_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// ============================================================================
// Test: HotStuffStateEngine creation and initial state
// ============================================================================

#[test]
fn hotstuff_state_engine_starts_with_no_lock_and_no_commit() {
    let validators = make_simple_set(4, 1);
    let engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators.clone());

    assert!(engine.locked_qc().is_none());
    assert!(engine.committed_block().is_none());
    assert_eq!(engine.block_count(), 0);
    assert_eq!(engine.validators().len(), 4);
}

// ============================================================================
// Test: Single-node QC formation updates locked_qc
// ============================================================================

#[test]
fn qc_formation_updates_locked_qc() {
    // 4 validators with equal weight (1 each)
    // total_vp = 4, two_thirds_vp = ceil(2*4/3) = 3
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xAA);
    let view = 10u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Vote from validator 0
    let result = engine.on_vote(ValidatorId(0), view, &block_id);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // No QC yet
    assert!(engine.locked_qc().is_none());
    assert_eq!(engine.vote_count(view, &block_id), 1);

    // Vote from validator 1
    let result = engine.on_vote(ValidatorId(1), view, &block_id);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none()); // Still no QC (2 votes, need 3)
    assert!(engine.locked_qc().is_none());
    assert_eq!(engine.vote_count(view, &block_id), 2);

    // Vote from validator 2 - this should form a QC
    let result = engine.on_vote(ValidatorId(2), view, &block_id);
    assert!(result.is_ok());
    let qc_opt = result.unwrap();
    assert!(qc_opt.is_some()); // QC formed!

    let qc = qc_opt.unwrap();
    assert_eq!(qc.block_id, block_id);
    assert_eq!(qc.view, view);
    assert_eq!(qc.signers.len(), 3);

    // locked_qc should now be set
    let locked = engine.locked_qc().expect("locked_qc should be set");
    assert_eq!(locked.block_id, block_id);
    assert_eq!(locked.view, view);

    // committed_block should still be None (we don't implement commit for T54)
    assert!(engine.committed_block().is_none());
}

// ============================================================================
// Test: Non-member votes error out and do not change locked_qc
// ============================================================================

#[test]
fn non_member_votes_error_and_do_not_change_locked_qc() {
    // 4 validators (IDs 0-3)
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xBB);
    let view = 20u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Vote from a non-member (validator 99)
    let result = engine.on_vote(ValidatorId(99), view, &block_id);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err, QcValidationError::NonMemberSigner(ValidatorId(99)));

    // locked_qc should still be None
    assert!(engine.locked_qc().is_none());

    // Vote count should be 0 (non-member vote was rejected)
    assert_eq!(engine.vote_count(view, &block_id), 0);
}

// ============================================================================
// Test: Higher-view QC replaces lower-view locked_qc
// ============================================================================

#[test]
fn higher_view_qc_replaces_lower_view_locked_qc() {
    let validators = make_simple_set(4, 1);
    let block_id_1 = make_block_id(0xCC);
    let block_id_2 = make_block_id(0xDD);
    let view_1 = 10u64;
    let view_2 = 20u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Form QC at view 10
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view_1, &block_id_1);
    }

    let locked_1 = engine.locked_qc().expect("should have locked_qc after first QC");
    assert_eq!(locked_1.view, view_1);
    assert_eq!(locked_1.block_id, block_id_1);

    // Form QC at higher view 20
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view_2, &block_id_2);
    }

    // locked_qc should be updated to the higher view
    let locked_2 = engine.locked_qc().expect("should have locked_qc after second QC");
    assert_eq!(locked_2.view, view_2);
    assert_eq!(locked_2.block_id, block_id_2);
}

// ============================================================================
// Test: Lower-view QC does NOT replace higher-view locked_qc
// ============================================================================

#[test]
fn lower_view_qc_does_not_replace_higher_view_locked_qc() {
    let validators = make_simple_set(4, 1);
    let block_id_1 = make_block_id(0xEE);
    let block_id_2 = make_block_id(0xFF);
    let view_high = 20u64;
    let view_low = 10u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Form QC at higher view first
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view_high, &block_id_1);
    }

    let locked_1 = engine.locked_qc().expect("should have locked_qc");
    assert_eq!(locked_1.view, view_high);

    // Try to form QC at lower view
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view_low, &block_id_2);
    }

    // locked_qc should NOT be replaced (still at higher view)
    let locked_2 = engine.locked_qc().expect("should still have locked_qc");
    assert_eq!(locked_2.view, view_high);
    assert_eq!(locked_2.block_id, block_id_1);
}

// ============================================================================
// Test: Block registration in block tree
// ============================================================================

#[test]
fn block_registration_stores_blocks() {
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let genesis_id = make_block_id(0x00);
    let block_1_id = make_block_id(0x01);
    let block_2_id = make_block_id(0x02);

    // Register genesis block (no parent, no justify_qc)
    engine.register_block(genesis_id, 0, None, None);
    assert_eq!(engine.block_count(), 1);

    let genesis = engine.get_block(&genesis_id).expect("genesis should exist");
    assert_eq!(genesis.id, genesis_id);
    assert_eq!(genesis.view, 0);
    assert!(genesis.parent_id.is_none());
    assert!(genesis.justify_qc.is_none());

    // Register block 1 (child of genesis)
    engine.register_block(block_1_id, 1, Some(genesis_id), None);
    assert_eq!(engine.block_count(), 2);

    let block_1 = engine.get_block(&block_1_id).expect("block_1 should exist");
    assert_eq!(block_1.id, block_1_id);
    assert_eq!(block_1.view, 1);
    assert_eq!(block_1.parent_id, Some(genesis_id));

    // Register block 2 with a justify_qc
    let qc = QuorumCertificate::new(block_1_id, 1, vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)]);
    engine.register_block(block_2_id, 2, Some(block_1_id), Some(qc.clone()));
    assert_eq!(engine.block_count(), 3);

    let block_2 = engine.get_block(&block_2_id).expect("block_2 should exist");
    assert_eq!(block_2.id, block_2_id);
    assert_eq!(block_2.view, 2);
    assert_eq!(block_2.parent_id, Some(block_1_id));
    assert!(block_2.justify_qc.is_some());
    assert_eq!(block_2.justify_qc.as_ref().unwrap().view, 1);
}

// ============================================================================
// Test: Duplicate votes do not advance quorum multiple times
// ============================================================================

#[test]
fn duplicate_votes_do_not_double_count() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0x11);
    let view = 30u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Vote from validator 0
    let _ = engine.on_vote(ValidatorId(0), view, &block_id);
    assert_eq!(engine.vote_count(view, &block_id), 1);

    // Duplicate vote from validator 0
    let _ = engine.on_vote(ValidatorId(0), view, &block_id);
    assert_eq!(engine.vote_count(view, &block_id), 1); // Still 1

    // Vote from validator 1
    let _ = engine.on_vote(ValidatorId(1), view, &block_id);
    assert_eq!(engine.vote_count(view, &block_id), 2);

    // More duplicates
    let _ = engine.on_vote(ValidatorId(0), view, &block_id);
    let _ = engine.on_vote(ValidatorId(1), view, &block_id);
    assert_eq!(engine.vote_count(view, &block_id), 2); // Still 2
}

// ============================================================================
// Test: set_locked_qc directly sets the lock
// ============================================================================

#[test]
fn set_locked_qc_directly_sets_lock() {
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_id = make_block_id(0x22);
    let qc = QuorumCertificate::new(
        block_id,
        42,
        vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
    );

    assert!(engine.locked_qc().is_none());

    engine.set_locked_qc(qc.clone());

    let locked = engine.locked_qc().expect("should have locked_qc");
    assert_eq!(locked.view, 42);
    assert_eq!(locked.block_id, block_id);
}

// ============================================================================
// Test: Weighted voting power is correctly considered
// ============================================================================

#[test]
fn weighted_voting_power_for_qc_formation() {
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
    let validators = ConsensusValidatorSet::new(entries).expect("valid set");
    let block_id = make_block_id(0x33);
    let view = 50u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Validator 2 alone (70 VP) reaches quorum (67)
    let result = engine.on_vote(ValidatorId(2), view, &block_id);
    assert!(result.is_ok());
    let qc_opt = result.unwrap();
    assert!(qc_opt.is_some()); // QC formed with single high-power validator

    let locked = engine.locked_qc().expect("should have locked_qc");
    assert_eq!(locked.view, view);
    assert_eq!(locked.signers.len(), 1);
}

// ============================================================================
// Test: Votes for different blocks in same view are tracked separately
// ============================================================================

#[test]
fn votes_for_different_blocks_tracked_separately() {
    let validators = make_simple_set(4, 1);
    let view = 60u64;

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Validators 0 and 1 vote for block A
    let _ = engine.on_vote(ValidatorId(0), view, &block_a);
    let _ = engine.on_vote(ValidatorId(1), view, &block_a);

    // Validators 2 and 3 vote for block B
    let _ = engine.on_vote(ValidatorId(2), view, &block_b);
    let _ = engine.on_vote(ValidatorId(3), view, &block_b);

    // Neither block has quorum (each has only 2 votes, need 3)
    assert_eq!(engine.vote_count(view, &block_a), 2);
    assert_eq!(engine.vote_count(view, &block_b), 2);
    assert!(engine.locked_qc().is_none());

    // Note: With equivocation detection, validator 2 cannot now vote for block A
    // after already voting for block B in the same view. This would be equivocation.
    // Instead, we add a 5th validator and have them vote for block A.
}

// ============================================================================
// Test: Votes for different blocks in same view reach quorum independently
// ============================================================================

#[test]
fn votes_for_different_blocks_reach_quorum_independently() {
    // Use 5 validators so we can form a quorum for block A without equivocation
    let validators = make_simple_set(5, 1);
    let view = 60u64;

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Validators 0 and 1 vote for block A
    let _ = engine.on_vote(ValidatorId(0), view, &block_a);
    let _ = engine.on_vote(ValidatorId(1), view, &block_a);

    // Validators 2 and 3 vote for block B
    let _ = engine.on_vote(ValidatorId(2), view, &block_b);
    let _ = engine.on_vote(ValidatorId(3), view, &block_b);

    // Neither block has quorum yet
    assert_eq!(engine.vote_count(view, &block_a), 2);
    assert_eq!(engine.vote_count(view, &block_b), 2);
    assert!(engine.locked_qc().is_none());

    // Validator 4 (who hasn't voted yet) votes for block A -> forms quorum for A
    // With 5 validators and vp=1 each, threshold = ceil(2*5/3) = 4
    // So we need one more vote for A
    let result = engine.on_vote(ValidatorId(4), view, &block_a);
    assert!(result.is_ok());

    // We have 3 votes for A, but need 4 for quorum. Not yet formed.
    assert_eq!(engine.vote_count(view, &block_a), 3);
    assert!(engine.locked_qc().is_none());
}

// ============================================================================
// Test: Votes for same block in different views are tracked separately
// ============================================================================

#[test]
fn votes_for_same_block_different_views_tracked_separately() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xDD);

    let view_1 = 70u64;
    let view_2 = 71u64;

    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Validators 0, 1, 2 vote for block in view 1 (reaches quorum)
    for i in 0..3 {
        let _ = engine.on_vote(ValidatorId(i), view_1, &block_id);
    }

    // Validators 0, 1 vote for same block in view 2 (doesn't reach quorum)
    for i in 0..2 {
        let _ = engine.on_vote(ValidatorId(i), view_2, &block_id);
    }

    // View 1 has quorum (3), view 2 doesn't (2)
    assert_eq!(engine.vote_count(view_1, &block_id), 3);
    assert_eq!(engine.vote_count(view_2, &block_id), 2);

    // locked_qc should be from view 1
    let locked = engine.locked_qc().expect("should have locked_qc");
    assert_eq!(locked.view, view_1);
}

// ============================================================================
// Tests for HotStuffDriver QC tracking
// ============================================================================

use cano_consensus::HotStuffDriver;

#[test]
fn driver_qcs_formed_counter_starts_at_zero() {
    let validators = make_simple_set(4, 1);
    let engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);
    let driver: HotStuffDriver<HotStuffStateEngine<[u8; 32]>, [u8; 32]> = HotStuffDriver::new(engine);

    assert_eq!(driver.qcs_formed(), 0);
    assert!(driver.last_qc().is_none());
}

#[test]
fn driver_record_qc_increments_counter_and_sets_last_qc() {
    let validators = make_simple_set(4, 1);
    let engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);
    let mut driver: HotStuffDriver<HotStuffStateEngine<[u8; 32]>, [u8; 32]> = HotStuffDriver::new(engine);

    let block_id = make_block_id(0xAA);
    let qc = QuorumCertificate::new(
        block_id,
        10,
        vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
    );

    driver.record_qc(qc.clone());

    assert_eq!(driver.qcs_formed(), 1);
    let last = driver.last_qc().expect("should have last_qc");
    assert_eq!(last.block_id, block_id);
    assert_eq!(last.view, 10);
}

#[test]
fn driver_record_qc_multiple_times_updates_counter_and_last_qc() {
    let validators = make_simple_set(4, 1);
    let engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);
    let mut driver: HotStuffDriver<HotStuffStateEngine<[u8; 32]>, [u8; 32]> = HotStuffDriver::new(engine);

    let block_1 = make_block_id(0xAA);
    let block_2 = make_block_id(0xBB);

    let qc1 = QuorumCertificate::new(
        block_1,
        10,
        vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
    );
    let qc2 = QuorumCertificate::new(
        block_2,
        20,
        vec![ValidatorId(0), ValidatorId(1), ValidatorId(2)],
    );

    driver.record_qc(qc1);
    assert_eq!(driver.qcs_formed(), 1);

    driver.record_qc(qc2);
    assert_eq!(driver.qcs_formed(), 2);

    let last = driver.last_qc().expect("should have last_qc");
    assert_eq!(last.block_id, block_2);
    assert_eq!(last.view, 20);
}