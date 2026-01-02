//! Tests for vote accumulator and HotStuff-like QC aggregation.
//!
//! These tests verify:
//! - QC formation when enough votes arrive
//! - Duplicate vote handling
//! - Separate tracking of votes for different blocks in the same view
//! - Rejection of non-member votes

use cano_consensus::{
    ConsensusValidatorSet, QcValidationError, ValidatorId, ValidatorSetEntry,
    VoteAccumulator,
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

/// Helper to create a dummy block ID.
fn make_block_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// ============================================================================
// Test: QC is formed when enough votes arrive
// ============================================================================

#[test]
fn qc_is_formed_after_quorum_votes() {
    // 4 validators, each with power 1
    // total_vp = 4, two_thirds_vp = ceil(2*4/3) = 3
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xAA);
    let view = 10;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Vote from validator 0
    let is_new = acc
        .on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    assert!(is_new);
    assert_eq!(acc.vote_count(view, &block_id), 1);

    // Vote from validator 1
    let is_new = acc
        .on_vote(&validators, ValidatorId(1), view, &block_id)
        .unwrap();
    assert!(is_new);
    assert_eq!(acc.vote_count(view, &block_id), 2);

    // Not enough yet (2 votes, need 3)
    let qc_opt = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc_opt.is_none());

    // Vote from validator 2
    let is_new = acc
        .on_vote(&validators, ValidatorId(2), view, &block_id)
        .unwrap();
    assert!(is_new);
    assert_eq!(acc.vote_count(view, &block_id), 3);

    // Now we should get a QC (3 votes >= 3 required)
    let qc_opt = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    let qc = qc_opt.expect("expected QC to be formed");

    // Validate the QC
    qc.validate(&validators).unwrap();
    assert_eq!(qc.block_id, block_id);
    assert_eq!(qc.view, view);
    assert_eq!(qc.signers.len(), 3);
}

// ============================================================================
// Test: QC with all four validators is also valid
// ============================================================================

#[test]
fn qc_formed_with_all_validators() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xBB);
    let view = 20;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // All 4 validators vote
    for i in 0..4 {
        acc.on_vote(&validators, ValidatorId(i), view, &block_id)
            .unwrap();
    }

    let qc = acc
        .maybe_qc_for(&validators, view, &block_id)
        .unwrap()
        .expect("expected QC");

    qc.validate(&validators).unwrap();
    assert_eq!(qc.signers.len(), 4);
}

// ============================================================================
// Test: Duplicate votes from same validator do not advance quorum
// ============================================================================

#[test]
fn duplicate_votes_do_not_advance_quorum() {
    // 4 validators, each with power 1 (need 3 for quorum)
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xCC);
    let view = 30;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Vote from validator 0 - first time
    let is_new = acc
        .on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    assert!(is_new);

    // Vote from validator 0 again - should be duplicate
    let is_new = acc
        .on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    assert!(!is_new); // duplicate!

    // Vote from validator 1 - first time
    let is_new = acc
        .on_vote(&validators, ValidatorId(1), view, &block_id)
        .unwrap();
    assert!(is_new);

    // Vote from validator 0 a third time - still duplicate
    let is_new = acc
        .on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    assert!(!is_new);

    // Only 2 unique votes, so no quorum
    assert_eq!(acc.vote_count(view, &block_id), 2);
    let qc_opt = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc_opt.is_none());

    // Add a third unique vote
    acc.on_vote(&validators, ValidatorId(2), view, &block_id)
        .unwrap();

    // Now we have quorum
    assert_eq!(acc.vote_count(view, &block_id), 3);
    let qc = acc
        .maybe_qc_for(&validators, view, &block_id)
        .unwrap()
        .expect("expected QC");
    qc.validate(&validators).unwrap();
}

// ============================================================================
// Test: Votes for different blocks in same view are tracked separately
// ============================================================================

#[test]
fn votes_for_different_blocks_tracked_separately() {
    // 4 validators, each with power 1 (need 3 for quorum)
    let validators = make_simple_set(4, 1);
    let view = 40;

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Validators 0 and 1 vote for block A
    acc.on_vote(&validators, ValidatorId(0), view, &block_a)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view, &block_a)
        .unwrap();

    // Validators 2 and 3 vote for block B
    acc.on_vote(&validators, ValidatorId(2), view, &block_b)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(3), view, &block_b)
        .unwrap();

    // Neither block has quorum (each has only 2 votes)
    assert_eq!(acc.vote_count(view, &block_a), 2);
    assert_eq!(acc.vote_count(view, &block_b), 2);

    let qc_a = acc.maybe_qc_for(&validators, view, &block_a).unwrap();
    assert!(qc_a.is_none());

    let qc_b = acc.maybe_qc_for(&validators, view, &block_b).unwrap();
    assert!(qc_b.is_none());

    // Now validator 2 also votes for block A (they can vote for both in this test)
    acc.on_vote(&validators, ValidatorId(2), view, &block_a)
        .unwrap();

    // Block A now has quorum (3 votes), block B still doesn't (2 votes)
    assert_eq!(acc.vote_count(view, &block_a), 3);
    assert_eq!(acc.vote_count(view, &block_b), 2);

    let qc_a = acc
        .maybe_qc_for(&validators, view, &block_a)
        .unwrap()
        .expect("expected QC for block A");
    qc_a.validate(&validators).unwrap();
    assert_eq!(qc_a.block_id, block_a);

    let qc_b = acc.maybe_qc_for(&validators, view, &block_b).unwrap();
    assert!(qc_b.is_none());
}

// ============================================================================
// Test: Votes for same block in different views are tracked separately
// ============================================================================

#[test]
fn votes_for_same_block_different_views_tracked_separately() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0xDD);

    let view1 = 50;
    let view2 = 51;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Validators 0, 1, 2 vote for block in view 1
    acc.on_vote(&validators, ValidatorId(0), view1, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view1, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), view1, &block_id)
        .unwrap();

    // Validators 0, 1 vote for same block in view 2
    acc.on_vote(&validators, ValidatorId(0), view2, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view2, &block_id)
        .unwrap();

    // View 1 has quorum, view 2 doesn't
    assert_eq!(acc.vote_count(view1, &block_id), 3);
    assert_eq!(acc.vote_count(view2, &block_id), 2);

    let qc1 = acc
        .maybe_qc_for(&validators, view1, &block_id)
        .unwrap()
        .expect("expected QC for view 1");
    qc1.validate(&validators).unwrap();
    assert_eq!(qc1.view, view1);

    let qc2 = acc.maybe_qc_for(&validators, view2, &block_id).unwrap();
    assert!(qc2.is_none());
}

// ============================================================================
// Test: Non-member votes cause QcValidationError::NonMemberSigner
// ============================================================================

#[test]
fn non_member_votes_cause_error() {
    // Validators are 0, 1, 2
    let validators = make_simple_set(3, 1);
    let block_id = make_block_id(0xEE);
    let view = 60;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Vote from a non-member (validator 99)
    let result = acc.on_vote(&validators, ValidatorId(99), view, &block_id);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err, QcValidationError::NonMemberSigner(ValidatorId(99)));
}

// ============================================================================
// Test: Non-member votes do not affect vote count
// ============================================================================

#[test]
fn non_member_votes_do_not_affect_count() {
    let validators = make_simple_set(3, 1);
    let block_id = make_block_id(0xFF);
    let view = 70;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Valid vote from member
    acc.on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();

    // Invalid vote from non-member
    let _ = acc.on_vote(&validators, ValidatorId(99), view, &block_id);

    // Vote count should still be 1 (non-member vote was rejected)
    assert_eq!(acc.vote_count(view, &block_id), 1);
}

// ============================================================================
// Test: remove_entry clears votes for a (view, block_id)
// ============================================================================

#[test]
fn remove_entry_clears_votes() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0x11);
    let view = 80;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Accumulate enough votes for quorum
    acc.on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(2), view, &block_id)
        .unwrap();

    assert_eq!(acc.vote_count(view, &block_id), 3);
    let qc = acc
        .maybe_qc_for(&validators, view, &block_id)
        .unwrap()
        .expect("expected QC");
    qc.validate(&validators).unwrap();

    // Remove the entry
    acc.remove_entry(view, &block_id);

    // Vote count should be 0 now
    assert_eq!(acc.vote_count(view, &block_id), 0);

    // No QC available anymore
    let qc_after = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc_after.is_none());
}

// ============================================================================
// Test: Weighted voting power is correctly considered for quorum
// ============================================================================

#[test]
fn weighted_voting_power_for_quorum() {
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
    let block_id = make_block_id(0x22);
    let view = 90;

    let mut acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    // Validators 0+1 (30 VP) does not reach quorum (67)
    acc.on_vote(&validators, ValidatorId(0), view, &block_id)
        .unwrap();
    acc.on_vote(&validators, ValidatorId(1), view, &block_id)
        .unwrap();

    let qc_opt = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc_opt.is_none());

    // Validator 2 alone (70 VP) reaches quorum (67)
    let block_id2 = make_block_id(0x33);
    acc.on_vote(&validators, ValidatorId(2), view, &block_id2)
        .unwrap();

    let qc = acc
        .maybe_qc_for(&validators, view, &block_id2)
        .unwrap()
        .expect("expected QC with single high-power validator");
    qc.validate(&validators).unwrap();
    assert_eq!(qc.signers.len(), 1);
}

// ============================================================================
// Test: Empty accumulator returns None for maybe_qc_for
// ============================================================================

#[test]
fn empty_accumulator_returns_none() {
    let validators = make_simple_set(4, 1);
    let block_id = make_block_id(0x44);
    let view = 100;

    let acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::new();

    let qc_opt = acc.maybe_qc_for(&validators, view, &block_id).unwrap();
    assert!(qc_opt.is_none());
}

// ============================================================================
// Test: VoteAccumulator default() works
// ============================================================================

#[test]
fn vote_accumulator_default() {
    let acc: VoteAccumulator<[u8; 32]> = VoteAccumulator::default();
    let block_id = make_block_id(0x55);
    let view = 110;

    // Should work the same as new()
    assert_eq!(acc.vote_count(view, &block_id), 0);
}
