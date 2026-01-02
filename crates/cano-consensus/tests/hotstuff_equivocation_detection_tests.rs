//! Tests for equivocation detection in HotStuffStateEngine.
//!
//! These tests verify:
//! - Equivocation is detected when a validator votes for different blocks in the same view
//! - Duplicate votes for the same block in the same view are NOT equivocation
//! - Votes for different blocks in different views are allowed (not equivocation)
//! - Equivocating votes do not contribute to QC formation

use cano_consensus::{
    ConsensusValidatorSet, HotStuffStateEngine, ValidatorId, ValidatorSetEntry,
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
// Test: Equivocation is detected on same view with different blocks
// ============================================================================

#[test]
fn hotstuff_detects_equivocation_same_view_different_block() {
    // Setup: 4 validators with power 1 each (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Two distinct block IDs
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view = 10u64;

    // Vote from validator 0 for block A
    let result = engine.on_vote(ValidatorId(0), view, &block_a);
    assert!(result.is_ok());
    assert_eq!(
        engine.equivocations_detected(),
        0,
        "no equivocation after first vote"
    );
    assert!(
        engine.equivocating_validators().is_empty(),
        "no equivocating validators after first vote"
    );

    // Vote from validator 0 for block B (same view, different block) - this is equivocation!
    let result = engine.on_vote(ValidatorId(0), view, &block_b);
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "equivocating vote should not form QC"
    );
    assert_eq!(
        engine.equivocations_detected(),
        1,
        "equivocation should be detected"
    );
    assert!(
        engine.equivocating_validators().contains(&ValidatorId(0)),
        "validator 0 should be in equivocating set"
    );
}

// ============================================================================
// Test: Duplicate vote for same block is NOT equivocation
// ============================================================================

#[test]
fn hotstuff_duplicate_vote_same_block_not_equivocation() {
    // Setup: 4 validators with power 1 each
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let view = 10u64;

    // First vote from validator 0 for block A
    let result = engine.on_vote(ValidatorId(0), view, &block_a);
    assert!(result.is_ok());

    // Second identical vote from validator 0 for block A (same view, same block)
    let result = engine.on_vote(ValidatorId(0), view, &block_a);
    assert!(result.is_ok());

    // This should NOT be counted as equivocation
    assert_eq!(
        engine.equivocations_detected(),
        0,
        "duplicate vote for same block should not be equivocation"
    );
    assert!(
        engine.equivocating_validators().is_empty(),
        "no validators should be marked as equivocating"
    );
}

// ============================================================================
// Test: Votes in different views are NOT equivocation
// ============================================================================

#[test]
fn hotstuff_votes_in_different_views_are_not_equivocation() {
    // Setup: 4 validators with power 1 each
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view_1 = 10u64;
    let view_2 = 11u64;

    // Vote from validator 0 for block A at view 10
    let result = engine.on_vote(ValidatorId(0), view_1, &block_a);
    assert!(result.is_ok());

    // Vote from validator 0 for block B at view 11 (different view, different block)
    let result = engine.on_vote(ValidatorId(0), view_2, &block_b);
    assert!(result.is_ok());

    // This should NOT be counted as equivocation (different views are allowed)
    assert_eq!(
        engine.equivocations_detected(),
        0,
        "voting for different blocks in different views should not be equivocation"
    );
    assert!(
        engine.equivocating_validators().is_empty(),
        "no validators should be marked as equivocating"
    );
}

// ============================================================================
// Test: Equivocating votes do NOT contribute to quorum
// ============================================================================

#[test]
fn hotstuff_equivocating_votes_do_not_contribute_to_quorum() {
    // Setup: 4 validators with power 1 each (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view = 10u64;

    // Register blocks so we can track QC formation
    engine.register_block(block_a, view, None, None);
    engine.register_block(block_b, view, None, None);

    // Sequence of votes:
    // 1. v0 votes for A
    // 2. v1 votes for A
    // 3. v0 votes for B (equivocation!) - should be ignored
    // 4. v2 votes for A -> should form QC for A

    // Vote 1: v0 for A
    let result = engine.on_vote(ValidatorId(0), view, &block_a);
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "no QC yet (only 1 vote)"
    );

    // Vote 2: v1 for A
    let result = engine.on_vote(ValidatorId(1), view, &block_a);
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "no QC yet (only 2 votes)"
    );

    // Vote 3: v0 for B (equivocation!)
    let result = engine.on_vote(ValidatorId(0), view, &block_b);
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "equivocating vote should return Ok(None)"
    );
    assert_eq!(
        engine.equivocations_detected(),
        1,
        "equivocation should be detected"
    );

    // At this point, block A has 2 valid votes (v0, v1)
    // The equivocating vote from v0 for B should NOT help form a QC

    // Vote 4: v2 for A -> should form QC for A (3 votes: v0, v1, v2)
    let result = engine.on_vote(ValidatorId(2), view, &block_a);
    assert!(result.is_ok());
    let qc = result.unwrap();
    assert!(qc.is_some(), "QC should be formed with 3 valid votes");

    let qc = qc.unwrap();
    assert_eq!(qc.block_id, block_a, "QC should be for block A");
    assert_eq!(qc.view, view, "QC should be for view 10");

    // Verify that the locked_qc is for block A
    let locked_qc = engine.locked_qc().expect("locked_qc should be set");
    assert_eq!(locked_qc.block_id, block_a, "locked_qc should be for block A");
}

// ============================================================================
// Test: Multiple equivocations from different validators
// ============================================================================

#[test]
fn hotstuff_detects_multiple_equivocations() {
    // Setup: 4 validators with power 1 each
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view = 10u64;

    // v0 votes for A, then for B (equivocation)
    engine.on_vote(ValidatorId(0), view, &block_a).unwrap();
    engine.on_vote(ValidatorId(0), view, &block_b).unwrap();

    // v1 votes for A, then for B (another equivocation)
    engine.on_vote(ValidatorId(1), view, &block_a).unwrap();
    engine.on_vote(ValidatorId(1), view, &block_b).unwrap();

    // Should have 2 equivocations detected
    assert_eq!(
        engine.equivocations_detected(),
        2,
        "two equivocations should be detected"
    );

    // Both validators should be in the equivocating set
    let equivocating = engine.equivocating_validators();
    assert!(
        equivocating.contains(&ValidatorId(0)),
        "validator 0 should be in equivocating set"
    );
    assert!(
        equivocating.contains(&ValidatorId(1)),
        "validator 1 should be in equivocating set"
    );
    assert_eq!(
        equivocating.len(),
        2,
        "exactly 2 validators should be marked as equivocating"
    );
}

// ============================================================================
// Test: Repeated equivocations from same validator count separately
// ============================================================================

#[test]
fn hotstuff_repeated_equivocations_from_same_validator() {
    // Setup: 4 validators with power 1 each
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);
    let view = 10u64;

    // v0 votes for A
    engine.on_vote(ValidatorId(0), view, &block_a).unwrap();
    assert_eq!(engine.equivocations_detected(), 0);

    // v0 votes for B (first equivocation)
    engine.on_vote(ValidatorId(0), view, &block_b).unwrap();
    assert_eq!(engine.equivocations_detected(), 1);

    // v0 votes for C (second equivocation - same validator, yet another block)
    engine.on_vote(ValidatorId(0), view, &block_c).unwrap();
    assert_eq!(
        engine.equivocations_detected(),
        2,
        "each equivocating vote should be counted"
    );

    // But there's still only one equivocating validator
    assert_eq!(
        engine.equivocating_validators().len(),
        1,
        "only one validator is equivocating"
    );
}

// ============================================================================
// Test: QC formation with mix of valid votes and equivocations
// ============================================================================

#[test]
fn hotstuff_qc_formation_with_equivocations_mixed() {
    // Setup: 5 validators with power 1 each (total=5, threshold=4)
    let validators = make_simple_set(5, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let view = 10u64;

    engine.register_block(block_a, view, None, None);

    // Scenario:
    // - v0, v1 vote for A (2 valid votes)
    // - v2 votes for A, then equivocates with B (1 valid vote for A, 1 equivocation)
    // - v3, v4 vote for A (2 more valid votes)
    // Total valid votes for A: v0, v1, v2, v3, v4 = 5 (but we check threshold=4)

    // v0 for A
    let r = engine.on_vote(ValidatorId(0), view, &block_a).unwrap();
    assert!(r.is_none());

    // v1 for A
    let r = engine.on_vote(ValidatorId(1), view, &block_a).unwrap();
    assert!(r.is_none());

    // v2 for A
    let r = engine.on_vote(ValidatorId(2), view, &block_a).unwrap();
    assert!(r.is_none());

    // v2 for B (equivocation - should be ignored)
    let r = engine.on_vote(ValidatorId(2), view, &block_b).unwrap();
    assert!(r.is_none());
    assert_eq!(engine.equivocations_detected(), 1);

    // v3 for A (4th valid vote - should form QC!)
    let r = engine.on_vote(ValidatorId(3), view, &block_a).unwrap();
    assert!(r.is_some(), "QC should form with 4 valid votes");

    // v4 for A (5th valid vote - QC already formed, but this should still work)
    let r = engine.on_vote(ValidatorId(4), view, &block_a);
    // Note: depending on implementation, this might return the same QC or None
    // The important thing is it doesn't error
    assert!(r.is_ok());

    // Verify locked_qc is for block A
    let locked = engine.locked_qc().expect("should have locked QC");
    assert_eq!(locked.block_id, block_a);
}
