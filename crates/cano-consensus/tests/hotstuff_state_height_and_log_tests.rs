//! Tests for HotStuffStateEngine block heights and commit log functionality.
//!
//! These tests verify:
//! - Heights are computed correctly along a chain
//! - 3-chain commit produces the right committed height sequence
//! - No height regressions / no double-commit of the same block

use cano_consensus::{
    ConsensusValidatorSet, HotStuffStateEngine, QuorumCertificate, ValidatorId,
    ValidatorSetEntry,
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

/// Helper to form a QC by voting from validators 0, 1, 2.
/// Returns the formed QC.
fn form_qc_for_block(
    engine: &mut HotStuffStateEngine<[u8; 32]>,
    view: u64,
    block_id: &[u8; 32],
) -> QuorumCertificate<[u8; 32]> {
    // Need 3 votes out of 4 (total=4, threshold=3)
    for i in 0..3 {
        let result = engine.on_vote(ValidatorId(i), view, block_id);
        if let Ok(Some(qc)) = result {
            return qc;
        }
    }
    panic!("Failed to form QC for block {:?} at view {}", block_id, view);
}

// ============================================================================
// Test: heights are computed correctly
// ============================================================================

#[test]
fn hotstuff_register_block_sets_correct_heights() {
    // Setup: 4 validators with power 1 (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A → B → C → D with increasing views
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);
    let block_d = make_block_id(0xDD);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;
    let view_d = 4u64;

    // Register blocks in order: A (genesis), B, C, D
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);
    engine.register_block(block_d, view_d, Some(block_c), None);

    // Check heights
    let node_a = engine.get_block(&block_a).expect("block A should exist");
    let node_b = engine.get_block(&block_b).expect("block B should exist");
    let node_c = engine.get_block(&block_c).expect("block C should exist");
    let node_d = engine.get_block(&block_d).expect("block D should exist");

    assert_eq!(node_a.height, 0, "A (genesis) should have height 0");
    assert_eq!(node_b.height, 1, "B should have height 1 (A.height + 1)");
    assert_eq!(node_c.height, 2, "C should have height 2 (B.height + 1)");
    assert_eq!(node_d.height, 3, "D should have height 3 (C.height + 1)");
}

// ============================================================================
// Test: commit log records correct height on 3-chain
// ============================================================================

#[test]
fn hotstuff_commit_log_records_grandparent_height() {
    // Setup: 4 validators with power 1 (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A → B → C with increasing views
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;

    // Register blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);

    // Before any QCs: no commit, no height, empty log
    assert!(engine.committed_block().is_none());
    assert!(engine.committed_height().is_none());
    assert!(engine.commit_log().is_empty());

    // Form QCs for A, B, C
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // After QC(C): A should be committed (3-chain: A → B → C)
    assert_eq!(
        engine.committed_block(),
        Some(&block_a),
        "grandparent A should be committed"
    );
    assert_eq!(
        engine.committed_height(),
        Some(0),
        "committed height should be 0 (A's height)"
    );

    // Check commit log
    let log = engine.commit_log();
    assert_eq!(log.len(), 1, "commit log should have 1 entry");
    assert_eq!(log[0].block_id, block_a, "log entry should be block A");
    assert_eq!(log[0].height, 0, "log entry height should be 0");
    assert_eq!(log[0].view, view_a, "log entry view should be A's view");
}

// ============================================================================
// Test: multiple commits build monotonic log
// ============================================================================

#[test]
fn hotstuff_commit_log_is_monotonic_in_height() {
    // Setup: 4 validators with power 1 (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A → B → C → D → E with increasing views
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);
    let block_c = make_block_id(0x03);
    let block_d = make_block_id(0x04);
    let block_e = make_block_id(0x05);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;
    let view_d = 4u64;
    let view_e = 5u64;

    // Register blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);
    engine.register_block(block_d, view_d, Some(block_c), None);
    engine.register_block(block_e, view_e, Some(block_d), None);

    // Form QCs for all blocks
    // 3-chain (A,B,C) → commit A (height=0)
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    assert_eq!(engine.committed_block(), Some(&block_a), "A should be committed after first 3-chain");
    assert_eq!(engine.committed_height(), Some(0), "height should be 0 after committing A");
    assert_eq!(engine.commit_log().len(), 1);

    // 3-chain (B,C,D) → commit B (height=1)
    let _qc_d = form_qc_for_block(&mut engine, view_d, &block_d);

    assert_eq!(engine.committed_block(), Some(&block_b), "B should be committed after second 3-chain");
    assert_eq!(engine.committed_height(), Some(1), "height should be 1 after committing B");
    assert_eq!(engine.commit_log().len(), 2);

    // 3-chain (C,D,E) → commit C (height=2)
    let _qc_e = form_qc_for_block(&mut engine, view_e, &block_e);

    assert_eq!(engine.committed_block(), Some(&block_c), "C should be committed after third 3-chain");
    assert_eq!(engine.committed_height(), Some(2), "height should be 2 after committing C");

    // Check full commit log
    let log = engine.commit_log();
    assert_eq!(log.len(), 3, "commit log should have 3 entries");

    // Heights should be strictly increasing: [0, 1, 2]
    assert_eq!(log[0].height, 0);
    assert_eq!(log[1].height, 1);
    assert_eq!(log[2].height, 2);

    // Block IDs should match
    assert_eq!(log[0].block_id, block_a);
    assert_eq!(log[1].block_id, block_b);
    assert_eq!(log[2].block_id, block_c);
}

// ============================================================================
// Test: same block not double-logged
// ============================================================================

#[test]
fn hotstuff_commit_log_does_not_duplicate_same_block() {
    // Setup: 4 validators with power 1 (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A → B → C with increasing views
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;

    // Register blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);

    // Form QCs for A, B, C → commits A
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // Verify A is committed
    assert_eq!(engine.committed_block(), Some(&block_a));
    assert_eq!(engine.commit_log().len(), 1);

    // Now create another chain that would also try to commit A:
    // If we had another set of blocks X → Y → Z where X's grandparent is also A,
    // the commit logic shouldn't add A again.
    //
    // However, the simplest way to test this is to verify that calling the
    // commit logic again with the same QC doesn't duplicate entries.
    // Since on_qc is private, we can simulate by examining that the existing
    // tests don't produce duplicates. Let's instead verify that repeated
    // 3-chains don't add duplicates.

    // Add more blocks D, E that form another potential 3-chain
    // but the grandparent would be B (already at height 1)
    let block_d = make_block_id(0xDD);
    let block_e = make_block_id(0xEE);

    let view_d = 4u64;
    let view_e = 5u64;

    engine.register_block(block_d, view_d, Some(block_c), None);
    engine.register_block(block_e, view_e, Some(block_d), None);

    // Form QC for D → 3-chain (B, C, D) commits B
    let _qc_d = form_qc_for_block(&mut engine, view_d, &block_d);

    assert_eq!(engine.committed_block(), Some(&block_b));
    assert_eq!(engine.commit_log().len(), 2);

    // Form QC for E → 3-chain (C, D, E) commits C
    let _qc_e = form_qc_for_block(&mut engine, view_e, &block_e);

    assert_eq!(engine.committed_block(), Some(&block_c));
    assert_eq!(engine.commit_log().len(), 3);

    // Verify no duplicates - each entry should be unique
    let log = engine.commit_log();
    assert_eq!(log[0].block_id, block_a);
    assert_eq!(log[1].block_id, block_b);
    assert_eq!(log[2].block_id, block_c);

    // Heights are monotonically increasing
    assert!(log[0].height < log[1].height);
    assert!(log[1].height < log[2].height);
}

// ============================================================================
// Test: no height regressions
// ============================================================================

#[test]
fn hotstuff_commit_height_does_not_regress() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build a longer chain: A → B → C → D → E → F
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);
    let block_c = make_block_id(0x03);
    let block_d = make_block_id(0x04);
    let block_e = make_block_id(0x05);
    let block_f = make_block_id(0x06);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;
    let view_d = 4u64;
    let view_e = 5u64;
    let view_f = 6u64;

    // Register all blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);
    engine.register_block(block_d, view_d, Some(block_c), None);
    engine.register_block(block_e, view_e, Some(block_d), None);
    engine.register_block(block_f, view_f, Some(block_e), None);

    // First, form QCs for D, E, F to commit D (height=3)
    // Skip A, B, C for this phase to commit D first
    let _qc_d = form_qc_for_block(&mut engine, view_d, &block_d);
    let _qc_e = form_qc_for_block(&mut engine, view_e, &block_e);
    let _qc_f = form_qc_for_block(&mut engine, view_f, &block_f);

    // D should be committed (3-chain: D → E → F) at height 3
    assert_eq!(engine.committed_block(), Some(&block_d));
    assert_eq!(engine.committed_height(), Some(3));
    let initial_log_len = engine.commit_log().len();

    // Now, try forming QCs for A, B, C (earlier blocks with lower heights)
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // Even though A, B, C form a valid 3-chain with increasing views,
    // A's height (0) is lower than D's height (3), so:
    // - committed_block should NOT regress from D to A
    // - committed_height should NOT regress from 3 to 0
    // - commit_log should NOT add A
    assert_eq!(
        engine.committed_block(),
        Some(&block_d),
        "committed_block should NOT regress from D to A"
    );
    assert_eq!(
        engine.committed_height(),
        Some(3),
        "committed_height should NOT regress from 3 to 0"
    );
    assert_eq!(
        engine.commit_log().len(),
        initial_log_len,
        "commit_log should NOT add A (height regression)"
    );
}
