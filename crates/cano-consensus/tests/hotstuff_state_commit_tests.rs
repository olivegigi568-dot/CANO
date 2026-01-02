//! Tests for HotStuffStateEngine 3-chain commit behavior.
//!
//! These tests verify the 3-chain commit rule:
//! - When QCs appear for three consecutive blocks (G → P → B) with increasing views,
//!   the grandparent block G becomes committed.
//! - committed_block tracks the highest committed block id (monotonic, no rollback)
//! - 2-chain does not commit
//! - Broken chains do not commit

use cano_consensus::{
    ConsensusValidatorSet, HotStuffStateEngine, QuorumCertificate,
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
// Test: 3-chain commit works - grandparent committed on three consecutive QCs
// ============================================================================

#[test]
fn hotstuff_commits_grandparent_on_three_consecutive_qcs() {
    // Setup: 4 validators with power 1 (total=4, threshold=3)
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A, B, C with parent chain A → B → C and increasing views
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;

    // Register the blocks in the engine
    // A is genesis (no parent)
    engine.register_block(block_a, view_a, None, None);
    // B's parent is A
    engine.register_block(block_b, view_b, Some(block_a), None);
    // C's parent is B
    engine.register_block(block_c, view_c, Some(block_b), None);

    // Before any QCs: no commit
    assert!(engine.committed_block().is_none(), "should not be committed before any QC");

    // Form QC for A
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);

    // After QC(A): still no commit (only 1 QC)
    assert!(engine.committed_block().is_none(), "should not be committed after QC(A)");

    // Form QC for B
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);

    // After QC(B): still no commit (only 2 QCs, need 3)
    assert!(engine.committed_block().is_none(), "should not be committed after QC(B)");

    // Form QC for C
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // After QC(C): A should be committed (3-chain: A → B → C)
    let committed = engine.committed_block().expect("expected committed block after 3-chain");
    assert_eq!(committed, &block_a, "grandparent A should be committed");
}

// ============================================================================
// Test: 2-chain does not commit
// ============================================================================

#[test]
fn hotstuff_does_not_commit_on_two_qcs_only() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A, B, C with parent chain A → B → C
    let block_a = make_block_id(0x11);
    let block_b = make_block_id(0x22);
    let block_c = make_block_id(0x33);

    let view_a = 10u64;
    let view_b = 11u64;
    let view_c = 12u64;

    // Register blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);

    // Form QC for A
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    assert!(engine.committed_block().is_none(), "no commit after QC(A)");

    // Form QC for B only (not C)
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);

    // After QC(A) and QC(B): still no commit (2-chain, not 3-chain)
    assert!(engine.committed_block().is_none(), "should not commit on 2-chain only");
}

// ============================================================================
// Test: commit is stable / monotonic
// ============================================================================

#[test]
fn hotstuff_commit_is_monotonic() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build a longer chain: A → B → C → D
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);
    let block_c = make_block_id(0x03);
    let block_d = make_block_id(0x04);

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;
    let view_d = 4u64;

    // Register blocks
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);
    engine.register_block(block_d, view_d, Some(block_c), None);

    // Form QCs for A, B, C (first 3-chain commits A)
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // After first 3-chain (A, B, C): A is committed
    let committed_1 = engine.committed_block().expect("A should be committed");
    assert_eq!(committed_1, &block_a, "first 3-chain commits A");

    // Form QC for D (second 3-chain: B, C, D)
    let _qc_d = form_qc_for_block(&mut engine, view_d, &block_d);

    // After second 3-chain (B, C, D): B is committed (monotonic advancement)
    let committed_2 = engine.committed_block().expect("B should be committed");
    assert_eq!(committed_2, &block_b, "second 3-chain commits B (monotonic)");

    // Verify that the commit moved forward, not backward
    // B's view (2) > A's view (1), so this is a forward commit
    let block_a_node = engine.get_block(&block_a).expect("block A exists");
    let block_b_node = engine.get_block(&block_b).expect("block B exists");
    assert!(block_b_node.view > block_a_node.view, "commit should progress forward");
}

// ============================================================================
// Test: no commit if QC chain is broken (parent links don't form proper chain)
// ============================================================================

#[test]
fn hotstuff_does_not_commit_when_chain_broken() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A, B, C but C's parent is NOT B (broken chain)
    let block_a = make_block_id(0xAA);
    let block_b = make_block_id(0xBB);
    let block_c = make_block_id(0xCC);
    let block_orphan = make_block_id(0xFF); // C's parent is this orphan, not B

    let view_a = 1u64;
    let view_b = 2u64;
    let view_c = 3u64;

    // Register blocks:
    // A has no parent
    engine.register_block(block_a, view_a, None, None);
    // B's parent is A
    engine.register_block(block_b, view_b, Some(block_a), None);
    // C's parent is orphan (NOT B) - this breaks the chain
    engine.register_block(block_c, view_c, Some(block_orphan), None);
    // The orphan is not registered, so the chain is broken

    // Form QCs for A, B, C with increasing views
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // Even with 3 QCs, no commit because the chain is broken
    // C → orphan (unknown) → ?, so no valid 3-chain
    assert!(
        engine.committed_block().is_none(),
        "should not commit when chain is broken (missing parent)"
    );
}

// ============================================================================
// Test: no commit if views are not strictly increasing
// ============================================================================

#[test]
fn hotstuff_does_not_commit_when_views_not_increasing() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A, B, C with proper parent chain but non-increasing views
    let block_a = make_block_id(0x11);
    let block_b = make_block_id(0x22);
    let block_c = make_block_id(0x33);

    // Views are NOT strictly increasing: A=10, B=5, C=15
    let view_a = 10u64;
    let view_b = 5u64; // view_b < view_a (violates strict increase)
    let view_c = 15u64;

    // Register blocks with proper parent links
    engine.register_block(block_a, view_a, None, None);
    engine.register_block(block_b, view_b, Some(block_a), None);
    engine.register_block(block_c, view_c, Some(block_b), None);

    // Form QCs
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // No commit because views are not strictly increasing (A.view=10 > B.view=5)
    assert!(
        engine.committed_block().is_none(),
        "should not commit when views are not strictly increasing"
    );
}

// ============================================================================
// Test: commit requires all three blocks to have own_qc
// ============================================================================

#[test]
fn hotstuff_does_not_commit_when_middle_block_has_no_qc() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Create blocks A, B, C with proper parent chain
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

    // Form QC only for A and C (skip B)
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    // Skip QC for B
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // No commit because B doesn't have own_qc
    assert!(
        engine.committed_block().is_none(),
        "should not commit when middle block (B) has no QC"
    );
}

// ============================================================================
// Test: commit does not regress to earlier block (explicit backward test)
// ============================================================================

#[test]
fn hotstuff_commit_does_not_regress_to_earlier_block() {
    // Setup: 4 validators with power 1
    let validators = make_simple_set(4, 1);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build a chain: A → B → C → D → E → F
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

    // First, form QCs for D, E, F to commit D (skipping A, B, C for this phase)
    let _qc_d = form_qc_for_block(&mut engine, view_d, &block_d);
    let _qc_e = form_qc_for_block(&mut engine, view_e, &block_e);
    let _qc_f = form_qc_for_block(&mut engine, view_f, &block_f);

    // D should be committed (3-chain: D → E → F)
    let committed_1 = engine.committed_block().expect("D should be committed");
    assert_eq!(committed_1, &block_d, "first 3-chain commits D");

    // Now, try forming QCs for A, B, C (earlier blocks with lower views)
    let _qc_a = form_qc_for_block(&mut engine, view_a, &block_a);
    let _qc_b = form_qc_for_block(&mut engine, view_b, &block_b);
    let _qc_c = form_qc_for_block(&mut engine, view_c, &block_c);

    // Even though A, B, C form a valid 3-chain with increasing views,
    // A's view (1) is lower than D's view (4), so commit should NOT regress
    let committed_2 = engine.committed_block().expect("commit should remain");
    assert_eq!(committed_2, &block_d, "commit should NOT regress from D to A");
}
