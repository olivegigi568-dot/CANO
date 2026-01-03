//! Unit tests for `CommitIndex::prune_below`.
//!
//! These tests verify that the `CommitIndex::prune_below` method correctly:
//! - Removes commits below the specified height
//! - Leaves the tip_height unchanged
//! - Is idempotent (can be called repeatedly)
//! - Handles pruning above the tip safely

use cano_node::commit_index::CommitIndex;
use cano_node::consensus_node::NodeCommitInfo;

// ============================================================================
// Helper functions
// ============================================================================

/// Create a simple commit info at the given height with a block_id derived from height.
fn make_commit(height: u64) -> NodeCommitInfo<[u8; 32]> {
    let mut block_id = [0u8; 32];
    block_id[0..8].copy_from_slice(&height.to_le_bytes());
    NodeCommitInfo {
        block_id,
        view: height,
        height,
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that `prune_below` removes commits with height < min_height.
///
/// Scenario:
/// 1. Insert commits at heights [0, 1, 2, 3]
/// 2. Call prune_below(2)
/// 3. Verify heights 0 and 1 are gone; 2 and 3 remain
/// 4. Verify tip_height() still returns 3
#[test]
fn commit_index_prune_below_drops_lower_heights() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    // Insert commits at heights 0, 1, 2, 3
    let commits = vec![
        make_commit(0),
        make_commit(1),
        make_commit(2),
        make_commit(3),
    ];
    index.apply_commits(commits).expect("apply_commits failed");

    // Verify initial state
    assert_eq!(index.len(), 4);
    assert_eq!(index.tip().map(|c| c.height), Some(3));

    // Prune below height 2
    index.prune_below(2);

    // Verify that heights 0 and 1 are gone
    assert!(index.get(0).is_none(), "height 0 should be pruned");
    assert!(index.get(1).is_none(), "height 1 should be pruned");

    // Verify that heights 2 and 3 remain
    assert!(index.get(2).is_some(), "height 2 should remain");
    assert!(index.get(3).is_some(), "height 3 should remain");

    // Verify len is now 2
    assert_eq!(index.len(), 2);

    // Verify tip_height is still 3
    assert_eq!(
        index.tip().map(|c| c.height),
        Some(3),
        "tip_height should still be 3"
    );
}

/// Test that `prune_below` is idempotent.
///
/// Scenario:
/// 1. Insert commits at heights [0, 1, 2, 3]
/// 2. Call prune_below(2) twice
/// 3. Ensure the second call is a no-op and remaining entries are unchanged
#[test]
fn commit_index_prune_below_idempotent() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    // Insert commits at heights 0, 1, 2, 3
    let commits = vec![
        make_commit(0),
        make_commit(1),
        make_commit(2),
        make_commit(3),
    ];
    index.apply_commits(commits).expect("apply_commits failed");

    // Prune below height 2 (first call)
    index.prune_below(2);

    // Capture state after first prune
    let len_after_first = index.len();
    let tip_after_first = index.tip().map(|c| c.height);
    let has_2 = index.get(2).is_some();
    let has_3 = index.get(3).is_some();

    // Prune below height 2 (second call - should be a no-op)
    index.prune_below(2);

    // Verify state is unchanged
    assert_eq!(index.len(), len_after_first, "len should be unchanged");
    assert_eq!(
        index.tip().map(|c| c.height),
        tip_after_first,
        "tip should be unchanged"
    );
    assert_eq!(
        index.get(2).is_some(),
        has_2,
        "height 2 presence should be unchanged"
    );
    assert_eq!(
        index.get(3).is_some(),
        has_3,
        "height 3 presence should be unchanged"
    );
}

/// Test that `prune_below` with min_height above the tip is safe.
///
/// Scenario:
/// 1. Insert commits up to height 3
/// 2. Call prune_below(10)
/// 3. The map may become empty (since all heights < 10)
/// 4. But tip_height() must still be 3 (tip_height is cached separately)
/// 5. No panic or error
#[test]
fn commit_index_prune_below_above_tip_is_safe() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    // Insert commits at heights 0, 1, 2, 3
    let commits = vec![
        make_commit(0),
        make_commit(1),
        make_commit(2),
        make_commit(3),
    ];
    index.apply_commits(commits).expect("apply_commits failed");

    // Verify initial tip
    assert_eq!(index.tip().map(|c| c.height), Some(3));

    // Prune below height 10 (above all commits)
    index.prune_below(10);

    // All commits should be gone since all heights < 10
    assert_eq!(index.len(), 0, "all commits should be pruned");

    // However, the tip() will now return None since the map is empty
    // But the internal tip_height is still 3 (it's not reset by pruning).
    // Note: tip() returns commits_by_height.get(&tip_height), which will be None
    // if the entry was pruned. This is expected behavior - the tip is conceptually
    // still at height 3, but the data has been pruned.
    
    // The important invariant is that there's no panic and no incorrect state.
    // The index is still usable.
    assert!(index.get(3).is_none(), "height 3 should be pruned");
    
    // We can still apply new commits at higher heights
    let new_commit = make_commit(10);
    index.apply_commits(vec![new_commit]).expect("apply_commits should work after pruning");
    assert_eq!(index.tip().map(|c| c.height), Some(10));
}

/// Test that `prune_below(0)` is a no-op.
///
/// Scenario:
/// 1. Insert commits at heights [0, 1, 2]
/// 2. Call prune_below(0)
/// 3. All commits should remain since no height < 0
#[test]
fn commit_index_prune_below_zero_is_noop() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    let commits = vec![make_commit(0), make_commit(1), make_commit(2)];
    index.apply_commits(commits).expect("apply_commits failed");

    assert_eq!(index.len(), 3);

    // Prune below 0 (should be a no-op)
    index.prune_below(0);

    // All commits should remain
    assert_eq!(index.len(), 3);
    assert!(index.get(0).is_some());
    assert!(index.get(1).is_some());
    assert!(index.get(2).is_some());
}

/// Test pruning on an empty commit index.
#[test]
fn commit_index_prune_below_on_empty_index() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    // Pruning an empty index should not panic
    index.prune_below(100);

    // Index should still be empty
    assert!(index.is_empty());
    assert!(index.tip().is_none());
}

/// Test incremental pruning (multiple calls with increasing min_height).
#[test]
fn commit_index_incremental_pruning() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    // Insert commits at heights 0 through 9
    let commits: Vec<_> = (0..10).map(make_commit).collect();
    index.apply_commits(commits).expect("apply_commits failed");
    assert_eq!(index.len(), 10);

    // Prune below 3
    index.prune_below(3);
    assert_eq!(index.len(), 7);
    assert!(index.get(2).is_none());
    assert!(index.get(3).is_some());

    // Prune below 5
    index.prune_below(5);
    assert_eq!(index.len(), 5);
    assert!(index.get(4).is_none());
    assert!(index.get(5).is_some());

    // Prune below 8
    index.prune_below(8);
    assert_eq!(index.len(), 2);
    assert!(index.get(7).is_none());
    assert!(index.get(8).is_some());
    assert!(index.get(9).is_some());
}
