//! Unit tests for `CommitIndex`.
//!
//! These tests verify that the `CommitIndex` struct correctly:
//! - Applies commits in monotonic order
//! - Rejects height regression
//! - Rejects conflicting blocks at the same height
//! - Is idempotent for the same block at the same height

use cano_node::commit_index::{CommitIndex, CommitIndexError};
use cano_node::consensus_node::NodeCommitInfo;

// ============================================================================
// Unit tests for CommitIndex
// ============================================================================

/// Test that CommitIndex applies commits monotonically.
///
/// This test:
/// 1. Creates an empty CommitIndex<u64>
/// 2. Applies commits with heights 1, 2, 3
/// 3. Asserts that is_empty() == false, len() == 3, and tip().unwrap().height == 3
#[test]
fn commit_index_applies_commits_monotonically() {
    let mut index: CommitIndex<u64> = CommitIndex::new();

    // Initially empty
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
    assert!(index.tip().is_none());

    // Apply commits with heights 1, 2, 3
    let commits = vec![
        NodeCommitInfo {
            block_id: 100,
            view: 1,
            height: 1,
        },
        NodeCommitInfo {
            block_id: 200,
            view: 2,
            height: 2,
        },
        NodeCommitInfo {
            block_id: 300,
            view: 3,
            height: 3,
        },
    ];

    let result = index.apply_commits(commits);
    assert!(result.is_ok());

    // Check state after commits
    assert!(!index.is_empty());
    assert_eq!(index.len(), 3);

    let tip = index.tip().expect("expected tip to be present");
    assert_eq!(tip.height, 3);
    assert_eq!(tip.block_id, 300);
    assert_eq!(tip.view, 3);

    // Check individual gets
    assert_eq!(index.get(1).map(|c| c.block_id), Some(100));
    assert_eq!(index.get(2).map(|c| c.block_id), Some(200));
    assert_eq!(index.get(3).map(|c| c.block_id), Some(300));
    assert!(index.get(4).is_none());
}

/// Test that CommitIndex rejects height regression.
///
/// This test:
/// 1. Applies a commit at height 5
/// 2. Tries to apply a commit at height 4
/// 3. Expects Err(CommitIndexError::HeightRegression { .. })
#[test]
fn commit_index_rejects_height_regression() {
    let mut index: CommitIndex<u64> = CommitIndex::new();

    // Apply commit at height 5
    let commit_h5 = NodeCommitInfo {
        block_id: 500,
        view: 5,
        height: 5,
    };
    let result = index.apply_commits(vec![commit_h5]);
    assert!(result.is_ok());

    // Try to apply commit at height 4 (regression)
    let commit_h4 = NodeCommitInfo {
        block_id: 400,
        view: 4,
        height: 4,
    };
    let result = index.apply_commits(vec![commit_h4]);

    match result {
        Err(CommitIndexError::HeightRegression {
            new_height,
            current_height,
        }) => {
            assert_eq!(new_height, 4);
            assert_eq!(current_height, 5);
        }
        _ => panic!("Expected HeightRegression error, got {:?}", result),
    }

    // Index should still have only the first commit
    assert_eq!(index.len(), 1);
    assert_eq!(index.tip().map(|c| c.height), Some(5));
}

/// Test that CommitIndex rejects conflicting blocks at the same height.
///
/// This test:
/// 1. Applies a commit at height 10 with block_id A
/// 2. Applies a commit at height 10 with block_id B (B != A)
/// 3. Expects Err(CommitIndexError::ConflictingBlock { .. })
#[test]
fn commit_index_rejects_conflicting_block_at_same_height() {
    let mut index: CommitIndex<u64> = CommitIndex::new();

    // Apply commit at height 10 with block_id A
    let commit_a = NodeCommitInfo {
        block_id: 1000, // block A
        view: 10,
        height: 10,
    };
    let result = index.apply_commits(vec![commit_a]);
    assert!(result.is_ok());

    // Try to apply commit at height 10 with block_id B (different)
    let commit_b = NodeCommitInfo {
        block_id: 1001, // block B != A
        view: 10,
        height: 10,
    };
    let result = index.apply_commits(vec![commit_b]);

    match result {
        Err(CommitIndexError::ConflictingBlock {
            height,
            existing_block_id,
            new_block_id,
        }) => {
            assert_eq!(height, 10);
            assert_eq!(existing_block_id, 1000);
            assert_eq!(new_block_id, 1001);
        }
        _ => panic!("Expected ConflictingBlock error, got {:?}", result),
    }

    // Index should still have only the first commit
    assert_eq!(index.len(), 1);
    assert_eq!(index.tip().map(|c| c.block_id), Some(1000));
}

/// Test that CommitIndex is idempotent for the same block at the same height.
///
/// This test:
/// 1. Applies a commit at height 7 with block_id A
/// 2. Applies the same commit again
/// 3. Expects Ok(()) both times and len() == 1
#[test]
fn commit_index_is_idempotent_for_same_block() {
    let mut index: CommitIndex<u64> = CommitIndex::new();

    // Apply commit at height 7 with block_id A
    let commit = NodeCommitInfo {
        block_id: 700,
        view: 7,
        height: 7,
    };

    // First application
    let result = index.apply_commits(vec![commit.clone()]);
    assert!(result.is_ok());
    assert_eq!(index.len(), 1);

    // Second application (same commit)
    let result = index.apply_commits(vec![commit.clone()]);
    assert!(result.is_ok());

    // Should still have only one entry
    assert_eq!(index.len(), 1);
    assert_eq!(index.tip().map(|c| c.block_id), Some(700));
}

/// Test that CommitIndex correctly handles non-contiguous heights.
///
/// This test verifies that commits can skip heights (e.g., 1, 3, 5)
/// without error, as long as they are strictly increasing.
#[test]
fn commit_index_handles_non_contiguous_heights() {
    let mut index: CommitIndex<u64> = CommitIndex::new();

    // Apply commits with non-contiguous heights: 1, 3, 5
    let commits = vec![
        NodeCommitInfo {
            block_id: 100,
            view: 1,
            height: 1,
        },
        NodeCommitInfo {
            block_id: 300,
            view: 3,
            height: 3,
        },
        NodeCommitInfo {
            block_id: 500,
            view: 5,
            height: 5,
        },
    ];

    let result = index.apply_commits(commits);
    assert!(result.is_ok());

    assert_eq!(index.len(), 3);
    assert_eq!(index.tip().map(|c| c.height), Some(5));

    // Height 2 and 4 should be missing
    assert!(index.get(2).is_none());
    assert!(index.get(4).is_none());
}

/// Test that CommitIndex with [u8; 32] block IDs works correctly.
///
/// This test uses the same block ID type as the actual harness.
#[test]
fn commit_index_with_byte_array_block_id() {
    let mut index: CommitIndex<[u8; 32]> = CommitIndex::new();

    let block_id_1 = [1u8; 32];
    let block_id_2 = [2u8; 32];
    let block_id_3 = [3u8; 32];

    let commits = vec![
        NodeCommitInfo {
            block_id: block_id_1,
            view: 1,
            height: 1,
        },
        NodeCommitInfo {
            block_id: block_id_2,
            view: 2,
            height: 2,
        },
        NodeCommitInfo {
            block_id: block_id_3,
            view: 3,
            height: 3,
        },
    ];

    let result = index.apply_commits(commits);
    assert!(result.is_ok());

    assert_eq!(index.len(), 3);
    let tip = index.tip().expect("expected tip");
    assert_eq!(tip.height, 3);
    assert_eq!(tip.block_id, block_id_3);
}
