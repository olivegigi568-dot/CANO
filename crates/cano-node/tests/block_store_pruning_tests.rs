//! Unit tests for `BlockStore::prune_below`.
//!
//! These tests verify that the `BlockStore::prune_below` method correctly:
//! - Removes blocks with height < min_height
//! - Leaves blocks at or above min_height unchanged
//! - Is idempotent (can be called repeatedly)

use cano_node::block_store::BlockStore;
use cano_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helper functions
// ============================================================================

/// Create a dummy block proposal at the given height.
fn make_dummy_proposal(proposer_index: u16, height: u64, parent: [u8; 32]) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height,
            round: height,
            parent_block_id: parent,
            payload_hash: [0u8; 32],
            proposer_index,
            reserved: 0,
            tx_count: 0,
            timestamp: 0,
        },
        qc: None,
        txs: vec![],
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that `prune_below` removes blocks with height < min_height.
///
/// Scenario:
/// 1. Create a BlockStore and insert proposals with heights [0, 1, 2, 3]
/// 2. Call prune_below(2)
/// 3. Assert that get() returns Some for heights 2 and 3
/// 4. Assert that get() returns None for heights 0 and 1
#[test]
fn block_store_prune_below_drops_lower_heights() {
    let mut store = BlockStore::new();

    // Insert proposals at heights 0, 1, 2, 3
    let p0 = make_dummy_proposal(1, 0, [0u8; 32]);
    let p1 = make_dummy_proposal(1, 1, [0u8; 32]);
    let p2 = make_dummy_proposal(1, 2, [0u8; 32]);
    let p3 = make_dummy_proposal(1, 3, [0u8; 32]);

    let id0 = store.store_proposal(&p0);
    let id1 = store.store_proposal(&p1);
    let id2 = store.store_proposal(&p2);
    let id3 = store.store_proposal(&p3);

    // Verify initial state
    assert_eq!(store.len(), 4);

    // Prune below height 2
    store.prune_below(2);

    // Verify heights 0 and 1 are gone
    assert!(store.get(&id0).is_none(), "height 0 should be pruned");
    assert!(store.get(&id1).is_none(), "height 1 should be pruned");

    // Verify heights 2 and 3 remain
    assert!(store.get(&id2).is_some(), "height 2 should remain");
    assert!(store.get(&id3).is_some(), "height 3 should remain");

    // Verify len is now 2
    assert_eq!(store.len(), 2);
}

/// Test that `prune_below` is idempotent.
///
/// Scenario:
/// 1. Insert proposals with heights [0, 1, 2, 3]
/// 2. Call prune_below(2) multiple times
/// 3. Check contents don't change after the first call
#[test]
fn block_store_prune_below_is_idempotent() {
    let mut store = BlockStore::new();

    // Insert proposals at heights 0, 1, 2, 3
    let p0 = make_dummy_proposal(1, 0, [0u8; 32]);
    let p1 = make_dummy_proposal(1, 1, [0u8; 32]);
    let p2 = make_dummy_proposal(1, 2, [0u8; 32]);
    let p3 = make_dummy_proposal(1, 3, [0u8; 32]);

    let id0 = store.store_proposal(&p0);
    let id1 = store.store_proposal(&p1);
    let id2 = store.store_proposal(&p2);
    let id3 = store.store_proposal(&p3);

    // Prune below height 2 (first call)
    store.prune_below(2);

    // Capture state after first prune
    let len_after_first = store.len();
    let has_id2 = store.get(&id2).is_some();
    let has_id3 = store.get(&id3).is_some();

    // Prune below height 2 (second call - should be a no-op)
    store.prune_below(2);

    // Verify state is unchanged
    assert_eq!(store.len(), len_after_first, "len should be unchanged");
    assert_eq!(
        store.get(&id2).is_some(),
        has_id2,
        "id2 presence should be unchanged"
    );
    assert_eq!(
        store.get(&id3).is_some(),
        has_id3,
        "id3 presence should be unchanged"
    );

    // Also verify pruned entries are still pruned
    assert!(store.get(&id0).is_none(), "id0 should still be pruned");
    assert!(store.get(&id1).is_none(), "id1 should still be pruned");
}

/// Test that `prune_below(0)` is a no-op.
#[test]
fn block_store_prune_below_zero_is_noop() {
    let mut store = BlockStore::new();

    let p0 = make_dummy_proposal(1, 0, [0u8; 32]);
    let p1 = make_dummy_proposal(1, 1, [0u8; 32]);
    let p2 = make_dummy_proposal(1, 2, [0u8; 32]);

    let id0 = store.store_proposal(&p0);
    let id1 = store.store_proposal(&p1);
    let id2 = store.store_proposal(&p2);

    assert_eq!(store.len(), 3);

    // Prune below 0 (should be a no-op)
    store.prune_below(0);

    // All proposals should remain
    assert_eq!(store.len(), 3);
    assert!(store.get(&id0).is_some());
    assert!(store.get(&id1).is_some());
    assert!(store.get(&id2).is_some());
}

/// Test pruning on an empty block store.
#[test]
fn block_store_prune_below_on_empty_store() {
    let mut store = BlockStore::new();

    // Pruning an empty store should not panic
    store.prune_below(100);

    // Store should still be empty
    assert!(store.is_empty());
}

/// Test pruning all blocks (min_height above all stored blocks).
#[test]
fn block_store_prune_below_all() {
    let mut store = BlockStore::new();

    let p0 = make_dummy_proposal(1, 0, [0u8; 32]);
    let p1 = make_dummy_proposal(1, 1, [0u8; 32]);
    let p2 = make_dummy_proposal(1, 2, [0u8; 32]);

    store.store_proposal(&p0);
    store.store_proposal(&p1);
    store.store_proposal(&p2);

    assert_eq!(store.len(), 3);

    // Prune below 100 (above all blocks)
    store.prune_below(100);

    // All blocks should be gone
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

/// Test incremental pruning.
#[test]
fn block_store_incremental_pruning() {
    let mut store = BlockStore::new();

    // Insert proposals at heights 0 through 9
    let proposals: Vec<(BlockProposal, [u8; 32])> = (0..10)
        .map(|h| {
            let p = make_dummy_proposal(1, h, [0u8; 32]);
            let id = BlockStore::compute_block_id(&p);
            (p, id)
        })
        .collect();

    for (p, _) in &proposals {
        store.store_proposal(p);
    }
    assert_eq!(store.len(), 10);

    // Prune below 3
    store.prune_below(3);
    assert_eq!(store.len(), 7);
    assert!(store.get(&proposals[2].1).is_none());
    assert!(store.get(&proposals[3].1).is_some());

    // Prune below 5
    store.prune_below(5);
    assert_eq!(store.len(), 5);
    assert!(store.get(&proposals[4].1).is_none());
    assert!(store.get(&proposals[5].1).is_some());

    // Prune below 8
    store.prune_below(8);
    assert_eq!(store.len(), 2);
    assert!(store.get(&proposals[7].1).is_none());
    assert!(store.get(&proposals[8].1).is_some());
    assert!(store.get(&proposals[9].1).is_some());
}

/// Test that the height field in StoredBlock is correctly set.
#[test]
fn block_store_stored_block_has_correct_height() {
    let mut store = BlockStore::new();

    let p5 = make_dummy_proposal(1, 5, [0u8; 32]);
    let id = store.store_proposal(&p5);

    let stored = store.get(&id).expect("proposal should exist");
    assert_eq!(stored.height, 5, "stored block should have height 5");
    assert_eq!(stored.proposal.header.height, 5);
}

/// Test pruning with the `insert` method.
#[test]
fn block_store_prune_below_with_insert_method() {
    let mut store = BlockStore::new();

    // Use the insert method instead of store_proposal
    let p0 = make_dummy_proposal(1, 0, [0u8; 32]);
    let p1 = make_dummy_proposal(1, 1, [0u8; 32]);
    let p2 = make_dummy_proposal(1, 2, [0u8; 32]);

    let id0 = store.insert(p0).expect("insert should succeed");
    let id1 = store.insert(p1).expect("insert should succeed");
    let id2 = store.insert(p2).expect("insert should succeed");

    assert_eq!(store.len(), 3);

    // Prune below height 1
    store.prune_below(1);

    assert_eq!(store.len(), 2);
    assert!(store.get(&id0).is_none(), "height 0 should be pruned");
    assert!(store.get(&id1).is_some(), "height 1 should remain");
    assert!(store.get(&id2).is_some(), "height 2 should remain");
}
