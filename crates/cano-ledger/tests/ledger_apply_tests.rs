use cano_ledger::{InMemoryLedger, LedgerApply, LedgerError};
use cano_wire::consensus::{BlockHeader, BlockProposal};
use std::sync::Arc;

fn make_dummy_proposal(height: u64) -> BlockProposal {
    let header = BlockHeader {
        version: 1,
        chain_id: 1,
        height,
        round: 0,
        parent_block_id: [0u8; 32],
        payload_hash: [0u8; 32],
        proposer_index: 0,
        reserved: 0,
        tx_count: 0,
        timestamp: 0,
    };

    BlockProposal {
        header,
        qc: None,
        txs: Vec::new(),
    }
}

#[test]
fn ledger_applies_blocks_monotonically() {
    let mut ledger = InMemoryLedger::<[u8; 32]>::new();

    let block_id_1: [u8; 32] = [1; 32];
    let block_id_2: [u8; 32] = [2; 32];
    let block_id_3: [u8; 32] = [3; 32];

    let proposal_1 = Arc::new(make_dummy_proposal(1));
    let proposal_2 = Arc::new(make_dummy_proposal(2));
    let proposal_3 = Arc::new(make_dummy_proposal(3));

    // Apply heights 1, 2, 3
    ledger
        .apply_committed_block(1, block_id_1, proposal_1)
        .expect("apply height 1");
    ledger
        .apply_committed_block(2, block_id_2, proposal_2)
        .expect("apply height 2");
    ledger
        .apply_committed_block(3, block_id_3, proposal_3)
        .expect("apply height 3");

    // Assert tip_height and len
    assert_eq!(ledger.tip_height(), Some(3));
    assert_eq!(ledger.len(), 3);

    // Assert entries exist for heights 1, 2, 3
    assert!(ledger.get(1).is_some());
    assert!(ledger.get(2).is_some());
    assert!(ledger.get(3).is_some());

    // Verify block IDs
    assert_eq!(ledger.get(1).unwrap().block_id, block_id_1);
    assert_eq!(ledger.get(2).unwrap().block_id, block_id_2);
    assert_eq!(ledger.get(3).unwrap().block_id, block_id_3);
}

#[test]
fn ledger_rejects_height_regression() {
    let mut ledger = InMemoryLedger::<[u8; 32]>::new();

    let block_id_5: [u8; 32] = [5; 32];
    let block_id_4: [u8; 32] = [4; 32];

    let proposal_5 = Arc::new(make_dummy_proposal(5));
    let proposal_4 = Arc::new(make_dummy_proposal(4));

    // Apply height 5
    ledger
        .apply_committed_block(5, block_id_5, proposal_5)
        .expect("apply height 5");

    // Attempt to apply height 4 (regression)
    let result = ledger.apply_committed_block(4, block_id_4, proposal_4);

    match result {
        Err(LedgerError::HeightRegression {
            new_height,
            current_height,
        }) => {
            assert_eq!(new_height, 4);
            assert_eq!(current_height, 5);
        }
        _ => panic!("expected HeightRegression error"),
    }
}

#[test]
fn ledger_rejects_conflicting_block_at_same_height() {
    let mut ledger = InMemoryLedger::<[u8; 32]>::new();

    let block_id_1: [u8; 32] = [1; 32];
    let block_id_2: [u8; 32] = [2; 32];

    let proposal = Arc::new(make_dummy_proposal(10));

    // Apply height 10 with block_id = [1; 32]
    ledger
        .apply_committed_block(10, block_id_1, proposal.clone())
        .expect("apply height 10");

    // Try to apply height 10 with block_id = [2; 32] (conflict)
    let result = ledger.apply_committed_block(10, block_id_2, proposal);

    match result {
        Err(LedgerError::ConflictingBlockAtHeight {
            height,
            existing_block_id,
            new_block_id,
        }) => {
            assert_eq!(height, 10);
            assert_eq!(existing_block_id, block_id_1);
            assert_eq!(new_block_id, block_id_2);
        }
        _ => panic!("expected ConflictingBlockAtHeight error"),
    }
}

#[test]
fn ledger_is_idempotent_for_same_block() {
    let mut ledger = InMemoryLedger::<[u8; 32]>::new();

    let block_id: [u8; 32] = [9; 32];
    let proposal = Arc::new(make_dummy_proposal(7));

    // Apply height 7 with block_id
    ledger
        .apply_committed_block(7, block_id, proposal.clone())
        .expect("apply height 7 first time");

    // Apply same height 7 with same block_id (idempotent)
    ledger
        .apply_committed_block(7, block_id, proposal)
        .expect("apply height 7 second time");

    // Should still have only one entry
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.tip_height(), Some(7));
}

#[test]
fn ledger_iterates_in_height_order() {
    let mut ledger = InMemoryLedger::<[u8; 32]>::new();

    let block_id_1: [u8; 32] = [1; 32];
    let block_id_3: [u8; 32] = [3; 32];
    let block_id_5: [u8; 32] = [5; 32];

    let proposal_1 = Arc::new(make_dummy_proposal(1));
    let proposal_3 = Arc::new(make_dummy_proposal(3));
    let proposal_5 = Arc::new(make_dummy_proposal(5));

    // Apply heights in monotonic order (1, 3, 5) with gaps
    ledger
        .apply_committed_block(1, block_id_1, proposal_1)
        .expect("apply height 1");
    ledger
        .apply_committed_block(3, block_id_3, proposal_3)
        .expect("apply height 3");
    ledger
        .apply_committed_block(5, block_id_5, proposal_5)
        .expect("apply height 5");

    // Confirm that ledger.iter() yields heights [1, 3, 5] in order
    let heights: Vec<u64> = ledger.iter().map(|(h, _)| *h).collect();
    assert_eq!(heights, vec![1, 3, 5]);
}