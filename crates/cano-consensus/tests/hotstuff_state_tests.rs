use cano_consensus::{ConsensusStateError, HotStuffState};

fn bid(x: u8) -> [u8; 32] {
    [x; 32]
}

#[test]
fn hotstuff_state_starts_unlocked() {
    let s = HotStuffState::new_at_height(5);
    assert_eq!(s.height(), 5);
    assert_eq!(s.round(), 0);
    assert_eq!(s.locked_height(), 0);
    assert_eq!(s.last_commit_height(), 0);
}

#[test]
fn hotstuff_can_vote_when_justify_qc_height_not_below_lock() {
    let mut s = HotStuffState::new_at_height(10);
    s.update_lock(8, bid(0xAA));

    // proposal at height 10, qc height 8 (equal to lock) should be ok.
    s.can_vote_hotstuff(10, 1, bid(0xBB), 8).expect("allowed");
}

#[test]
fn hotstuff_can_vote_when_justify_qc_height_above_lock() {
    let mut s = HotStuffState::new_at_height(10);
    s.update_lock(8, bid(0xAA));

    // proposal at height 10, qc height 9 (above lock) should be ok.
    s.can_vote_hotstuff(10, 1, bid(0xBB), 9).expect("allowed");
}

#[test]
fn hotstuff_rejects_vote_when_justify_qc_below_lock() {
    let mut s = HotStuffState::new_at_height(10);
    s.update_lock(8, bid(0xAA));

    let err = s
        .can_vote_hotstuff(10, 1, bid(0xBB), 7)
        .expect_err("justify below lock must be rejected");

    match err {
        ConsensusStateError::StaleHeight {
            current_height,
            requested_height,
        } => {
            assert_eq!(current_height, 8);
            assert_eq!(requested_height, 7);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_record_vote_tracks_last_voted() {
    let mut s = HotStuffState::new_at_height(5);
    s.record_vote_hotstuff(5, 1, bid(0xCC)).expect("record ok");
    assert_eq!(s.height(), 5);
    assert!(s.round() >= 1);

    // Second identical vote must fail.
    let err = s
        .record_vote_hotstuff(5, 1, bid(0xCC))
        .expect_err("double vote must fail");
    match err {
        ConsensusStateError::DoubleVote { height, round } => {
            assert_eq!(height, 5);
            assert_eq!(round, 1);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_rejects_vote_on_stale_height() {
    let s = HotStuffState::new_at_height(10);
    let err = s
        .can_vote_hotstuff(8, 0, bid(0xAA), 0)
        .expect_err("stale height must be rejected");

    match err {
        ConsensusStateError::StaleHeight {
            current_height,
            requested_height,
        } => {
            assert_eq!(current_height, 10);
            assert_eq!(requested_height, 8);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_rejects_vote_on_stale_round() {
    let mut s = HotStuffState::new_at_height(10);
    s.advance_round(5).expect("advance round ok");

    let err = s
        .can_vote_hotstuff(10, 3, bid(0xAA), 0)
        .expect_err("stale round must be rejected");

    match err {
        ConsensusStateError::StaleRound {
            current_round,
            requested_round,
        } => {
            assert_eq!(current_round, 5);
            assert_eq!(requested_round, 3);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_advance_round_works() {
    let mut s = HotStuffState::new_at_height(5);
    s.advance_round(3).expect("advance ok");
    assert_eq!(s.round(), 3);
    s.advance_round(3).expect("same round ok");
    assert_eq!(s.round(), 3);
    s.advance_round(5).expect("higher round ok");
    assert_eq!(s.round(), 5);
}

#[test]
fn hotstuff_advance_round_rejects_regression() {
    let mut s = HotStuffState::new_at_height(5);
    s.advance_round(5).expect("advance ok");

    let err = s
        .advance_round(3)
        .expect_err("round regression must be rejected");
    match err {
        ConsensusStateError::RoundRegression {
            current_round,
            requested_round,
        } => {
            assert_eq!(current_round, 5);
            assert_eq!(requested_round, 3);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_advance_height_resets_round_and_last_voted() {
    let mut s = HotStuffState::new_at_height(5);
    s.advance_round(3).expect("advance round ok");
    s.record_vote_hotstuff(5, 3, bid(0xAA))
        .expect("record vote ok");

    s.advance_height(7).expect("advance height ok");
    assert_eq!(s.height(), 7);
    assert_eq!(s.round(), 0);

    // Should be able to vote at height 7 since last_voted was reset
    s.record_vote_hotstuff(7, 0, bid(0xBB))
        .expect("vote after height advance ok");
}

#[test]
fn hotstuff_advance_height_rejects_regression() {
    let mut s = HotStuffState::new_at_height(10);

    let err = s
        .advance_height(8)
        .expect_err("height regression must be rejected");
    match err {
        ConsensusStateError::StaleHeight {
            current_height,
            requested_height,
        } => {
            assert_eq!(current_height, 10);
            assert_eq!(requested_height, 8);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn hotstuff_update_lock_is_monotonic() {
    let mut s = HotStuffState::new_at_height(10);
    assert_eq!(s.locked_height(), 0);

    s.update_lock(5, bid(0xAA));
    assert_eq!(s.locked_height(), 5);

    // Lower height doesn't update
    s.update_lock(3, bid(0xBB));
    assert_eq!(s.locked_height(), 5);

    // Equal height doesn't update
    s.update_lock(5, bid(0xCC));
    assert_eq!(s.locked_height(), 5);

    // Higher height updates
    s.update_lock(8, bid(0xDD));
    assert_eq!(s.locked_height(), 8);
}

#[test]
fn hotstuff_update_commit_height_is_monotonic() {
    let mut s = HotStuffState::new_at_height(10);
    assert_eq!(s.last_commit_height(), 0);

    s.update_commit_height(5);
    assert_eq!(s.last_commit_height(), 5);

    // Lower height doesn't update
    s.update_commit_height(3);
    assert_eq!(s.last_commit_height(), 5);

    // Equal height doesn't update
    s.update_commit_height(5);
    assert_eq!(s.last_commit_height(), 5);

    // Higher height updates
    s.update_commit_height(8);
    assert_eq!(s.last_commit_height(), 8);
}

#[test]
fn hotstuff_vote_at_future_height_updates_state() {
    let mut s = HotStuffState::new_at_height(5);
    s.record_vote_hotstuff(8, 2, bid(0xAA))
        .expect("vote at future height ok");

    assert_eq!(s.height(), 8);
}

#[test]
fn hotstuff_vote_different_block_same_height_round_rejected() {
    let mut s = HotStuffState::new_at_height(5);
    s.record_vote_hotstuff(5, 1, bid(0xAA)).expect("first vote ok");

    // Different block_id at same (height, round) is a double-vote and should be rejected
    let err = s
        .record_vote_hotstuff(5, 1, bid(0xBB))
        .expect_err("double vote at same height/round must be rejected");

    match err {
        ConsensusStateError::DoubleVote { height, round } => {
            assert_eq!(height, 5);
            assert_eq!(round, 1);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}