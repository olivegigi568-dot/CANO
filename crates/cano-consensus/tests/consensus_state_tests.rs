use cano_consensus::{ConsensusState, ConsensusStateError};

#[test]
fn new_state_starts_at_height_with_round_zero() {
    let cs = ConsensusState::new_at_height(5);
    assert_eq!(cs.height(), 5);
    assert_eq!(cs.round(), 0);
}

#[test]
fn can_vote_for_future_height_and_round() {
    let mut cs = ConsensusState::new_at_height(5);

    // Vote at same height, higher round.
    cs.can_vote_for(5, 1).expect("can vote at (5,1)");
    cs.record_vote(5, 1).expect("record vote at (5,1)");
    assert_eq!(cs.height(), 5);
    assert_eq!(cs.round(), 1);

    // Vote at higher height.
    cs.advance_height(6).expect("advance to height 6");
    assert_eq!(cs.height(), 6);
    assert_eq!(cs.round(), 0);
    cs.can_vote_for(6, 0).expect("can vote at (6,0)");
    cs.record_vote(6, 0).expect("record vote at (6,0)");
}

#[test]
fn record_vote_at_future_height_resets_round() {
    let mut cs = ConsensusState::new_at_height(5);

    // Advance to round 3 at height 5.
    cs.advance_round(3).expect("advance to round 3");
    assert_eq!(cs.height(), 5);
    assert_eq!(cs.round(), 3);

    // Vote at future height 7, round 0.
    // This should set height to 7 and round to 0 (not stay at 3).
    cs.record_vote(7, 0).expect("vote at (7,0)");
    assert_eq!(cs.height(), 7);
    assert_eq!(cs.round(), 0);
}

#[test]
fn cannot_double_vote_same_height_round() {
    let mut cs = ConsensusState::new_at_height(5);

    cs.record_vote(5, 0).expect("first vote ok");
    let err = cs.record_vote(5, 0).expect_err("second vote must fail");
    match err {
        ConsensusStateError::DoubleVote { height, round } => {
            assert_eq!(height, 5);
            assert_eq!(round, 0);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn cannot_vote_on_stale_height() {
    let mut cs = ConsensusState::new_at_height(5);
    cs.record_vote(5, 0).expect("first vote ok");

    let err = cs.can_vote_for(4, 1).expect_err("stale height must be rejected");
    match err {
        ConsensusStateError::StaleHeight {
            current_height,
            requested_height,
        } => {
            assert_eq!(current_height, 5);
            assert_eq!(requested_height, 4);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn cannot_vote_on_stale_round_at_current_height() {
    let mut cs = ConsensusState::new_at_height(5);
    cs.record_vote(5, 2).expect("vote at (5,2) ok");

    // Now round() should be at least 2.
    let err = cs.can_vote_for(5, 1).expect_err("stale round must be rejected");
    match err {
        ConsensusStateError::StaleRound {
            current_round,
            requested_round,
        } => {
            assert!(current_round >= 2);
            assert_eq!(requested_round, 1);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn advance_round_cannot_regress() {
    let mut cs = ConsensusState::new_at_height(5);
    cs.advance_round(3).expect("advance to round 3");

    let err = cs.advance_round(2).expect_err("cannot regress round");
    match err {
        ConsensusStateError::RoundRegression {
            current_round,
            requested_round,
        } => {
            assert_eq!(current_round, 3);
            assert_eq!(requested_round, 2);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn advance_height_cannot_regress() {
    let mut cs = ConsensusState::new_at_height(5);
    cs.advance_height(7).expect("advance to height 7");

    let err = cs.advance_height(6).expect_err("cannot regress height");
    match err {
        ConsensusStateError::StaleHeight {
            current_height,
            requested_height,
        } => {
            assert_eq!(current_height, 7);
            assert_eq!(requested_height, 6);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}