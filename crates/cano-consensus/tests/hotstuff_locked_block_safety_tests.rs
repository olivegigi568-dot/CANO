//! Tests for HotStuff locked-block safety rule.
//!
//! These tests verify:
//! - Proposals on a chain that includes the locked block are allowed
//! - Proposals on conflicting forks (not descending from locked block) are rejected
//! - Without a locked QC, all proposals are allowed

use cano_consensus::{
    BasicHotStuffEngine, ConsensusEngineAction, ConsensusValidatorSet,
    HotStuffStateEngine, QuorumCertificate, ValidatorId, ValidatorSetEntry,
};
use cano_wire::consensus::{BlockHeader, BlockProposal};

// ============================================================================
// Helpers
// ============================================================================

/// Helper to build a validator set with `num` validators, each with `vp` voting power.
/// Validator IDs start from `start_id` and go to `start_id + num - 1`.
fn make_validator_set_from(start_id: u64, num: u64, vp: u64) -> ConsensusValidatorSet {
    let entries = (start_id..start_id + num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: vp,
        })
        .collect::<Vec<_>>();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Helper to build a simple validator set with `num` validators, each with `vp` voting power.
/// Validator IDs are 0, 1, 2, ..., num-1 (0-indexed for state engine tests).
fn make_simple_set(num: u64, vp: u64) -> ConsensusValidatorSet {
    make_validator_set_from(0, num, vp)
}

/// Helper to build a validator set with `num` validators, each with `vp` voting power.
/// Validator IDs are 1, 2, 3, ..., num (1-indexed for engine tests).
fn make_validator_set(num: u64, vp: u64) -> ConsensusValidatorSet {
    make_validator_set_from(1, num, vp)
}

/// Helper to create a dummy block ID from a seed byte.
fn make_block_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

/// Helper to create a dummy BlockProposal for testing.
fn make_proposal(
    view: u64,
    parent_block_id: [u8; 32],
    proposer_index: u16,
) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            height: view,
            round: view,
            parent_block_id,
            payload_hash: [0u8; 32],
            proposer_index,
            reserved: 0,
            tx_count: 0,
            timestamp: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

// ============================================================================
// Test: No lock yet → proposals allowed (no_locked_qc_allows_proposals)
// ============================================================================

/// Test that without a locked QC, any proposal can be voted on.
///
/// Scenario:
/// 1. Create a HotStuffStateEngine with no votes/QCs (so locked_qc is None)
/// 2. Register two disjoint blocks (different parents)
/// 3. Verify is_safe_to_vote_on_block returns true for each
#[test]
fn no_locked_qc_allows_proposals() {
    // 3 validators with equal weight (10 each)
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Verify no lock initially
    assert!(engine.locked_qc().is_none());

    // Register two disjoint blocks with different parents
    let genesis_a = make_block_id(0xAA);
    let genesis_b = make_block_id(0xBB);
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);

    // Register genesis blocks
    engine.register_block(genesis_a, 0, None, None);
    engine.register_block(genesis_b, 0, None, None);

    // Register blocks A and B with different parents
    engine.register_block(block_a, 1, Some(genesis_a), None);
    engine.register_block(block_b, 1, Some(genesis_b), None);

    // Without a locked QC, both blocks should be safe to vote on
    assert!(
        engine.is_safe_to_vote_on_block(&block_a),
        "Block A should be safe to vote on when no lock exists"
    );
    assert!(
        engine.is_safe_to_vote_on_block(&block_b),
        "Block B should be safe to vote on when no lock exists"
    );
}

/// Test that on_proposal_event emits votes when there is no locked QC.
#[test]
fn no_locked_qc_allows_proposals_via_engine() {
    // 3 validators with equal weight - use 1-indexed IDs for the engine
    let validators = make_validator_set(3, 10);

    // Create engine for validator 1 (leader at view 0)
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);

    // Verify no lock initially
    assert!(engine.locked_qc().is_none());

    // At view 0, validator 1 is the leader
    assert!(engine.is_leader_for_current_view());

    // Create a proposal from the leader
    let proposal = make_proposal(0, [0u8; 32], 1);

    // on_proposal_event should return a vote since there's no lock
    // Note: Since validator 1 is the leader at view 0, it processes its own proposal
    let action = engine.on_proposal_event(ValidatorId(1), &proposal);

    // Should produce a BroadcastVote action
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "Should produce a vote when no lock exists"
    );
}

// ============================================================================
// Test: Proposals on locked chain are voted (locked_block_allows_descendant_proposals)
// ============================================================================

/// Test that proposals on a chain that includes the locked block are allowed.
///
/// Scenario:
/// 1. Build 3 validators (v0, v1, v2) with equal voting power
/// 2. Construct a chain: genesis -> A -> B -> C
/// 3. Set locked_qc to point at block B
/// 4. Verify that block C (descendant of B) is safe to vote on
/// 5. Verify that a new block D (child of C) is also safe to vote on
/// 6. Verify that block B (the locked block itself) is safe to vote on
/// 7. Verify that block A (ancestor of locked block) is NOT safe to vote on
///    (because A does not descend from B; B is not in A's ancestor chain)
#[test]
fn locked_block_allows_descendant_proposals() {
    // 3 validators with equal weight
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build chain: genesis -> A -> B -> C
    let genesis_id = make_block_id(0x00);
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);
    let block_c = make_block_id(0x03);
    let block_d = make_block_id(0x04);

    engine.register_block(genesis_id, 0, None, None);
    engine.register_block(block_a, 1, Some(genesis_id), None);
    engine.register_block(block_b, 2, Some(block_a), None);
    engine.register_block(block_c, 3, Some(block_b), None);

    // Set locked_qc to point at block B
    let locked_qc = QuorumCertificate::new(
        block_b,
        2,
        vec![ValidatorId(0), ValidatorId(1)],
    );
    engine.set_locked_qc(locked_qc);

    // Verify lock is set
    assert!(engine.locked_qc().is_some());
    assert_eq!(engine.locked_qc().unwrap().block_id, block_b);

    // Block C (descendant of B) should be safe to vote on
    assert!(
        engine.is_safe_to_vote_on_block(&block_c),
        "Block C (descendant of locked block B) should be safe to vote on"
    );

    // Block B (the locked block itself) should be safe to vote on
    assert!(
        engine.is_safe_to_vote_on_block(&block_b),
        "Block B (the locked block itself) should be safe to vote on"
    );

    // Block A (ancestor of locked block) should NOT be safe to vote on
    // because B is not in A's ancestor chain (A is a predecessor of B, not a descendant)
    assert!(
        !engine.is_safe_to_vote_on_block(&block_a),
        "Block A (ancestor of locked block B) should NOT be safe to vote on"
    );

    // Now register block D as child of C and verify it's also safe
    engine.register_block(block_d, 4, Some(block_c), None);
    assert!(
        engine.is_safe_to_vote_on_block(&block_d),
        "Block D (descendant of locked block B via C) should be safe to vote on"
    );
}

/// Test that on_proposal_event emits votes for proposals descending from the locked block.
#[test]
fn locked_block_allows_descendant_proposals_via_engine() {
    // 3 validators with equal weight
    let validators = make_validator_set(3, 10);

    // Create engine for validator 2 (not the leader at view 0, but will be at view 1)
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators);

    // Build a chain and set a lock
    let genesis_id = make_block_id(0x00);
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);

    engine.state_mut().register_block(genesis_id, 0, None, None);
    engine.state_mut().register_block(block_a, 1, Some(genesis_id), None);
    engine.state_mut().register_block(block_b, 2, Some(block_a), None);

    // Set locked_qc to point at block A
    let locked_qc = QuorumCertificate::new(
        block_a,
        1,
        vec![ValidatorId(1), ValidatorId(2)],
    );
    engine.state_mut().set_locked_qc(locked_qc);

    // Advance engine to view 1 where validator 2 is the leader
    // Leaders: [1, 2, 3], view 1 -> leader[1] = 2
    while engine.current_view() < 1 {
        engine.advance_view();
    }
    assert_eq!(engine.current_view(), 1);
    assert_eq!(engine.leader_for_view(1), ValidatorId(2));

    // Create a proposal from validator 2 at view 1, with parent = block_a (the locked block)
    let proposal = make_proposal(1, block_a, 2);

    // on_proposal_event should return a vote since block_a is the locked block
    let action = engine.on_proposal_event(ValidatorId(2), &proposal);

    // Should produce a BroadcastVote action
    assert!(
        matches!(action, Some(ConsensusEngineAction::BroadcastVote(_))),
        "Should produce a vote for proposal descending from locked block"
    );
}

// ============================================================================
// Test: Proposals on conflicting fork are rejected (locked_block_rejects_conflicting_proposals)
// ============================================================================

/// Test that proposals on chains that don't include the locked block are rejected.
///
/// Scenario:
/// 1. Build chain: genesis -> A -> B (with locked_qc on B)
/// 2. Build a fork: genesis -> B' -> C'
/// 3. Verify that B' and C' (on the fork) are NOT safe to vote on
#[test]
fn locked_block_rejects_conflicting_proposals() {
    // 3 validators with equal weight
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build main chain: genesis -> A -> B
    let genesis_id = make_block_id(0x00);
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);

    engine.register_block(genesis_id, 0, None, None);
    engine.register_block(block_a, 1, Some(genesis_id), None);
    engine.register_block(block_b, 2, Some(block_a), None);

    // Set locked_qc to point at block B
    let locked_qc = QuorumCertificate::new(
        block_b,
        2,
        vec![ValidatorId(0), ValidatorId(1)],
    );
    engine.set_locked_qc(locked_qc);

    // Build a fork: genesis -> B' -> C'
    let block_b_prime = make_block_id(0xB2);  // Different from block_b
    let block_c_prime = make_block_id(0xC2);

    engine.register_block(block_b_prime, 2, Some(genesis_id), None);  // Parent is genesis, not A
    engine.register_block(block_c_prime, 3, Some(block_b_prime), None);

    // Fork blocks should NOT be safe to vote on
    assert!(
        !engine.is_safe_to_vote_on_block(&block_b_prime),
        "Block B' (on fork, not descending from locked block B) should NOT be safe to vote on"
    );
    assert!(
        !engine.is_safe_to_vote_on_block(&block_c_prime),
        "Block C' (on fork, not descending from locked block B) should NOT be safe to vote on"
    );
}

/// Test that on_proposal_event does NOT emit votes for proposals on conflicting forks.
#[test]
fn locked_block_rejects_conflicting_proposals_via_engine() {
    // 3 validators with equal weight
    let validators = make_validator_set(3, 10);

    // Create engine for validator 2
    let mut engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(2), validators);

    // Build main chain: genesis -> A -> B and lock on A
    let genesis_id = make_block_id(0x00);
    let block_a = make_block_id(0x01);

    engine.state_mut().register_block(genesis_id, 0, None, None);
    engine.state_mut().register_block(block_a, 1, Some(genesis_id), None);

    // Set locked_qc to point at block A
    let locked_qc = QuorumCertificate::new(
        block_a,
        1,
        vec![ValidatorId(1), ValidatorId(2)],
    );
    engine.state_mut().set_locked_qc(locked_qc);

    // Advance engine to view 1 where validator 2 is the leader
    while engine.current_view() < 1 {
        engine.advance_view();
    }
    assert_eq!(engine.current_view(), 1);

    // Create a proposal from validator 2 at view 1, with a conflicting parent
    // Parent is [0xFF; 32] which is not genesis and not in the chain containing block_a
    let conflicting_parent = [0xFF; 32];
    engine.state_mut().register_block(conflicting_parent, 0, None, None);  // Register the parent
    
    let proposal = make_proposal(1, conflicting_parent, 2);

    // on_proposal_event should NOT return a vote since the proposal is on a conflicting fork
    let action = engine.on_proposal_event(ValidatorId(2), &proposal);

    // Should return None (no vote emitted)
    assert!(
        action.is_none(),
        "Should NOT produce a vote for proposal on conflicting fork"
    );
}

// ============================================================================
// Additional edge case tests
// ============================================================================

/// Test that voting on an unregistered block returns false (conservative behavior).
#[test]
fn unregistered_block_is_not_safe_to_vote_on() {
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Register a block and lock on it
    let block_a = make_block_id(0x01);
    engine.register_block(block_a, 1, None, None);
    
    let locked_qc = QuorumCertificate::new(block_a, 1, vec![ValidatorId(0), ValidatorId(1)]);
    engine.set_locked_qc(locked_qc);

    // An unregistered block should not be safe to vote on
    let unregistered_block = make_block_id(0xFF);
    assert!(
        !engine.is_safe_to_vote_on_block(&unregistered_block),
        "Unregistered block should NOT be safe to vote on"
    );
}

/// Test that the locked block itself is safe to vote on.
#[test]
fn locked_block_itself_is_safe_to_vote_on() {
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Register a block and lock on it
    let block_a = make_block_id(0x01);
    engine.register_block(block_a, 1, None, None);
    
    let locked_qc = QuorumCertificate::new(block_a, 1, vec![ValidatorId(0), ValidatorId(1)]);
    engine.set_locked_qc(locked_qc);

    // The locked block itself should be safe to vote on
    assert!(
        engine.is_safe_to_vote_on_block(&block_a),
        "The locked block itself should be safe to vote on"
    );
}

/// Test equivocation detection still works with locked block safety.
#[test]
fn equivocation_detection_works_with_locked_block_safety() {
    let validators = make_simple_set(3, 10);
    let mut engine: HotStuffStateEngine<[u8; 32]> = HotStuffStateEngine::new(validators);

    // Build chain: genesis -> A -> B
    let genesis_id = make_block_id(0x00);
    let block_a = make_block_id(0x01);
    let block_b = make_block_id(0x02);

    engine.register_block(genesis_id, 0, None, None);
    engine.register_block(block_a, 1, Some(genesis_id), None);
    engine.register_block(block_b, 2, Some(block_a), None);

    // Lock on A
    let locked_qc = QuorumCertificate::new(
        block_a,
        1,
        vec![ValidatorId(0), ValidatorId(1)],
    );
    engine.set_locked_qc(locked_qc);

    // Vote for block B (which is safe, descends from A)
    let _ = engine.on_vote(ValidatorId(0), 2, &block_b);

    // No equivocations yet
    assert_eq!(engine.equivocations_detected(), 0);

    // Now try to vote for a different block at the same view
    let block_b_prime = make_block_id(0xB2);
    engine.register_block(block_b_prime, 2, Some(genesis_id), None);  // Fork block
    
    // Validator 0 votes again at view 2 for a different block
    let _ = engine.on_vote(ValidatorId(0), 2, &block_b_prime);

    // Equivocation should be detected
    assert_eq!(engine.equivocations_detected(), 1);
    assert!(engine.equivocating_validators().contains(&ValidatorId(0)));
}