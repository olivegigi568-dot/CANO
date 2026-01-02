//! Tests for commit notification API on HotStuffDriver.
//!
//! These tests verify that:
//! - `new_commits()` returns an empty slice before any commits occur
//! - `drain_new_commits()` returns commits exactly once, then clears them
//! - Commit notifications are monotonic (heights strictly increasing)
//!
//! All tests use only public exports from `cano-consensus`.

use cano_consensus::{
    BasicHotStuffEngine, CommittedEntry, ConsensusEngineAction, ConsensusEngineDriver,
    ConsensusNetworkEvent, ConsensusValidatorSet, HotStuffDriver,
    MockConsensusNetwork, SingleNodeSim, ValidatorContext, ValidatorId, ValidatorSetEntry,
};

// ============================================================================
// Helpers
// ============================================================================

/// Create a validator set with `num` validators, each with `vp` voting power.
/// Validator IDs are 1, 2, 3, ..., num.
fn make_simple_set(num: u64, vp: u64) -> ConsensusValidatorSet {
    let entries: Vec<ValidatorSetEntry> = (1..=num)
        .map(|i| ValidatorSetEntry {
            id: ValidatorId(i),
            voting_power: vp,
        })
        .collect();
    ConsensusValidatorSet::new(entries).expect("valid set")
}

/// Create a BasicHotStuffEngine with driver for the given local_id and validator set.
///
/// Returns a tuple of:
/// - HotStuffDriver wrapping a BasicHotStuffEngine
/// - MockConsensusNetwork for the driver
fn make_basic_driver(
    local_id: ValidatorId,
    set: ConsensusValidatorSet,
) -> (
    HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]>,
    MockConsensusNetwork<ValidatorId>,
) {
    let engine: BasicHotStuffEngine<[u8; 32]> = BasicHotStuffEngine::new(local_id, set.clone());
    let ctx = ValidatorContext::new(set);
    let driver = HotStuffDriver::with_validators(engine, ctx);
    let net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    (driver, net)
}

// ============================================================================
// Custom Driver for BasicHotStuffEngine (needed for step trait impl)
// ============================================================================

/// A driver wrapper that integrates BasicHotStuffEngine with the ConsensusEngineDriver trait,
/// while also exposing commit notification methods.
///
/// This driver:
/// - Processes incoming proposals and votes through the engine
/// - Generates proposals when the engine is the leader
/// - Tracks QC formation and view advancement
/// - Exposes `new_commits()` and `drain_new_commits()` via the underlying HotStuffDriver
#[derive(Debug)]
struct BasicHotStuffEngineDriverWithCommitNotifications {
    /// The underlying HotStuffDriver wrapping a BasicHotStuffEngine.
    inner: HotStuffDriver<BasicHotStuffEngine<[u8; 32]>, [u8; 32]>,
    /// Validator context for membership checks.
    validators: ValidatorContext,
}

impl BasicHotStuffEngineDriverWithCommitNotifications {
    fn new(
        engine: BasicHotStuffEngine<[u8; 32]>,
        validators: ValidatorContext,
    ) -> Self {
        let inner = HotStuffDriver::with_validators(engine, validators.clone());
        BasicHotStuffEngineDriverWithCommitNotifications { inner, validators }
    }

    fn engine(&self) -> &BasicHotStuffEngine<[u8; 32]> {
        self.inner.engine()
    }

    fn engine_mut(&mut self) -> &mut BasicHotStuffEngine<[u8; 32]> {
        self.inner.engine_mut()
    }

    /// Returns a slice view of all commits that have occurred since the last
    /// time `drain_new_commits` was called.
    fn new_commits(&self) -> &[CommittedEntry<[u8; 32]>] {
        self.inner.new_commits()
    }

    /// Returns a Vec of all new commits since the last drain and advances
    /// the driver's internal index to the end of the commit log.
    fn drain_new_commits(&mut self) -> Vec<CommittedEntry<[u8; 32]>> {
        self.inner.drain_new_commits()
    }
}

impl ConsensusEngineDriver<MockConsensusNetwork<ValidatorId>>
    for BasicHotStuffEngineDriverWithCommitNotifications
{
    fn step(
        &mut self,
        _net: &mut MockConsensusNetwork<ValidatorId>,
        maybe_event: Option<ConsensusNetworkEvent<ValidatorId>>,
    ) -> Result<Vec<ConsensusEngineAction<ValidatorId>>, cano_consensus::NetworkError> {
        let mut actions = Vec::new();

        // Process incoming event
        if let Some(event) = maybe_event {
            match event {
                ConsensusNetworkEvent::IncomingVote { from, vote } => {
                    // Check validator membership
                    if !self.validators.is_member(from) {
                        return Ok(vec![ConsensusEngineAction::Noop]);
                    }
                    // Ingest vote into engine
                    if let Err(_e) = self.engine_mut().on_vote_event(from, &vote) {
                        // Vote from unknown validator or other validation error - ignore
                    }
                }
                ConsensusNetworkEvent::IncomingProposal { from, proposal } => {
                    // Check validator membership
                    if !self.validators.is_member(from) {
                        return Ok(vec![ConsensusEngineAction::Noop]);
                    }
                    // Process proposal and possibly vote
                    if let Some(action) = self.engine_mut().on_proposal_event(from, &proposal) {
                        actions.push(action);
                    }
                }
            }
        }

        // Try to generate a proposal if we're the leader
        if let Some(action) = self.engine_mut().try_propose() {
            actions.push(action);
        }

        if actions.is_empty() {
            actions.push(ConsensusEngineAction::Noop);
        }

        Ok(actions)
    }
}

// ============================================================================
// Test 1: No commits → new_commits empty
// ============================================================================

/// Test that `new_commits()` and `drain_new_commits()` return empty before any commit.
///
/// Scenario:
/// 1. Create a 3-node validator set (quorum requires 2+ nodes)
/// 2. Create a driver for node 1 (leader at view 0)
/// 3. Do NOT run any steps (no QCs form, no commits)
/// 4. Assert both `new_commits()` and `drain_new_commits()` are empty
#[test]
fn driver_new_commits_empty_before_any_commit() {
    // With 3 validators, quorum needs ceil(2*30/3) = 20 VP
    // Single node has 10 VP, so no QC can form without other votes
    let validators = make_simple_set(3, 10);
    let ctx = ValidatorContext::new(validators.clone());

    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);
    let mut driver = BasicHotStuffEngineDriverWithCommitNotifications::new(engine, ctx);

    // No steps run - no commits should exist
    assert!(
        driver.new_commits().is_empty(),
        "new_commits() should be empty before any commit"
    );
    assert!(
        driver.drain_new_commits().is_empty(),
        "drain_new_commits() should be empty before any commit"
    );
}

// ============================================================================
// Test 2: Commits show up once via drain
// ============================================================================

/// Test that `drain_new_commits()` returns commits exactly once and clears them.
///
/// Scenario:
/// 1. Create a single-node setup (n=1, always has quorum)
/// 2. Run the engine until at least one commit occurs
/// 3. Call `drain_new_commits()` - should return the commits
/// 4. Call `drain_new_commits()` again - should return empty (no double-delivery)
/// 5. `new_commits()` should also be empty after drain
#[test]
fn driver_drain_new_commits_yields_and_clears() {
    // Single node: quorum = 1 validator, QC forms immediately with self-vote
    let validators = make_simple_set(1, 10);
    let ctx = ValidatorContext::new(validators.clone());

    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);
    let driver = BasicHotStuffEngineDriverWithCommitNotifications::new(engine, ctx);

    let net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let mut sim = SingleNodeSim::new(net, driver);

    // Run until at least one commit occurs
    // With a single node, QC forms immediately on each proposal
    // After 3 blocks with QCs (3-chain), the grandparent commits
    // We run more iterations to be safe
    let iterations = 10;
    for _ in 0..iterations {
        sim.step_once().unwrap();
    }

    // Verify at least one commit has occurred
    let commit_log = sim.driver.engine().commit_log();
    assert!(
        !commit_log.is_empty(),
        "At least one commit should have occurred after {} iterations",
        iterations
    );

    // First drain: should yield commits
    let first = sim.driver.drain_new_commits();
    assert!(
        !first.is_empty(),
        "First drain should return commits (got {} entries)",
        first.len()
    );

    // Verify entries match the engine's commit log prefix
    let engine_log = sim.driver.engine().commit_log();
    assert_eq!(
        first.len(),
        engine_log.len(),
        "First drain should return all commits so far"
    );
    for (i, entry) in first.iter().enumerate() {
        assert_eq!(
            entry, &engine_log[i],
            "Drained entry {} should match engine commit log",
            i
        );
    }

    // Second drain: should be empty (no double-delivery)
    let second = sim.driver.drain_new_commits();
    assert!(
        second.is_empty(),
        "Second drain should return empty (no double-delivery)"
    );

    // new_commits() should also be empty after drain
    assert!(
        sim.driver.new_commits().is_empty(),
        "new_commits() should be empty after drain"
    );
}

// ============================================================================
// Test 3: Multiple commits over time (monotonicity)
// ============================================================================

/// Test that commit notifications are monotonic across multiple drains.
///
/// Scenario:
/// 1. Create a single-node setup
/// 2. Run the engine in multiple phases, draining commits between phases
/// 3. Collect all drained entries
/// 4. Assert that:
///    - The concatenation of all drained entries equals the engine's commit_log
///    - Heights in the drained entries are strictly increasing
#[test]
fn driver_commit_notifications_are_monotonic() {
    // Single node for simplicity
    let validators = make_simple_set(1, 10);
    let ctx = ValidatorContext::new(validators.clone());

    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);
    let driver = BasicHotStuffEngineDriverWithCommitNotifications::new(engine, ctx);

    let net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let mut sim = SingleNodeSim::new(net, driver);

    // Collect all drained commits across multiple phases
    let mut all_drained: Vec<CommittedEntry<[u8; 32]>> = Vec::new();

    // Phase 1: Run a few iterations and drain
    for _ in 0..5 {
        sim.step_once().unwrap();
    }
    let phase1 = sim.driver.drain_new_commits();
    all_drained.extend(phase1);

    // Phase 2: Run more iterations and drain again
    for _ in 0..5 {
        sim.step_once().unwrap();
    }
    let phase2 = sim.driver.drain_new_commits();
    all_drained.extend(phase2);

    // Phase 3: Run even more iterations and drain
    for _ in 0..5 {
        sim.step_once().unwrap();
    }
    let phase3 = sim.driver.drain_new_commits();
    all_drained.extend(phase3);

    // Verify at least some commits occurred
    let engine_log = sim.driver.engine().commit_log();
    assert!(
        !engine_log.is_empty(),
        "At least one commit should have occurred"
    );

    // The concatenation of all drained entries should equal the engine's commit_log
    assert_eq!(
        all_drained.len(),
        engine_log.len(),
        "Concatenated drained entries should equal commit log length"
    );
    for (i, entry) in all_drained.iter().enumerate() {
        assert_eq!(
            entry, &engine_log[i],
            "Drained entry {} should match engine commit log",
            i
        );
    }

    // Heights should be strictly increasing (monotonicity)
    let mut last_height: Option<u64> = None;
    for entry in &all_drained {
        if let Some(prev) = last_height {
            assert!(
                entry.height > prev,
                "Heights must be strictly increasing: prev={}, current={}",
                prev,
                entry.height
            );
        }
        last_height = Some(entry.height);
    }
}

// ============================================================================
// Test 4: new_commits() reflects pending commits without advancing index
// ============================================================================

/// Test that `new_commits()` shows pending commits without advancing the index.
///
/// Scenario:
/// 1. Create a single-node setup and run until commits occur
/// 2. Call `new_commits()` multiple times - should return the same slice each time
/// 3. Call `drain_new_commits()` - should clear them
/// 4. `new_commits()` should now be empty
#[test]
fn driver_new_commits_does_not_advance_index() {
    let validators = make_simple_set(1, 10);
    let ctx = ValidatorContext::new(validators.clone());

    let engine: BasicHotStuffEngine<[u8; 32]> =
        BasicHotStuffEngine::new(ValidatorId(1), validators);
    let driver = BasicHotStuffEngineDriverWithCommitNotifications::new(engine, ctx);

    let net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();
    let mut sim = SingleNodeSim::new(net, driver);

    // Run until commits occur
    for _ in 0..10 {
        sim.step_once().unwrap();
    }

    // Call new_commits() multiple times
    let first_view = sim.driver.new_commits().len();
    let second_view = sim.driver.new_commits().len();
    let third_view = sim.driver.new_commits().len();

    // All views should be identical (index not advanced)
    assert_eq!(
        first_view, second_view,
        "new_commits() should return same length on repeated calls"
    );
    assert_eq!(
        second_view, third_view,
        "new_commits() should return same length on repeated calls"
    );

    // Now drain
    let drained = sim.driver.drain_new_commits();
    assert_eq!(
        drained.len(),
        first_view,
        "drain should return same entries that new_commits showed"
    );

    // new_commits() should now be empty
    assert!(
        sim.driver.new_commits().is_empty(),
        "new_commits() should be empty after drain"
    );
}

// ============================================================================
// Test 5: Direct driver usage (without SingleNodeSim)
// ============================================================================

/// Test commit notifications using direct driver usage without SingleNodeSim.
///
/// This test verifies the API works without the simulation harness.
#[test]
fn driver_commit_notifications_direct_usage() {
    let validators = make_simple_set(1, 10);
    let (mut driver, _net) = make_basic_driver(ValidatorId(1), validators);

    // Initially, no commits
    assert!(driver.new_commits().is_empty());
    assert!(driver.drain_new_commits().is_empty());

    // Run the engine manually until commits occur
    // For a single-node setup, we need to call try_propose() repeatedly
    // and let the engine self-vote and form QCs
    for _ in 0..10 {
        if let Some(_action) = driver.engine_mut().try_propose() {
            // Proposal generated - engine self-votes and may form QC
        }
    }

    // Check if commits occurred
    let engine_commits = driver.engine().commit_log().len();
    let new_commits_len = driver.new_commits().len();

    // Both should reflect the same state
    assert_eq!(
        new_commits_len, engine_commits,
        "new_commits() length should match engine commit log"
    );

    // Drain and verify
    let drained = driver.drain_new_commits();
    assert_eq!(
        drained.len(),
        engine_commits,
        "drain should return all commits"
    );

    // After drain, should be empty
    assert!(driver.new_commits().is_empty());
    assert!(driver.drain_new_commits().is_empty());
}
