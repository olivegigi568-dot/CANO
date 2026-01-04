//! Unit tests for BasicTickPacemaker.
//!
//! These tests verify the tick-based pacemaker behavior:
//! - Allows exactly one proposal per view
//! - Respects min_ticks_between_proposals
//! - Resets state on view change
//! - Resets state on QC observation

use cano_consensus::pacemaker::{BasicTickPacemaker, Pacemaker, PacemakerConfig};

/// Test that BasicTickPacemaker allows exactly one proposal per view when
/// min_ticks_between_proposals is 1.
#[test]
fn basic_tick_pacemaker_allows_single_proposal_per_view() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 1,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // First tick at view 0 should return true (allow proposal)
    assert!(pm.on_tick(0), "First tick at view 0 should allow proposal");

    // Second tick at view 0 should return false (already proposed)
    assert!(
        !pm.on_tick(0),
        "Second tick at view 0 should NOT allow proposal"
    );

    // Third tick at same view should also return false
    assert!(
        !pm.on_tick(0),
        "Third tick at view 0 should NOT allow proposal"
    );

    // Fourth tick at same view should still return false
    assert!(
        !pm.on_tick(0),
        "Fourth tick at view 0 should NOT allow proposal"
    );

    // Now move to view 1 - first tick at new view should return true
    assert!(pm.on_tick(1), "First tick at view 1 should allow proposal");

    // Second tick at view 1 should return false
    assert!(
        !pm.on_tick(1),
        "Second tick at view 1 should NOT allow proposal"
    );

    // Move to view 2
    assert!(pm.on_tick(2), "First tick at view 2 should allow proposal");

    // More ticks at view 2 should return false
    assert!(!pm.on_tick(2), "More ticks at view 2 should NOT allow proposal");
    assert!(!pm.on_tick(2), "More ticks at view 2 should NOT allow proposal");
}

/// Test that BasicTickPacemaker respects min_ticks_between_proposals > 1.
#[test]
fn basic_tick_pacemaker_respects_min_ticks_between_proposals() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 3,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // At view 0:
    // Tick 1: ticks_in_view = 1 < 3, should return false
    assert!(
        !pm.on_tick(0),
        "Tick 1 at view 0: ticks_in_view=1 < min=3, should NOT allow proposal"
    );

    // Tick 2: ticks_in_view = 2 < 3, should return false
    assert!(
        !pm.on_tick(0),
        "Tick 2 at view 0: ticks_in_view=2 < min=3, should NOT allow proposal"
    );

    // Tick 3: ticks_in_view = 3 >= 3, first proposal in view, should return true
    assert!(
        pm.on_tick(0),
        "Tick 3 at view 0: ticks_in_view=3 >= min=3, should allow proposal"
    );

    // Tick 4: already proposed in this view, should return false
    assert!(
        !pm.on_tick(0),
        "Tick 4 at view 0: already proposed, should NOT allow proposal"
    );

    // Tick 5: still in same view with proposal made, should return false
    assert!(
        !pm.on_tick(0),
        "Tick 5 at view 0: already proposed, should NOT allow proposal"
    );

    // Move to view 1 and verify it resets
    // Tick 1 at view 1: ticks_in_view = 1 < 3, should return false
    assert!(
        !pm.on_tick(1),
        "Tick 1 at view 1: ticks_in_view=1 < min=3, should NOT allow proposal"
    );

    // Tick 2 at view 1: ticks_in_view = 2 < 3, should return false
    assert!(
        !pm.on_tick(1),
        "Tick 2 at view 1: ticks_in_view=2 < min=3, should NOT allow proposal"
    );

    // Tick 3 at view 1: ticks_in_view = 3 >= 3, should return true
    assert!(
        pm.on_tick(1),
        "Tick 3 at view 1: ticks_in_view=3 >= min=3, should allow proposal"
    );

    // Tick 4 at view 1: already proposed, should return false
    assert!(
        !pm.on_tick(1),
        "Tick 4 at view 1: already proposed, should NOT allow proposal"
    );
}

/// Test that BasicTickPacemaker resets state on view change.
#[test]
fn basic_tick_pacemaker_resets_on_view_change() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 2,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // At view 0:
    // Tick 1: ticks_in_view = 1 < 2, should return false
    assert!(!pm.on_tick(0), "Tick 1 at view 0 should NOT allow proposal");

    // Tick 2: ticks_in_view = 2 >= 2, first proposal, should return true
    assert!(pm.on_tick(0), "Tick 2 at view 0 should allow proposal");

    // Tick 3: already proposed, should return false
    assert!(!pm.on_tick(0), "Tick 3 at view 0 should NOT allow proposal");

    // Switch to view 1: state should reset
    // Tick 1 at view 1: ticks_in_view = 1 < 2, should return false
    assert!(
        !pm.on_tick(1),
        "Tick 1 at view 1: after view change, ticks_in_view=1 < 2"
    );

    // Tick 2 at view 1: ticks_in_view = 2 >= 2, should return true
    assert!(
        pm.on_tick(1),
        "Tick 2 at view 1: after view change, should allow proposal"
    );

    // Tick 3 at view 1: already proposed
    assert!(
        !pm.on_tick(1),
        "Tick 3 at view 1: already proposed, should NOT allow proposal"
    );

    // Switch to view 5 (skipping views is fine)
    assert!(
        !pm.on_tick(5),
        "Tick 1 at view 5: ticks_in_view=1 < 2"
    );
    assert!(
        pm.on_tick(5),
        "Tick 2 at view 5: should allow proposal"
    );
}

/// Test that on_qc resets state when QC view is higher than last view.
#[test]
fn basic_tick_pacemaker_on_qc_resets_when_higher_view() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 1,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // Propose at view 0
    assert!(pm.on_tick(0), "First tick at view 0 should allow proposal");
    assert!(!pm.on_tick(0), "Second tick at view 0 should NOT allow proposal");

    // Call on_qc with a higher view (view 2)
    pm.on_qc(2);

    // Now at view 2 due to on_qc reset, the next on_tick(2) should act fresh
    assert!(
        pm.on_tick(2),
        "After on_qc(2), first tick at view 2 should allow proposal"
    );

    assert!(
        !pm.on_tick(2),
        "After proposing at view 2, second tick should NOT allow proposal"
    );
}

/// Test that on_qc does not reset state when QC view is not higher than last view.
#[test]
fn basic_tick_pacemaker_on_qc_no_reset_when_lower_or_equal_view() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 1,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // Advance to view 3
    assert!(pm.on_tick(3), "First tick at view 3 should allow proposal");
    assert!(!pm.on_tick(3), "Second tick at view 3 should NOT allow proposal");

    // Call on_qc with a lower view (view 1) - should NOT reset
    pm.on_qc(1);

    // Still at view 3, already proposed, should return false
    assert!(
        !pm.on_tick(3),
        "on_qc(1) should not reset state for view 3"
    );

    // Call on_qc with same view (view 3) - should NOT reset
    pm.on_qc(3);

    // Still at view 3, already proposed, should return false
    assert!(
        !pm.on_tick(3),
        "on_qc(3) should not reset state for view 3"
    );
}

/// Test with min_ticks_between_proposals = 0 (edge case, but should allow immediate proposal).
#[test]
fn basic_tick_pacemaker_with_zero_min_ticks() {
    let cfg = PacemakerConfig {
        min_ticks_between_proposals: 0,
    };
    let mut pm = BasicTickPacemaker::new(cfg);

    // With min_ticks = 0, the condition (ticks_in_view >= min) becomes (1 >= 0) = true
    // on the first tick
    assert!(
        pm.on_tick(0),
        "With min_ticks=0, first tick should allow proposal"
    );

    // Already proposed, should return false
    assert!(
        !pm.on_tick(0),
        "With min_ticks=0, second tick should NOT allow (already proposed)"
    );

    // Move to new view
    assert!(
        pm.on_tick(1),
        "With min_ticks=0, first tick at new view should allow"
    );
}