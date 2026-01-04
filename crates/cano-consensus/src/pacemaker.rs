//! Pacemaker abstraction for HotStuff-style consensus.
//!
//! This module provides a minimal pacemaker interface that decides when a leader
//! should attempt to propose. The pacemaker is driven by "ticks" (logical time)
//! and the consensus engine's current view.
//!
//! # Design
//!
//! The pacemaker is intentionally simple:
//! - It does NOT drive view changes.
//! - It only decides "should we propose in this view on this tick?"
//! - `on_qc` is an advisory hook for future refinement.
//!
//! # Example
//!
//! ```
//! use cano_consensus::pacemaker::{Pacemaker, PacemakerConfig, BasicTickPacemaker};
//!
//! let cfg = PacemakerConfig { min_ticks_between_proposals: 1 };
//! let mut pm = BasicTickPacemaker::new(cfg);
//!
//! // First tick at view 0 allows proposal
//! assert!(pm.on_tick(0));
//!
//! // Second tick at same view does not allow another proposal
//! assert!(!pm.on_tick(0));
//!
//! // Moving to a new view resets
//! assert!(pm.on_tick(1));
//! ```

/// Configuration for a simple tick-based pacemaker.
#[derive(Clone, Debug)]
pub struct PacemakerConfig {
    /// Minimum number of ticks between proposals in the same view.
    pub min_ticks_between_proposals: u32,
}

/// A minimal pacemaker interface for HotStuff-style consensus.
///
/// This trait is intentionally small; it is driven by "ticks" (logical time)
/// and the consensus engine's current view. It decides whether the local
/// leader should attempt a proposal on this tick.
pub trait Pacemaker {
    /// Called once per logical tick. Returns `true` if the local node should
    /// attempt to propose in the current view (assuming it is the leader).
    ///
    /// `engine_view` is the current view as seen by the consensus engine.
    fn on_tick(&mut self, engine_view: u64) -> bool;

    /// Notify the pacemaker that a QC for `qc_view` was observed.
    ///
    /// This can be used to reset internal state when progress is made.
    fn on_qc(&mut self, qc_view: u64);
}

/// A very simple tick-based pacemaker:
/// - Tracks the last view it saw from the engine.
/// - Counts ticks since the last proposal in that view.
/// - Allows at most one proposal per view per `min_ticks_between_proposals`.
#[derive(Debug)]
pub struct BasicTickPacemaker {
    cfg: PacemakerConfig,
    last_view: u64,
    ticks_in_view: u32,
    proposals_in_view: u32,
}

impl BasicTickPacemaker {
    /// Create a new `BasicTickPacemaker` with the given configuration.
    pub fn new(cfg: PacemakerConfig) -> Self {
        BasicTickPacemaker {
            cfg,
            last_view: 0,
            ticks_in_view: 0,
            proposals_in_view: 0,
        }
    }
}

impl Pacemaker for BasicTickPacemaker {
    fn on_tick(&mut self, engine_view: u64) -> bool {
        if engine_view != self.last_view {
            // We moved to a new view: reset counters.
            self.last_view = engine_view;
            self.ticks_in_view = 0;
            self.proposals_in_view = 0;
        }

        self.ticks_in_view = self.ticks_in_view.saturating_add(1);

        // Allow a proposal if:
        // - we haven't proposed yet in this view, AND
        // - we have waited at least min_ticks_between_proposals ticks.
        if self.proposals_in_view == 0 && self.ticks_in_view >= self.cfg.min_ticks_between_proposals {
            self.proposals_in_view = 1;
            true
        } else {
            false
        }
    }

    fn on_qc(&mut self, qc_view: u64) {
        // For now, we only use QC as a hint to reset if we somehow lagged.
        if qc_view > self.last_view {
            self.last_view = qc_view;
            self.ticks_in_view = 0;
            self.proposals_in_view = 0;
        }
    }
}