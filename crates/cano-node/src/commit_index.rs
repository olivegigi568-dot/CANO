//! Commit index for tracking the canonical committed chain at the node level.
//!
//! This module provides a `CommitIndex` struct that:
//! - Tracks the canonical committed chain view (by height + block id)
//! - Enforces basic invariants:
//!   - Heights are strictly monotonic
//!   - No conflicting block at the same height
//!   - Commit height never regresses
//! - Provides a simple read API for tests and (later) the ledger
//!
//! This is not a full ledger — it's just the consensus-level commit index at the node.

use crate::consensus_node::NodeCommitInfo;
use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// CommitIndexError
// ============================================================================

/// Error type for violations of commit index monotonicity and consistency.
#[derive(Debug)]
pub enum CommitIndexError<BlockIdT> {
    /// New commit has a height less than the current tip height.
    HeightRegression {
        new_height: u64,
        current_height: u64,
    },
    /// There is already a different block committed at this height.
    ConflictingBlock {
        height: u64,
        existing_block_id: BlockIdT,
        new_block_id: BlockIdT,
    },
}

impl<BlockIdT: fmt::Debug> fmt::Display for CommitIndexError<BlockIdT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitIndexError::HeightRegression {
                new_height,
                current_height,
            } => {
                write!(
                    f,
                    "commit index height regression: new={}, current={}",
                    new_height, current_height
                )
            }
            CommitIndexError::ConflictingBlock {
                height,
                existing_block_id,
                new_block_id,
            } => {
                write!(
                    f,
                    "conflicting commit at height {}: existing={:?}, new={:?}",
                    height, existing_block_id, new_block_id
                )
            }
        }
    }
}

// ============================================================================
// CommitIndex
// ============================================================================

/// A generic commit index over block IDs.
///
/// This struct tracks the canonical committed chain at the node level,
/// enforcing monotonicity and consistency invariants.
#[derive(Debug, Default)]
pub struct CommitIndex<BlockIdT> {
    /// Map from height to commit info. We assume at most one block per height.
    commits_by_height: BTreeMap<u64, NodeCommitInfo<BlockIdT>>,
    /// Cached tip height for quick access; None means no commits yet.
    tip_height: Option<u64>,
}

impl<BlockIdT: Clone + Eq> CommitIndex<BlockIdT> {
    /// Create a new empty commit index.
    pub fn new() -> Self {
        Self {
            commits_by_height: BTreeMap::new(),
            tip_height: None,
        }
    }

    /// Remove all commits with height < min_height.
    ///
    /// - Guaranteed not to affect tip_height.
    /// - Safe to call repeatedly with increasing min_height.
    pub fn prune_below(&mut self, min_height: u64) {
        // split_off(min_height) splits the map at the given key:
        // - Returns a new BTreeMap containing all entries with key >= min_height
        // - Leaves entries with key < min_height in the original map
        // We want to keep entries >= min_height, so we reassign to the split_off result.
        self.commits_by_height = self.commits_by_height.split_off(&min_height);
    }

    /// Returns `true` if no commits have been recorded.
    pub fn is_empty(&self) -> bool {
        self.tip_height.is_none()
    }

    /// Returns the number of committed blocks tracked.
    pub fn len(&self) -> usize {
        self.commits_by_height.len()
    }

    /// Returns the current tip (highest committed block), if any.
    pub fn tip(&self) -> Option<&NodeCommitInfo<BlockIdT>> {
        match self.tip_height {
            Some(h) => self.commits_by_height.get(&h),
            None => None,
        }
    }

    /// Returns the commit info at the given height, if any.
    pub fn get(&self, height: u64) -> Option<&NodeCommitInfo<BlockIdT>> {
        self.commits_by_height.get(&height)
    }

    /// Returns an iterator over all commits by ascending height.
    ///
    /// This allows iterating over committed blocks in height order without
    /// modifying the commit index.
    pub fn iter_by_height(&self) -> impl Iterator<Item = (&u64, &NodeCommitInfo<BlockIdT>)> {
        self.commits_by_height.iter()
    }

    /// Apply a batch of new commits, in order, enforcing height monotonicity
    /// and non-conflicting blocks at each height.
    ///
    /// # Errors
    ///
    /// Returns `CommitIndexError::HeightRegression` if a commit has a height
    /// less than the current tip height.
    ///
    /// Returns `CommitIndexError::ConflictingBlock` if a commit has the same
    /// height as an existing commit but a different block ID.
    pub fn apply_commits(
        &mut self,
        commits: impl IntoIterator<Item = NodeCommitInfo<BlockIdT>>,
    ) -> Result<(), CommitIndexError<BlockIdT>> {
        for commit in commits {
            self.apply_single(commit)?;
        }
        Ok(())
    }

    /// Apply a single commit to the index.
    fn apply_single(
        &mut self,
        commit: NodeCommitInfo<BlockIdT>,
    ) -> Result<(), CommitIndexError<BlockIdT>> {
        let height = commit.height;

        // Check for height regression
        if let Some(tip_h) = self.tip_height {
            if height < tip_h {
                return Err(CommitIndexError::HeightRegression {
                    new_height: height,
                    current_height: tip_h,
                });
            }
        }

        // Check for conflicting block at the same height
        if let Some(existing) = self.commits_by_height.get(&height) {
            if existing.block_id != commit.block_id {
                return Err(CommitIndexError::ConflictingBlock {
                    height,
                    existing_block_id: existing.block_id.clone(),
                    new_block_id: commit.block_id.clone(),
                });
            } else {
                // Same block at same height; treat as idempotent
                return Ok(());
            }
        }

        // Insert commit and update tip height if this is the highest so far
        self.commits_by_height.insert(height, commit);
        match self.tip_height {
            Some(tip_h) => {
                if height > tip_h {
                    self.tip_height = Some(height);
                }
            }
            None => {
                self.tip_height = Some(height);
            }
        }

        Ok(())
    }
}