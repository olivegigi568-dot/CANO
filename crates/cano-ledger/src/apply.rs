//! Ledger apply harness for committed blocks.

use std::collections::BTreeMap;
use std::fmt;

use cano_wire::consensus::BlockProposal;

/// Errors that can occur when applying blocks to the ledger.
#[derive(Debug)]
pub enum LedgerError<BlockIdT> {
    /// New block height is less than the current tip height.
    HeightRegression {
        new_height: u64,
        current_height: u64,
    },
    /// Same height, but conflicting block_id.
    ConflictingBlockAtHeight {
        height: u64,
        existing_block_id: BlockIdT,
        new_block_id: BlockIdT,
    },
}

impl<BlockIdT: fmt::Debug> fmt::Display for LedgerError<BlockIdT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::HeightRegression {
                new_height,
                current_height,
            } => {
                write!(
                    f,
                    "ledger height regression: new_height={}, current_height={}",
                    new_height, current_height
                )
            }
            LedgerError::ConflictingBlockAtHeight {
                height,
                existing_block_id,
                new_block_id,
            } => {
                write!(
                    f,
                    "conflicting block at height {}: existing={:?}, new={:?}",
                    height, existing_block_id, new_block_id
                )
            }
        }
    }
}

impl<BlockIdT: fmt::Debug> std::error::Error for LedgerError<BlockIdT> {}

/// Ledger-side view of a committed block.
#[derive(Clone, Debug)]
pub struct LedgerBlockInfo<BlockIdT> {
    pub block_id: BlockIdT,
    pub height: u64,
    pub proposal: BlockProposal,
}

/// Trait for a ledger that can ingest committed blocks.
pub trait LedgerApply<BlockIdT> {
    type Error;

    /// Apply a committed block to the ledger.
    ///
    /// The block is assumed to be final from consensus. The ledger is
    /// responsible for enforcing height monotonicity and detecting conflicts.
    fn apply_committed_block(
        &mut self,
        height: u64,
        block_id: BlockIdT,
        proposal: &BlockProposal,
    ) -> Result<(), Self::Error>;
}

/// A simple, test-friendly in-memory ledger implementation.
#[derive(Debug, Default)]
pub struct InMemoryLedger<BlockIdT> {
    applied: BTreeMap<u64, LedgerBlockInfo<BlockIdT>>,
    tip_height: Option<u64>,
}

impl<BlockIdT: Clone + Eq> InMemoryLedger<BlockIdT> {
    pub fn new() -> Self {
        Self {
            applied: BTreeMap::new(),
            tip_height: None,
        }
    }

    pub fn len(&self) -> usize {
        self.applied.len()
    }

    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }

    pub fn tip_height(&self) -> Option<u64> {
        self.tip_height
    }

    pub fn get(&self, height: u64) -> Option<&LedgerBlockInfo<BlockIdT>> {
        self.applied.get(&height)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &LedgerBlockInfo<BlockIdT>)> {
        self.applied.iter()
    }
}

impl LedgerApply<[u8; 32]> for InMemoryLedger<[u8; 32]> {
    type Error = LedgerError<[u8; 32]>;

    fn apply_committed_block(
        &mut self,
        height: u64,
        block_id: [u8; 32],
        proposal: &BlockProposal,
    ) -> Result<(), Self::Error> {
        // enforce monotonic height
        if let Some(tip) = self.tip_height {
            if height < tip {
                return Err(LedgerError::HeightRegression {
                    new_height: height,
                    current_height: tip,
                });
            }
        }

        if let Some(existing) = self.applied.get(&height) {
            if existing.block_id != block_id {
                return Err(LedgerError::ConflictingBlockAtHeight {
                    height,
                    existing_block_id: existing.block_id,
                    new_block_id: block_id,
                });
            } else {
                // Idempotent: same block at same height, do nothing.
                return Ok(());
            }
        }

        let info = LedgerBlockInfo {
            block_id,
            height,
            proposal: proposal.clone(),
        };

        self.applied.insert(height, info);
        match self.tip_height {
            Some(tip) => {
                if height > tip {
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