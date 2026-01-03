//! Node↔Ledger integration harness for the cano post-quantum blockchain.
//!
//! This module provides `NodeLedgerHarness<L>`, a harness that wires together:
//! - `NodeHotstuffHarness` (consensus + networking)
//! - A `LedgerApply<[u8; 32]>` implementation (ledger state machine)
//!
//! The harness provides a unified `step_once()` method that:
//! 1. Advances the node (network + consensus)
//! 2. Drains newly committed blocks
//! 3. Applies them to the ledger in order
//!
//! # Usage
//!
//! ```ignore
//! use cano_node::ledger_bridge::{InMemoryNodeLedgerHarness, NodeLedgerHarness};
//! use cano_node::hotstuff_node_sim::NodeHotstuffHarness;
//! use cano_ledger::InMemoryLedger;
//!
//! let node = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg)?;
//! let ledger = InMemoryLedger::<[u8; 32]>::new();
//!
//! let mut harness = InMemoryNodeLedgerHarness::new(node, ledger);
//!
//! // Run simulation steps
//! for _ in 0..100 {
//!     harness.step_once()?;
//! }
//! ```

use crate::consensus_node::NodeCommittedBlock;
use crate::hotstuff_node_sim::{NodeHotstuffHarness, NodeHotstuffHarnessError};

use cano_ledger::{InMemoryLedger, LedgerApply, LedgerError};

// ============================================================================
// Error type: NodeLedgerError
// ============================================================================

/// Integration error that wraps node + ledger failures.
///
/// This error type provides ergonomic propagation of errors from both
/// the `NodeHotstuffHarness` and the ledger implementation.
#[derive(Debug)]
pub enum NodeLedgerError {
    /// Error from the underlying `NodeHotstuffHarness`.
    Node(NodeHotstuffHarnessError),
    /// Error from the ledger implementation.
    Ledger(LedgerError<[u8; 32]>),
}

impl From<NodeHotstuffHarnessError> for NodeLedgerError {
    fn from(e: NodeHotstuffHarnessError) -> Self {
        NodeLedgerError::Node(e)
    }
}

impl From<LedgerError<[u8; 32]>> for NodeLedgerError {
    fn from(e: LedgerError<[u8; 32]>) -> Self {
        NodeLedgerError::Ledger(e)
    }
}

// ============================================================================
// Generic harness: NodeLedgerHarness<L>
// ============================================================================

/// A harness that wires `NodeHotstuffHarness` to any `LedgerApply<[u8; 32]>`.
///
/// This struct provides a unified interface for running consensus and ledger
/// together in tests or simulations.
///
/// # Type Parameter
///
/// - `L`: A ledger implementation that implements `LedgerApply<[u8; 32]>`.
#[derive(Debug)]
pub struct NodeLedgerHarness<L> {
    node: NodeHotstuffHarness,
    ledger: L,
}

impl<L> NodeLedgerHarness<L>
where
    L: LedgerApply<[u8; 32], Error = LedgerError<[u8; 32]>>,
{
    /// Create a new `NodeLedgerHarness` with the given node and ledger.
    pub fn new(node: NodeHotstuffHarness, ledger: L) -> Self {
        Self { node, ledger }
    }

    /// Access the underlying `NodeHotstuffHarness`.
    pub fn node(&self) -> &NodeHotstuffHarness {
        &self.node
    }

    /// Mutably access the underlying `NodeHotstuffHarness`.
    pub fn node_mut(&mut self) -> &mut NodeHotstuffHarness {
        &mut self.node
    }

    /// Access the underlying ledger.
    pub fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Mutably access the underlying ledger.
    pub fn ledger_mut(&mut self) -> &mut L {
        &mut self.ledger
    }

    /// Advance the node (network + consensus), drain newly committed blocks,
    /// and apply them to the ledger in order.
    ///
    /// This method performs the following sequence:
    /// 1. Advance node (network, consensus, commit index, block store)
    /// 2. Drain newly committed blocks at the node level
    /// 3. Apply them to the ledger in order
    ///
    /// # Errors
    ///
    /// Returns `NodeLedgerError::Node` if the node step fails, or
    /// `NodeLedgerError::Ledger` if ledger application fails.
    pub fn step_once(&mut self) -> Result<(), NodeLedgerError> {
        // 1. Advance node (network, consensus, commit index, block store)
        self.node.step_once()?;

        // 2. Drain newly committed blocks at the node level
        let committed: Vec<NodeCommittedBlock<[u8; 32]>> = self.node.drain_committed_blocks()?;

        // 3. Apply them to the ledger in order
        for block in committed {
            self.ledger
                .apply_committed_block(block.height, block.block_id, &block.proposal)?;
        }

        Ok(())
    }
}

// ============================================================================
// Convenience alias for InMemoryLedger
// ============================================================================

/// Type alias for a `NodeLedgerHarness` with an in-memory ledger.
///
/// This makes tests and future devnet code easier to write.
pub type InMemoryNodeLedgerHarness = NodeLedgerHarness<InMemoryLedger<[u8; 32]>>;