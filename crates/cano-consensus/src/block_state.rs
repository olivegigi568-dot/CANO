//! Block state representation for HotStuff consensus.
//!
//! This module provides a minimal internal representation of blocks in the
//! HotStuff block tree. Each `BlockNode` represents a block with its
//! identifier, view, parent relationship, and justifying QC.
//!
//! # Design Note
//!
//! This is a simplified block representation for T54. It stores only the
//! minimal fields needed for HotStuff locking and commit logic:
//! - Block identifier
//! - View/round number
//! - Parent block reference
//! - Justifying QC (QC that justifies this block)

use crate::qc::QuorumCertificate;

/// A minimal internal node structure representing a block in the HotStuff tree.
///
/// This struct stores the essential information about a block needed for
/// HotStuff consensus operations like locking and commit tracking.
///
/// # Type Parameter
///
/// - `BlockIdT`: The type used to identify blocks. Must implement `Eq + Hash + Clone`.
///   The canonical type in cano-consensus is `[u8; 32]`.
#[derive(Debug, Clone)]
pub struct BlockNode<BlockIdT> {
    /// Unique identifier for this block.
    pub id: BlockIdT,
    /// View / round / height at which this block was proposed.
    pub view: u64,
    /// Parent block identifier, if any. Genesis blocks have no parent.
    pub parent_id: Option<BlockIdT>,
    /// QC that justifies this block (the QC for its parent).
    /// This may be None for genesis or early blocks.
    pub justify_qc: Option<QuorumCertificate<BlockIdT>>,
    /// QC formed *for this block* (when votes reach quorum).
    /// This is set when a QC is formed that references this block.
    pub own_qc: Option<QuorumCertificate<BlockIdT>>,
    /// Height of this block in the chain from genesis.
    pub height: u64,
}

impl<BlockIdT: Clone> BlockNode<BlockIdT> {
    /// Create a new `BlockNode` with the given fields.
    ///
    /// The `own_qc` field is initialized to `None`. It will be set when
    /// a QC is formed for this block.
    pub fn new(
        id: BlockIdT,
        view: u64,
        parent_id: Option<BlockIdT>,
        justify_qc: Option<QuorumCertificate<BlockIdT>>,
        height: u64,
    ) -> Self {
        BlockNode {
            id,
            view,
            parent_id,
            justify_qc,
            own_qc: None,
            height,
        }
    }
}