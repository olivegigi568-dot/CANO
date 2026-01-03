//! BlockStore: A local store for block proposals keyed by block_id.
//!
//! This module provides `BlockStore`, an in-memory storage layer that:
//! - Stores `BlockProposal` objects keyed by their computed `block_id`
//! - Computes `block_id` using the same deterministic derivation as `BasicHotStuffEngine`
//! - Allows retrieval of stored proposals by `block_id`
//!
//! # Design Notes
//!
//! The `BlockStore` uses `derive_block_id_from_header()` to compute block IDs from
//! proposal header fields. This ensures consistency with the consensus layer's
//! block ID derivation.
//!
//! ## Arc<BlockProposal> Sharing
//!
//! Block proposals are stored as `Arc<BlockProposal>` (aliased as `SharedProposal`)
//! to allow zero-copy sharing with other components like the ledger and commit index.
//! This avoids expensive clones of potentially large proposal payloads.
//!
//! ## Limitations (Current Implementation)
//!
//! - **In-memory only**: No disk persistence; all data is lost on restart
//! - **No pruning**: Proposals are never removed; memory grows unbounded
//! - **Local proposals only**: Currently only stores locally broadcast proposals
//! - **No verification**: Proposals are stored without cryptographic verification
//!
//! # Usage
//!
//! ```ignore
//! use cano_node::block_store::BlockStore;
//! use cano_wire::consensus::BlockProposal;
//!
//! let mut store = BlockStore::new();
//!
//! // Store a proposal
//! let proposal: BlockProposal = /* ... */;
//! let block_id = store.store_proposal(&proposal);
//!
//! // Retrieve it later
//! let retrieved = store.get(&block_id);
//! assert!(retrieved.is_some());
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use cano_consensus::ids::ValidatorId;
use cano_wire::consensus::BlockProposal;

// ============================================================================
// SharedProposal type alias
// ============================================================================

/// A shared reference to a `BlockProposal`.
///
/// Using `Arc<BlockProposal>` allows zero-copy sharing of proposals between
/// the block store, commit index, and ledger components.
pub type SharedProposal = Arc<BlockProposal>;

// ============================================================================
// BlockStoreError
// ============================================================================

/// Error type for `BlockStore` operations.
#[derive(Debug, Clone)]
pub enum BlockStoreError {
    /// Attempt to insert a different proposal for the same block_id.
    ///
    /// This indicates a serious consistency error: the same block_id should
    /// always map to an identical proposal.
    ConflictingProposal {
        /// The block_id that caused the conflict.
        block_id: [u8; 32],
        /// The proposer index of the existing proposal.
        existing_proposer: u16,
        /// The proposer index of the new proposal.
        new_proposer: u16,
    },
}

impl fmt::Display for BlockStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockStoreError::ConflictingProposal {
                block_id,
                existing_proposer,
                new_proposer,
            } => {
                write!(
                    f,
                    "conflicting proposal for block_id {:?}: proposals differ (existing_proposer={}, new_proposer={})",
                    block_id, existing_proposer, new_proposer
                )
            }
        }
    }
}

impl std::error::Error for BlockStoreError {}

// ============================================================================
// StoredBlock
// ============================================================================

/// A stored block entry containing the block_id and shared proposal.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    /// The block identifier computed from the proposal header.
    pub block_id: [u8; 32],
    /// The shared reference to the block proposal.
    pub proposal: SharedProposal,
}

// ============================================================================
// BlockStore
// ============================================================================

/// A local in-memory store for block proposals.
///
/// This struct provides a simple key-value store where:
/// - Keys are `[u8; 32]` block IDs (computed from proposal headers)
/// - Values are `SharedProposal` (Arc<BlockProposal>) objects
///
/// The block ID is computed deterministically from the proposal header fields
/// using `derive_block_id_from_header()`, which ensures that:
/// - Both proposer and followers derive the same block_id for the same proposal
/// - Block IDs are unique per (proposer, view, parent_block_id) tuple
#[derive(Debug, Clone)]
pub struct BlockStore {
    /// Internal storage mapping block_id -> StoredBlock
    inner: HashMap<[u8; 32], StoredBlock>,
}

impl Default for BlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore {
    /// Create a new, empty `BlockStore`.
    pub fn new() -> Self {
        BlockStore {
            inner: HashMap::new(),
        }
    }

    /// Derive a block ID from proposal header fields.
    ///
    /// This function uses the same derivation logic as `BasicHotStuffEngine::derive_block_id_from_header()`:
    /// - Bytes 0-7: proposer ID (little-endian u64)
    /// - Bytes 8-15: view/height (little-endian u64)
    /// - Bytes 16-31: first 16 bytes of parent_block_id
    ///
    /// # Arguments
    ///
    /// - `proposer`: The validator ID of the block proposer
    /// - `view`: The view/height of the block
    /// - `parent_block_id`: The parent block's ID
    ///
    /// # Returns
    ///
    /// A 32-byte block ID.
    pub fn derive_block_id_from_header(
        proposer: ValidatorId,
        view: u64,
        parent_block_id: &[u8; 32],
    ) -> [u8; 32] {
        let mut id = [0u8; 32];
        // Encode proposer id in the first 8 bytes
        let proposer_bytes = proposer.0.to_le_bytes();
        id[..8].copy_from_slice(&proposer_bytes);
        // Encode view in bytes 8-15
        let view_bytes = view.to_le_bytes();
        id[8..16].copy_from_slice(&view_bytes);
        // Copy first 16 bytes of parent_block_id for uniqueness
        id[16..32].copy_from_slice(&parent_block_id[..16]);
        id
    }

    /// Compute the block ID for a given proposal.
    ///
    /// This extracts the proposer_index, height, and parent_block_id from the
    /// proposal header and computes the block ID using `derive_block_id_from_header()`.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to compute the ID for
    ///
    /// # Returns
    ///
    /// A 32-byte block ID.
    pub fn compute_block_id(proposal: &BlockProposal) -> [u8; 32] {
        let proposer = ValidatorId::new(proposal.header.proposer_index as u64);
        let view = proposal.header.height;
        let parent_block_id = &proposal.header.parent_block_id;
        Self::derive_block_id_from_header(proposer, view, parent_block_id)
    }

    /// Store a proposal in the block store.
    ///
    /// The block ID is computed automatically from the proposal header.
    /// If a proposal with the same block ID already exists, it will be overwritten.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to store
    ///
    /// # Returns
    ///
    /// The computed block ID for the stored proposal.
    pub fn store_proposal(&mut self, proposal: &BlockProposal) -> [u8; 32] {
        let block_id = Self::compute_block_id(proposal);
        let shared = Arc::new(proposal.clone());
        self.inner.insert(
            block_id,
            StoredBlock {
                block_id,
                proposal: shared,
            },
        );
        block_id
    }

    /// Store a proposal with a pre-computed block ID.
    ///
    /// This method allows storing a proposal with a block ID that was computed
    /// elsewhere (e.g., by the consensus engine). Use this when you already
    /// have the block ID and don't want to recompute it.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The pre-computed block ID
    /// - `proposal`: The block proposal to store
    pub fn store_proposal_with_id(&mut self, block_id: [u8; 32], proposal: &BlockProposal) {
        let shared = Arc::new(proposal.clone());
        self.inner.insert(
            block_id,
            StoredBlock {
                block_id,
                proposal: shared,
            },
        );
    }

    /// Idempotent insert of a proposal into the block store.
    ///
    /// The block ID is computed automatically from the proposal header.
    ///
    /// # Behavior
    ///
    /// - If no proposal exists for the computed block_id, the proposal is inserted.
    /// - If a proposal with the same block_id and identical content already exists,
    ///   this is treated as a no-op and returns `Ok(block_id)`.
    /// - If a proposal with the same block_id but **different** content exists,
    ///   returns `Err(BlockStoreError::ConflictingProposal)`.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to insert
    ///
    /// # Returns
    ///
    /// `Ok(block_id)` on success (including idempotent re-inserts), or
    /// `Err(BlockStoreError::ConflictingProposal)` if the block_id maps to a
    /// different proposal.
    pub fn insert(&mut self, proposal: BlockProposal) -> Result<[u8; 32], BlockStoreError> {
        let block_id = Self::compute_block_id(&proposal);
        let shared = Arc::new(proposal);

        if let Some(existing) = self.inner.get(&block_id) {
            // If the same block_id with an identical proposal is inserted again,
            // treat this as idempotent and return Ok without error.
            if *existing.proposal == *shared {
                return Ok(block_id);
            }

            // If the same block_id maps to a different proposal, this is a serious
            // consistency error.
            return Err(BlockStoreError::ConflictingProposal {
                block_id,
                existing_proposer: existing.proposal.header.proposer_index,
                new_proposer: shared.header.proposer_index,
            });
        }

        // Otherwise, insert normally.
        self.inner.insert(
            block_id,
            StoredBlock {
                block_id,
                proposal: shared,
            },
        );

        Ok(block_id)
    }

    /// Retrieve a stored block entry by its block ID.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The block ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the stored `StoredBlock`, or `None` if not found.
    pub fn get(&self, block_id: &[u8; 32]) -> Option<&StoredBlock> {
        self.inner.get(block_id)
    }

    /// Check if a proposal with the given block ID exists in the store.
    ///
    /// # Arguments
    ///
    /// - `block_id`: The block ID to check
    ///
    /// # Returns
    ///
    /// `true` if a proposal with this ID exists, `false` otherwise.
    pub fn contains(&self, block_id: &[u8; 32]) -> bool {
        self.inner.contains_key(block_id)
    }

    /// Get the number of proposals stored.
    ///
    /// # Returns
    ///
    /// The count of stored proposals.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the store is empty.
    ///
    /// # Returns
    ///
    /// `true` if no proposals are stored, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get an iterator over all stored (block_id, stored_block) pairs.
    ///
    /// # Returns
    ///
    /// An iterator over references to stored entries.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &StoredBlock)> {
        self.inner.iter()
    }

    /// Clear all stored proposals.
    ///
    /// This removes all proposals from the store, freeing memory.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cano_wire::consensus::BlockHeader;

    fn make_test_proposal(proposer_index: u16, height: u64, parent: [u8; 32]) -> BlockProposal {
        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                height,
                round: height,
                parent_block_id: parent,
                payload_hash: [0u8; 32],
                proposer_index,
                reserved: 0,
                tx_count: 0,
                timestamp: 0,
            },
            qc: None,
            txs: vec![],
        }
    }

    #[test]
    fn block_store_new_is_empty() {
        let store = BlockStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn block_store_stores_and_retrieves_proposal() {
        let mut store = BlockStore::new();
        let proposal = make_test_proposal(1, 0, [0u8; 32]);

        let block_id = store.store_proposal(&proposal);

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        assert!(store.contains(&block_id));

        let retrieved = store.get(&block_id);
        assert!(retrieved.is_some());
        let stored = retrieved.unwrap();
        assert_eq!(stored.proposal.header.height, proposal.header.height);
        assert_eq!(stored.proposal.header.proposer_index, proposal.header.proposer_index);
    }

    #[test]
    fn block_store_compute_block_id_matches_derive() {
        let proposal = make_test_proposal(5, 10, [1u8; 32]);

        let computed = BlockStore::compute_block_id(&proposal);
        let derived = BlockStore::derive_block_id_from_header(
            ValidatorId::new(5),
            10,
            &[1u8; 32],
        );

        assert_eq!(computed, derived);
    }

    #[test]
    fn block_store_different_proposals_have_different_ids() {
        let proposal1 = make_test_proposal(1, 0, [0u8; 32]);
        let proposal2 = make_test_proposal(2, 0, [0u8; 32]);
        let proposal3 = make_test_proposal(1, 1, [0u8; 32]);

        let id1 = BlockStore::compute_block_id(&proposal1);
        let id2 = BlockStore::compute_block_id(&proposal2);
        let id3 = BlockStore::compute_block_id(&proposal3);

        assert_ne!(id1, id2, "Different proposers should have different IDs");
        assert_ne!(id1, id3, "Different heights should have different IDs");
        assert_ne!(id2, id3, "All three should be different");
    }

    #[test]
    fn block_store_clear_removes_all() {
        let mut store = BlockStore::new();
        store.store_proposal(&make_test_proposal(1, 0, [0u8; 32]));
        store.store_proposal(&make_test_proposal(2, 1, [0u8; 32]));

        assert_eq!(store.len(), 2);

        store.clear();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn block_store_iter_returns_all_entries() {
        let mut store = BlockStore::new();
        let p1 = make_test_proposal(1, 0, [0u8; 32]);
        let p2 = make_test_proposal(2, 1, [0u8; 32]);

        let id1 = store.store_proposal(&p1);
        let id2 = store.store_proposal(&p2);

        let entries: Vec<_> = store.iter().collect();
        assert_eq!(entries.len(), 2);

        let ids: Vec<_> = entries.iter().map(|(id, _)| **id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }

    #[test]
    fn block_store_store_with_id() {
        let mut store = BlockStore::new();
        let proposal = make_test_proposal(1, 0, [0u8; 32]);
        let custom_id = [42u8; 32];

        store.store_proposal_with_id(custom_id, &proposal);

        assert!(store.contains(&custom_id));
        assert_eq!(store.len(), 1);

        let retrieved = store.get(&custom_id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn block_store_get_nonexistent_returns_none() {
        let store = BlockStore::new();
        let nonexistent = [99u8; 32];

        assert!(store.get(&nonexistent).is_none());
        assert!(!store.contains(&nonexistent));
    }

    #[test]
    fn block_store_overwrite_replaces_proposal() {
        let mut store = BlockStore::new();

        // Store initial proposal
        let p1 = make_test_proposal(1, 0, [0u8; 32]);
        let block_id = store.store_proposal(&p1);
        assert_eq!(store.len(), 1);

        // Store again with same header fields (same block_id)
        let mut p2 = make_test_proposal(1, 0, [0u8; 32]);
        p2.txs = vec![vec![1, 2, 3]]; // Different transactions
        let block_id2 = store.store_proposal(&p2);

        // Should be the same block_id
        assert_eq!(block_id, block_id2);
        // Should still have only one entry
        assert_eq!(store.len(), 1);

        // Should return the newer proposal
        let stored = store.get(&block_id).unwrap();
        assert_eq!(stored.proposal.txs.len(), 1);
    }

    #[test]
    fn derive_block_id_from_header_consistency() {
        // Test that the derivation is consistent with BasicHotStuffEngine's method
        let proposer = ValidatorId::new(42);
        let view = 100u64;
        let parent = [0xABu8; 32];

        let id = BlockStore::derive_block_id_from_header(proposer, view, &parent);

        // Verify the structure:
        // - Bytes 0-7: proposer ID (42 in little-endian)
        let expected_proposer_bytes = 42u64.to_le_bytes();
        assert_eq!(&id[..8], &expected_proposer_bytes);

        // - Bytes 8-15: view (100 in little-endian)
        let expected_view_bytes = 100u64.to_le_bytes();
        assert_eq!(&id[8..16], &expected_view_bytes);

        // - Bytes 16-31: first 16 bytes of parent_block_id
        assert_eq!(&id[16..32], &parent[..16]);
    }
}