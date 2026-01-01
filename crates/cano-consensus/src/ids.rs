//! Identity types for consensus.
//!
//! This module defines canonical identity types used in the consensus layer.
//! These types provide explicit, typed identifiers that can be used to track
//! "who sent this message" across the consensus network layer.

/// A canonical validator identity in the consensus layer.
///
/// This type represents a validator's identity as used in consensus messages
/// and network events. It is distinct from:
/// - `validator_index` (u16) used in Vote/QC for compact wire representation
/// - `PeerId` from cano-node which is a transport-level identifier
///
/// Currently, `ValidatorId` wraps a `u64` and does not include cryptographic
/// verification. A future task will bind this to actual validator keys.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct ValidatorId(pub u64);

impl ValidatorId {
    /// Create a new `ValidatorId` from a raw `u64`.
    pub fn new(id: u64) -> Self {
        ValidatorId(id)
    }

    /// Get the raw `u64` value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for ValidatorId {
    fn from(id: u64) -> Self {
        ValidatorId(id)
    }
}

impl From<ValidatorId> for u64 {
    fn from(id: ValidatorId) -> Self {
        id.0
    }
}

/// Type alias for the consensus node ID.
///
/// When using `MockConsensusNetwork` in tests that model "real validators",
/// prefer `MockConsensusNetwork<ConsensusNodeId>` to make the identity semantics
/// explicit.
///
/// This alias makes it natural to use `ValidatorId` as the network ID type
/// in consensus simulations.
pub type ConsensusNodeId = ValidatorId;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_id_basic_operations() {
        let id1 = ValidatorId::new(42);
        let id2 = ValidatorId(42);
        let id3: ValidatorId = 42.into();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id1.as_u64(), 42);

        let raw: u64 = id1.into();
        assert_eq!(raw, 42);
    }

    #[test]
    fn validator_id_hash_and_ord() {
        use std::collections::HashSet;

        let id1 = ValidatorId::new(1);
        let id2 = ValidatorId::new(2);
        let id3 = ValidatorId::new(1);

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        set.insert(id3);

        assert_eq!(set.len(), 2);
        assert!(id1 < id2);
        assert_eq!(id1, id3);
    }

    #[test]
    fn consensus_node_id_is_validator_id() {
        let vid: ValidatorId = ValidatorId::new(100);
        let cid: ConsensusNodeId = vid;
        assert_eq!(vid, cid);
    }
}
