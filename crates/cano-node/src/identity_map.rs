//! Identity mapping between transport-level peers and consensus-level validators.
//!
//! This module provides `PeerValidatorMap`, a simple mapping between `PeerId`
//! (transport-level identifier from cano-node) and `ValidatorId` (consensus-level
//! identifier from cano-consensus).
//!
//! # Design Note
//!
//! For now, this is a thin, in-memory map with no cryptographic checks.
//! It exists so we can make the binding explicit and testable. Future tasks
//! will add:
//! - Cryptographic verification that a peer's handshake corresponds to a validator's key
//! - Automatic population of the map during the handshake
//! - Enforcement of the mapping at runtime when processing consensus messages

use std::collections::HashMap;

use cano_consensus::ValidatorId;

use crate::peer::PeerId;

/// Simple mapping between transport-level `PeerId` and consensus-level `ValidatorId`.
///
/// For now this is a thin, in-memory map with no cryptographic checks.
/// It exists so we can make the binding explicit and testable.
///
/// # Example
///
/// ```
/// use cano_node::identity_map::PeerValidatorMap;
/// use cano_node::peer::PeerId;
/// use cano_consensus::ValidatorId;
///
/// let mut map = PeerValidatorMap::new();
/// map.insert(PeerId(1), ValidatorId::new(100));
/// assert_eq!(map.get(&PeerId(1)), Some(ValidatorId::new(100)));
/// ```
#[derive(Debug, Default, Clone)]
pub struct PeerValidatorMap {
    inner: HashMap<PeerId, ValidatorId>,
}

impl PeerValidatorMap {
    /// Create a new empty `PeerValidatorMap`.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a mapping from `PeerId` to `ValidatorId`.
    ///
    /// If the peer was already mapped, the old value is returned.
    pub fn insert(&mut self, peer: PeerId, val: ValidatorId) -> Option<ValidatorId> {
        self.inner.insert(peer, val)
    }

    /// Get the `ValidatorId` for a given `PeerId`, if present.
    pub fn get(&self, peer: &PeerId) -> Option<ValidatorId> {
        self.inner.get(peer).copied()
    }

    /// Remove the mapping for a given `PeerId`.
    ///
    /// Returns the `ValidatorId` that was mapped, if any.
    pub fn remove(&mut self, peer: &PeerId) -> Option<ValidatorId> {
        self.inner.remove(peer)
    }

    /// Check if a `PeerId` is in the map.
    pub fn contains_peer(&self, peer: &PeerId) -> bool {
        self.inner.contains_key(peer)
    }

    /// Return the number of mappings.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over all (PeerId, ValidatorId) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &ValidatorId)> {
        self.inner.iter()
    }

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_validator_map_insert_and_get() {
        let mut map = PeerValidatorMap::new();
        let peer = PeerId(42);
        let validator = ValidatorId::new(100);

        assert!(map.get(&peer).is_none());
        assert!(!map.contains_peer(&peer));

        map.insert(peer, validator);

        assert_eq!(map.get(&peer), Some(validator));
        assert!(map.contains_peer(&peer));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn peer_validator_map_insert_overwrites() {
        let mut map = PeerValidatorMap::new();
        let peer = PeerId(1);
        let val1 = ValidatorId::new(10);
        let val2 = ValidatorId::new(20);

        assert!(map.insert(peer, val1).is_none());
        assert_eq!(map.insert(peer, val2), Some(val1));
        assert_eq!(map.get(&peer), Some(val2));
    }

    #[test]
    fn peer_validator_map_remove() {
        let mut map = PeerValidatorMap::new();
        let peer = PeerId(1);
        let validator = ValidatorId::new(100);

        map.insert(peer, validator);
        assert_eq!(map.remove(&peer), Some(validator));
        assert!(map.get(&peer).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn peer_validator_map_iter() {
        let mut map = PeerValidatorMap::new();
        map.insert(PeerId(1), ValidatorId::new(10));
        map.insert(PeerId(2), ValidatorId::new(20));

        let pairs: Vec<_> = map.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn peer_validator_map_clear() {
        let mut map = PeerValidatorMap::new();
        map.insert(PeerId(1), ValidatorId::new(10));
        map.insert(PeerId(2), ValidatorId::new(20));

        assert!(!map.is_empty());
        map.clear();
        assert!(map.is_empty());
    }
}
