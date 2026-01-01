//! Adversarial multi-node simulation harness with fault injection.
//!
//! This module provides a fault-injecting layer on top of `MultiNodeSim` that can simulate:
//! - Message drops
//! - Message duplication
//! - Simple link partitions
//! - Message reordering
//!
//! This stays entirely inside cano-consensus – no cano-node, no TCP.

use std::collections::HashSet;

use crate::driver::{ConsensusEngineAction, ConsensusEngineDriver};
use crate::multi_sim::MultiNodeSim;
use crate::network::{ConsensusNetworkEvent, MockConsensusNetwork, NetworkError};

// ============================================================================
// InFlightMessage
// ============================================================================

/// A scheduled in-flight message between nodes.
#[derive(Debug, Clone)]
pub struct InFlightMessage<Id> {
    /// The source node that sent this message.
    pub from: Id,
    /// The destination node that should receive this message.
    pub to: Id,
    /// The network event to be delivered.
    pub event: ConsensusNetworkEvent<Id>,
}

// ============================================================================
// PartitionConfig
// ============================================================================

/// A simple partition model as a set of blocked directed edges.
///
/// If (from, to) is present in `blocked_links`, messages from `from` to `to` are dropped.
#[derive(Debug, Clone)]
pub struct PartitionConfig<Id>
where
    Id: Eq + std::hash::Hash,
{
    /// If (from, to) is present, messages from `from` to `to` are dropped.
    pub blocked_links: HashSet<(Id, Id)>,
}

impl<Id> Default for PartitionConfig<Id>
where
    Id: Eq + std::hash::Hash,
{
    fn default() -> Self {
        PartitionConfig {
            blocked_links: HashSet::new(),
        }
    }
}

impl<Id> PartitionConfig<Id>
where
    Id: Eq + std::hash::Hash + Copy,
{
    /// Block messages from `from` to `to`.
    pub fn block(&mut self, from: Id, to: Id) {
        self.blocked_links.insert((from, to));
    }

    /// Unblock messages from `from` to `to`.
    pub fn unblock(&mut self, from: Id, to: Id) {
        self.blocked_links.remove(&(from, to));
    }

    /// Check if messages from `from` to `to` are blocked.
    pub fn is_blocked(&self, from: Id, to: Id) -> bool {
        self.blocked_links.contains(&(from, to))
    }
}

// ============================================================================
// AdversarialMultiNodeSim
// ============================================================================

/// A multi-node simulation harness with adversarial fault injection.
///
/// This wraps `MultiNodeSim` and adds:
/// - A vector of in-flight messages
/// - A partition configuration
/// - Simple knobs for drop/duplicate behavior
#[derive(Debug)]
pub struct AdversarialMultiNodeSim<Id, D>
where
    Id: Copy + Eq + std::hash::Hash,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    inner: MultiNodeSim<Id, D>,

    /// Messages that have been produced by drivers but not yet delivered.
    in_flight: Vec<InFlightMessage<Id>>,

    /// Link-level partition configuration.
    partitions: PartitionConfig<Id>,

    /// Drop probability in [0.0, 1.0].
    drop_prob: f32,

    /// Duplication probability in [0.0, 1.0].
    dup_prob: f32,
}

impl<Id, D> AdversarialMultiNodeSim<Id, D>
where
    Id: Copy + Eq + std::hash::Hash,
    D: ConsensusEngineDriver<MockConsensusNetwork<Id>>,
{
    /// Create a new adversarial simulation wrapping an existing `MultiNodeSim`.
    pub fn new(inner: MultiNodeSim<Id, D>) -> Self {
        AdversarialMultiNodeSim {
            inner,
            in_flight: Vec::new(),
            partitions: PartitionConfig::default(),
            drop_prob: 0.0,
            dup_prob: 0.0,
        }
    }

    /// Access the partition configuration for modification.
    pub fn partitions_mut(&mut self) -> &mut PartitionConfig<Id> {
        &mut self.partitions
    }

    /// Set the drop probability (clamped to [0.0, 1.0]).
    pub fn set_drop_prob(&mut self, p: f32) {
        self.drop_prob = p.clamp(0.0, 1.0);
    }

    /// Set the duplication probability (clamped to [0.0, 1.0]).
    pub fn set_dup_prob(&mut self, p: f32) {
        self.dup_prob = p.clamp(0.0, 1.0);
    }

    /// Access the underlying `MultiNodeSim`.
    pub fn inner(&self) -> &MultiNodeSim<Id, D> {
        &self.inner
    }

    /// Mutably access the underlying `MultiNodeSim`.
    pub fn inner_mut(&mut self) -> &mut MultiNodeSim<Id, D> {
        &mut self.inner
    }

    /// One adversarial step:
    /// - Runs all drivers via `inner.step_collect_actions()`
    /// - Translates actions to `InFlightMessage<Id>`
    /// - Applies partitions, drops, and duplication
    /// - Delivers surviving messages into each node's `MockConsensusNetwork.inbound`
    pub fn step_once(&mut self, rng: &mut impl rand::Rng) -> Result<(), NetworkError> {
        use rand::seq::SliceRandom;

        let all_actions = self.inner.step_collect_actions()?;

        // 1) Convert actions to in-flight messages.
        for (from_id, actions) in all_actions {
            for action in actions {
                match action {
                    ConsensusEngineAction::BroadcastProposal(proposal) => {
                        for (&to_id, _net) in self.inner.nets.iter() {
                            if to_id == from_id {
                                continue;
                            }
                            self.in_flight.push(InFlightMessage {
                                from: from_id,
                                to: to_id,
                                event: ConsensusNetworkEvent::IncomingProposal {
                                    from: from_id,
                                    proposal: proposal.clone(),
                                },
                            });
                        }
                    }
                    ConsensusEngineAction::BroadcastVote(vote) => {
                        for (&to_id, _net) in self.inner.nets.iter() {
                            if to_id == from_id {
                                continue;
                            }
                            self.in_flight.push(InFlightMessage {
                                from: from_id,
                                to: to_id,
                                event: ConsensusNetworkEvent::IncomingVote {
                                    from: from_id,
                                    vote: vote.clone(),
                                },
                            });
                        }
                    }
                    ConsensusEngineAction::SendVoteTo { to, vote } => {
                        self.in_flight.push(InFlightMessage {
                            from: from_id,
                            to,
                            event: ConsensusNetworkEvent::IncomingVote {
                                from: from_id,
                                vote,
                            },
                        });
                    }
                    ConsensusEngineAction::Noop => {}
                }
            }
        }

        // 2) Apply partitions, drops, and duplication, then deliver.
        let mut delivered: Vec<InFlightMessage<Id>> = Vec::new();

        for msg in self.in_flight.drain(..) {
            // Partition check
            if self.partitions.is_blocked(msg.from, msg.to) {
                continue;
            }

            // Drop?
            if rng.gen::<f32>() < self.drop_prob {
                continue;
            }

            // Deliver original
            delivered.push(msg.clone());

            // Duplicate?
            if rng.gen::<f32>() < self.dup_prob {
                delivered.push(msg.clone());
            }
        }

        // Simple reordering: shuffle delivered before enqueuing.
        delivered.shuffle(rng);

        // 3) Enqueue into each destination's inbound queue.
        for msg in delivered {
            if let Some(net) = self.inner.nets.get_mut(&msg.to) {
                net.inbound.push_back(msg.event);
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_config_block_and_unblock() {
        let mut config: PartitionConfig<u64> = PartitionConfig::default();

        assert!(!config.is_blocked(1, 2));

        config.block(1, 2);
        assert!(config.is_blocked(1, 2));
        assert!(!config.is_blocked(2, 1)); // Direction matters

        config.unblock(1, 2);
        assert!(!config.is_blocked(1, 2));
    }

    #[test]
    fn partition_config_default_is_empty() {
        let config: PartitionConfig<u64> = PartitionConfig::default();
        assert!(config.blocked_links.is_empty());
    }
}
