//! Consensus verification logic for the cano post-quantum blockchain.
//!
//! This crate provides pure verification functions for consensus messages:
//! - `verify_vote`: verifies a single Vote signature
//! - `verify_quorum_certificate`: verifies a QuorumCertificate with bitmap and signatures
//! - `verify_block_proposal`: verifies a BlockProposal's structure and embedded QC
//!
//! It also provides a node-level voting decision layer:
//! - `evaluate_proposal_for_vote`: checks if a node should vote for a proposal
//! - `decide_and_record_vote`: evaluates and records the vote in consensus state
//!
//! HotStuff-style locking and commit tracking:
//! - `HotStuffState`: local consensus state with locking and commit tracking
//! - `hotstuff_decide_and_maybe_record_vote`: HotStuff-aware voting decision function
//! - `HotStuffStateEngine`: state machine with QC-based locking and vote accumulation
//! - `BlockNode`: minimal block representation in the HotStuff block tree
//!
//! Consensus networking abstraction:
//! - `ConsensusNetwork`: trait for abstracting network operations
//! - `ConsensusNetworkEvent`: events received from the network
//! - `NetworkError`: error type for network operations
//! - `MockConsensusNetwork`: in-memory mock for testing
//!
//! Consensus engine driver interface:
//! - `ConsensusEngineDriver`: trait for driving a consensus engine
//! - `ConsensusEngineAction`: actions the engine wants performed on the network
//! - `HotStuffDriver`: thin wrapper for running HotStuff via the driver interface
//!
//! Identity types:
//! - `ValidatorId`: canonical validator identity in the consensus layer
//! - `ConsensusNodeId`: type alias for `ValidatorId` used in simulations
//!
//! Single-node simulation harness:
//! - `SingleNodeSim`: minimal harness for testing consensus with MockConsensusNetwork

pub mod adversarial_multi_sim;
pub mod basic_hotstuff_engine;
pub mod block_state;
pub mod driver;
pub mod hotstuff_state_engine;
pub mod ids;
pub mod multi_sim;
pub mod network;
pub mod qc;
pub mod sim;
pub mod validator_set;
pub mod vote_accumulator;

pub use adversarial_multi_sim::{AdversarialMultiNodeSim, InFlightMessage, PartitionConfig};
pub use basic_hotstuff_engine::BasicHotStuffEngine;
pub use block_state::BlockNode;
pub use driver::{ConsensusEngineAction, ConsensusEngineDriver, HotStuffDriver, ToValidatorId, ValidatorContext};
pub use hotstuff_state_engine::HotStuffStateEngine;
pub use ids::{ConsensusNodeId, ValidatorId};
pub use multi_sim::MultiNodeSim;
pub use network::{ConsensusNetwork, ConsensusNetworkEvent, MockConsensusNetwork, NetworkError};
pub use qc::{QcValidationError, QuorumCertificate};
pub use sim::SingleNodeSim;
pub use validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
pub use vote_accumulator::VoteAccumulator;


use cano_crypto::CryptoProvider;
use cano_hash::vote_digest;
use cano_wire::consensus::{BlockProposal, QuorumCertificate as WireQuorumCertificate, Vote};

/// Information about a single consensus validator that the verifier needs.
#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub validator_id: u32,
    pub suite_id: u8,
    pub consensus_pk: Vec<u8>,
    pub voting_power: u64,
}

/// Immutable view of the active validator set used for consensus verification.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    /// Validators indexed by `validator_index` as used in Votes/QCs.
    pub validators: Vec<ValidatorInfo>,
    /// Minimum total voting power required for a QC to be valid (e.g., 2f+1).
    pub qc_threshold: u64,
}

impl ValidatorSet {
    pub fn get(&self, index: u16) -> Option<&ValidatorInfo> {
        self.validators.get(index as usize)
    }
}

/// Errors that can occur during consensus message verification.
#[derive(Debug, Clone)]
pub enum ConsensusVerifyError {
    UnknownValidator(u16),
    UnknownSuite(u8),
    SignatureFailed(u16),
    SignatureError(u16, &'static str),
    InsufficientVotingPower { have: u64, need: u64 },
    BitmapLengthMismatch,
    InconsistentVoteFields,
    BlockHeaderMismatch,
    TxCountOverflow,
    InvalidValue(&'static str),
}

impl std::fmt::Display for ConsensusVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusVerifyError::UnknownValidator(idx) => {
                write!(f, "unknown validator index {}", idx)
            }
            ConsensusVerifyError::UnknownSuite(id) => {
                write!(f, "unknown signature suite id {}", id)
            }
            ConsensusVerifyError::SignatureFailed(idx) => {
                write!(f, "signature verification failed for validator index {}", idx)
            }
            ConsensusVerifyError::SignatureError(idx, msg) => {
                write!(f, "signature error for validator index {}: {}", idx, msg)
            }
            ConsensusVerifyError::InsufficientVotingPower { have, need } => {
                write!(
                    f,
                    "qc does not meet voting power threshold: have {}, need {}",
                    have, need
                )
            }
            ConsensusVerifyError::BitmapLengthMismatch => {
                write!(f, "qc bitmap and signatures length mismatch")
            }
            ConsensusVerifyError::InconsistentVoteFields => {
                write!(
                    f,
                    "qc references inconsistent (height, round, step, block_id) across votes"
                )
            }
            ConsensusVerifyError::BlockHeaderMismatch => {
                write!(f, "block proposal header and QC height/round/parent mismatch")
            }
            ConsensusVerifyError::TxCountOverflow => {
                write!(f, "block proposal exceeds tx count limit")
            }
            ConsensusVerifyError::InvalidValue(msg) => {
                write!(f, "invalid value: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConsensusVerifyError {}

/// Errors related to local consensus state / voting rules.
#[derive(Debug, Clone)]
pub enum ConsensusStateError {
    /// Attempted to vote for an old height.
    StaleHeight {
        current_height: u64,
        requested_height: u64,
    },

    /// Attempted to vote for an old round at the current height.
    StaleRound {
        current_round: u64,
        requested_round: u64,
    },

    /// Attempted to advance round backwards.
    RoundRegression {
        current_round: u64,
        requested_round: u64,
    },

    /// Attempted to vote twice in the same (height, round).
    DoubleVote { height: u64, round: u64 },
}

impl std::fmt::Display for ConsensusStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusStateError::StaleHeight {
                current_height,
                requested_height,
            } => {
                write!(
                    f,
                    "stale height: current {}, requested {}",
                    current_height, requested_height
                )
            }
            ConsensusStateError::StaleRound {
                current_round,
                requested_round,
            } => {
                write!(
                    f,
                    "stale round: current {}, requested {}",
                    current_round, requested_round
                )
            }
            ConsensusStateError::RoundRegression {
                current_round,
                requested_round,
            } => {
                write!(
                    f,
                    "round regression: current {}, requested {}",
                    current_round, requested_round
                )
            }
            ConsensusStateError::DoubleVote { height, round } => {
                write!(f, "double vote at height {}, round {}", height, round)
            }
        }
    }
}

impl std::error::Error for ConsensusStateError {}

/// Errors at the node decision layer, combining verification and local state.
#[derive(Debug, Clone)]
pub enum ConsensusNodeError {
    /// Structural / cryptographic verification failed.
    Verify(ConsensusVerifyError),

    /// Local state (height/round / double-vote) rules failed.
    State(ConsensusStateError),
}

impl std::fmt::Display for ConsensusNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusNodeError::Verify(e) => write!(f, "verify error: {}", e),
            ConsensusNodeError::State(e) => write!(f, "state error: {}", e),
        }
    }
}

impl std::error::Error for ConsensusNodeError {}

/// Outcome of evaluating a BlockProposal for voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteDecision {
    /// The proposal is acceptable; the caller may construct and sign a Vote.
    /// The (height, round) parameters are what should be used for the Vote.
    ShouldVote { height: u64, round: u64 },

    /// Reserved for future use: the proposal is valid, but this node
    /// intentionally skips voting for policy reasons (e.g., liveness tweaks).
    ///
    /// Note: In the current T21 implementation, all non-voting conditions
    /// are expressed as `ConsensusNodeError`. This variant is not currently
    /// returned by any function but is included for forward compatibility.
    Skip,
}

/// Local consensus state for a single node.
///
/// This type does NOT do networking, leader selection, or full HotStuff locking logic.
/// It only enforces basic "no double-vote" and monotonic height/round rules.
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current height this node is working on.
    height: u64,
    /// Current round at this height.
    round: u64,
    /// Last (height, round) at which this node cast a vote, if any.
    last_voted: Option<(u64, u64)>,
}

impl ConsensusState {
    /// Construct a new state at a given height, starting at round 0.
    pub fn new_at_height(height: u64) -> Self {
        ConsensusState {
            height,
            round: 0,
            last_voted: None,
        }
    }

    /// Return the current height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Return the current round.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Advance to a new round at the current height.
    ///
    /// new_round must be >= current round.
    pub fn advance_round(&mut self, new_round: u64) -> Result<(), ConsensusStateError> {
        if new_round < self.round {
            return Err(ConsensusStateError::RoundRegression {
                current_round: self.round,
                requested_round: new_round,
            });
        }
        self.round = new_round;
        Ok(())
    }

    /// Move to a new height, resetting round and last_voted.
    ///
    /// new_height must be >= current height.
    pub fn advance_height(&mut self, new_height: u64) -> Result<(), ConsensusStateError> {
        if new_height < self.height {
            return Err(ConsensusStateError::StaleHeight {
                current_height: self.height,
                requested_height: new_height,
            });
        }
        self.height = new_height;
        self.round = 0;
        self.last_voted = None;
        Ok(())
    }

    /// Check whether this node is allowed to vote at (height, round)
    /// according to basic safety rules:
    ///
    ///  - height must be >= current height,
    ///  - if height == current height, round must be >= current round,
    ///  - must not have already voted in this exact (height, round).
    pub fn can_vote_for(&self, height: u64, round: u64) -> Result<(), ConsensusStateError> {
        // Height monotonicity.
        if height < self.height {
            return Err(ConsensusStateError::StaleHeight {
                current_height: self.height,
                requested_height: height,
            });
        }

        // If same height, enforce round monotonicity.
        if height == self.height && round < self.round {
            return Err(ConsensusStateError::StaleRound {
                current_round: self.round,
                requested_round: round,
            });
        }

        // Prevent double-voting at the same (height, round).
        if let Some((vh, vr)) = self.last_voted {
            if vh == height && vr == round {
                return Err(ConsensusStateError::DoubleVote { height, round });
            }
        }

        Ok(())
    }

    /// Record that we *have* voted at (height, round).
    ///
    /// This should only be called after a successful can_vote_for(height, round).
    pub fn record_vote(&mut self, height: u64, round: u64) -> Result<(), ConsensusStateError> {
        // Reuse the same checks to avoid accidental misuse.
        self.can_vote_for(height, round)?;

        if height > self.height {
            // Moving to a new height: set height and round directly.
            self.height = height;
            self.round = round;
        } else if height == self.height && round > self.round {
            // Same height but higher round: update round.
            self.round = round;
        }

        self.last_voted = Some((height, round));
        Ok(())
    }
}

/// HotStuff-style local consensus state with locking and commit tracking.
///
/// This struct is a stricter extension of ConsensusState:
///  - it tracks last voted (height, round, block_id),
///  - it tracks a locked block and its height,
///  - it tracks the last committed height.
#[derive(Debug, Clone)]
pub struct HotStuffState {
    /// Current height this node is working on (same as ConsensusState).
    height: u64,
    /// Current round at this height.
    round: u64,

    /// Last (height, round, block_id) this node voted for, if any.
    last_voted: Option<(u64, u64, [u8; 32])>,

    /// Locked block and height: we will not vote for proposals
    /// that conflict with this lock.
    locked_height: u64,
    locked_block_id: [u8; 32],

    /// Last committed height (monotonic).
    last_commit_height: u64,
}

impl HotStuffState {
    /// Initialize a new HotStuffState at a given height.
    ///
    /// Initially:
    ///  - round = 0
    ///  - no last_voted
    ///  - locked_height = 0, locked_block_id = [0u8; 32]
    ///  - last_commit_height = 0
    pub fn new_at_height(height: u64) -> Self {
        HotStuffState {
            height,
            round: 0,
            last_voted: None,
            locked_height: 0,
            locked_block_id: [0u8; 32],
            last_commit_height: 0,
        }
    }

    /// Return the current height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Return the current round.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Return the locked height.
    pub fn locked_height(&self) -> u64 {
        self.locked_height
    }

    /// Return the last committed height.
    pub fn last_commit_height(&self) -> u64 {
        self.last_commit_height
    }

    /// Advance to a new round at the current height.
    pub fn advance_round(&mut self, new_round: u64) -> Result<(), ConsensusStateError> {
        if new_round < self.round {
            return Err(ConsensusStateError::RoundRegression {
                current_round: self.round,
                requested_round: new_round,
            });
        }
        self.round = new_round;
        Ok(())
    }

    /// Advance to a new height, resetting round and last_voted.
    pub fn advance_height(&mut self, new_height: u64) -> Result<(), ConsensusStateError> {
        if new_height < self.height {
            return Err(ConsensusStateError::StaleHeight {
                current_height: self.height,
                requested_height: new_height,
            });
        }
        self.height = new_height;
        self.round = 0;
        self.last_voted = None;
        Ok(())
    }

    /// Basic HotStuff-style safety: can we vote for this (height, round, block_id, justify_qc_height)?
    ///
    /// Conditions:
    ///  - height >= current height (no stale height),
    ///  - if height == current height, round >= current round (no stale round),
    ///  - no double-vote at the same (height, round, block_id),
    ///  - justify_qc_height >= locked_height (no lock regression).
    pub fn can_vote_hotstuff(
        &self,
        height: u64,
        round: u64,
        _block_id: [u8; 32],
        justify_qc_height: u64,
    ) -> Result<(), ConsensusStateError> {
        // Height monotonicity
        if height < self.height {
            return Err(ConsensusStateError::StaleHeight {
                current_height: self.height,
                requested_height: height,
            });
        }

        // Round monotonicity at the same height.
        if height == self.height && round < self.round {
            return Err(ConsensusStateError::StaleRound {
                current_round: self.round,
                requested_round: round,
            });
        }

        // Double-vote prevention for same (height, round).
        // We prevent voting twice at the same (height, round) regardless of block_id
        // to maintain BFT safety.
        if let Some((vh, vr, _)) = self.last_voted {
            if vh == height && vr == round {
                return Err(ConsensusStateError::DoubleVote { height, round });
            }
        }

        // HotStuff locking rule: justify QC must not be lower than locked height.
        if justify_qc_height < self.locked_height {
            return Err(ConsensusStateError::StaleHeight {
                current_height: self.locked_height,
                requested_height: justify_qc_height,
            });
        }

        Ok(())
    }

    /// Record that we have voted for this block at (height, round),
    /// and update height/round monotonicity.
    pub fn record_vote_hotstuff(
        &mut self,
        height: u64,
        round: u64,
        block_id: [u8; 32],
    ) -> Result<(), ConsensusStateError> {
        self.can_vote_hotstuff(height, round, block_id, self.locked_height)?;
        self.height = self.height.max(height);
        if height == self.height && round > self.round {
            self.round = round;
        }
        self.last_voted = Some((height, round, block_id));
        Ok(())
    }

    /// Update locked block given a new "lock" at (height, block_id).
    ///
    /// In a 3-chain HotStuff, this is called when we see a QC that justifies
    /// locking a child of the current lock. For T22, we expose a simple setter
    /// with monotonicity.
    pub fn update_lock(&mut self, new_locked_height: u64, new_locked_block_id: [u8; 32]) {
        if new_locked_height > self.locked_height {
            self.locked_height = new_locked_height;
            self.locked_block_id = new_locked_block_id;
        }
    }

    /// Record that blocks up to commit_height have been committed.
    pub fn update_commit_height(&mut self, commit_height: u64) {
        if commit_height > self.last_commit_height {
            self.last_commit_height = commit_height;
        }
    }
}

/// Verify a single Vote:
///  - validator_index must exist in ValidatorSet
///  - suite_id must match the validator's suite_id
///  - signature must verify over vote_digest(vote)
pub fn verify_vote(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    vote: &Vote,
) -> Result<(), ConsensusVerifyError> {
    let vindex = vote.validator_index;
    let vinfo = vs
        .get(vindex)
        .ok_or(ConsensusVerifyError::UnknownValidator(vindex))?;

    let suite = crypto
        .signature_suite(vinfo.suite_id)
        .ok_or(ConsensusVerifyError::UnknownSuite(vinfo.suite_id))?;

    let digest = vote_digest(vote);

    suite
        .verify(&vinfo.consensus_pk, &digest, &vote.signature)
        .map_err(|_e| ConsensusVerifyError::SignatureFailed(vindex))?;

    Ok(())
}

/// Verify a QuorumCertificate:
///  - Use bitmap to determine which validators signed
///  - For each bit set, verify the corresponding signature
///  - Ensure total voting power of valid signatures >= ValidatorSet.qc_threshold
pub fn verify_quorum_certificate(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    qc: &WireQuorumCertificate,
) -> Result<(), ConsensusVerifyError> {
    let mut total_power: u64 = 0;
    let need = vs.qc_threshold;

    // Extract canonical (height, round, step, block_id) from the QC header fields.
    let height = qc.height;
    let round = qc.round;
    let step = qc.step;
    let block_id = qc.block_id;

    // Iterate over all validators, checking bitmap bits.
    let bitmap = &qc.signer_bitmap;
    let sig_entries = &qc.signatures;

    // We expect exactly one signature per bit set.
    // Bitmap length * 8 defines max indices; signatures.len() must equal popcount(bitmap).
    let expected_sigs = bitmap.iter().map(|b| b.count_ones() as usize).sum::<usize>();
    if expected_sigs != sig_entries.len() {
        return Err(ConsensusVerifyError::BitmapLengthMismatch);
    }

    let mut sig_iter = sig_entries.iter();

    for (byte_index, byte) in bitmap.iter().enumerate() {
        if *byte == 0 {
            continue;
        }

        for bit in 0..8 {
            if (byte & (1 << bit)) == 0 {
                continue;
            }
            let vindex = (byte_index as u16) * 8 + (bit as u16);

            let vinfo = vs
                .get(vindex)
                .ok_or(ConsensusVerifyError::UnknownValidator(vindex))?;

            let sig = sig_iter
                .next()
                .ok_or(ConsensusVerifyError::BitmapLengthMismatch)?;

            // Build a Vote-like struct for digest calculation.
            // Use qc.(height, round, step, block_id) + validator_index as the logical Vote.
            // Note: signature field is not used in vote_digest, so we use an empty vec.
            let vote_for_digest = Vote {
                version: qc.version,
                chain_id: qc.chain_id,
                height,
                round,
                step,
                block_id,
                validator_index: vindex,
                reserved: 0,
                signature: Vec::new(),
            };

            let digest = vote_digest(&vote_for_digest);

            let suite = crypto
                .signature_suite(vinfo.suite_id)
                .ok_or(ConsensusVerifyError::UnknownSuite(vinfo.suite_id))?;

            suite
                .verify(&vinfo.consensus_pk, &digest, sig)
                .map_err(|_e| ConsensusVerifyError::SignatureFailed(vindex))?;

            total_power = total_power
                .checked_add(vinfo.voting_power)
                .ok_or(ConsensusVerifyError::InvalidValue("voting power overflow"))?;
        }
    }

    if total_power < need {
        return Err(ConsensusVerifyError::InsufficientVotingPower {
            have: total_power,
            need,
        });
    }

    Ok(())
}

/// Configuration for block proposal verification.
pub struct BlockVerifyConfig {
    /// Maximum number of transactions allowed in a block.
    pub max_tx_count: usize,
}

/// Verify a BlockProposal against:
///  - structural invariants,
///  - an optional parent QC,
///  - the validator set and crypto provider (for QC signatures).
pub fn verify_block_proposal(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    cfg: &BlockVerifyConfig,
    block: &BlockProposal,
) -> Result<(), ConsensusVerifyError> {
    // 1) Basic tx count bound.
    let tx_count = block.txs.len();
    if tx_count > cfg.max_tx_count {
        return Err(ConsensusVerifyError::TxCountOverflow);
    }

    // 2) If QC is present, verify it.
    if let Some(ref qc) = block.qc {
        // Height/round/parent linking checks: QC's block_id should match header's parent_block_id.
        if qc.block_id != block.header.parent_block_id {
            return Err(ConsensusVerifyError::BlockHeaderMismatch);
        }

        verify_quorum_certificate(vs, crypto, qc)?;
    }

    Ok(())
}

/// Evaluate whether this node should vote for the given BlockProposal.
///
/// Semantics as of T21:
///   1. verify_block_proposal(...) must succeed.
///   2. ConsensusState::can_vote_for(header.height, header.round) must succeed.
///   3. If both pass, this returns Ok(VoteDecision::ShouldVote { .. }) and
///      the caller is expected to call ConsensusState::record_vote(..).
///
/// This function does NOT perform signing or IO.
pub fn evaluate_proposal_for_vote(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    cfg: &BlockVerifyConfig,
    state: &ConsensusState,
    block: &BlockProposal,
) -> Result<VoteDecision, ConsensusNodeError> {
    // 1) Structural and QC verification.
    verify_block_proposal(vs, crypto, cfg, block)
        .map_err(ConsensusNodeError::Verify)?;

    let height = block.header.height;
    let round = block.header.round;

    // 2) Local state rules.
    state
        .can_vote_for(height, round)
        .map_err(ConsensusNodeError::State)?;

    Ok(VoteDecision::ShouldVote { height, round })
}

/// Evaluate a proposal and, on success, record the vote in the state.
///
/// This is a convenience wrapper for:
///   - evaluate_proposal_for_vote(...)
///   - ConsensusState::record_vote(...)
pub fn decide_and_record_vote(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    cfg: &BlockVerifyConfig,
    state: &mut ConsensusState,
    block: &BlockProposal,
) -> Result<VoteDecision, ConsensusNodeError> {
    let decision = evaluate_proposal_for_vote(vs, crypto, cfg, state, block)?;

    if let VoteDecision::ShouldVote { height, round } = decision {
        state
            .record_vote(height, round)
            .map_err(ConsensusNodeError::State)?;
    }

    Ok(decision)
}

/// Evaluate a BlockProposal under HotStuff-style locking rules,
/// and optionally record the vote.
///
/// Semantics:
///  1. verify_block_proposal(...) must succeed.
///  2. Extract:
///       - height = block.header.height
///       - round = block.header.round
///       - block_id = block.header.parent_block_id (used as identifier for voting)
///       - justify_qc_height = block.qc.as_ref().map(|qc| qc.height).unwrap_or(0)
///  3. HotStuffState::can_vote_hotstuff(...) must succeed.
///  4. If `record` is true, call HotStuffState::record_vote_hotstuff(...).
pub fn hotstuff_decide_and_maybe_record_vote(
    vs: &ValidatorSet,
    crypto: &dyn CryptoProvider,
    cfg: &BlockVerifyConfig,
    state: &mut HotStuffState,
    block: &BlockProposal,
    record: bool,
) -> Result<VoteDecision, ConsensusNodeError> {
    // 1) structural + QC verification.
    verify_block_proposal(vs, crypto, cfg, block).map_err(ConsensusNodeError::Verify)?;

    let height = block.header.height;
    let round = block.header.round;
    let block_id = block.header.parent_block_id;

    let justify_qc_height = block.qc.as_ref().map(|qc| qc.height).unwrap_or(0);

    // 2) local HotStuff safety.
    state
        .can_vote_hotstuff(height, round, block_id, justify_qc_height)
        .map_err(ConsensusNodeError::State)?;

    // 3) Optionally record the vote.
    if record {
        state
            .record_vote_hotstuff(height, round, block_id)
            .map_err(ConsensusNodeError::State)?;
    }

    Ok(VoteDecision::ShouldVote { height, round })
}