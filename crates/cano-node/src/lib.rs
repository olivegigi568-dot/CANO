//! Node-local block pipeline for the cano post-quantum blockchain.
//!
//! This crate integrates:
//!  - cano-wire (BlockProposal, Transaction, WireDecode)
//!  - cano-consensus (ValidatorSet, HotStuffState, BlockVerifyConfig, hotstuff_decide_and_maybe_record_vote)
//!  - cano-runtime (BlockExecutor, BlockExecutionResult)
//!  - cano-ledger (AccountStore)
//!  - cano-crypto (CryptoProvider)
//!
//! Given a BlockProposal, validator set, HotStuffState, CryptoProvider, AccountStore, and BlockExecutor:
//!  1. Verify the block under consensus rules (structural + HotStuff safety).
//!  2. Decode transactions from the proposal.
//!  3. Execute them sequentially using BlockExecutor.
//!  4. Return a structured outcome.
//!
//! No networking, no DAG, no signing or IO.

pub mod consensus_net;
pub mod peer;
pub mod peer_manager;
pub mod secure_channel;

pub use consensus_net::{ConsensusNetAdapter, ConsensusNetError, ConsensusNetEvent};
pub use peer::{Peer, PeerId};
pub use peer_manager::{PeerManager, PeerManagerError};

use std::sync::Arc;

use cano_wire::consensus::BlockProposal;
use cano_wire::tx::Transaction;
use cano_wire::io::WireDecode;
use cano_consensus::{
    ValidatorSet,
    HotStuffState,
    BlockVerifyConfig,
    VoteDecision,
    ConsensusNodeError,
    hotstuff_decide_and_maybe_record_vote,
};
use cano_runtime::{BlockExecutor, BlockExecutionResult};
use cano_ledger::AccountStore;
use cano_crypto::CryptoProvider;

/// Node-level errors that can occur when processing a block.
#[derive(Debug)]
pub enum NodeError {
    /// Consensus verification or HotStuff safety failed.
    Consensus(ConsensusNodeError),

    /// Wire-level decoding of transactions failed.
    Wire(String),

    /// Execution of one or more transactions failed in a fatal way.
    ///
    /// Note: BlockExecutionResult already records per-tx failures. This error
    /// variant is for global, unrecoverable execution errors (e.g., internal
    /// invariants).
    Execution(String),
}

impl From<ConsensusNodeError> for NodeError {
    fn from(e: ConsensusNodeError) -> Self {
        NodeError::Consensus(e)
    }
}

/// Result of applying a single block to local state.
#[derive(Debug)]
pub struct BlockApplyOutcome {
    /// Block height.
    pub height: u64,
    /// Block round.
    pub round: u64,
    /// Block payload hash (used as the block identifier).
    pub block_id: [u8; 32],
    /// Outcome of executing all transactions.
    pub exec_result: BlockExecutionResult,
    /// Whether this node decided it *should* vote for this block.
    pub vote_decision: VoteDecision,
}

/// A minimal node-core that can verify and execute blocks locally.
///
/// This struct does NOT handle networking, leader selection, or DAG.
/// It only provides a deterministic pipeline:
///   BlockProposal -> consensus checks -> transaction decode -> execution.
pub struct Node<S: AccountStore> {
    validator_set: ValidatorSet,
    consensus_state: HotStuffState,
    verify_cfg: BlockVerifyConfig,
    block_executor: BlockExecutor<S>,
    crypto: Arc<dyn CryptoProvider>,
}

impl<S: AccountStore> Node<S> {
    /// Create a new Node with the given validator set, HotStuffState, config, crypto provider,
    /// and a default BlockExecutor.
    pub fn new(
        validator_set: ValidatorSet,
        consensus_state: HotStuffState,
        verify_cfg: BlockVerifyConfig,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Self {
        Node {
            validator_set,
            consensus_state,
            verify_cfg,
            block_executor: BlockExecutor::new(),
            crypto,
        }
    }

    /// Accessors for tests or external code.
    pub fn consensus_state(&self) -> &HotStuffState {
        &self.consensus_state
    }

    pub fn consensus_state_mut(&mut self) -> &mut HotStuffState {
        &mut self.consensus_state
    }

    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Apply a block locally: verify under consensus rules, decode txs, execute them.
    ///
    /// Semantics:
    ///  1) Use HotStuff consensus to decide if this node *would* vote for the block.
    ///     - hotstuff_decide_and_maybe_record_vote(..., record = false)
    ///  2) Decode each tx blob into a Transaction.
    ///  3) Execute the txs sequentially via BlockExecutor.
    ///  4) Return a BlockApplyOutcome with height, round, block_id, execution result, and vote decision.
    ///
    /// This function does NOT:
    ///  - send any network messages,
    ///  - sign votes,
    ///  - update locks or commit heights.
    pub fn apply_block(
        &mut self,
        store: &mut S,
        proposal: &BlockProposal,
    ) -> Result<BlockApplyOutcome, NodeError> {
        // 1) Consensus check: structural + HotStuff safety, but do NOT record vote.
        let vote_decision = hotstuff_decide_and_maybe_record_vote(
            &self.validator_set,
            self.crypto.as_ref(),
            &self.verify_cfg,
            &mut self.consensus_state,
            proposal,
            /* record = */ false,
        ).map_err(NodeError::Consensus)?;

        // 2) Decode txs into Transactions.
        let mut txs = Vec::with_capacity(proposal.txs.len());
        for blob in &proposal.txs {
            let mut slice: &[u8] = blob;
            let tx = Transaction::decode(&mut slice)
                .map_err(|e| NodeError::Wire(format!("failed to decode transaction: {:?}", e)))?;
            if !slice.is_empty() {
                return Err(NodeError::Wire("extra bytes after transaction decode".to_string()));
            }
            txs.push(tx);
        }

        // 3) Execute block via BlockExecutor.
        let exec_result = self
            .block_executor
            .execute_block(store, self.crypto.clone(), &txs);

        // 4) Build outcome.
        let outcome = BlockApplyOutcome {
            height: proposal.header.height,
            round: proposal.header.round,
            block_id: proposal.header.payload_hash,
            exec_result,
            vote_decision,
        };

        Ok(outcome)
    }
}