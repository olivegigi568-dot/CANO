use std::sync::Arc;

use cano_consensus::{
    hotstuff_decide_and_maybe_record_vote, BlockVerifyConfig, ConsensusNodeError,
    ConsensusStateError, HotStuffState, ValidatorInfo, ValidatorSet, VoteDecision,
};
use cano_crypto::{CryptoError, CryptoProvider, SignatureSuite};
use cano_hash::vote_digest;
use cano_types::Hash32;
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};

/// A test signature suite that verifies signatures by comparing them to the digest.
/// WARNING: This is a simplified implementation for testing purposes ONLY.
/// This approach is cryptographically insecure and MUST NEVER be used in production.
/// Real signature verification would involve cryptographic primitives like
/// ML-DSA or SLH-DSA.
struct EchoSignatureSuite;

impl SignatureSuite for EchoSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, _pk: &[u8], msg_digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError> {
        // TEST ONLY: signature must equal the digest exactly.
        // This is NOT cryptographically secure and exists solely for unit testing.
        if sig == msg_digest {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

struct TestCryptoProvider;

impl CryptoProvider for TestCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        if suite_id == 1 {
            static SUITE: EchoSignatureSuite = EchoSignatureSuite;
            Some(&SUITE)
        } else {
            None
        }
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn cano_crypto::AeadSuite> {
        None
    }
}

fn test_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(TestCryptoProvider)
}

fn small_validator_set() -> ValidatorSet {
    ValidatorSet {
        validators: vec![
            ValidatorInfo {
                validator_id: 0,
                suite_id: 1,
                consensus_pk: vec![0; 32],
                voting_power: 1,
            },
            ValidatorInfo {
                validator_id: 1,
                suite_id: 1,
                consensus_pk: vec![1; 32],
                voting_power: 1,
            },
            ValidatorInfo {
                validator_id: 2,
                suite_id: 1,
                consensus_pk: vec![2; 32],
                voting_power: 1,
            },
        ],
        qc_threshold: 2,
    }
}

fn make_qc_with_signers(
    signer_indices: &[u16],
    block_id: Hash32,
    height: u64,
    round: u64,
) -> QuorumCertificate {
    let max_index = signer_indices.iter().max().copied().unwrap_or(0);
    let bitmap_len = (max_index as usize / 8) + 1;
    let mut signer_bitmap = vec![0u8; bitmap_len];

    let mut signed_votes: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let byte_index = idx as usize / 8;
        let bit_index = idx % 8;
        signer_bitmap[byte_index] |= 1 << bit_index;

        let vote = Vote {
            version: 1,
            chain_id: 42,
            height,
            round,
            step: 0,
            block_id,
            validator_index: idx,
            reserved: 0,
            signature: vec![],
        };
        let digest = vote_digest(&vote);
        signed_votes.push((idx, digest.to_vec()));
    }

    signed_votes.sort_by_key(|(idx, _)| *idx);
    let signatures: Vec<Vec<u8>> = signed_votes.into_iter().map(|(_, sig)| sig).collect();

    QuorumCertificate {
        version: 1,
        chain_id: 42,
        height,
        round,
        step: 0,
        block_id,
        signer_bitmap,
        signatures,
    }
}

fn basic_block_proposal() -> BlockProposal {
    let parent_id = [0xCD; 32];
    let qc = make_qc_with_signers(&[0, 1], parent_id, 9, 2);

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 10,
            round: 3,
            parent_block_id: parent_id,
            payload_hash: [0xCC; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: Some(qc),
        txs: Vec::new(),
    }
}

fn make_block_at_height_with_qc_height(
    block_height: u64,
    block_round: u64,
    qc_height: u64,
) -> BlockProposal {
    let parent_id = [0xCD; 32];
    let qc = make_qc_with_signers(&[0, 1], parent_id, qc_height, 1);

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: block_height,
            round: block_round,
            parent_block_id: parent_id,
            payload_hash: [0xCC; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: Some(qc),
        txs: Vec::new(),
    }
}

#[test]
fn hotstuff_accepts_fresh_proposal_when_lock_is_zero() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    let block = basic_block_proposal();

    let decision =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("decision should succeed");

    match decision {
        VoteDecision::ShouldVote { height, round } => {
            assert_eq!(height, block.header.height);
            assert_eq!(round, block.header.round);
        }
        VoteDecision::Skip => panic!("unexpected Skip"),
    }
}

#[test]
fn hotstuff_rejects_proposal_with_qc_height_below_lock() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    // Lock at height 8
    state.update_lock(8, [0xAA; 32]);

    // Proposal at height 10 with QC height 7 (below lock)
    let block = make_block_at_height_with_qc_height(10, 1, 7);

    let err = hotstuff_decide_and_maybe_record_vote(
        &vs,
        crypto.as_ref(),
        &cfg,
        &mut state,
        &block,
        false,
    )
    .expect_err("proposal with qc below lock should be rejected");

    match err {
        ConsensusNodeError::State(e) => match e {
            ConsensusStateError::StaleHeight {
                current_height,
                requested_height,
            } => {
                assert_eq!(current_height, 8); // locked height
                assert_eq!(requested_height, 7); // qc height
            }
            other => panic!("unexpected state error: {:?}", other),
        },
        other => panic!("unexpected node error: {:?}", other),
    }
}

#[test]
fn hotstuff_accepts_proposal_with_qc_height_equal_to_lock() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    // Lock at height 8
    state.update_lock(8, [0xAA; 32]);

    // Proposal at height 10 with QC height 8 (equal to lock)
    let block = make_block_at_height_with_qc_height(10, 1, 8);

    let decision =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("proposal with qc equal to lock should succeed");

    assert!(matches!(decision, VoteDecision::ShouldVote { .. }));
}

#[test]
fn hotstuff_accepts_proposal_with_qc_height_above_lock() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    // Lock at height 8
    state.update_lock(8, [0xAA; 32]);

    // Proposal at height 10 with QC height 9 (above lock)
    let block = make_block_at_height_with_qc_height(10, 1, 9);

    let decision =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("proposal with qc above lock should succeed");

    assert!(matches!(decision, VoteDecision::ShouldVote { .. }));
}

#[test]
fn hotstuff_double_vote_same_proposal_with_record_fails() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    let block = basic_block_proposal();

    // First vote should succeed
    let decision1 =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("first decision should succeed");
    assert!(matches!(decision1, VoteDecision::ShouldVote { .. }));

    // Second vote on the same proposal with record=true should fail
    let err =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect_err("second vote must be rejected");

    match err {
        ConsensusNodeError::State(e) => match e {
            ConsensusStateError::DoubleVote { height, round } => {
                assert_eq!(height, block.header.height);
                assert_eq!(round, block.header.round);
            }
            other => panic!("unexpected state error: {:?}", other),
        },
        other => panic!("unexpected node error: {:?}", other),
    }
}

#[test]
fn hotstuff_evaluate_without_record_does_not_track_vote() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    let block = basic_block_proposal();

    // First call with record=false should succeed
    let decision1 = hotstuff_decide_and_maybe_record_vote(
        &vs,
        crypto.as_ref(),
        &cfg,
        &mut state,
        &block,
        false,
    )
    .expect("first decision should succeed");
    assert!(matches!(decision1, VoteDecision::ShouldVote { .. }));

    // Second call with record=false should also succeed (no state change)
    let decision2 = hotstuff_decide_and_maybe_record_vote(
        &vs,
        crypto.as_ref(),
        &cfg,
        &mut state,
        &block,
        false,
    )
    .expect("second decision without record should succeed");
    assert!(matches!(decision2, VoteDecision::ShouldVote { .. }));

    // Now call with record=true should succeed (first actual vote)
    let decision3 =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("first recorded decision should succeed");
    assert!(matches!(decision3, VoteDecision::ShouldVote { .. }));
}

#[test]
fn hotstuff_rejects_stale_height() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(15); // state ahead of block
    let block = basic_block_proposal(); // height = 10

    let err = hotstuff_decide_and_maybe_record_vote(
        &vs,
        crypto.as_ref(),
        &cfg,
        &mut state,
        &block,
        false,
    )
    .expect_err("stale block should be rejected");

    match err {
        ConsensusNodeError::State(e) => match e {
            ConsensusStateError::StaleHeight {
                current_height,
                requested_height,
            } => {
                assert_eq!(current_height, 15);
                assert_eq!(requested_height, 10);
            }
            other => panic!("unexpected state error: {:?}", other),
        },
        other => panic!("unexpected node error: {:?}", other),
    }
}

#[test]
fn hotstuff_accepts_proposal_without_qc_when_lock_is_zero() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);

    // Block without QC (genesis-like), justify_qc_height will be 0
    let block = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 10,
            round: 1,
            parent_block_id: [0xAA; 32],
            payload_hash: [0xCC; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: None,
        txs: Vec::new(),
    };

    let decision =
        hotstuff_decide_and_maybe_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block, true)
            .expect("proposal without QC should succeed when lock is 0");

    assert!(matches!(decision, VoteDecision::ShouldVote { .. }));
}

#[test]
fn hotstuff_rejects_proposal_without_qc_when_locked() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = HotStuffState::new_at_height(10);
    state.update_lock(5, [0xBB; 32]);

    // Block without QC, justify_qc_height will be 0, which is < locked_height=5
    let block = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 10,
            round: 1,
            parent_block_id: [0xAA; 32],
            payload_hash: [0xCC; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: None,
        txs: Vec::new(),
    };

    let err = hotstuff_decide_and_maybe_record_vote(
        &vs,
        crypto.as_ref(),
        &cfg,
        &mut state,
        &block,
        false,
    )
    .expect_err("proposal without QC should be rejected when locked");

    match err {
        ConsensusNodeError::State(e) => match e {
            ConsensusStateError::StaleHeight {
                current_height,
                requested_height,
            } => {
                assert_eq!(current_height, 5); // locked height
                assert_eq!(requested_height, 0); // qc height (none)
            }
            other => panic!("unexpected state error: {:?}", other),
        },
        other => panic!("unexpected node error: {:?}", other),
    }
}