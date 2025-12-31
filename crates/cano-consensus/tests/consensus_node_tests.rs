use std::sync::Arc;

use cano_consensus::{
    decide_and_record_vote, BlockVerifyConfig, ConsensusNodeError, ConsensusState,
    ConsensusStateError, ConsensusVerifyError, ValidatorInfo, ValidatorSet, VoteDecision,
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

fn make_qc_with_signers(signer_indices: &[u16], block_id: Hash32) -> QuorumCertificate {
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
            height: 9,
            round: 2,
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
        height: 9,
        round: 2,
        step: 0,
        block_id,
        signer_bitmap,
        signatures,
    }
}

fn basic_block_proposal() -> BlockProposal {
    let parent_id = [0xCD; 32];
    let qc = make_qc_with_signers(&[0, 1], parent_id);

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

#[test]
fn decide_and_record_vote_accepts_valid_fresh_proposal() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = ConsensusState::new_at_height(10);
    let block = basic_block_proposal();

    let decision = decide_and_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block)
        .expect("decision should succeed");

    match decision {
        VoteDecision::ShouldVote { height, round } => {
            assert_eq!(height, block.header.height);
            assert_eq!(round, block.header.round);
        }
        VoteDecision::Skip => panic!("unexpected Skip"),
    }

    // State should be updated to last_voted = (10,3).
    assert_eq!(state.height(), 10);
    assert!(state.round() >= 3);
}

#[test]
fn decide_and_record_vote_rejects_stale_height() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = ConsensusState::new_at_height(15); // state ahead of block
    let block = basic_block_proposal(); // height = 10

    let err = decide_and_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block)
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
fn decide_and_record_vote_prevents_double_vote_same_height_round() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };

    let mut state = ConsensusState::new_at_height(10);
    let block = basic_block_proposal();

    // First vote should succeed.
    let decision1 = decide_and_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block)
        .expect("first decision should succeed");
    assert!(matches!(decision1, VoteDecision::ShouldVote { .. }));

    // Second vote on the same (height, round) should fail.
    let err = decide_and_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block)
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
fn decide_and_record_vote_rejects_verify_failure_tx_overflow() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 0 }; // max = 0

    let mut state = ConsensusState::new_at_height(10);
    let mut block = basic_block_proposal();
    block.txs = vec![vec![1, 2, 3]]; // 1 tx > max 0

    let err = decide_and_record_vote(&vs, crypto.as_ref(), &cfg, &mut state, &block)
        .expect_err("verification should fail");

    match err {
        ConsensusNodeError::Verify(e) => match e {
            ConsensusVerifyError::TxCountOverflow => {}
            other => panic!("unexpected verify error: {:?}", other),
        },
        other => panic!("unexpected node error: {:?}", other),
    }
}

#[test]
fn consensus_node_error_display_works() {
    let verify_err = ConsensusNodeError::Verify(ConsensusVerifyError::TxCountOverflow);
    let state_err = ConsensusNodeError::State(ConsensusStateError::DoubleVote {
        height: 5,
        round: 3,
    });

    let verify_msg = format!("{}", verify_err);
    let state_msg = format!("{}", state_err);

    assert!(verify_msg.contains("verify error:"));
    assert!(state_msg.contains("state error:"));
    assert!(state_msg.contains("double vote"));
}