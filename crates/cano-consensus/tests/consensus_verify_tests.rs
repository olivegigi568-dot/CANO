use std::sync::Arc;

use cano_consensus::{
    verify_block_proposal, verify_quorum_certificate, verify_vote, BlockVerifyConfig,
    ConsensusVerifyError, ValidatorInfo, ValidatorSet,
};
use cano_crypto::{CryptoError, CryptoProvider, SignatureSuite};
use cano_hash::vote_digest;
use cano_types::Hash32;
use cano_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};

/// A test signature suite that verifies signatures by comparing them to the digest.
/// NOTE: This is a simplified implementation for testing purposes only.
/// Real signature verification would involve cryptographic primitives like
/// ML-DSA or SLH-DSA, which are not needed for unit testing the consensus logic.
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
        // For testing: signature must equal the digest exactly.
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
            // Return a static reference to the suite
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

fn make_test_vote(validator_index: u16) -> Vote {
    Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 1,
        step: 0, // Prevote
        block_id: [0xAA; 32],
        validator_index,
        reserved: 0,
        signature: vec![],
    }
}

#[test]
fn verify_vote_accepts_valid_signature() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    let mut vote = make_test_vote(1);

    // Compute digest and construct a matching signature.
    let digest = vote_digest(&vote);
    vote.signature = digest.to_vec();

    let res = verify_vote(&vs, crypto.as_ref(), &vote);
    assert!(res.is_ok());
}

#[test]
fn verify_vote_rejects_unknown_validator() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    let mut vote = make_test_vote(99); // Index 99 doesn't exist
    let digest = vote_digest(&vote);
    vote.signature = digest.to_vec();

    let res = verify_vote(&vs, crypto.as_ref(), &vote);
    assert!(matches!(res, Err(ConsensusVerifyError::UnknownValidator(99))));
}

#[test]
fn verify_vote_rejects_invalid_signature() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    let mut vote = make_test_vote(1);
    vote.signature = vec![0xFF; 32]; // Wrong signature

    let res = verify_vote(&vs, crypto.as_ref(), &vote);
    assert!(matches!(res, Err(ConsensusVerifyError::SignatureFailed(1))));
}

fn make_qc_with_signers(signer_indices: &[u16], block_id: Hash32) -> QuorumCertificate {
    // Create bitmap
    let max_index = signer_indices.iter().max().copied().unwrap_or(0);
    let bitmap_len = (max_index as usize / 8) + 1;
    let mut signer_bitmap = vec![0u8; bitmap_len];

    // Collect signatures with their indices for sorting
    let mut signed_votes: Vec<(u16, Vec<u8>)> = Vec::new();

    for &idx in signer_indices {
        let byte_index = idx as usize / 8;
        let bit_index = idx % 8;
        signer_bitmap[byte_index] |= 1 << bit_index;

        // Create vote for this validator and compute its digest
        let vote = Vote {
            version: 1,
            chain_id: 42,
            height: 100,
            round: 1,
            step: 0,
            block_id,
            validator_index: idx,
            reserved: 0,
            signature: vec![],
        };
        let digest = vote_digest(&vote);
        signed_votes.push((idx, digest.to_vec()));
    }

    // Sort signatures in bitmap order (by index)
    signed_votes.sort_by_key(|(idx, _)| *idx);
    let signatures: Vec<Vec<u8>> = signed_votes.into_iter().map(|(_, sig)| sig).collect();

    QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 1,
        step: 0,
        block_id,
        signer_bitmap,
        signatures,
    }
}

#[test]
fn verify_quorum_certificate_accepts_valid_qc() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    // Create QC with 2 valid signatures (indices 0 and 1), which meets threshold of 2
    let qc = make_qc_with_signers(&[0, 1], [0xAA; 32]);

    let res = verify_quorum_certificate(&vs, crypto.as_ref(), &qc);
    assert!(res.is_ok());
}

#[test]
fn verify_quorum_certificate_rejects_insufficient_voting_power() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    // Create QC with only 1 signature (index 0), which doesn't meet threshold of 2
    let qc = make_qc_with_signers(&[0], [0xAA; 32]);

    let res = verify_quorum_certificate(&vs, crypto.as_ref(), &qc);
    assert!(matches!(
        res,
        Err(ConsensusVerifyError::InsufficientVotingPower { have: 1, need: 2 })
    ));
}

#[test]
fn verify_quorum_certificate_rejects_bitmap_mismatch() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    let mut qc = make_qc_with_signers(&[0, 1], [0xAA; 32]);
    // Remove one signature but keep bitmap unchanged
    qc.signatures.pop();

    let res = verify_quorum_certificate(&vs, crypto.as_ref(), &qc);
    assert!(matches!(res, Err(ConsensusVerifyError::BitmapLengthMismatch)));
}

#[test]
fn verify_quorum_certificate_rejects_invalid_signature() {
    let vs = small_validator_set();
    let crypto = test_crypto();

    let mut qc = make_qc_with_signers(&[0, 1], [0xAA; 32]);
    // Corrupt the first signature
    qc.signatures[0] = vec![0xFF; 32];

    let res = verify_quorum_certificate(&vs, crypto.as_ref(), &qc);
    assert!(matches!(res, Err(ConsensusVerifyError::SignatureFailed(_))));
}

fn make_block_proposal(
    parent_block_id: Hash32,
    qc: Option<QuorumCertificate>,
    tx_count: usize,
) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 101,
            round: 1,
            parent_block_id,
            payload_hash: [0xCC; 32],
            proposer_index: 0,
            reserved: 0,
            tx_count: tx_count as u32,
            timestamp: 1234567890,
        },
        qc,
        txs: (0..tx_count).map(|i| vec![i as u8]).collect(),
    }
}

#[test]
fn verify_block_proposal_accepts_valid_proposal_with_qc() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 100 };

    let parent_id = [0xAA; 32];
    let qc = make_qc_with_signers(&[0, 1], parent_id);
    let block = make_block_proposal(parent_id, Some(qc), 5);

    let res = verify_block_proposal(&vs, crypto.as_ref(), &cfg, &block);
    assert!(res.is_ok());
}

#[test]
fn verify_block_proposal_accepts_valid_proposal_without_qc() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 100 };

    let block = make_block_proposal([0xBB; 32], None, 5);

    let res = verify_block_proposal(&vs, crypto.as_ref(), &cfg, &block);
    assert!(res.is_ok());
}

#[test]
fn verify_block_proposal_rejects_tx_count_overflow() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 3 };

    let block = make_block_proposal([0xBB; 32], None, 5); // 5 txs > max 3

    let res = verify_block_proposal(&vs, crypto.as_ref(), &cfg, &block);
    assert!(matches!(res, Err(ConsensusVerifyError::TxCountOverflow)));
}

#[test]
fn verify_block_proposal_rejects_header_mismatch() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 100 };

    let qc_block_id = [0xAA; 32];
    let parent_id = [0xBB; 32]; // Different from QC's block_id
    let qc = make_qc_with_signers(&[0, 1], qc_block_id);
    let block = make_block_proposal(parent_id, Some(qc), 5);

    let res = verify_block_proposal(&vs, crypto.as_ref(), &cfg, &block);
    assert!(matches!(res, Err(ConsensusVerifyError::BlockHeaderMismatch)));
}

#[test]
fn verify_block_proposal_rejects_invalid_qc() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 100 };

    let parent_id = [0xAA; 32];
    // QC with insufficient voting power
    let qc = make_qc_with_signers(&[0], parent_id);
    let block = make_block_proposal(parent_id, Some(qc), 5);

    let res = verify_block_proposal(&vs, crypto.as_ref(), &cfg, &block);
    assert!(matches!(
        res,
        Err(ConsensusVerifyError::InsufficientVotingPower { .. })
    ));
}