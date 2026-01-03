//! Tests for signing preimage helpers on Vote and BlockProposal.
//!
//! These tests verify:
//! - signing_preimage() excludes the signature field
//! - signing_preimage() produces stable output for fixed inputs
//! - Changing signature does not change the preimage

use cano_wire::consensus::{
    BlockHeader, BlockProposal, QuorumCertificate, Vote,
    VOTE_DOMAIN_TAG, PROPOSAL_DOMAIN_TAG,
};

// ============================================================================
// Vote signing preimage tests
// ============================================================================

/// Helper to create a dummy Vote for testing.
fn make_dummy_vote() -> Vote {
    Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    }
}

#[test]
fn vote_signing_preimage_excludes_signature() {
    // Build a Vote with non-empty signature bytes
    let sig = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let vote = Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: sig.clone(),
    };

    // Call signing_preimage()
    let preimage = vote.signing_preimage();

    // Assert that the resulting bytes do not contain the exact signature byte sequence
    let found = preimage.windows(sig.len()).any(|w| w == sig.as_slice());
    assert!(
        !found,
        "signing_preimage() should not contain the exact signature bytes"
    );

    // Also assert that changing the signature field does not change the preimage
    let mut vote2 = vote.clone();
    vote2.signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let preimage2 = vote2.signing_preimage();
    assert_eq!(
        preimage, preimage2,
        "Changing signature should not change the preimage"
    );

    // And a vote with empty signature should produce the same preimage
    let mut vote3 = vote.clone();
    vote3.signature = vec![];
    let preimage3 = vote3.signing_preimage();
    assert_eq!(
        preimage, preimage3,
        "Empty signature should produce the same preimage"
    );
}

#[test]
fn vote_signing_preimage_stable_for_fields() {
    // Create a Vote with fixed field values and empty signature
    let vote = Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: vec![],
    };

    // Call signing_preimage() and compare to expected
    let preimage = vote.signing_preimage();

    // Build expected preimage manually:
    // domain_tag: "CANO:VOTE:v1" (12 bytes)
    // version: u8 (1)
    // chain_id: u32 LE (42)
    // height: u64 LE (100)
    // round: u64 LE (5)
    // step: u8 (0)
    // block_id: [0xAB; 32]
    // validator_index: u16 LE (7)
    // reserved: u16 LE (0)
    let mut expected = Vec::new();
    expected.extend_from_slice(VOTE_DOMAIN_TAG); // 12 bytes: "CANO:VOTE:v1"
    expected.push(1u8); // version
    expected.extend_from_slice(&42u32.to_le_bytes()); // chain_id
    expected.extend_from_slice(&100u64.to_le_bytes()); // height
    expected.extend_from_slice(&5u64.to_le_bytes()); // round
    expected.push(0u8); // step
    expected.extend_from_slice(&[0xAB; 32]); // block_id
    expected.extend_from_slice(&7u16.to_le_bytes()); // validator_index
    expected.extend_from_slice(&0u16.to_le_bytes()); // reserved

    assert_eq!(
        preimage, expected,
        "Vote signing preimage does not match expected layout"
    );

    // Hard-coded expected bytes for stability test (captured from a known-good implementation)
    // This ensures the preimage structure doesn't accidentally change
    let expected_bytes: Vec<u8> = vec![
        // "CANO:VOTE:v1"
        0x43, 0x41, 0x4e, 0x4f, 0x3a, 0x56, 0x4f, 0x54, 0x45, 0x3a, 0x76, 0x31,
        // version: 1
        0x01,
        // chain_id: 42 (LE)
        0x2a, 0x00, 0x00, 0x00,
        // height: 100 (LE)
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // round: 5 (LE)
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // step: 0
        0x00,
        // block_id: [0xAB; 32]
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        // validator_index: 7 (LE)
        0x07, 0x00,
        // reserved: 0 (LE)
        0x00, 0x00,
    ];
    assert_eq!(
        preimage, expected_bytes,
        "Vote signing preimage bytes do not match hard-coded expected value"
    );
}

#[test]
fn vote_signing_preimage_starts_with_domain_tag() {
    let vote = make_dummy_vote();
    let preimage = vote.signing_preimage();

    assert!(
        preimage.starts_with(VOTE_DOMAIN_TAG),
        "Vote signing preimage must start with domain tag"
    );
}

#[test]
fn vote_signing_preimage_length_is_correct() {
    let vote = make_dummy_vote();
    let preimage = vote.signing_preimage();

    // Expected length:
    // domain_tag: 12 bytes ("CANO:VOTE:v1")
    // version: 1
    // chain_id: 4
    // height: 8
    // round: 8
    // step: 1
    // block_id: 32
    // validator_index: 2
    // reserved: 2
    // Total: 12 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 2 = 70
    let expected_len = 12 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 2;
    assert_eq!(preimage.len(), expected_len);
}

// ============================================================================
// BlockProposal signing preimage tests
// ============================================================================

/// Helper to create a dummy BlockProposal for testing.
fn make_dummy_block_proposal() -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![],
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

/// Helper to create a BlockProposal with a QC.
fn make_proposal_with_qc() -> BlockProposal {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        signer_bitmap: vec![0xFF, 0x00],
        signatures: vec![vec![0xAA, 0xBB]],
    };

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            reserved: 0,
            tx_count: 2,
            timestamp: 1234567890,
        },
        qc: Some(qc),
        txs: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
        signature: vec![0xDE, 0xAD],
    }
}

#[test]
fn proposal_signing_preimage_excludes_signature() {
    // Build a BlockProposal with non-empty signature bytes
    let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut proposal = make_dummy_block_proposal();
    proposal.signature = sig.clone();

    // Call signing_preimage()
    let preimage = proposal.signing_preimage();

    // Assert that the resulting bytes do not contain the exact signature byte sequence
    let found = preimage.windows(sig.len()).any(|w| w == sig.as_slice());
    assert!(
        !found,
        "signing_preimage() should not contain the exact signature bytes"
    );

    // Also assert that changing the signature field does not change the preimage
    let mut proposal2 = proposal.clone();
    proposal2.signature = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let preimage2 = proposal2.signing_preimage();
    assert_eq!(
        preimage, preimage2,
        "Changing signature should not change the preimage"
    );

    // And a proposal with empty signature should produce the same preimage
    let mut proposal3 = proposal.clone();
    proposal3.signature = vec![];
    let preimage3 = proposal3.signing_preimage();
    assert_eq!(
        preimage, preimage3,
        "Empty signature should produce the same preimage"
    );
}

#[test]
fn proposal_signing_preimage_stable_for_fields() {
    // Create a BlockProposal with fixed field values and empty signature, no QC, no txs
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            reserved: 0,
            tx_count: 0,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    // Call signing_preimage()
    let preimage = proposal.signing_preimage();

    // Build expected preimage manually:
    // domain_tag: "CANO:PROPOSAL:v1" (16 bytes)
    // version: u8 (1)
    // chain_id: u32 LE (42)
    // height: u64 LE (100)
    // round: u64 LE (5)
    // parent_block_id: [0x11; 32]
    // payload_hash: [0x22; 32]
    // proposer_index: u16 LE (3)
    // reserved: u16 LE (0)
    // tx_count: u32 LE (0)
    // timestamp: u64 LE (1234567890)
    // qc_len: u32 LE (0)
    // (no qc_bytes)
    // (no txs)
    let mut expected = Vec::new();
    expected.extend_from_slice(PROPOSAL_DOMAIN_TAG); // 16 bytes
    expected.push(1u8); // version
    expected.extend_from_slice(&42u32.to_le_bytes()); // chain_id
    expected.extend_from_slice(&100u64.to_le_bytes()); // height
    expected.extend_from_slice(&5u64.to_le_bytes()); // round
    expected.extend_from_slice(&[0x11; 32]); // parent_block_id
    expected.extend_from_slice(&[0x22; 32]); // payload_hash
    expected.extend_from_slice(&3u16.to_le_bytes()); // proposer_index
    expected.extend_from_slice(&0u16.to_le_bytes()); // reserved
    expected.extend_from_slice(&0u32.to_le_bytes()); // tx_count
    expected.extend_from_slice(&1234567890u64.to_le_bytes()); // timestamp
    expected.extend_from_slice(&0u32.to_le_bytes()); // qc_len = 0

    assert_eq!(
        preimage, expected,
        "BlockProposal signing preimage does not match expected layout"
    );

    // Hard-coded expected bytes for stability test (captured from a known-good implementation)
    // This ensures the preimage structure doesn't accidentally change
    let expected_bytes: Vec<u8> = vec![
        // "CANO:PROPOSAL:v1"
        0x43, 0x41, 0x4e, 0x4f, 0x3a, 0x50, 0x52, 0x4f, 0x50, 0x4f, 0x53, 0x41, 0x4c, 0x3a, 0x76, 0x31,
        // version: 1
        0x01,
        // chain_id: 42 (LE)
        0x2a, 0x00, 0x00, 0x00,
        // height: 100 (LE)
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // round: 5 (LE)
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // parent_block_id: [0x11; 32]
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        // payload_hash: [0x22; 32]
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        // proposer_index: 3 (LE)
        0x03, 0x00,
        // reserved: 0 (LE)
        0x00, 0x00,
        // tx_count: 0 (LE)
        0x00, 0x00, 0x00, 0x00,
        // timestamp: 1234567890 (LE)
        0xd2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00,
        // qc_len: 0 (LE)
        0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        preimage, expected_bytes,
        "BlockProposal signing preimage bytes do not match hard-coded expected value"
    );
}

#[test]
fn proposal_signing_preimage_starts_with_domain_tag() {
    let proposal = make_dummy_block_proposal();
    let preimage = proposal.signing_preimage();

    assert!(
        preimage.starts_with(PROPOSAL_DOMAIN_TAG),
        "BlockProposal signing preimage must start with domain tag"
    );
}

#[test]
fn proposal_signing_preimage_includes_qc_and_txs() {
    // Create proposal with QC and transactions
    let proposal = make_proposal_with_qc();
    let preimage = proposal.signing_preimage();

    // The preimage should include QC bytes and transaction bytes
    // We verify this by checking the length is larger than a proposal without QC/txs
    let proposal_no_qc = make_dummy_block_proposal();
    let preimage_no_qc = proposal_no_qc.signing_preimage();

    assert!(
        preimage.len() > preimage_no_qc.len(),
        "Proposal with QC and txs should have larger preimage"
    );

    // Verify the preimage still starts with domain tag
    assert!(preimage.starts_with(PROPOSAL_DOMAIN_TAG));
}

#[test]
fn proposal_signing_preimage_length_no_qc_no_txs() {
    let proposal = make_dummy_block_proposal();
    let preimage = proposal.signing_preimage();

    // Expected length (no QC, no txs):
    // domain_tag: 16 bytes ("CANO:PROPOSAL:v1")
    // version: 1
    // chain_id: 4
    // height: 8
    // round: 8
    // parent_block_id: 32
    // payload_hash: 32
    // proposer_index: 2
    // reserved: 2
    // tx_count: 4
    // timestamp: 8
    // qc_len: 4
    // Total: 16 + 1 + 4 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 4 = 121
    let expected_len = 16 + 1 + 4 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 4;
    assert_eq!(preimage.len(), expected_len);
}

#[test]
fn proposal_signing_preimage_different_txs_produce_different_preimages() {
    let mut proposal1 = make_dummy_block_proposal();
    proposal1.txs = vec![vec![0x01, 0x02, 0x03]];
    proposal1.header.tx_count = 1;

    let mut proposal2 = make_dummy_block_proposal();
    proposal2.txs = vec![vec![0x04, 0x05, 0x06]];
    proposal2.header.tx_count = 1;

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different transactions should produce different preimages"
    );
}

#[test]
fn proposal_signing_preimage_different_qcs_produce_different_preimages() {
    let qc1 = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA]],
    };

    let qc2 = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x44; 32], // Different block_id
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA]],
    };

    let mut proposal1 = make_dummy_block_proposal();
    proposal1.qc = Some(qc1);

    let mut proposal2 = make_dummy_block_proposal();
    proposal2.qc = Some(qc2);

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different QCs should produce different preimages"
    );
}