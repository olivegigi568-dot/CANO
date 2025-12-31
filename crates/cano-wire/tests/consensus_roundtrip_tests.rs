use cano_wire::consensus::{Vote, QuorumCertificate, BlockProposal, BlockHeader};
use cano_wire::io::{WireEncode, WireDecode};

#[test]
fn roundtrip_vote() {
    let vote = Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let mut encoded = Vec::new();
    vote.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = Vote::decode(&mut input).unwrap();

    assert_eq!(vote, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_qc() {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 1,
        block_id: [0xCD; 32],
        signer_bitmap: vec![0xFF, 0x00, 0xFF, 0x00, 0xAA, 0xBB, 0xCC, 0xDD],
        signatures: vec![
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
            vec![0x06, 0x07, 0x08, 0x09, 0x0A],
        ],
    };

    let mut encoded = Vec::new();
    qc.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = QuorumCertificate::decode(&mut input).unwrap();

    assert_eq!(qc, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_block_proposal_no_qc() {
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
    };

    let mut encoded = Vec::new();
    proposal.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = BlockProposal::decode(&mut input).unwrap();

    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_block_proposal_with_qc_and_txs() {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        signer_bitmap: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
        signatures: vec![
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            vec![0x11, 0x22, 0x33, 0x44, 0x55],
        ],
    };

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            height: 100,
            round: 5,
            parent_block_id: [0x44; 32],
            payload_hash: [0x55; 32],
            proposer_index: 7,
            reserved: 0,
            tx_count: 2,
            timestamp: 9876543210,
        },
        qc: Some(qc),
        txs: vec![
            vec![0x01, 0x02, 0x03],
            vec![0x04, 0x05, 0x06, 0x07],
        ],
    };

    let mut encoded = Vec::new();
    proposal.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = BlockProposal::decode(&mut input).unwrap();

    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}

#[test]
fn vote_encoded_length_ml_dsa_like() {
    // Test Vote with ML-DSA-like sig length (3309 bytes)
    let vote = Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: vec![0x00; 3309], // ML-DSA-like signature
    };

    let mut encoded = Vec::new();
    vote.encode(&mut encoded);

    // Expected length:
    // msg_type: 1 + version: 1 + chain_id: 4 + height: 8 + round: 8 + step: 1 +
    // block_id: 32 + validator_index: 2 + reserved: 2 + sig_len: 2 + sig: 3309
    // = 1 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 2 + 2 + 3309 = 3370
    assert_eq!(encoded.len(), 1 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 2 + 2 + 3309);

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = Vote::decode(&mut input).unwrap();
    assert_eq!(vote, decoded);
}

#[test]
fn qc_encoded_length() {
    // Test QC with bitmap_len = 8, 2 signatures of len 5 each
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 1,
        block_id: [0xCD; 32],
        signer_bitmap: vec![0xFF, 0x00, 0xFF, 0x00, 0xAA, 0xBB, 0xCC, 0xDD], // 8 bytes
        signatures: vec![
            vec![0x01, 0x02, 0x03, 0x04, 0x05], // 5 bytes
            vec![0x06, 0x07, 0x08, 0x09, 0x0A], // 5 bytes
        ],
    };

    let mut encoded = Vec::new();
    qc.encode(&mut encoded);

    // Expected length:
    // msg_type: 1 + version: 1 + chain_id: 4 + height: 8 + round: 8 + step: 1 +
    // block_id: 32 + bitmap_len: 2 + signer_bitmap: 8 + sig_count: 2 +
    // (sig_len: 2 + sig: 5) * 2
    // = 1 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 8 + 2 + (2 + 5) * 2
    // = 67 + 14 = 81
    assert_eq!(encoded.len(), 1 + 1 + 4 + 8 + 8 + 1 + 32 + 2 + 8 + 2 + 14);

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = QuorumCertificate::decode(&mut input).unwrap();
    assert_eq!(qc, decoded);
}