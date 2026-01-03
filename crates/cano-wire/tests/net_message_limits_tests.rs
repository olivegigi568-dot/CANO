//! Tests for NetMessage size limits.
//!
//! These tests verify that:
//!  - Normal NetMessage encoding succeeds and respects size limits.
//!  - Decoding rejects inputs larger than MAX_NET_MESSAGE_BYTES.

use cano_wire::error::WireError;
use cano_wire::net::{NetMessage, MAX_NET_MESSAGE_BYTES};
use cano_wire::consensus::{Vote, BlockProposal, BlockHeader, QuorumCertificate};

#[test]
fn encode_normal_ping_succeeds_within_limit() {
    let msg = NetMessage::Ping(123);
    let result = msg.encode_to_vec();
    assert!(result.is_ok());
    let bytes = result.unwrap();
    // Ping encoding: 1 byte msg_type + 8 bytes nonce = 9 bytes
    assert_eq!(bytes.len(), 9);
    assert!(bytes.len() <= MAX_NET_MESSAGE_BYTES);
}

#[test]
fn encode_normal_pong_succeeds_within_limit() {
    let msg = NetMessage::Pong(0xDEADBEEF_CAFEBABE);
    let result = msg.encode_to_vec();
    assert!(result.is_ok());
    let bytes = result.unwrap();
    // Pong encoding: 1 byte msg_type + 8 bytes nonce = 9 bytes
    assert_eq!(bytes.len(), 9);
    assert!(bytes.len() <= MAX_NET_MESSAGE_BYTES);
}

#[test]
fn decode_oversized_input_returns_too_large_error() {
    // Create an input vector that exceeds MAX_NET_MESSAGE_BYTES
    let oversized = vec![0u8; MAX_NET_MESSAGE_BYTES + 1];
    let result = NetMessage::decode_from_slice(&oversized);

    assert!(result.is_err());
    match result.unwrap_err() {
        WireError::TooLarge { actual, max } => {
            assert_eq!(actual, MAX_NET_MESSAGE_BYTES + 1);
            assert_eq!(max, MAX_NET_MESSAGE_BYTES);
        }
        other => panic!("expected TooLarge error, got: {:?}", other),
    }
}

#[test]
fn decode_exactly_at_limit_does_not_return_too_large() {
    // Create an input vector exactly at MAX_NET_MESSAGE_BYTES
    // This will fail decoding (invalid message type), but NOT with TooLarge
    let at_limit = vec![0u8; MAX_NET_MESSAGE_BYTES];
    let result = NetMessage::decode_from_slice(&at_limit);

    // The error should be InvalidValue (unknown msg_type), not TooLarge
    assert!(result.is_err());
    match result.unwrap_err() {
        WireError::TooLarge { .. } => {
            panic!("expected non-TooLarge error for input at exactly the limit")
        }
        WireError::InvalidValue(_) => {
            // Expected: 0x00 is not a valid NetMessage type
        }
        other => {
            // Any other error is also acceptable (not TooLarge)
            assert!(!matches!(other, WireError::TooLarge { .. }));
        }
    }
}

#[test]
fn roundtrip_ping_through_encode_decode_helpers() {
    let original = NetMessage::Ping(42);
    let bytes = original.encode_to_vec().expect("encode should succeed");
    let decoded = NetMessage::decode_from_slice(&bytes).expect("decode should succeed");
    assert_eq!(original, decoded);
}

#[test]
fn roundtrip_pong_through_encode_decode_helpers() {
    let original = NetMessage::Pong(0x1234567890ABCDEF);
    let bytes = original.encode_to_vec().expect("encode should succeed");
    let decoded = NetMessage::decode_from_slice(&bytes).expect("decode should succeed");
    assert_eq!(original, decoded);
}

#[test]
fn max_net_message_bytes_is_one_mib() {
    // Verify the constant value
    assert_eq!(MAX_NET_MESSAGE_BYTES, 1024 * 1024);
}

// ============================================================================
// Tests for ConsensusVote and BlockProposal variants
// ============================================================================

#[test]
fn roundtrip_consensus_vote_through_net_message() {
    let vote = Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 5,
        step: 0, // Prevote
        block_id: [0xAB; 32],
        validator_index: 7,
        reserved: 0,
        signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let msg = NetMessage::ConsensusVote(vote.clone());
    let bytes = msg.encode_to_vec().expect("encode should succeed");
    let decoded = NetMessage::decode_from_slice(&bytes).expect("decode should succeed");

    assert_eq!(decoded, NetMessage::ConsensusVote(vote));
}

#[test]
fn roundtrip_block_proposal_through_net_message() {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        height: 99,
        round: 4,
        step: 1, // Precommit
        block_id: [0x33; 32],
        signer_bitmap: vec![0xFF, 0xFF, 0xFF, 0xFF],
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
        signature: vec![],
    };

    let msg = NetMessage::BlockProposal(proposal.clone());
    let bytes = msg.encode_to_vec().expect("encode should succeed");
    let decoded = NetMessage::decode_from_slice(&bytes).expect("decode should succeed");

    assert_eq!(decoded, NetMessage::BlockProposal(proposal));
}

#[test]
fn encode_small_block_proposal_succeeds_within_limit() {
    // Build a small BlockProposal (a few KB)
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
            tx_count: 1,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![vec![0x00; 1024]], // 1 KB transaction
        signature: vec![],
    };

    let msg = NetMessage::BlockProposal(proposal);
    let result = msg.encode_to_vec();
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert!(bytes.len() <= MAX_NET_MESSAGE_BYTES);
}

#[test]
fn encode_oversized_block_proposal_returns_too_large_error() {
    // Build a BlockProposal that exceeds MAX_NET_MESSAGE_BYTES
    // The header + QC overhead is small, so we need a large tx_blob
    let large_tx_blob = vec![0x00; MAX_NET_MESSAGE_BYTES]; // 1 MiB blob

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
            tx_count: 1,
            timestamp: 1234567890,
        },
        qc: None,
        txs: vec![large_tx_blob],
        signature: vec![],
    };

    let msg = NetMessage::BlockProposal(proposal);
    let result = msg.encode_to_vec();

    assert!(result.is_err());
    match result.unwrap_err() {
        WireError::TooLarge { actual, max } => {
            assert!(actual > MAX_NET_MESSAGE_BYTES);
            assert_eq!(max, MAX_NET_MESSAGE_BYTES);
        }
        other => panic!("expected TooLarge error, got: {:?}", other),
    }
}

#[test]
fn mixed_message_sequence_roundtrip() {
    // Create a small Vote for the sequence
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

    // Create a small BlockProposal for the sequence
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

    // A mixed sequence of all message types
    let messages: Vec<NetMessage> = vec![
        NetMessage::Ping(1),
        NetMessage::ConsensusVote(vote),
        NetMessage::BlockProposal(proposal),
        NetMessage::Pong(2),
    ];

    // Roundtrip each message
    for original in messages {
        let bytes = original.encode_to_vec().expect("encode should succeed");
        let decoded = NetMessage::decode_from_slice(&bytes).expect("decode should succeed");
        assert_eq!(original, decoded);
    }
}