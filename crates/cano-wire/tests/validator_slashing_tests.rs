use cano_wire::validator::{SlashingProofCall, ProofKind, OP_REPORT_CONSENSUS_EQUIVOCATION};
use cano_wire::io::{WireEncode, WireDecode};

#[test]
fn roundtrip_slashing_proof_call_double_precommit() {
    let proof = SlashingProofCall {
        proof_kind: ProofKind::DoublePrecommit,
        height: 42,
        round: 7,
        step: 1,
        validator_index: 3,
        vote1: vec![0x01, 0x02],
        vote2: vec![0x03, 0x04, 0x05],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    // Verify the op_code byte
    assert_eq!(encoded[0], OP_REPORT_CONSENSUS_EQUIVOCATION);
    // Verify the proof_kind byte
    assert_eq!(encoded[1], ProofKind::DoublePrecommit as u8);

    let mut input = encoded.as_slice();
    let decoded = SlashingProofCall::decode(&mut input).unwrap();

    assert_eq!(proof, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_slashing_proof_call_double_prevote() {
    let proof = SlashingProofCall {
        proof_kind: ProofKind::DoublePrevote,
        height: 100,
        round: 10,
        step: 0,
        validator_index: 15,
        vote1: vec![0xAA, 0xBB, 0xCC],
        vote2: vec![0xDD, 0xEE],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    // Verify the proof_kind byte
    assert_eq!(encoded[1], ProofKind::DoublePrevote as u8);

    let mut input = encoded.as_slice();
    let decoded = SlashingProofCall::decode(&mut input).unwrap();

    assert_eq!(proof, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_slashing_proof_call_empty_votes() {
    let proof = SlashingProofCall {
        proof_kind: ProofKind::DoublePrevote,
        height: 0,
        round: 0,
        step: 0,
        validator_index: 0,
        vote1: vec![],
        vote2: vec![],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = SlashingProofCall::decode(&mut input).unwrap();

    assert_eq!(proof, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_slashing_proof_call_large_values() {
    let proof = SlashingProofCall {
        proof_kind: ProofKind::DoublePrecommit,
        height: u64::MAX,
        round: u64::MAX,
        step: 255,
        validator_index: u16::MAX,
        vote1: vec![0xFF; 100],
        vote2: vec![0xAA; 200],
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = SlashingProofCall::decode(&mut input).unwrap();

    assert_eq!(proof, decoded);
    assert!(input.is_empty());
}

#[test]
fn slashing_proof_call_encoded_length() {
    let proof = SlashingProofCall {
        proof_kind: ProofKind::DoublePrecommit,
        height: 42,
        round: 7,
        step: 1,
        validator_index: 3,
        vote1: vec![0x01, 0x02],       // 2 bytes
        vote2: vec![0x03, 0x04, 0x05], // 3 bytes
    };

    let mut encoded = Vec::new();
    proof.encode(&mut encoded);

    // Expected length:
    // op_code: 1 + proof_kind: 1 + reserved0: 2 + height: 8 + round: 8 + step: 1 +
    // reserved1: 7 + validator_index: 2 + reserved2: 2 + vote1_len: 2 + vote2_len: 2 +
    // vote1: 2 + vote2: 3
    // = 1+1+2+8+8+1+7+2+2+2+2+2+3 = 41
    assert_eq!(encoded.len(), 1 + 1 + 2 + 8 + 8 + 1 + 7 + 2 + 2 + 2 + 2 + 2 + 3);

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = SlashingProofCall::decode(&mut input).unwrap();
    assert_eq!(proof, decoded);
}

#[test]
fn proof_kind_values() {
    // Verify the proof_kind enum values match the spec
    assert_eq!(ProofKind::DoublePrevote as u8, 0x01);
    assert_eq!(ProofKind::DoublePrecommit as u8, 0x02);
}