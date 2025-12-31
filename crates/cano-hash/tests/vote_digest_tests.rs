use cano_hash::vote_digest;
use cano_wire::consensus::Vote;

fn make_test_vote() -> Vote {
    Vote {
        version: 1,
        chain_id: 42,
        height: 100,
        round: 1,
        step: 0, // Prevote
        block_id: [0xAA; 32],
        validator_index: 5,
        reserved: 0,
        signature: vec![], // Empty signature is fine; digest does not depend on signature
    }
}

#[test]
fn vote_digest_is_stable() {
    let vote = make_test_vote();
    let digest1 = vote_digest(&vote);
    let digest2 = vote_digest(&vote);
    assert_eq!(digest1, digest2);
}

#[test]
fn vote_digest_changes_with_block_id() {
    let vote1 = make_test_vote();
    let mut vote2 = make_test_vote();
    vote2.block_id = [0xBB; 32];

    let digest1 = vote_digest(&vote1);
    let digest2 = vote_digest(&vote2);
    assert_ne!(digest1, digest2);
}

#[test]
fn vote_digest_ignores_signature() {
    let vote1 = make_test_vote();
    let mut vote2 = make_test_vote();
    vote2.signature = vec![0x01, 0x02, 0x03];

    // Digest should be the same since signature is NOT part of the vote digest
    let digest1 = vote_digest(&vote1);
    let digest2 = vote_digest(&vote2);
    assert_eq!(digest1, digest2);
}

#[test]
fn vote_digest_ignores_version() {
    let vote1 = make_test_vote();
    let mut vote2 = make_test_vote();
    vote2.version = 2;

    // Digest should be the same since version is NOT part of the vote digest
    let digest1 = vote_digest(&vote1);
    let digest2 = vote_digest(&vote2);
    assert_eq!(digest1, digest2);
}