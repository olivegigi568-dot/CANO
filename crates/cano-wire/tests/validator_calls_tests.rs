use cano_wire::validator::{
    OP_REGISTER_VALIDATOR, OP_UPDATE_CONSENSUS_KEY, OP_UPDATE_NETWORK_KEY,
    RegisterValidatorCall, UpdateConsensusKeyCall, UpdateNetworkKeyCall,
};
use cano_wire::io::{WireEncode, WireDecode};
use cano_types::AccountId;

fn dummy_account(id_byte: u8) -> AccountId {
    [id_byte; 32]
}

#[test]
fn register_validator_roundtrip() {
    let call = RegisterValidatorCall {
        version: 1,
        validator_id: dummy_account(0x11),
        owner_keyset_id: dummy_account(0x22),
        consensus_suite_id: 0x01,
        consensus_pk: vec![0xAA, 0xBB, 0xCC],
        network_suite_id: 0x02,
        network_pk: vec![0xDD, 0xEE],
        stake: 1_000_000,
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);

    // First byte should be op_code
    assert_eq!(buf[0], OP_REGISTER_VALIDATOR);

    let mut slice: &[u8] = &buf;
    let decoded = RegisterValidatorCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn update_consensus_key_roundtrip() {
    let call = UpdateConsensusKeyCall {
        version: 1,
        validator_id: dummy_account(0x33),
        new_consensus_suite_id: 0x02,
        new_consensus_pk: vec![1, 2, 3, 4],
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_UPDATE_CONSENSUS_KEY);

    let mut slice: &[u8] = &buf;
    let decoded = UpdateConsensusKeyCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn update_network_key_roundtrip() {
    let call = UpdateNetworkKeyCall {
        version: 1,
        validator_id: dummy_account(0x44),
        new_network_suite_id: 0x03,
        new_network_pk: vec![9, 8, 7],
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_UPDATE_NETWORK_KEY);

    let mut slice: &[u8] = &buf;
    let decoded = UpdateNetworkKeyCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}