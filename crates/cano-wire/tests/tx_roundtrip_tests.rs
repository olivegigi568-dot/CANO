use cano_wire::tx::{Transaction, TxAccountMeta, TxAuth};
use cano_wire::io::{WireEncode, WireDecode};

#[test]
fn roundtrip_transaction_basic() {
    let tx = Transaction {
        version: 1,
        chain_id: 42,
        payer: [0x11; 32],
        nonce: 12345,
        fee_limit: 100000,
        accounts: vec![
            TxAccountMeta {
                account_id: [0x22; 32],
                flags: 0b00000011, // is_signer + is_writable
                access_hint: 0b00000011, // may_read + may_write
                reserved0: [0, 0],
            },
            TxAccountMeta {
                account_id: [0x33; 32],
                flags: 0b00000001, // is_signer only
                access_hint: 0b00000001, // may_read only
                reserved0: [0, 0],
            },
        ],
        program_id: [0x44; 32],
        call_data: vec![0xAA, 0xBB],
        auths: vec![
            TxAuth {
                account_index: 0,
                suite_id: 1,
                reserved: 0,
                signature: vec![0xCC, 0xDD, 0xEE],
            },
        ],
    };

    let mut encoded = Vec::new();
    tx.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = Transaction::decode(&mut input).unwrap();

    assert_eq!(tx, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_empty_auths_and_accounts() {
    let tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: [0x00; 32],
        nonce: 0,
        fee_limit: 0,
        accounts: vec![],
        program_id: [0xFF; 32],
        call_data: vec![],
        auths: vec![],
    };

    let mut encoded = Vec::new();
    tx.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = Transaction::decode(&mut input).unwrap();

    assert_eq!(tx, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_tx_account_meta() {
    let meta = TxAccountMeta {
        account_id: [0xAB; 32],
        flags: 0x03,
        access_hint: 0x01,
        reserved0: [0x00, 0x00],
    };

    let mut encoded = Vec::new();
    meta.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = TxAccountMeta::decode(&mut input).unwrap();

    assert_eq!(meta, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_tx_auth() {
    let auth = TxAuth {
        account_index: 5,
        suite_id: 2,
        reserved: 0,
        signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };

    let mut encoded = Vec::new();
    auth.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = TxAuth::decode(&mut input).unwrap();

    assert_eq!(auth, decoded);
    assert!(input.is_empty());
}