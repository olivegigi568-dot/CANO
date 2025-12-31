use cano_hash::{tx_sign_body_preimage, tx_digest};
use cano_wire::tx::{Transaction, TxAccountMeta, TxAuth};

fn make_test_transaction() -> Transaction {
    Transaction {
        version: 1,
        chain_id: 42,
        payer: [1; 32],
        nonce: 7,
        fee_limit: 1000,
        accounts: vec![
            TxAccountMeta {
                account_id: [0x22; 32],
                flags: 0b00000011, // is_signer + is_writable
                access_hint: 0b00000011, // may_read + may_write
                reserved0: [0, 0],
            },
        ],
        program_id: [0x44; 32],
        call_data: vec![0xAA, 0xBB],
        auths: vec![],
    }
}

#[test]
fn tx_sign_body_preimage_is_stable() {
    let tx = make_test_transaction();
    let preimage1 = tx_sign_body_preimage(&tx);
    let preimage2 = tx_sign_body_preimage(&tx);
    assert_eq!(preimage1, preimage2);
}

#[test]
fn tx_digest_is_stable() {
    let tx = make_test_transaction();
    let digest1 = tx_digest(&tx);
    let digest2 = tx_digest(&tx);
    assert_eq!(digest1, digest2);
}

#[test]
fn tx_digest_changes_with_nonce() {
    let tx1 = make_test_transaction();
    let mut tx2 = make_test_transaction();
    tx2.nonce = 8;

    let digest1 = tx_digest(&tx1);
    let digest2 = tx_digest(&tx2);
    assert_ne!(digest1, digest2);
}

#[test]
fn tx_digest_ignores_auths() {
    let tx1 = make_test_transaction();
    let mut tx2 = make_test_transaction();
    tx2.auths = vec![
        TxAuth {
            account_index: 0,
            suite_id: 1,
            reserved: 0,
            signature: vec![0xCC, 0xDD, 0xEE],
        },
    ];

    // Digest should be the same since auths are NOT part of the sign body
    let digest1 = tx_digest(&tx1);
    let digest2 = tx_digest(&tx2);
    assert_eq!(digest1, digest2);
}