use cano_types::Hash32;
use cano_wire::tx::{Transaction, TxAccountMeta};
use cano_wire::io::{put_u8, put_u16, put_u32, put_u64, put_bytes, len_to_u16, len_to_u32};
use crate::hash::sha3_256_tagged;

/// Compute the canonical TxSignBody preimage according to the wire spec.
/// This does NOT include msg_type or auths[].
pub fn tx_sign_body_preimage(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();

    // version
    put_u8(&mut out, tx.version);
    // chain_id
    put_u32(&mut out, tx.chain_id);
    // payer
    put_bytes(&mut out, &tx.payer);
    // nonce
    put_u64(&mut out, tx.nonce);
    // fee_limit
    put_u64(&mut out, tx.fee_limit);

    // accounts
    let account_count = tx.accounts.len();
    let account_count_u16 = len_to_u16(account_count);
    put_u16(&mut out, account_count_u16);
    for meta in &tx.accounts {
        encode_account_meta(&mut out, meta);
    }

    // program_id
    put_bytes(&mut out, &tx.program_id);

    // call_data
    let call_len = tx.call_data.len();
    let call_len_u32 = len_to_u32(call_len);
    put_u32(&mut out, call_len_u32);
    put_bytes(&mut out, &tx.call_data);

    out
}

/// Helper: encode TxAccountMeta in the same order as its wire format.
fn encode_account_meta(out: &mut Vec<u8>, meta: &TxAccountMeta) {
    put_bytes(out, &meta.account_id);
    put_u8(out, meta.flags);
    put_u8(out, meta.access_hint);
    put_bytes(out, &meta.reserved0);
}

/// Canonical tx_digest = SHA3-256("CANO:TX" || TxSignBody).
pub fn tx_digest(tx: &Transaction) -> Hash32 {
    let preimage = tx_sign_body_preimage(tx);
    sha3_256_tagged("CANO:TX", &preimage)
}