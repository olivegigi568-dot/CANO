use std::sync::Arc;

use cano_crypto::CryptoProvider;
use cano_hash::tx::tx_digest;
use cano_serde::StateDecode;
use cano_types::{Hash32, KeysetAccount};
use cano_wire::tx::{Transaction, TxAuth};

use crate::store::AccountStore;
use crate::ExecutionError;

/// Verify all TxAuth entries on a Transaction against on-chain keyset accounts.
///
/// For each TxAuth:
///  - interpret auth.account_index as an index into tx.accounts
///  - use that account's account_id as the keyset AccountId
///  - load the corresponding account from AccountStore
///  - decode KeysetAccount from account.data via cano-serde
///  - look up a KeysetEntry with matching suite_id
///  - use CryptoProvider to fetch a SignatureSuite and verify the signature
///
/// This function does NOT enforce thresholds/weights yet; it only checks that each
/// TxAuth verifies successfully against at least one key in its keyset.
pub fn verify_transaction_auth<S: AccountStore>(
    store: &mut S,
    crypto: Arc<dyn CryptoProvider>,
    tx: &Transaction,
) -> Result<(), ExecutionError> {
    // If there are no auths, we succeed trivially for now.
    // Later we may require at least one auth for payer, etc.
    if tx.auths.is_empty() {
        return Ok(());
    }

    let digest = tx_digest(tx);

    for auth in &tx.auths {
        verify_single_auth(store, crypto.as_ref(), tx, auth, &digest)?;
    }

    Ok(())
}

fn verify_single_auth<S: AccountStore>(
    store: &mut S,
    crypto: &dyn CryptoProvider,
    tx: &Transaction,
    auth: &TxAuth,
    digest: &Hash32,
) -> Result<(), ExecutionError> {
    // 1) Resolve account_index into tx.accounts.
    let account_index = auth.account_index as usize;
    if account_index >= tx.accounts.len() {
        return Err(ExecutionError::InvalidCallData(
            "auth.account_index out of range",
        ));
    }
    let meta = &tx.accounts[account_index];
    let keyset_id = meta.account_id;

    // 2) Load account from store.
    let account = store
        .get(&keyset_id)
        .ok_or(ExecutionError::AccountNotFound)?;

    // 3) Decode KeysetAccount from account.data.
    let mut slice: &[u8] = &account.data;
    let keyset = KeysetAccount::decode_state(&mut slice)
        .map_err(|_| ExecutionError::SerializationError("decode KeysetAccount"))?;
    if !slice.is_empty() {
        return Err(ExecutionError::SerializationError(
            "trailing bytes in KeysetAccount account",
        ));
    }

    // 4) Find a KeysetEntry with matching suite_id.
    let suite_id = auth.suite_id;
    let maybe_entry = keyset.entries.iter().find(|e| e.suite_id == suite_id);
    let entry = match maybe_entry {
        Some(e) => e,
        None => {
            return Err(ExecutionError::InvalidCallData(
                "no key in keyset for given suite_id",
            ));
        }
    };

    // 5) Obtain SignatureSuite from CryptoProvider.
    let suite = crypto
        .signature_suite(suite_id)
        .ok_or(ExecutionError::CryptoError("signature suite not found"))?;

    // 6) Extract signature bytes from TxAuth.
    let sig_bytes: &[u8] = &auth.signature;
    let pk_bytes: &[u8] = &entry.pubkey_bytes;

    // 7) Verify using the suite.
    suite
        .verify(pk_bytes, digest, sig_bytes)
        .map_err(|_| ExecutionError::CryptoError("signature verification failed"))?;

    Ok(())
}