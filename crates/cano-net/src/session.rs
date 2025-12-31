use cano_crypto::{AeadSuite, CryptoProvider};

use crate::error::NetError;
use crate::keys::SessionKeys;

/// 12-byte nonce: flag(1) || session_id(3) || counter(8).
fn make_nonce(flag: u8, session_id: &[u8; 3], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = flag;
    nonce[1..4].copy_from_slice(session_id);
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Directional AEAD state (one per direction).
///
/// Note: `session_id` is a 3-byte prefix used in nonce construction:
///   nonce = flag(1) || session_id(3) || counter(8)
/// It is *not* required to be globally unique across all sessions.
/// AEAD safety relies on each session using independent keys and
/// monotonic per-direction counters, so (key, nonce) pairs are never reused.
pub struct AeadDirection<'a> {
    aead: &'a dyn AeadSuite,
    key: Vec<u8>,
    session_id: [u8; 3],
    flag: u8,
    counter: u64,
}

impl<'a> std::fmt::Debug for AeadDirection<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadDirection")
            .field("session_id", &self.session_id)
            .field("flag", &self.flag)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl<'a> AeadDirection<'a> {
    fn new(aead: &'a dyn AeadSuite, key: Vec<u8>, session_id: [u8; 3], flag: u8) -> Self {
        AeadDirection {
            aead,
            key,
            session_id,
            flag,
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], NetError> {
        let counter = self.counter;
        if counter == u64::MAX {
            return Err(NetError::NonceOverflow);
        }
        self.counter = self.counter.wrapping_add(1);
        Ok(make_nonce(self.flag, &self.session_id, counter))
    }

    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NetError> {
        let nonce = self.next_nonce()?;
        self.aead
            .seal(&self.key, &nonce, aad, plaintext)
            .map_err(|_| NetError::Aead("encrypt failed"))
    }

    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NetError> {
        let nonce = self.next_nonce()?;
        self.aead
            .open(&self.key, &nonce, aad, ciphertext)
            .map_err(|_| NetError::Aead("decrypt failed"))
    }
}

/// Bi-directional AEAD session for validator/validator transport.
pub struct AeadSession<'a> {
    /// Client -> Server direction.
    pub c2s: AeadDirection<'a>,
    /// Server -> Client direction.
    pub s2c: AeadDirection<'a>,
}

impl<'a> std::fmt::Debug for AeadSession<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadSession")
            .field("c2s", &self.c2s)
            .field("s2c", &self.s2c)
            .finish()
    }
}

impl<'a> AeadSession<'a> {
    /// Construct an AEAD session from SessionKeys and a CryptoProvider.
    ///
    /// The provider must support the AEAD suite id passed by the caller.
    pub fn new(
        crypto: &'a dyn CryptoProvider,
        aead_suite_id: u8,
        keys: &SessionKeys,
    ) -> Result<Self, NetError> {
        let suite_c2s = crypto
            .aead_suite(aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(aead_suite_id))?;

        let suite_s2c = crypto
            .aead_suite(aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(aead_suite_id))?;

        let c2s = AeadDirection::new(suite_c2s, keys.k_c2s.clone(), keys.session_id, 0x01);
        let s2c = AeadDirection::new(suite_s2c, keys.k_s2c.clone(), keys.session_id, 0x02);

        Ok(AeadSession { c2s, s2c })
    }
}