use crate::CryptoError;

/// AEAD suite (e.g. ChaCha20-Poly1305).
pub trait AeadSuite: Send + Sync {
    /// Numeric suite_id, e.g. 0x01 for ChaCha20-Poly1305 in cano v1.
    fn suite_id(&self) -> u8;

    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;
    fn tag_len(&self) -> usize;

    /// Seal (encrypt + authenticate) a message.
    ///
    /// `key`: secret key bytes
    /// `nonce`: unique nonce per key and direction
    /// `aad`: associated data
    /// `plaintext`: data to encrypt
    ///
    /// Returns ciphertext || tag.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Open (decrypt + verify) a message.
    ///
    /// Returns plaintext if authentication passes.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}