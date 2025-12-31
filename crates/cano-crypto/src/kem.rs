use crate::CryptoError;

/// A KEM suite for KEMTLS (e.g. ML-KEM-768/1024).
pub trait KemSuite: Send + Sync {
    /// Numeric suite_id matching SuiteRegistry.suite_id.
    fn suite_id(&self) -> u8;

    /// Public key length in bytes (0 = unknown/variable).
    fn public_key_len(&self) -> usize;

    /// Secret key length in bytes (0 = unknown/variable).
    fn secret_key_len(&self) -> usize;

    /// Ciphertext length in bytes (0 = unknown/variable).
    fn ciphertext_len(&self) -> usize;

    /// Shared secret length in bytes (32 is typical, but we do not enforce).
    fn shared_secret_len(&self) -> usize;

    /// Encapsulate to a given public key.
    ///
    /// Returns (ciphertext, shared_secret).
    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;

    /// Decapsulate a ciphertext with a given secret key.
    ///
    /// Returns shared_secret on success.
    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError>;
}