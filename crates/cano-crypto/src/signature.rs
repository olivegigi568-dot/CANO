use cano_types::Hash32;
use crate::CryptoError;

/// A verification-only signature suite (e.g. ML-DSA-65/87 or SLH-DSA).
/// This is algorithm-agnostic: we don't expose key formats or parameters here.
pub trait SignatureSuite: Send + Sync {
    /// Numeric suite_id, must match on-chain SuiteRegistry.suite_id for this suite.
    fn suite_id(&self) -> u8;

    /// Expected public key length in bytes, if known; 0 may mean "variable or unknown".
    fn public_key_len(&self) -> usize;

    /// Expected signature length in bytes, if known; 0 may mean "variable or unknown".
    fn signature_len(&self) -> usize;

    /// Verify a signature over a 32-byte digest.
    ///
    /// `pk` is the raw public key bytes as stored on-chain.
    /// `msg_digest` is the canonical digest (e.g. tx_digest or vote_digest).
    fn verify(&self, pk: &[u8], msg_digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError>;
}

/// Optional signing interface, for local key-holding components (e.g. validator nodes).
/// This is not used by consensus to *verify*; it's used by nodes to produce signatures.
pub trait Signer {
    /// suite_id must match the SignatureSuite used by verifiers.
    fn suite_id(&self) -> u8;

    /// Return the public key bytes associated with this signer.
    fn public_key(&self) -> &[u8];

    /// Sign a canonical digest and return the raw signature bytes.
    fn sign(&self, msg_digest: &Hash32) -> Result<Vec<u8>, CryptoError>;
}