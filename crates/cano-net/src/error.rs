#[derive(Debug)]
pub enum NetError {
    /// HKDF or key derivation failure.
    KeySchedule(&'static str),

    /// AEAD encrypt/decrypt failure.
    Aead(&'static str),

    /// Nonce counter overflow.
    NonceOverflow,

    /// Unsupported or unknown suite.
    UnsupportedSuite(u8),

    /// Protocol or framing error (e.g., packet parsing).
    Protocol(&'static str),
}