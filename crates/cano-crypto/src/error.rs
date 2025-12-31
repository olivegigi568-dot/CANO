#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    InvalidCiphertext,
    InvalidSuite,
    IncompatibleSuite,
    InternalError(&'static str),
}