#[derive(Debug, Clone)]
pub enum ExecutionError {
    AccountNotFound,
    AccountOwnerMismatch,
    InsufficientFunds,
    InvalidCallData(&'static str),
    SerializationError(&'static str),
    CryptoError(&'static str),
    ProgramError(&'static str),
}