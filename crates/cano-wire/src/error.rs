#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnexpectedEof,
    InvalidValue(&'static str),
    LengthOverflow,
    /// Message exceeds the maximum allowed size.
    TooLarge {
        /// Actual size of the message in bytes.
        actual: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },
}