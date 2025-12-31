#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    UnexpectedEof,
    InvalidValue(&'static str),
    LengthOverflow,
}