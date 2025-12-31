use crate::StateError;

pub trait StateEncode {
    fn encode_state(&self, out: &mut Vec<u8>);
}

pub trait StateDecode: Sized {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError>;
}

// Primitive helpers: same style as cano-wire, but separate.

pub fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

pub fn get_u8(input: &mut &[u8]) -> Result<u8, StateError> {
    if input.is_empty() {
        return Err(StateError::UnexpectedEof);
    }
    let (b, rest) = input.split_at(1);
    *input = rest;
    Ok(b[0])
}

pub fn get_u16(input: &mut &[u8]) -> Result<u16, StateError> {
    if input.len() < 2 {
        return Err(StateError::UnexpectedEof);
    }
    let (b, rest) = input.split_at(2);
    *input = rest;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub fn get_u32(input: &mut &[u8]) -> Result<u32, StateError> {
    if input.len() < 4 {
        return Err(StateError::UnexpectedEof);
    }
    let (b, rest) = input.split_at(4);
    *input = rest;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn get_u64(input: &mut &[u8]) -> Result<u64, StateError> {
    if input.len() < 8 {
        return Err(StateError::UnexpectedEof);
    }
    let (b, rest) = input.split_at(8);
    *input = rest;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub fn get_bytes<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], StateError> {
    if input.len() < len {
        return Err(StateError::UnexpectedEof);
    }
    let (b, rest) = input.split_at(len);
    *input = rest;
    Ok(b)
}

/// Convert a usize length to u16, panicking on overflow.
/// This is only used for locally constructed state entries and is considered a programming error if it overflows.
pub fn len_to_u16(len: usize) -> u16 {
    assert!(
        len <= u16::MAX as usize,
        "state length {} exceeds u16::MAX; this is a programming error",
        len
    );
    len as u16
}