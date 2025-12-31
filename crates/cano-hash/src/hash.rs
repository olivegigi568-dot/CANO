use cano_types::Hash32;
use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 over arbitrary bytes.
pub fn sha3_256(data: &[u8]) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Helper for domain-separated hashing:
/// H(tag || body)
pub fn sha3_256_tagged(tag: &str, body: &[u8]) -> Hash32 {
    let mut hasher = Sha3_256::new();
    hasher.update(tag.as_bytes());
    hasher.update(body);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}