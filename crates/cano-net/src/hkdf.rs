use hmac::{Hmac, Mac};
use sha3::Sha3_256;

// HMAC-SHA3-256 type alias.
type HmacSha3_256 = Hmac<Sha3_256>;

/// HKDF-Extract with HMAC-SHA3-256.
///
/// PRK = HMAC-Hash(salt, IKM)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // If salt is empty, RFC 5869 treats it as a zero-filled string HashLen long.
    let mut mac = if salt.is_empty() {
        let zero_salt = [0u8; 32];
        HmacSha3_256::new_from_slice(&zero_salt).expect("HMAC can take key of any size")
    } else {
        HmacSha3_256::new_from_slice(salt).expect("HMAC can take key of any size")
    };

    mac.update(ikm);
    let prk_bytes = mac.finalize().into_bytes();

    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_bytes[..32]);
    prk
}

/// HKDF-Expand with HMAC-SHA3-256, with an explicit label for domain separation.
///
/// This is NOT a full TLS HKDF-Expand-Label implementation, but follows the HKDF
/// "T(1) || T(2) || ..." pattern from RFC 5869.
///
/// For now, we only need out_len <= 32 bytes.
///
/// Arguments:
///   - prk: 32-byte pseudo-random key from hkdf_extract
///   - label: domain separation label, e.g. "CANO:session-id"
///   - info: additional context bytes (e.g. [kem_suite_id, aead_suite_id])
///   - out_len: length of output keying material in bytes (<= 32)
pub fn hkdf_expand_label(prk: &[u8; 32], label: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len <= 32, "hkdf_expand_label: out_len > 32 not supported");

    // Construct HKDF info = label || 0x00 || info
    // (simple, self-contained domain separation).
    let mut info_buf = Vec::with_capacity(label.len() + 1 + info.len());
    info_buf.extend_from_slice(label);
    info_buf.push(0u8);
    info_buf.extend_from_slice(info);

    // HKDF-Expand: T(1) = HMAC-Hash(PRK, T(0) || info || 0x01)
    let mut mac = HmacSha3_256::new_from_slice(prk).expect("HMAC can take key of any size");
    // T(0) is empty
    mac.update(&info_buf);
    mac.update(&[0x01]); // block counter
    let okm_block = mac.finalize().into_bytes();

    okm_block[..out_len].to_vec()
}