use crate::hkdf::{hkdf_extract, hkdf_expand_label};

/// Session keys derived from a KEM shared secret and transcript hash.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// 3-byte session identifier.
    pub session_id: [u8; 3],
    /// Client-to-server AEAD key bytes.
    pub k_c2s: Vec<u8>,
    /// Server-to-client AEAD key bytes.
    pub k_s2c: Vec<u8>,
    /// AEAD key length in bytes.
    pub key_len: usize,
}

impl SessionKeys {
    /// Derive session keys from:
    ///  - shared_secret: KEM shared secret,
    ///  - transcript_hash: hash of the KEMTLS transcript (caller-provided),
    ///  - kem_suite_id, aead_suite_id: one-byte identifiers,
    ///  - key_len: desired AEAD key length in bytes.
    ///
    /// HKDF layout:
    ///  - prk = HKDF-Extract(salt = "CANO:KDF" || transcript_hash, ikm = shared_secret)
    ///  - session_id = first 3 bytes of HKDF-Expand-Label(prk, "CANO:session-id", info, 3)
    ///  - k_c2s = HKDF-Expand-Label(prk, "CANO:k_c2s", info, key_len)
    ///  - k_s2c = HKDF-Expand-Label(prk, "CANO:k_s2c", info, key_len)
    ///
    /// where info = [kem_suite_id, aead_suite_id].
    pub fn derive(
        shared_secret: &[u8],
        transcript_hash: &[u8],
        kem_suite_id: u8,
        aead_suite_id: u8,
        key_len: usize,
    ) -> Self {
        let mut salt = b"CANO:KDF".to_vec();
        salt.extend_from_slice(transcript_hash);

        let prk = hkdf_extract(&salt, shared_secret);

        let info = [kem_suite_id, aead_suite_id];

        let sid_bytes = hkdf_expand_label(&prk, b"CANO:session-id", &info, 3);
        let mut session_id = [0u8; 3];
        session_id.copy_from_slice(&sid_bytes[..3]);

        let k_c2s = hkdf_expand_label(&prk, b"CANO:k_c2s", &info, key_len);
        let k_s2c = hkdf_expand_label(&prk, b"CANO:k_s2c", &info, key_len);

        SessionKeys {
            session_id,
            k_c2s,
            k_s2c,
            key_len,
        }
    }
}