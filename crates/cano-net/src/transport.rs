//! Encrypted transport frame for post-handshake application data.

use crate::error::NetError;
use crate::session::AeadDirection;

/// Message type for generic application payload.
pub const TRANSPORT_TYPE_APP_MESSAGE: u8 = 0x01;

/// AAD used for application frames.
const APP_FRAME_AAD: &[u8] = b"CANO:net:app-frame";

/// Encrypted transport frame for post-handshake application data.
///
/// Wire format (big-endian):
///   - msg_type: u8
///   - len: u32
///   - ciphertext: [u8; len]
///
/// The `ciphertext` is an AEAD-encrypted payload produced by `AeadDirection::seal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFrame {
    pub msg_type: u8,
    pub ciphertext: Vec<u8>,
}

impl TransportFrame {
    /// Encode this frame to a length-prefixed binary representation.
    ///
    /// Layout:
    ///   - msg_type: u8
    ///   - len: u32 (big-endian, ciphertext length)
    ///   - ciphertext: [u8; len]
    pub fn encode(&self) -> Result<Vec<u8>, NetError> {
        let len = self.ciphertext.len();
        if len > u32::MAX as usize {
            return Err(NetError::Protocol("transport frame too large"));
        }

        let mut out = Vec::with_capacity(1 + 4 + len);
        out.push(self.msg_type);
        out.extend_from_slice(&(len as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Decode a TransportFrame from a buffer.
    ///
    /// Expects the entire frame to be present; does not support streaming.
    pub fn decode(buf: &[u8]) -> Result<Self, NetError> {
        if buf.len() < 5 {
            return Err(NetError::Protocol("transport frame too short"));
        }

        let msg_type = buf[0];

        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

        if buf.len() < 5 + len {
            return Err(NetError::Protocol("transport frame payload truncated"));
        }

        let ciphertext = buf[5..5 + len].to_vec();

        Ok(TransportFrame { msg_type, ciphertext })
    }
}

/// Encrypt application data into a TransportFrame using the given AEAD direction.
///
/// The caller chooses which direction (c2s or s2c) to use.
pub fn encrypt_app_frame(
    direction: &mut AeadDirection,
    plaintext: &[u8],
) -> Result<TransportFrame, NetError> {
    let ciphertext = direction.seal(APP_FRAME_AAD, plaintext)?;
    Ok(TransportFrame {
        msg_type: TRANSPORT_TYPE_APP_MESSAGE,
        ciphertext,
    })
}

/// Decrypt a TransportFrame into application data using the given AEAD direction.
///
/// Returns an error if the msg_type is unexpected or decryption fails.
pub fn decrypt_app_frame(
    direction: &mut AeadDirection,
    frame: &TransportFrame,
) -> Result<Vec<u8>, NetError> {
    if frame.msg_type != TRANSPORT_TYPE_APP_MESSAGE {
        return Err(NetError::Protocol("unexpected transport msg_type"));
    }
    direction.open(APP_FRAME_AAD, &frame.ciphertext)
}