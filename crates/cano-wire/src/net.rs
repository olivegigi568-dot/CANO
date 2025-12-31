use cano_types::{AccountId, Hash32};
use crate::consensus::{Vote, BlockProposal};
use crate::error::WireError;
use crate::io::{
    WireEncode, WireDecode,
    put_u8, put_u16, put_u64, put_bytes,
    get_u8, get_u16, get_u64, get_bytes,
    len_to_u16,
};

/// Upper bound on the size of any encoded NetMessage, in bytes.
/// This is a conservative bound to prevent unbounded allocations.
pub const MAX_NET_MESSAGE_BYTES: usize = 1 * 1024 * 1024; // 1 MiB for now

/// Fixed constants for message types and cert_type.
pub const MSG_TYPE_CLIENT_INIT: u8 = 0x20;
pub const MSG_TYPE_SERVER_ACCEPT: u8 = 0x21;
pub const MSG_TYPE_SERVER_COOKIE: u8 = 0x22;
pub const CERT_TYPE_NETWORK_DELEGATION: u8 = 0xA0;

/// NetworkDelegationCert wire layout:
/// cert_type: u8 // 0xA0
/// version: u8 // 0x01
/// validator_id: [u8;32]
/// root_key_id: [u8;32]
/// leaf_kem_suite_id: u8
/// reserved1: u8 // 0x00
/// leaf_pk_len: u16
/// leaf_kem_pk: [u8; leaf_pk_len]
/// not_before: u64
/// not_after: u64
/// ext_len: u16
/// ext_bytes: [u8; ext_len]
/// sig_suite_id: u8
/// reserved2: u8
/// sig_len: u16
/// sig_bytes: [u8; sig_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDelegationCert {
    pub version: u8,
    pub validator_id: AccountId,
    pub root_key_id: Hash32,
    pub leaf_kem_suite_id: u8,
    pub leaf_kem_pk: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub ext_bytes: Vec<u8>,
    pub sig_suite_id: u8,
    pub sig_bytes: Vec<u8>,
}

impl WireEncode for NetworkDelegationCert {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, CERT_TYPE_NETWORK_DELEGATION);
        put_u8(out, self.version);
        put_bytes(out, &self.validator_id);
        put_bytes(out, &self.root_key_id);
        put_u8(out, self.leaf_kem_suite_id);
        put_u8(out, 0); // reserved1

        let leaf_pk_len = self.leaf_kem_pk.len();
        let leaf_pk_len_u16 = len_to_u16(leaf_pk_len);
        put_u16(out, leaf_pk_len_u16);
        put_bytes(out, &self.leaf_kem_pk);

        put_u64(out, self.not_before);
        put_u64(out, self.not_after);

        let ext_len = self.ext_bytes.len();
        let ext_len_u16 = len_to_u16(ext_len);
        put_u16(out, ext_len_u16);
        put_bytes(out, &self.ext_bytes);

        put_u8(out, self.sig_suite_id);
        put_u8(out, 0); // reserved2

        let sig_len = self.sig_bytes.len();
        let sig_len_u16 = len_to_u16(sig_len);
        put_u16(out, sig_len_u16);
        put_bytes(out, &self.sig_bytes);
    }
}

impl WireDecode for NetworkDelegationCert {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let cert_type = get_u8(input)?;
        if cert_type != CERT_TYPE_NETWORK_DELEGATION {
            return Err(WireError::InvalidValue("unexpected cert_type for NetworkDelegationCert"));
        }
        let version = get_u8(input)?;

        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let root_key_id_bytes = get_bytes(input, 32)?;
        let mut root_key_id = [0u8; 32];
        root_key_id.copy_from_slice(root_key_id_bytes);

        let leaf_kem_suite_id = get_u8(input)?;
        let _reserved1 = get_u8(input)?; // consume reserved1

        let leaf_pk_len = get_u16(input)? as usize;
        let leaf_kem_pk = get_bytes(input, leaf_pk_len)?.to_vec();

        let not_before = get_u64(input)?;
        let not_after = get_u64(input)?;

        let ext_len = get_u16(input)? as usize;
        let ext_bytes = get_bytes(input, ext_len)?.to_vec();

        let sig_suite_id = get_u8(input)?;
        let _reserved2 = get_u8(input)?; // consume reserved2

        let sig_len = get_u16(input)? as usize;
        let sig_bytes = get_bytes(input, sig_len)?.to_vec();

        Ok(NetworkDelegationCert {
            version,
            validator_id,
            root_key_id,
            leaf_kem_suite_id,
            leaf_kem_pk,
            not_before,
            not_after,
            ext_bytes,
            sig_suite_id,
            sig_bytes,
        })
    }
}

/// ClientInit wire layout:
/// msg_type: u8 // 0x20
/// version: u8 // 0x01
/// kem_suite_id: u8
/// aead_suite_id: u8
/// client_random: [u8;32]
/// validator_id: [u8;32]
/// cookie_len: u16
/// cookie: [u8; cookie_len]
/// kem_ct_len: u16
/// kem_ct: [u8; kem_ct_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientInit {
    pub version: u8,
    pub kem_suite_id: u8,
    pub aead_suite_id: u8,
    pub client_random: [u8; 32],
    pub validator_id: AccountId,
    pub cookie: Vec<u8>,
    pub kem_ct: Vec<u8>,
}

impl WireEncode for ClientInit {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_CLIENT_INIT);
        put_u8(out, self.version);
        put_u8(out, self.kem_suite_id);
        put_u8(out, self.aead_suite_id);
        put_bytes(out, &self.client_random);
        put_bytes(out, &self.validator_id);

        let cookie_len = self.cookie.len();
        let cookie_len_u16 = len_to_u16(cookie_len);
        put_u16(out, cookie_len_u16);
        put_bytes(out, &self.cookie);

        let kem_ct_len = self.kem_ct.len();
        let kem_ct_len_u16 = len_to_u16(kem_ct_len);
        put_u16(out, kem_ct_len_u16);
        put_bytes(out, &self.kem_ct);
    }
}

impl WireDecode for ClientInit {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_CLIENT_INIT {
            return Err(WireError::InvalidValue("unexpected msg_type for ClientInit"));
        }
        let version = get_u8(input)?;
        let kem_suite_id = get_u8(input)?;
        let aead_suite_id = get_u8(input)?;

        let client_random_bytes = get_bytes(input, 32)?;
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(client_random_bytes);

        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let cookie_len = get_u16(input)? as usize;
        let cookie = get_bytes(input, cookie_len)?.to_vec();

        let kem_ct_len = get_u16(input)? as usize;
        let kem_ct = get_bytes(input, kem_ct_len)?.to_vec();

        Ok(ClientInit {
            version,
            kem_suite_id,
            aead_suite_id,
            client_random,
            validator_id,
            cookie,
            kem_ct,
        })
    }
}

/// ServerAccept wire layout:
/// msg_type: u8 // 0x21
/// version: u8 // 0x01
/// kem_suite_id: u8
/// aead_suite_id: u8
/// server_random: [u8;32]
/// validator_id: [u8;32]
/// client_random: [u8;32]
/// cert_len: u16
/// delegation_cert: [u8; cert_len]
/// flags: u16
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerAccept {
    pub version: u8,
    pub kem_suite_id: u8,
    pub aead_suite_id: u8,
    pub server_random: [u8; 32],
    pub validator_id: AccountId,
    pub client_random: [u8; 32],
    pub delegation_cert: Vec<u8>, // raw bytes; caller may parse as NetworkDelegationCert
    pub flags: u16,
}

impl WireEncode for ServerAccept {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_SERVER_ACCEPT);
        put_u8(out, self.version);
        put_u8(out, self.kem_suite_id);
        put_u8(out, self.aead_suite_id);
        put_bytes(out, &self.server_random);
        put_bytes(out, &self.validator_id);
        put_bytes(out, &self.client_random);

        let cert_len = self.delegation_cert.len();
        let cert_len_u16 = len_to_u16(cert_len);
        put_u16(out, cert_len_u16);
        put_bytes(out, &self.delegation_cert);

        put_u16(out, self.flags);
    }
}

impl WireDecode for ServerAccept {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_SERVER_ACCEPT {
            return Err(WireError::InvalidValue("unexpected msg_type for ServerAccept"));
        }
        let version = get_u8(input)?;
        let kem_suite_id = get_u8(input)?;
        let aead_suite_id = get_u8(input)?;

        let server_random_bytes = get_bytes(input, 32)?;
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(server_random_bytes);

        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let client_random_bytes = get_bytes(input, 32)?;
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(client_random_bytes);

        let cert_len = get_u16(input)? as usize;
        let delegation_cert = get_bytes(input, cert_len)?.to_vec();

        let flags = get_u16(input)?;

        Ok(ServerAccept {
            version,
            kem_suite_id,
            aead_suite_id,
            server_random,
            validator_id,
            client_random,
            delegation_cert,
            flags,
        })
    }
}

/// ServerCookie wire layout:
/// msg_type: u8 // 0x22
/// version: u8 // 0x01
/// kem_suite_id: u8
/// aead_suite_id: u8
/// validator_id: [u8;32]
/// client_random: [u8;32]
/// cookie_len: u16
/// cookie: [u8; cookie_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerCookie {
    pub version: u8,
    pub kem_suite_id: u8,
    pub aead_suite_id: u8,
    pub validator_id: AccountId,
    pub client_random: [u8; 32],
    pub cookie: Vec<u8>,
}

impl WireEncode for ServerCookie {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_SERVER_COOKIE);
        put_u8(out, self.version);
        put_u8(out, self.kem_suite_id);
        put_u8(out, self.aead_suite_id);
        put_bytes(out, &self.validator_id);
        put_bytes(out, &self.client_random);

        let cookie_len = self.cookie.len();
        let cookie_len_u16 = len_to_u16(cookie_len);
        put_u16(out, cookie_len_u16);
        put_bytes(out, &self.cookie);
    }
}

impl WireDecode for ServerCookie {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_SERVER_COOKIE {
            return Err(WireError::InvalidValue("unexpected msg_type for ServerCookie"));
        }
        let version = get_u8(input)?;
        let kem_suite_id = get_u8(input)?;
        let aead_suite_id = get_u8(input)?;

        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let client_random_bytes = get_bytes(input, 32)?;
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(client_random_bytes);

        let cookie_len = get_u16(input)? as usize;
        let cookie = get_bytes(input, cookie_len)?.to_vec();

        Ok(ServerCookie {
            version,
            kem_suite_id,
            aead_suite_id,
            validator_id,
            client_random,
            cookie,
        })
    }
}

// ============================================================================
// Application-level network messages
// ============================================================================

/// Message type constants for application-level messages
pub const MSG_TYPE_PING: u8 = 0x30;
pub const MSG_TYPE_PONG: u8 = 0x31;

// New message type tags for consensus messages
pub const MSG_TYPE_CONSENSUS_VOTE: u8 = 0x40;
pub const MSG_TYPE_NET_BLOCK_PROPOSAL: u8 = 0x41;

/// A general-purpose network message enum for peer-to-peer communication.
///
/// This enum is used for application-level messages sent over established
/// secure channels, separate from the KEMTLS handshake messages above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetMessage {
    /// Ping message with a nonce value for connectivity testing.
    Ping(u64),
    /// Pong message echoing back the nonce from a Ping.
    Pong(u64),

    // New: consensus-plane messages
    /// A consensus vote message.
    ConsensusVote(Vote),
    /// A block proposal message.
    BlockProposal(BlockProposal),
}

impl WireEncode for NetMessage {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            NetMessage::Ping(nonce) => {
                put_u8(out, MSG_TYPE_PING);
                put_u64(out, *nonce);
            }
            NetMessage::Pong(nonce) => {
                put_u8(out, MSG_TYPE_PONG);
                put_u64(out, *nonce);
            }
            NetMessage::ConsensusVote(v) => {
                put_u8(out, MSG_TYPE_CONSENSUS_VOTE);
                v.encode(out);
            }
            NetMessage::BlockProposal(b) => {
                put_u8(out, MSG_TYPE_NET_BLOCK_PROPOSAL);
                b.encode(out);
            }
        }
    }
}

impl WireDecode for NetMessage {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        match msg_type {
            MSG_TYPE_PING => {
                let nonce = get_u64(input)?;
                Ok(NetMessage::Ping(nonce))
            }
            MSG_TYPE_PONG => {
                let nonce = get_u64(input)?;
                Ok(NetMessage::Pong(nonce))
            }
            MSG_TYPE_CONSENSUS_VOTE => {
                let v = Vote::decode(input)?;
                Ok(NetMessage::ConsensusVote(v))
            }
            MSG_TYPE_NET_BLOCK_PROPOSAL => {
                let b = BlockProposal::decode(input)?;
                Ok(NetMessage::BlockProposal(b))
            }
            _ => Err(WireError::InvalidValue("unknown NetMessage msg_type")),
        }
    }
}

impl NetMessage {
    /// Encode this message to a `Vec<u8>`, checking the size limit.
    ///
    /// Returns `Err(WireError::TooLarge)` if the encoded message exceeds
    /// `MAX_NET_MESSAGE_BYTES`.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.encode(&mut out);

        if out.len() > MAX_NET_MESSAGE_BYTES {
            return Err(WireError::TooLarge {
                actual: out.len(),
                max: MAX_NET_MESSAGE_BYTES,
            });
        }

        Ok(out)
    }

    /// Decode a `NetMessage` from a byte slice, checking the size limit first.
    ///
    /// Returns `Err(WireError::TooLarge)` if `bytes.len() > MAX_NET_MESSAGE_BYTES`.
    pub fn decode_from_slice(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_NET_MESSAGE_BYTES {
            return Err(WireError::TooLarge {
                actual: bytes.len(),
                max: MAX_NET_MESSAGE_BYTES,
            });
        }

        let mut slice = bytes;
        Self::decode(&mut slice)
    }
}