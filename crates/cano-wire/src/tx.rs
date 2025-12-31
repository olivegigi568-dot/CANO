use cano_types::{AccountId, ProgramId};
use crate::error::WireError;
use crate::io::{WireEncode, WireDecode, put_u8, put_u16, put_u32, put_u64, put_bytes, get_u8, get_u16, get_u32, get_u64, get_bytes, len_to_u16, len_to_u32};

pub const MSG_TYPE_TX: u8 = 0x10;

/// TxAccountMeta:
/// account_id:  AccountId (32 bytes)
/// flags:       u8  (bit0 is_signer, bit1 is_writable)
/// access_hint: u8  (bit0 may_read, bit1 may_write - advisory)
/// reserved0:   [u8; 2] for alignment/future use
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAccountMeta {
    pub account_id:  AccountId,
    pub flags:       u8,
    pub access_hint: u8,
    pub reserved0:   [u8; 2],
}

impl WireEncode for TxAccountMeta {
    fn encode(&self, out: &mut Vec<u8>) {
        put_bytes(out, &self.account_id);
        put_u8(out, self.flags);
        put_u8(out, self.access_hint);
        put_bytes(out, &self.reserved0);
    }
}

impl WireDecode for TxAccountMeta {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let account_id_bytes = get_bytes(input, 32)?;
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(account_id_bytes);
        let flags = get_u8(input)?;
        let access_hint = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 2)?;
        let mut reserved0 = [0u8; 2];
        reserved0.copy_from_slice(reserved0_bytes);
        Ok(TxAccountMeta {
            account_id,
            flags,
            access_hint,
            reserved0,
        })
    }
}

/// TxAuth:
/// account_index: u16
/// suite_id:      u8
/// reserved:      u8
/// sig_len:       u16
/// sig_bytes:     [u8; sig_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAuth {
    pub account_index: u16,
    pub suite_id:      u8,
    pub reserved:      u8,
    pub signature:     Vec<u8>,
}

impl WireEncode for TxAuth {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u16(out, self.account_index);
        put_u8(out, self.suite_id);
        put_u8(out, self.reserved);
        let sig_len = self.signature.len();
        let sig_len_u16 = len_to_u16(sig_len);
        put_u16(out, sig_len_u16);
        put_bytes(out, &self.signature);
    }
}

impl WireDecode for TxAuth {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let account_index = get_u16(input)?;
        let suite_id = get_u8(input)?;
        let reserved = get_u8(input)?;
        let sig_len = get_u16(input)? as usize;
        let signature = get_bytes(input, sig_len)?.to_vec();
        Ok(TxAuth {
            account_index,
            suite_id,
            reserved,
            signature,
        })
    }
}

/// Transaction:
/// msg_type:      u8   // 0x10
/// version:       u8   // 0x01
/// chain_id:      u32
/// payer:         AccountId (32 bytes)
/// nonce:         u64
/// fee_limit:     u64
/// account_count: u16
/// accounts:      [TxAccountMeta; account_count]
/// program_id:    ProgramId (32 bytes)
/// call_data_len: u32
/// call_data:     [u8; call_data_len]
/// auth_count:    u16
/// auths:         [TxAuth; auth_count]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version:       u8,
    pub chain_id:      u32,
    pub payer:         AccountId,
    pub nonce:         u64,
    pub fee_limit:     u64,
    pub accounts:      Vec<TxAccountMeta>,
    pub program_id:    ProgramId,
    pub call_data:     Vec<u8>,
    pub auths:         Vec<TxAuth>,
}

impl WireEncode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_TX);
        put_u8(out, self.version);
        put_u32(out, self.chain_id);
        put_bytes(out, &self.payer);
        put_u64(out, self.nonce);
        put_u64(out, self.fee_limit);

        let account_count = self.accounts.len();
        let account_count_u16 = len_to_u16(account_count);
        put_u16(out, account_count_u16);
        for meta in &self.accounts {
            meta.encode(out);
        }

        put_bytes(out, &self.program_id);

        let call_len = self.call_data.len();
        let call_len_u32 = len_to_u32(call_len);
        put_u32(out, call_len_u32);
        put_bytes(out, &self.call_data);

        let auth_count = self.auths.len();
        let auth_count_u16 = len_to_u16(auth_count);
        put_u16(out, auth_count_u16);
        for a in &self.auths {
            a.encode(out);
        }
    }
}

impl WireDecode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_TX {
            return Err(WireError::InvalidValue("unexpected msg_type for Transaction"));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let payer_bytes = get_bytes(input, 32)?;
        let mut payer = [0u8; 32];
        payer.copy_from_slice(payer_bytes);
        let nonce = get_u64(input)?;
        let fee_limit = get_u64(input)?;

        let account_count = get_u16(input)? as usize;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            accounts.push(TxAccountMeta::decode(input)?);
        }

        let program_id_bytes = get_bytes(input, 32)?;
        let mut program_id = [0u8; 32];
        program_id.copy_from_slice(program_id_bytes);

        let call_len = get_u32(input)? as usize;
        let call_data = get_bytes(input, call_len)?.to_vec();

        let auth_count = get_u16(input)? as usize;
        let mut auths = Vec::with_capacity(auth_count);
        for _ in 0..auth_count {
            auths.push(TxAuth::decode(input)?);
        }

        Ok(Transaction {
            version,
            chain_id,
            payer,
            nonce,
            fee_limit,
            accounts,
            program_id,
            call_data,
            auths,
        })
    }
}