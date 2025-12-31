use cano_types::AccountId;
use crate::error::WireError;
use crate::io::{
    WireEncode, WireDecode,
    put_u8, put_u16, put_bytes,
    get_u8, get_u16, get_bytes,
    len_to_u16,
};

/// Opcode for creating a new keyset account.
pub const OP_KEYSET_CREATE: u8 = 0x30;

/// Wire-level representation of a single key entry in CreateKeysetCall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireKeyEntry {
    pub suite_id: u8,
    pub weight: u16,
    pub pubkey_bytes: Vec<u8>,
}

/// Call_data for keyset creation:
///
/// op_code:     u8   // 0x30
/// version:     u8   // 0x01
/// target_id:   [u8; 32]  // AccountId where the keyset account will live
/// threshold:   u16
/// entry_count: u16
/// reserved0:   [u8; 4]
/// entries:     repeated { suite_id: u8, weight: u16, pk_len: u16, pk_bytes: [u8; pk_len] }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateKeysetCall {
    pub version: u8,
    pub target_id: AccountId,
    pub threshold: u16,
    pub entries: Vec<WireKeyEntry>,
}

impl WireEncode for WireKeyEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.suite_id);
        put_u16(out, self.weight);
        let pk_len = len_to_u16(self.pubkey_bytes.len());
        put_u16(out, pk_len);
        put_bytes(out, &self.pubkey_bytes);
    }
}

impl WireDecode for WireKeyEntry {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let suite_id = get_u8(input)?;
        let weight = get_u16(input)?;
        let pk_len = get_u16(input)? as usize;
        let pk_bytes = get_bytes(input, pk_len)?.to_vec();
        Ok(WireKeyEntry {
            suite_id,
            weight,
            pubkey_bytes: pk_bytes,
        })
    }
}

impl WireEncode for CreateKeysetCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_KEYSET_CREATE);
        put_u8(out, self.version);
        put_bytes(out, &self.target_id);
        put_u16(out, self.threshold);
        let entry_count_u16 = len_to_u16(self.entries.len());
        put_u16(out, entry_count_u16);
        put_bytes(out, &[0u8; 4]); // reserved0
        for e in &self.entries {
            e.encode(out);
        }
    }
}

impl WireDecode for CreateKeysetCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_KEYSET_CREATE {
            return Err(WireError::InvalidValue("unexpected op_code for CreateKeysetCall"));
        }
        let version = get_u8(input)?;
        let id_bytes = get_bytes(input, 32)?;
        let mut target_id = [0u8; 32];
        target_id.copy_from_slice(id_bytes);
        let threshold = get_u16(input)?;
        let entry_count = get_u16(input)? as usize;
        let _reserved0 = get_bytes(input, 4)?;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(WireKeyEntry::decode(input)?);
        }
        Ok(CreateKeysetCall {
            version,
            target_id,
            threshold,
            entries,
        })
    }
}