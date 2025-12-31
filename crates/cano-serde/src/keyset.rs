use cano_types::{KeysetEntry, KeysetAccount};
use crate::error::StateError;
use crate::io::{
    StateEncode, StateDecode,
    put_u8, put_u16, put_bytes,
    get_u8, get_u16, get_bytes,
};

impl StateEncode for KeysetEntry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.suite_id);
        put_u16(out, self.weight);
        put_bytes(out, &self.reserved0);
        // Use the stored pubkey_len field for encoding to maintain consistency.
        // Callers are responsible for ensuring pubkey_len matches pubkey_bytes.len().
        put_u16(out, self.pubkey_len);
        put_bytes(out, &self.pubkey_bytes);
    }
}

impl StateDecode for KeysetEntry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let suite_id = get_u8(input)?;
        let weight = get_u16(input)?;
        let reserved0_bytes = get_bytes(input, 1)?;
        let mut reserved0 = [0u8; 1];
        reserved0.copy_from_slice(reserved0_bytes);
        let pubkey_len = get_u16(input)? as usize;
        let pubkey_bytes = get_bytes(input, pubkey_len)?.to_vec();

        Ok(KeysetEntry {
            suite_id,
            weight,
            reserved0,
            pubkey_len: pubkey_len as u16,
            pubkey_bytes,
        })
    }
}

impl StateEncode for KeysetAccount {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        put_u16(out, self.threshold);
        // Use the stored entry_count field for encoding to maintain consistency.
        // Callers are responsible for ensuring entry_count matches entries.len().
        put_u16(out, self.entry_count);
        put_bytes(out, &self.reserved1);
        for entry in &self.entries {
            entry.encode_state(out);
        }
    }
}

impl StateDecode for KeysetAccount {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);
        let threshold = get_u16(input)?;
        let entry_count = get_u16(input)? as usize;
        let reserved1_bytes = get_bytes(input, 4)?;
        let mut reserved1 = [0u8; 4];
        reserved1.copy_from_slice(reserved1_bytes);

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(KeysetEntry::decode_state(input)?);
        }

        Ok(KeysetAccount {
            version,
            reserved0,
            threshold,
            entry_count: entry_count as u16,
            reserved1,
            entries,
        })
    }
}