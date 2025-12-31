use cano_types::{SuiteFamily, SecurityCategory, SuiteTier, SuiteStatus};
use cano_types::{SuiteEntry, SuiteRegistry};
use crate::error::StateError;
use crate::io::{StateEncode, StateDecode, put_u8, put_u16, put_bytes, get_u8, get_u16, get_bytes, len_to_u16};

impl StateEncode for SuiteEntry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        // suite_id
        put_u8(out, self.suite_id);
        // family/category/tier/status as u8
        put_u8(out, self.family as u8);
        put_u8(out, self.category as u8);
        put_u8(out, self.tier as u8);
        put_u8(out, self.status as u8);
        // reserved0
        put_bytes(out, &self.reserved0);
        // params_hash
        put_bytes(out, &self.params_hash);
        // ext_len + ext_bytes
        let ext_len = self.ext_bytes.len();
        let ext_len_u16 = len_to_u16(ext_len);
        put_u16(out, ext_len_u16);
        put_bytes(out, &self.ext_bytes);
    }
}

impl StateDecode for SuiteEntry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let suite_id = get_u8(input)?;
        let family = match get_u8(input)? {
            0x00 => SuiteFamily::Lattice,
            0x01 => SuiteFamily::HashBased,
            0x02 => SuiteFamily::CodeBased,
            0x03 => SuiteFamily::Isogeny,
            _    => SuiteFamily::Reserved,
        };
        let category = match get_u8(input)? {
            0x01 => SecurityCategory::Cat1,
            0x03 => SecurityCategory::Cat3,
            0x05 => SecurityCategory::Cat5,
            _    => return Err(StateError::InvalidValue("invalid SecurityCategory")),
        };
        let tier = match get_u8(input)? {
            0x00 => SuiteTier::Core,
            0x01 => SuiteTier::Experimental,
            _    => return Err(StateError::InvalidValue("invalid SuiteTier")),
        };
        let status = match get_u8(input)? {
            0x00 => SuiteStatus::Active,
            0x01 => SuiteStatus::Legacy,
            0x02 => SuiteStatus::Disabled,
            _    => return Err(StateError::InvalidValue("invalid SuiteStatus")),
        };

        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);

        let params_hash_bytes = get_bytes(input, 32)?;
        let mut params_hash = [0u8; 32];
        params_hash.copy_from_slice(params_hash_bytes);

        let ext_len = get_u16(input)? as usize;
        let ext_bytes = get_bytes(input, ext_len)?.to_vec();

        Ok(SuiteEntry {
            suite_id,
            family,
            category,
            tier,
            status,
            reserved0,
            params_hash,
            ext_len: ext_len as u16,
            ext_bytes,
        })
    }
}

impl StateEncode for SuiteRegistry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        let count = self.suites.len();
        let count_u16 = len_to_u16(count);
        put_u16(out, count_u16);
        put_u16(out, self.reserved1);
        for entry in &self.suites {
            entry.encode_state(out);
        }
    }
}

impl StateDecode for SuiteRegistry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);
        let suite_count = get_u16(input)? as usize;
        let reserved1 = get_u16(input)?;

        let mut suites = Vec::with_capacity(suite_count);
        for _ in 0..suite_count {
            suites.push(SuiteEntry::decode_state(input)?);
        }

        Ok(SuiteRegistry {
            version,
            reserved0,
            suite_count: suite_count as u16,
            reserved1,
            suites,
        })
    }
}