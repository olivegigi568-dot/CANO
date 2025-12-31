use cano_types::{Role, SecurityCategory, RolePolicyEntry, KeyRolePolicy};
use crate::error::StateError;
use crate::io::{StateEncode, StateDecode, put_u8, put_u16, put_bytes, get_u8, get_u16, get_bytes, len_to_u16};

impl StateEncode for RolePolicyEntry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.role_id as u8);
        put_u8(out, self.min_category as u8);
        put_u8(out, self.allowed_tiers);
        put_u8(out, self.allow_legacy);
        put_bytes(out, &self.reserved0);
    }
}

impl StateDecode for RolePolicyEntry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let role_id = match get_u8(input)? {
            0x00 => Role::ValidatorOwner,
            0x01 => Role::ValidatorConsensus,
            0x02 => Role::ValidatorNetwork,
            0x03 => Role::Governance,
            0x04 => Role::BridgeOperator,
            _    => return Err(StateError::InvalidValue("invalid Role")),
        };
        let min_category = match get_u8(input)? {
            0x01 => SecurityCategory::Cat1,
            0x03 => SecurityCategory::Cat3,
            0x05 => SecurityCategory::Cat5,
            _    => return Err(StateError::InvalidValue("invalid SecurityCategory")),
        };
        let allowed_tiers = get_u8(input)?;
        let allow_legacy = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 4)?;
        let mut reserved0 = [0u8; 4];
        reserved0.copy_from_slice(reserved0_bytes);

        Ok(RolePolicyEntry {
            role_id,
            min_category,
            allowed_tiers,
            allow_legacy,
            reserved0,
        })
    }
}

impl StateEncode for KeyRolePolicy {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        let role_count = self.roles.len();
        let role_count_u16 = len_to_u16(role_count);
        put_u16(out, role_count_u16);
        put_u16(out, self.reserved1);
        for role in &self.roles {
            role.encode_state(out);
        }
    }
}

impl StateDecode for KeyRolePolicy {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);
        let role_count = get_u16(input)? as usize;
        let reserved1 = get_u16(input)?;

        let mut roles = Vec::with_capacity(role_count);
        for _ in 0..role_count {
            roles.push(RolePolicyEntry::decode_state(input)?);
        }

        Ok(KeyRolePolicy {
            version,
            reserved0,
            role_count: role_count as u16,
            reserved1,
            roles,
        })
    }
}