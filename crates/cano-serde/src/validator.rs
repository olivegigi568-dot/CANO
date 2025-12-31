use cano_types::{ValidatorStatus, ValidatorRecord, SlashingEvent};
use crate::error::StateError;
use crate::io::{StateEncode, StateDecode, put_u8, put_u16, put_u64, put_bytes, get_u8, get_u16, get_u64, get_bytes, len_to_u16};

impl StateEncode for ValidatorRecord {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u8(out, self.status as u8);
        put_bytes(out, &self.reserved0);
        put_bytes(out, &self.owner_keyset_id);

        put_u8(out, self.consensus_suite_id);
        put_bytes(out, &self.reserved1);
        let cons_pk_len = self.consensus_pk.len();
        let cons_pk_len_u16 = len_to_u16(cons_pk_len);
        put_u16(out, cons_pk_len_u16);
        put_bytes(out, &self.consensus_pk);

        put_u8(out, self.network_suite_id);
        put_bytes(out, &self.reserved2);
        let net_pk_len = self.network_pk.len();
        let net_pk_len_u16 = len_to_u16(net_pk_len);
        put_u16(out, net_pk_len_u16);
        put_bytes(out, &self.network_pk);

        put_u64(out, self.stake);
        put_u64(out, self.last_slash_height);

        let ext_len = self.ext_bytes.len();
        let ext_len_u16 = len_to_u16(ext_len);
        put_u16(out, ext_len_u16);
        put_bytes(out, &self.ext_bytes);
    }
}

impl StateDecode for ValidatorRecord {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let status = match get_u8(input)? {
            0 => ValidatorStatus::Inactive,
            1 => ValidatorStatus::Active,
            2 => ValidatorStatus::Jailed,
            3 => ValidatorStatus::Exiting,
            _ => return Err(StateError::InvalidValue("invalid ValidatorStatus")),
        };
        let reserved0_bytes = get_bytes(input, 2)?;
        let mut reserved0 = [0u8; 2];
        reserved0.copy_from_slice(reserved0_bytes);

        let owner_bytes = get_bytes(input, 32)?;
        let mut owner_keyset_id = [0u8; 32];
        owner_keyset_id.copy_from_slice(owner_bytes);

        let consensus_suite_id = get_u8(input)?;
        let reserved1_bytes = get_bytes(input, 3)?;
        let mut reserved1 = [0u8; 3];
        reserved1.copy_from_slice(reserved1_bytes);
        let cons_pk_len = get_u16(input)? as usize;
        let consensus_pk = get_bytes(input, cons_pk_len)?.to_vec();

        let network_suite_id = get_u8(input)?;
        let reserved2_bytes = get_bytes(input, 3)?;
        let mut reserved2 = [0u8; 3];
        reserved2.copy_from_slice(reserved2_bytes);
        let net_pk_len = get_u16(input)? as usize;
        let network_pk = get_bytes(input, net_pk_len)?.to_vec();

        let stake = get_u64(input)?;
        let last_slash_height = get_u64(input)?;

        let ext_len = get_u16(input)? as usize;
        let ext_bytes = get_bytes(input, ext_len)?.to_vec();

        Ok(ValidatorRecord {
            version,
            status,
            reserved0,
            owner_keyset_id,
            consensus_suite_id,
            reserved1,
            consensus_pk,
            network_suite_id,
            reserved2,
            network_pk,
            stake,
            last_slash_height,
            ext_bytes,
        })
    }
}

impl StateEncode for SlashingEvent {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        put_bytes(out, &self.validator_id);
        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &self.reserved1);
    }
}

impl StateDecode for SlashingEvent {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);

        let id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(id_bytes);

        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let reserved1_bytes = get_bytes(input, 7)?;
        let mut reserved1 = [0u8; 7];
        reserved1.copy_from_slice(reserved1_bytes);

        Ok(SlashingEvent {
            version,
            reserved0,
            validator_id,
            height,
            round,
            step,
            reserved1,
        })
    }
}