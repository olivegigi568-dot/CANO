use cano_types::{
    Hash32, MainnetStatus,
    SafetyCouncilKeyAccount, SafetyCouncilKeyset,
    LaunchChecklist, ParamRegistry,
};
use crate::error::StateError;
use crate::io::{StateEncode, StateDecode, put_u8, put_u16, put_bytes, get_u8, get_u16, get_bytes, len_to_u16};

impl StateEncode for SafetyCouncilKeyAccount {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u8(out, self.suite_id);
        put_bytes(out, &self.reserved0);
        let pk_len = self.pk_bytes.len();
        let pk_len_u16 = len_to_u16(pk_len);
        put_u16(out, pk_len_u16);
        put_bytes(out, &self.pk_bytes);
    }
}

impl StateDecode for SafetyCouncilKeyAccount {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let suite_id = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 2)?;
        let mut reserved0 = [0u8; 2];
        reserved0.copy_from_slice(reserved0_bytes);
        let pk_len = get_u16(input)? as usize;
        let pk_bytes = get_bytes(input, pk_len)?.to_vec();

        Ok(SafetyCouncilKeyAccount {
            version,
            suite_id,
            reserved0,
            pk_bytes,
        })
    }
}

impl StateEncode for SafetyCouncilKeyset {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u8(out, self.threshold);
        put_u8(out, self.member_count);
        put_u8(out, self.reserved0);
        for id in &self.members {
            put_bytes(out, id);
        }
    }
}

impl StateDecode for SafetyCouncilKeyset {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let threshold = get_u8(input)?;
        let member_count = get_u8(input)? as usize;
        let reserved0 = get_u8(input)?;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let id_bytes = get_bytes(input, 32)?;
            let mut id = [0u8; 32];
            id.copy_from_slice(id_bytes);
            members.push(id);
        }

        Ok(SafetyCouncilKeyset {
            version,
            threshold,
            member_count: member_count as u8,
            reserved0,
            members,
        })
    }
}

impl StateEncode for LaunchChecklist {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        put_u8(out, self.devnet_ok as u8);
        put_u8(out, self.testnet_ok as u8);
        put_u8(out, self.perf_ok as u8);
        put_u8(out, self.adversarial_ok as u8);
        put_u8(out, self.crypto_audit_ok as u8);
        put_u8(out, self.proto_audit_ok as u8);
        put_u8(out, self.spec_ok as u8);
        put_u8(out, self.reserved1);

        put_bytes(out, &self.devnet_report_hash);
        put_bytes(out, &self.testnet_report_hash);
        put_bytes(out, &self.perf_report_hash);
        put_bytes(out, &self.adversarial_report_hash);
        put_bytes(out, &self.crypto_audit_hash);
        put_bytes(out, &self.proto_audit_hash);
        put_bytes(out, &self.spec_hash);
    }
}

impl StateDecode for LaunchChecklist {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);

        let devnet_ok = get_u8(input)? != 0;
        let testnet_ok = get_u8(input)? != 0;
        let perf_ok = get_u8(input)? != 0;
        let adversarial_ok = get_u8(input)? != 0;
        let crypto_audit_ok = get_u8(input)? != 0;
        let proto_audit_ok = get_u8(input)? != 0;
        let spec_ok = get_u8(input)? != 0;
        let reserved1 = get_u8(input)?;

        fn read_hash(input: &mut &[u8]) -> Result<Hash32, StateError> {
            let bytes = get_bytes(input, 32)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(bytes);
            Ok(h)
        }

        let devnet_report_hash = read_hash(input)?;
        let testnet_report_hash = read_hash(input)?;
        let perf_report_hash = read_hash(input)?;
        let adversarial_report_hash = read_hash(input)?;
        let crypto_audit_hash = read_hash(input)?;
        let proto_audit_hash = read_hash(input)?;
        let spec_hash = read_hash(input)?;

        Ok(LaunchChecklist {
            version,
            reserved0,
            devnet_ok,
            testnet_ok,
            perf_ok,
            adversarial_ok,
            crypto_audit_ok,
            proto_audit_ok,
            spec_ok,
            reserved1,
            devnet_report_hash,
            testnet_report_hash,
            perf_report_hash,
            adversarial_report_hash,
            crypto_audit_hash,
            proto_audit_hash,
            spec_hash,
        })
    }
}

impl StateEncode for ParamRegistry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_u8(out, self.mainnet_status as u8);
        put_bytes(out, &self.reserved0);
        put_u16(out, self.slash_bps_prevote);
        put_u16(out, self.slash_bps_precommit);
        put_u16(out, self.reporter_reward_bps);
        put_u16(out, self.reserved1);
    }
}

impl StateDecode for ParamRegistry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let status = match get_u8(input)? {
            0x00 => MainnetStatus::PreGenesis,
            0x01 => MainnetStatus::Ready,
            0x02 => MainnetStatus::Activated,
            _    => return Err(StateError::InvalidValue("invalid MainnetStatus")),
        };
        let reserved0_bytes = get_bytes(input, 6)?;
        let mut reserved0 = [0u8; 6];
        reserved0.copy_from_slice(reserved0_bytes);
        let slash_bps_prevote = get_u16(input)?;
        let slash_bps_precommit = get_u16(input)?;
        let reporter_reward_bps = get_u16(input)?;
        let reserved1 = get_u16(input)?;

        Ok(ParamRegistry {
            version,
            mainnet_status: status,
            reserved0,
            slash_bps_prevote,
            slash_bps_precommit,
            reporter_reward_bps,
            reserved1,
        })
    }
}