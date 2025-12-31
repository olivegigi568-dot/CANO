use crate::error::WireError;
use crate::io::{WireEncode, WireDecode, put_u8, put_u16, put_u64, put_bytes, get_u8, get_u16, get_u64, get_bytes, len_to_u16};
use cano_types::AccountId;

/// op_code for VALIDATOR_PROGRAM call_data: RegisterValidator
pub const OP_REGISTER_VALIDATOR: u8 = 0x01;
/// op_code for VALIDATOR_PROGRAM call_data: UpdateConsensusKey
pub const OP_UPDATE_CONSENSUS_KEY: u8 = 0x02;
/// op_code for VALIDATOR_PROGRAM call_data: UpdateNetworkKey
pub const OP_UPDATE_NETWORK_KEY: u8 = 0x03;
/// op_code for VALIDATOR_PROGRAM call_data: ReportConsensusEquivocation
pub const OP_REPORT_CONSENSUS_EQUIVOCATION: u8 = 0x10;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProofKind {
    DoublePrevote = 0x01,
    DoublePrecommit = 0x02,
}

impl ProofKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(ProofKind::DoublePrevote),
            0x02 => Some(ProofKind::DoublePrecommit),
            _ => None,
        }
    }
}

/// RegisterValidatorCall wire layout:
/// op_code:          u8   // 0x01 = OP_REGISTER_VALIDATOR
/// version:          u8   // 0x01
/// validator_id:     [u8; 32]
/// owner_keyset_id:  [u8; 32]
/// consensus_suite_id: u8
/// reserved0:        u8   // 0x00
/// cons_pk_len:      u16
/// consensus_pk:     [u8; cons_pk_len]
/// network_suite_id: u8
/// reserved1:        u8   // 0x00
/// net_pk_len:       u16
/// network_pk:       [u8; net_pk_len]
/// stake:            u64  // initial bonded stake units
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterValidatorCall {
    pub version: u8,
    pub validator_id: AccountId,
    pub owner_keyset_id: AccountId,
    pub consensus_suite_id: u8,
    pub consensus_pk: Vec<u8>,
    pub network_suite_id: u8,
    pub network_pk: Vec<u8>,
    pub stake: u64,
}

impl WireEncode for RegisterValidatorCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_REGISTER_VALIDATOR);
        put_u8(out, self.version);
        put_bytes(out, &self.validator_id);
        put_bytes(out, &self.owner_keyset_id);

        put_u8(out, self.consensus_suite_id);
        put_u8(out, 0x00); // reserved0

        let cons_pk_len = self.consensus_pk.len();
        let cons_pk_len_u16 = len_to_u16(cons_pk_len);
        put_u16(out, cons_pk_len_u16);
        put_bytes(out, &self.consensus_pk);

        put_u8(out, self.network_suite_id);
        put_u8(out, 0x00); // reserved1

        let net_pk_len = self.network_pk.len();
        let net_pk_len_u16 = len_to_u16(net_pk_len);
        put_u16(out, net_pk_len_u16);
        put_bytes(out, &self.network_pk);

        put_u64(out, self.stake);
    }
}

impl WireDecode for RegisterValidatorCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op_code = get_u8(input)?;
        if op_code != OP_REGISTER_VALIDATOR {
            return Err(WireError::InvalidValue("unexpected op_code for RegisterValidatorCall"));
        }

        let version = get_u8(input)?;
        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let owner_keyset_id_bytes = get_bytes(input, 32)?;
        let mut owner_keyset_id = [0u8; 32];
        owner_keyset_id.copy_from_slice(owner_keyset_id_bytes);

        let consensus_suite_id = get_u8(input)?;
        let _reserved0 = get_u8(input)?; // consume reserved0

        let cons_pk_len = get_u16(input)? as usize;
        let consensus_pk = get_bytes(input, cons_pk_len)?.to_vec();

        let network_suite_id = get_u8(input)?;
        let _reserved1 = get_u8(input)?; // consume reserved1

        let net_pk_len = get_u16(input)? as usize;
        let network_pk = get_bytes(input, net_pk_len)?.to_vec();

        let stake = get_u64(input)?;

        Ok(RegisterValidatorCall {
            version,
            validator_id,
            owner_keyset_id,
            consensus_suite_id,
            consensus_pk,
            network_suite_id,
            network_pk,
            stake,
        })
    }
}

/// UpdateConsensusKeyCall wire layout:
/// op_code:               u8   // 0x02 = OP_UPDATE_CONSENSUS_KEY
/// version:               u8   // 0x01
/// validator_id:          [u8; 32]
/// new_consensus_suite_id: u8
/// reserved0:             u8   // 0x00
/// new_cons_pk_len:       u16
/// new_consensus_pk:      [u8; new_cons_pk_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateConsensusKeyCall {
    pub version: u8,
    pub validator_id: AccountId,
    pub new_consensus_suite_id: u8,
    pub new_consensus_pk: Vec<u8>,
}

impl WireEncode for UpdateConsensusKeyCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_UPDATE_CONSENSUS_KEY);
        put_u8(out, self.version);
        put_bytes(out, &self.validator_id);

        put_u8(out, self.new_consensus_suite_id);
        put_u8(out, 0x00); // reserved0

        let new_cons_pk_len = self.new_consensus_pk.len();
        let new_cons_pk_len_u16 = len_to_u16(new_cons_pk_len);
        put_u16(out, new_cons_pk_len_u16);
        put_bytes(out, &self.new_consensus_pk);
    }
}

impl WireDecode for UpdateConsensusKeyCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op_code = get_u8(input)?;
        if op_code != OP_UPDATE_CONSENSUS_KEY {
            return Err(WireError::InvalidValue("unexpected op_code for UpdateConsensusKeyCall"));
        }

        let version = get_u8(input)?;
        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let new_consensus_suite_id = get_u8(input)?;
        let _reserved0 = get_u8(input)?; // consume reserved0

        let new_cons_pk_len = get_u16(input)? as usize;
        let new_consensus_pk = get_bytes(input, new_cons_pk_len)?.to_vec();

        Ok(UpdateConsensusKeyCall {
            version,
            validator_id,
            new_consensus_suite_id,
            new_consensus_pk,
        })
    }
}

/// UpdateNetworkKeyCall wire layout:
/// op_code:               u8   // 0x03 = OP_UPDATE_NETWORK_KEY
/// version:               u8   // 0x01
/// validator_id:          [u8; 32]
/// new_network_suite_id:  u8
/// reserved0:             u8   // 0x00
/// new_net_pk_len:        u16
/// new_network_pk:        [u8; new_net_pk_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateNetworkKeyCall {
    pub version: u8,
    pub validator_id: AccountId,
    pub new_network_suite_id: u8,
    pub new_network_pk: Vec<u8>,
}

impl WireEncode for UpdateNetworkKeyCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_UPDATE_NETWORK_KEY);
        put_u8(out, self.version);
        put_bytes(out, &self.validator_id);

        put_u8(out, self.new_network_suite_id);
        put_u8(out, 0x00); // reserved0

        let new_net_pk_len = self.new_network_pk.len();
        let new_net_pk_len_u16 = len_to_u16(new_net_pk_len);
        put_u16(out, new_net_pk_len_u16);
        put_bytes(out, &self.new_network_pk);
    }
}

impl WireDecode for UpdateNetworkKeyCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op_code = get_u8(input)?;
        if op_code != OP_UPDATE_NETWORK_KEY {
            return Err(WireError::InvalidValue("unexpected op_code for UpdateNetworkKeyCall"));
        }

        let version = get_u8(input)?;
        let validator_id_bytes = get_bytes(input, 32)?;
        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(validator_id_bytes);

        let new_network_suite_id = get_u8(input)?;
        let _reserved0 = get_u8(input)?; // consume reserved0

        let new_net_pk_len = get_u16(input)? as usize;
        let new_network_pk = get_bytes(input, new_net_pk_len)?.to_vec();

        Ok(UpdateNetworkKeyCall {
            version,
            validator_id,
            new_network_suite_id,
            new_network_pk,
        })
    }
}

/// SlashingProofCall wire layout:
/// op_code: u8 // 0x10
/// proof_kind: u8 // 0x01 or 0x02
/// reserved0: [u8; 2] // zeros
/// height: u64
/// round: u64
/// step: u8
/// reserved1: [u8; 7] // zeros
/// validator_index: u16
/// reserved2: [u8; 2] // zeros
/// vote1_len: u16
/// vote2_len: u16
/// vote1_bytes: [u8; vote1_len]
/// vote2_bytes: [u8; vote2_len]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingProofCall {
    pub proof_kind: ProofKind,
    pub height: u64,
    pub round: u64,
    pub step: u8,
    pub validator_index: u16,
    pub vote1: Vec<u8>, // raw Vote message bytes
    pub vote2: Vec<u8>,
}

impl WireEncode for SlashingProofCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_REPORT_CONSENSUS_EQUIVOCATION);
        put_u8(out, self.proof_kind as u8);
        put_bytes(out, &[0u8; 2]); // reserved0

        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &[0u8; 7]); // reserved1

        put_u16(out, self.validator_index);
        put_bytes(out, &[0u8; 2]); // reserved2

        let vote1_len = self.vote1.len();
        let vote1_len_u16 = len_to_u16(vote1_len);
        let vote2_len = self.vote2.len();
        let vote2_len_u16 = len_to_u16(vote2_len);

        put_u16(out, vote1_len_u16);
        put_u16(out, vote2_len_u16);
        put_bytes(out, &self.vote1);
        put_bytes(out, &self.vote2);
    }
}

impl WireDecode for SlashingProofCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op_code = get_u8(input)?;
        if op_code != OP_REPORT_CONSENSUS_EQUIVOCATION {
            return Err(WireError::InvalidValue("unexpected op_code for SlashingProofCall"));
        }

        let proof_kind_byte = get_u8(input)?;
        let proof_kind = ProofKind::from_u8(proof_kind_byte)
            .ok_or(WireError::InvalidValue("unknown proof_kind"))?;

        let _reserved0 = get_bytes(input, 2)?; // consume reserved0

        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let _reserved1 = get_bytes(input, 7)?; // consume reserved1

        let validator_index = get_u16(input)?;
        let _reserved2 = get_bytes(input, 2)?; // consume reserved2

        let vote1_len = get_u16(input)? as usize;
        let vote2_len = get_u16(input)? as usize;

        let vote1 = get_bytes(input, vote1_len)?.to_vec();
        let vote2 = get_bytes(input, vote2_len)?.to_vec();

        Ok(SlashingProofCall {
            proof_kind,
            height,
            round,
            step,
            validator_index,
            vote1,
            vote2,
        })
    }
}