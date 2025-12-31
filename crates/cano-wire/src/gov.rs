//! Governance call_data structs and codecs for GOVERNANCE_PROGRAM transactions.

use cano_types::{Hash32, MainnetStatus};
use crate::error::WireError;
use crate::io::{
    WireEncode, WireDecode,
    put_u8, put_u16, put_u64, put_bytes,
    get_u8, get_u16, get_u64, get_bytes,
};

pub const OP_GOV_UPDATE_SUITE_STATUS:      u8 = 0x20;
pub const OP_GOV_UPDATE_PARAM_REGISTRY:    u8 = 0x21;
pub const OP_GOV_UPDATE_LAUNCH_CHECKLIST:  u8 = 0x22;
pub const OP_GOV_SET_MAINNET_STATUS:       u8 = 0x23;

// -----------------------------------------------------------------------------
// GovUpdateSuiteStatusCall
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovUpdateSuiteStatusCall {
    pub version:     u8,
    pub suite_id:    u8,
    pub new_status:  u8,
    pub proposal_id: u64,
    pub eta_height:  u64,
}

impl WireEncode for GovUpdateSuiteStatusCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_GOV_UPDATE_SUITE_STATUS);
        put_u8(out, self.version);
        put_u8(out, self.suite_id);
        put_u8(out, self.new_status);
        // reserved0
        put_bytes(out, &[0u8; 4]);
        put_u64(out, self.proposal_id);
        put_u64(out, self.eta_height);
    }
}

impl WireDecode for GovUpdateSuiteStatusCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_GOV_UPDATE_SUITE_STATUS {
            return Err(WireError::InvalidValue("unexpected op_code for GovUpdateSuiteStatusCall"));
        }
        let version = get_u8(input)?;
        let suite_id = get_u8(input)?;
        let new_status = get_u8(input)?;
        // reserved0
        let _r0 = get_bytes(input, 4)?;
        let proposal_id = get_u64(input)?;
        let eta_height = get_u64(input)?;
        Ok(GovUpdateSuiteStatusCall {
            version,
            suite_id,
            new_status,
            proposal_id,
            eta_height,
        })
    }
}

// -----------------------------------------------------------------------------
// GovUpdateParamRegistryCall
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovUpdateParamRegistryCall {
    pub version:             u8,
    pub proposal_id:         u64,
    pub eta_height:          u64,
    pub slash_bps_prevote:   u16,
    pub slash_bps_precommit: u16,
    pub reporter_reward_bps: u16,
}

impl WireEncode for GovUpdateParamRegistryCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_GOV_UPDATE_PARAM_REGISTRY);
        put_u8(out, self.version);
        // reserved0
        put_bytes(out, &[0u8; 2]);
        put_u64(out, self.proposal_id);
        put_u64(out, self.eta_height);
        put_u16(out, self.slash_bps_prevote);
        put_u16(out, self.slash_bps_precommit);
        put_u16(out, self.reporter_reward_bps);
        // reserved1
        put_bytes(out, &[0u8; 2]);
    }
}

impl WireDecode for GovUpdateParamRegistryCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_GOV_UPDATE_PARAM_REGISTRY {
            return Err(WireError::InvalidValue("unexpected op_code for GovUpdateParamRegistryCall"));
        }
        let version = get_u8(input)?;
        let _r0 = get_bytes(input, 2)?;
        let proposal_id = get_u64(input)?;
        let eta_height = get_u64(input)?;
        let slash_bps_prevote = get_u16(input)?;
        let slash_bps_precommit = get_u16(input)?;
        let reporter_reward_bps = get_u16(input)?;
        let _r1 = get_bytes(input, 2)?;
        Ok(GovUpdateParamRegistryCall {
            version,
            proposal_id,
            eta_height,
            slash_bps_prevote,
            slash_bps_precommit,
            reporter_reward_bps,
        })
    }
}

// -----------------------------------------------------------------------------
// GovUpdateLaunchChecklistCall
// -----------------------------------------------------------------------------

fn put_hash(out: &mut Vec<u8>, h: &Hash32) {
    put_bytes(out, h);
}

fn get_hash(input: &mut &[u8]) -> Result<Hash32, WireError> {
    let bytes = get_bytes(input, 32)?;
    let mut h = [0u8; 32];
    h.copy_from_slice(bytes);
    Ok(h)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovUpdateLaunchChecklistCall {
    pub version:               u8,
    pub proposal_id:           u64,
    pub eta_height:            u64,
    pub devnet_ok:             bool,
    pub testnet_ok:            bool,
    pub perf_ok:               bool,
    pub adversarial_ok:        bool,
    pub crypto_audit_ok:       bool,
    pub proto_audit_ok:        bool,
    pub spec_ok:               bool,
    pub devnet_report_hash:    Hash32,
    pub testnet_report_hash:   Hash32,
    pub perf_report_hash:      Hash32,
    pub adversarial_report_hash: Hash32,
    pub crypto_audit_hash:     Hash32,
    pub proto_audit_hash:      Hash32,
    pub spec_hash:             Hash32,
}

impl WireEncode for GovUpdateLaunchChecklistCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_GOV_UPDATE_LAUNCH_CHECKLIST);
        put_u8(out, self.version);
        // reserved0
        put_bytes(out, &[0u8; 2]);
        put_u64(out, self.proposal_id);
        put_u64(out, self.eta_height);

        put_u8(out, self.devnet_ok as u8);
        put_u8(out, self.testnet_ok as u8);
        put_u8(out, self.perf_ok as u8);
        put_u8(out, self.adversarial_ok as u8);
        put_u8(out, self.crypto_audit_ok as u8);
        put_u8(out, self.proto_audit_ok as u8);
        put_u8(out, self.spec_ok as u8);
        // reserved1
        put_u8(out, 0);

        put_hash(out, &self.devnet_report_hash);
        put_hash(out, &self.testnet_report_hash);
        put_hash(out, &self.perf_report_hash);
        put_hash(out, &self.adversarial_report_hash);
        put_hash(out, &self.crypto_audit_hash);
        put_hash(out, &self.proto_audit_hash);
        put_hash(out, &self.spec_hash);
    }
}

impl WireDecode for GovUpdateLaunchChecklistCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_GOV_UPDATE_LAUNCH_CHECKLIST {
            return Err(WireError::InvalidValue("unexpected op_code for GovUpdateLaunchChecklistCall"));
        }
        let version = get_u8(input)?;
        let _r0 = get_bytes(input, 2)?;
        let proposal_id = get_u64(input)?;
        let eta_height = get_u64(input)?;

        let devnet_ok       = get_u8(input)? != 0;
        let testnet_ok      = get_u8(input)? != 0;
        let perf_ok         = get_u8(input)? != 0;
        let adversarial_ok  = get_u8(input)? != 0;
        let crypto_audit_ok = get_u8(input)? != 0;
        let proto_audit_ok  = get_u8(input)? != 0;
        let spec_ok         = get_u8(input)? != 0;
        let _r1 = get_u8(input)?; // reserved1

        let devnet_report_hash        = get_hash(input)?;
        let testnet_report_hash       = get_hash(input)?;
        let perf_report_hash          = get_hash(input)?;
        let adversarial_report_hash   = get_hash(input)?;
        let crypto_audit_hash         = get_hash(input)?;
        let proto_audit_hash          = get_hash(input)?;
        let spec_hash                 = get_hash(input)?;

        Ok(GovUpdateLaunchChecklistCall {
            version,
            proposal_id,
            eta_height,
            devnet_ok,
            testnet_ok,
            perf_ok,
            adversarial_ok,
            crypto_audit_ok,
            proto_audit_ok,
            spec_ok,
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

// -----------------------------------------------------------------------------
// GovSetMainnetStatusCall
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovSetMainnetStatusCall {
    pub version:     u8,
    pub new_status:  MainnetStatus,
    pub proposal_id: u64,
    pub eta_height:  u64,
}

impl WireEncode for GovSetMainnetStatusCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_GOV_SET_MAINNET_STATUS);
        put_u8(out, self.version);
        put_u8(out, self.new_status as u8);
        put_u8(out, 0); // reserved0
        put_u64(out, self.proposal_id);
        put_u64(out, self.eta_height);
    }
}

impl WireDecode for GovSetMainnetStatusCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_GOV_SET_MAINNET_STATUS {
            return Err(WireError::InvalidValue("unexpected op_code for GovSetMainnetStatusCall"));
        }
        let version = get_u8(input)?;
        let status_byte = get_u8(input)?;
        let status = match status_byte {
            0x00 => MainnetStatus::PreGenesis,
            0x01 => MainnetStatus::Ready,
            0x02 => MainnetStatus::Activated,
            _    => return Err(WireError::InvalidValue("invalid MainnetStatus")),
        };
        let _r0 = get_u8(input)?; // reserved0
        let proposal_id = get_u64(input)?;
        let eta_height = get_u64(input)?;
        Ok(GovSetMainnetStatusCall {
            version,
            new_status: status,
            proposal_id,
            eta_height,
        })
    }
}