use cano_wire::gov::{
    OP_GOV_UPDATE_SUITE_STATUS,
    OP_GOV_UPDATE_PARAM_REGISTRY,
    OP_GOV_UPDATE_LAUNCH_CHECKLIST,
    OP_GOV_SET_MAINNET_STATUS,
    GovUpdateSuiteStatusCall,
    GovUpdateParamRegistryCall,
    GovUpdateLaunchChecklistCall,
    GovSetMainnetStatusCall,
};
use cano_wire::io::{WireEncode, WireDecode};
use cano_types::{Hash32, MainnetStatus};

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

#[test]
fn gov_update_suite_status_roundtrip() {
    let call = GovUpdateSuiteStatusCall {
        version: 1,
        suite_id: 0x01,
        new_status: 0x02,
        proposal_id: 42,
        eta_height: 1_000,
    };
    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_GOV_UPDATE_SUITE_STATUS);

    let mut slice: &[u8] = &buf;
    let decoded = GovUpdateSuiteStatusCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn gov_update_param_registry_roundtrip() {
    let call = GovUpdateParamRegistryCall {
        version: 1,
        proposal_id: 7,
        eta_height: 2_000,
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 50,
    };
    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_GOV_UPDATE_PARAM_REGISTRY);

    let mut slice: &[u8] = &buf;
    let decoded = GovUpdateParamRegistryCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn gov_update_launch_checklist_roundtrip() {
    let call = GovUpdateLaunchChecklistCall {
        version: 1,
        proposal_id: 9,
        eta_height: 3_000,
        devnet_ok: true,
        testnet_ok: true,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: true,
        proto_audit_ok: false,
        spec_ok: true,
        devnet_report_hash: zero_hash(),
        testnet_report_hash: zero_hash(),
        perf_report_hash: zero_hash(),
        adversarial_report_hash: zero_hash(),
        crypto_audit_hash: zero_hash(),
        proto_audit_hash: zero_hash(),
        spec_hash: zero_hash(),
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_GOV_UPDATE_LAUNCH_CHECKLIST);

    let mut slice: &[u8] = &buf;
    let decoded = GovUpdateLaunchChecklistCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}

#[test]
fn gov_set_mainnet_status_roundtrip() {
    let call = GovSetMainnetStatusCall {
        version: 1,
        new_status: MainnetStatus::Ready,
        proposal_id: 11,
        eta_height: 4_000,
    };

    let mut buf = Vec::new();
    call.encode(&mut buf);
    assert_eq!(buf[0], OP_GOV_SET_MAINNET_STATUS);

    let mut slice: &[u8] = &buf;
    let decoded = GovSetMainnetStatusCall::decode(&mut slice).expect("decode");
    assert_eq!(decoded, call);
    assert!(slice.is_empty());
}