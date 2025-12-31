//! Governance-related state types for cano.

use crate::primitives::{AccountId, Hash32, MainnetStatus};
use crate::state_suite::SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyCouncilKeyAccount {
    pub version: u8,
    pub suite_id: u8,
    pub reserved0: [u8; 2],
    pub pk_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyCouncilKeyset {
    pub version: u8,
    pub threshold: u8,
    pub member_count: u8,
    pub reserved0: u8,
    pub members: Vec<AccountId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchChecklist {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub devnet_ok: bool,
    pub testnet_ok: bool,
    pub perf_ok: bool,
    pub adversarial_ok: bool,
    pub crypto_audit_ok: bool,
    pub proto_audit_ok: bool,
    pub spec_ok: bool,
    pub reserved1: u8,
    pub devnet_report_hash: Hash32,
    pub testnet_report_hash: Hash32,
    pub perf_report_hash: Hash32,
    pub adversarial_report_hash: Hash32,
    pub crypto_audit_hash: Hash32,
    pub proto_audit_hash: Hash32,
    pub spec_hash: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamRegistry {
    pub version: u8,
    pub mainnet_status: MainnetStatus,
    pub reserved0: [u8; 6],
    // slashing parameters (basis points out of 10_000)
    pub slash_bps_prevote: u16,
    pub slash_bps_precommit: u16,
    pub reporter_reward_bps: u16,
    pub reserved1: u16,
    // future: other global params (validator caps, epochs, etc.)
}

/// Canonical SafetyCouncilKeyset for cano v1 genesis.
///
/// We model a 5-of-7 council over a single Cat-5 lattice suite (ML-DSA-87).
/// The member AccountIds reference `SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS` from
/// `cano_system::governance_program`.
pub fn genesis_safety_council_keyset(member_ids: &[AccountId; 7]) -> SafetyCouncilKeyset {
    SafetyCouncilKeyset {
        version: 1,
        threshold: 5,
        member_count: 7,
        reserved0: 0,
        members: member_ids.to_vec(),
    }
}

/// Canonical SafetyCouncilKeyAccount entries for cano v1 genesis.
///
/// Returns 7 SafetyCouncilKeyAccount entries, each using the Cat-5 lattice
/// suite (ML-DSA-87) and placeholder public key bytes. In production,
/// operators should replace these with real keys.
pub fn genesis_safety_council_accounts() -> Vec<SafetyCouncilKeyAccount> {
    (0..7)
        .map(|i| {
            // Distinct placeholder keys for each member to avoid accidental reuse.
            // Byte pattern: 0xD1 for member 0, 0xD2 for member 1, etc.
            let pk_byte = 0xD1u8 + i;
            SafetyCouncilKeyAccount {
                version: 1,
                suite_id: SUITE_ID_LATTICE_L5_MLDSA87_MLKEM1024,
                reserved0: [0u8; 2],
                pk_bytes: vec![pk_byte; 32],
            }
        })
        .collect()
}