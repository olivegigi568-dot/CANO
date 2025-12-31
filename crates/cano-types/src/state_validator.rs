//! ValidatorRecord and SlashingEvent state types for cano.

use crate::primitives::AccountId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ValidatorStatus {
    Inactive = 0,
    Active = 1,
    Jailed = 2,
    Exiting = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRecord {
    pub version: u8,
    pub status: ValidatorStatus,
    pub reserved0: [u8; 2],
    pub owner_keyset_id: AccountId,
    pub consensus_suite_id: u8,
    pub reserved1: [u8; 3],
    pub consensus_pk: Vec<u8>,
    pub network_suite_id: u8,
    pub reserved2: [u8; 3],
    pub network_pk: Vec<u8>,
    pub stake: u64,
    pub last_slash_height: u64,
    pub ext_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvent {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub validator_id: AccountId,
    pub height: u64,
    pub round: u64,
    pub step: u8,
    pub reserved1: [u8; 7],
}
