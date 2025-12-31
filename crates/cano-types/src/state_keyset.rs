//! KeysetEntry and KeysetAccount state types for cano.

/// Represents one public key in a keyset, with a suite and voting weight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysetEntry {
    pub suite_id: u8,
    pub weight: u16,
    pub reserved0: [u8; 1],
    pub pubkey_len: u16,
    pub pubkey_bytes: Vec<u8>,
}

/// On-chain account storing a weighted multisig keyset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysetAccount {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub threshold: u16,
    pub entry_count: u16,
    pub reserved1: [u8; 4],
    pub entries: Vec<KeysetEntry>,
}