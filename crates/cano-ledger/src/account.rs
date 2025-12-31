use cano_types::{AccountId, ProgramId};

/// Minimal generic account header, similar in spirit to Solana.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountHeader {
    pub owner: ProgramId,
    pub lamports: u64,
    pub is_executable: bool,
    pub rent_epoch: u64,
    pub reserved: [u8; 8],
}

/// Full in-memory account representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub header: AccountHeader,
    pub data: Vec<u8>,
}

impl Account {
    pub fn new(id: AccountId, owner: ProgramId, lamports: u64, data: Vec<u8>) -> Self {
        Account {
            id,
            header: AccountHeader {
                owner,
                lamports,
                is_executable: false,
                rent_epoch: 0,
                reserved: [0u8; 8],
            },
            data,
        }
    }

    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}