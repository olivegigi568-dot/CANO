//! Core primitives and enums for cano post-quantum blockchain.

pub type AccountId = [u8; 32];
pub type ProgramId = [u8; 32];
pub type Hash32 = [u8; 32];

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteFamily {
    Lattice = 0x00,
    HashBased = 0x01,
    CodeBased = 0x02,
    Isogeny = 0x03,
    Reserved = 0xFF,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecurityCategory {
    Cat1 = 0x01,
    Cat3 = 0x03,
    Cat5 = 0x05,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteTier {
    Core = 0x00,
    Experimental = 0x01,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuiteStatus {
    Active = 0x00,
    Legacy = 0x01,
    Disabled = 0x02,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    ValidatorOwner = 0x00,
    ValidatorConsensus = 0x01,
    ValidatorNetwork = 0x02,
    Governance = 0x03,
    BridgeOperator = 0x04,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MainnetStatus {
    PreGenesis = 0x00,
    Ready = 0x01,
    Activated = 0x02,
}
