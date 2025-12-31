//! KeyRolePolicy state types for cano.

use crate::primitives::{Role, SecurityCategory};

// Tier mask constants for allowed_tiers field.
/// Core tier only (bit 0).
pub const TIER_MASK_CORE: u8 = 0x01;
/// Experimental tier only (bit 1).
pub const TIER_MASK_EXPERIMENTAL: u8 = 0x02;
/// Both Core and Experimental tiers.
pub const TIER_MASK_BOTH: u8 = TIER_MASK_CORE | TIER_MASK_EXPERIMENTAL;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePolicyEntry {
    pub role_id: Role,
    pub min_category: SecurityCategory,
    /// Bit 0 = Core allowed, Bit 1 = Experimental allowed.
    pub allowed_tiers: u8,
    /// 0 = false, 1 = true.
    pub allow_legacy: u8,
    pub reserved0: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRolePolicy {
    pub version: u8,
    pub reserved0: [u8; 3],
    pub role_count: u16,
    pub reserved1: u16,
    pub roles: Vec<RolePolicyEntry>,
}

/// Canonical KeyRolePolicy for cano v1 genesis.
///
/// Policy enforces:
/// - ValidatorOwner: Cat5 Core only (no Cat1, no Experimental)
/// - ValidatorConsensus: Cat3+ Core only (ML-DSA-65 or ML-DSA-87)
/// - ValidatorNetwork: Cat3+ Core or Experimental
/// - Governance: Cat5 Core or Experimental
/// - BridgeOperator: Cat3+ Core only
pub fn genesis_key_role_policy() -> KeyRolePolicy {
    let roles = vec![
        // ValidatorOwner: only Cat5 Core allowed (no Cat1, no Experimental).
        RolePolicyEntry {
            role_id: Role::ValidatorOwner,
            min_category: SecurityCategory::Cat5,
            allowed_tiers: TIER_MASK_CORE,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        // ValidatorConsensus: Cat3+ Core allowed (65 or 87).
        RolePolicyEntry {
            role_id: Role::ValidatorConsensus,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: TIER_MASK_CORE,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        // ValidatorNetwork: Cat3+ Core or Experimental allowed.
        RolePolicyEntry {
            role_id: Role::ValidatorNetwork,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: TIER_MASK_BOTH,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        // Governance: Cat5 Core or Experimental.
        RolePolicyEntry {
            role_id: Role::Governance,
            min_category: SecurityCategory::Cat5,
            allowed_tiers: TIER_MASK_BOTH,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
        // BridgeOperator: Cat3+ Core only.
        RolePolicyEntry {
            role_id: Role::BridgeOperator,
            min_category: SecurityCategory::Cat3,
            allowed_tiers: TIER_MASK_CORE,
            allow_legacy: 0,
            reserved0: [0u8; 4],
        },
    ];

    KeyRolePolicy {
        version: 1,
        reserved0: [0u8; 3],
        role_count: roles.len() as u16,
        reserved1: 0,
        roles,
    }
}