use crate::access_mask::{
    GenericMapping, NormalizedDesiredAccess, ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_READ,
    GENERIC_WRITE, WRITE_DAC, WRITE_OWNER,
};
use crate::error::KacsResult;

/// Privilege-intent flag enabling backup semantics for AccessCheck.
pub const BACKUP_INTENT: u32 = 0x0000_0001;
/// Privilege-intent flag enabling restore semantics for AccessCheck.
pub const RESTORE_INTENT: u32 = 0x0000_0002;

/// Bit position for `SeSecurityPrivilege`.
pub const SE_SECURITY_PRIVILEGE: u64 = 1u64 << 8;
/// Bit position for `SeTakeOwnershipPrivilege`.
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u64 = 1u64 << 9;
/// Bit position for `SeBackupPrivilege`.
pub const SE_BACKUP_PRIVILEGE: u64 = 1u64 << 17;
/// Bit position for `SeRestorePrivilege`.
pub const SE_RESTORE_PRIVILEGE: u64 = 1u64 << 18;
/// Bit position for `SeRelabelPrivilege`.
pub const SE_RELABEL_PRIVILEGE: u64 = 1u64 << 32;

/// Token privilege bitmap state used by the slow-track core.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenPrivileges {
    /// Privileges present on the token.
    pub present: u64,
    /// Privileges currently enabled on the token.
    pub enabled: u64,
    /// Privileges enabled by default on the token.
    pub enabled_by_default: u64,
    /// Privileges marked as used by successful step-13 accounting.
    pub used: u64,
}

impl TokenPrivileges {
    /// Returns the mask of present and enabled privileges.
    pub fn enabled_mask(&self) -> u64 {
        self.present & self.enabled
    }

    /// Returns whether a specific privilege bit is enabled.
    pub fn privilege_enabled(&self, privilege: u64) -> bool {
        (self.enabled_mask() & privilege) != 0
    }

    /// Returns the privilege mask that can participate in AccessCheck after
    /// applying the caller's privilege-intent flags.
    pub fn effective_access_check_mask(&self, privilege_intent: u32) -> u64 {
        let mut effective = self.enabled_mask();
        if (privilege_intent & BACKUP_INTENT) == 0 {
            effective &= !SE_BACKUP_PRIVILEGE;
        }
        if (privilege_intent & RESTORE_INTENT) == 0 {
            effective &= !SE_RESTORE_PRIVILEGE;
        }
        effective
    }
}

/// Per-privilege provenance used to track which bits were granted by each
/// privilege.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrivilegeProvenance {
    /// Bits granted by `SeSecurityPrivilege`.
    pub security_granted: u32,
    /// Bits granted by `SeBackupPrivilege`.
    pub backup_granted: u32,
    /// Bits granted by `SeRestorePrivilege`.
    pub restore_granted: u32,
    /// Bits granted by `SeTakeOwnershipPrivilege`.
    pub take_ownership_granted: u32,
    /// Bits for which `SeRelabelPrivilege` loosened MIC.
    pub relabel_granted: u32,
}

impl PrivilegeProvenance {
    /// Returns the subset of provenance that counts as privilege-granted access
    /// for restricted-pass restoration.
    pub fn privilege_granted(&self) -> u32 {
        self.security_granted
            | self.backup_granted
            | self.restore_granted
            | self.take_ownership_granted
    }
}

/// Simple decided/granted pair used while merging access states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessDecisionState {
    /// Bits already decided.
    pub decided: u32,
    /// Bits currently granted.
    pub granted: u32,
}

/// Result of the initial privilege seeding step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegeGrantState {
    /// Effective privilege mask after intent filtering.
    pub effective_privileges: u64,
    /// Bits decided during privilege seeding.
    pub decided: u32,
    /// Bits granted during privilege seeding.
    pub granted: u32,
    /// Detailed per-privilege provenance.
    pub provenance: PrivilegeProvenance,
}

impl PrivilegeGrantState {
    /// Returns the combined privilege-granted bits from this seeding result.
    pub fn privilege_granted(&self) -> u32 {
        self.provenance.privilege_granted()
    }
}

/// Seeds privilege-granted access before SACL, DACL, CAAP, and later narrowing
/// steps run.
pub fn seed_access_check_privileges(
    privileges: &TokenPrivileges,
    mapping: &GenericMapping,
    privilege_intent: u32,
) -> KacsResult<PrivilegeGrantState> {
    let effective_privileges = privileges.effective_access_check_mask(privilege_intent);
    let mut decided = ACCESS_SYSTEM_SECURITY;
    let mut granted = 0u32;
    let mut provenance = PrivilegeProvenance::default();

    if (effective_privileges & SE_SECURITY_PRIVILEGE) != 0 {
        granted |= ACCESS_SYSTEM_SECURITY;
        provenance.security_granted |= ACCESS_SYSTEM_SECURITY;
    }

    if (effective_privileges & SE_BACKUP_PRIVILEGE) != 0 {
        let backup_bits = mapping.map_mask(GENERIC_READ)?;
        decided |= backup_bits;
        granted |= backup_bits;
        provenance.backup_granted |= backup_bits;
    }

    if (effective_privileges & SE_RESTORE_PRIVILEGE) != 0 {
        let restore_bits = mapping.map_mask(GENERIC_WRITE)?
            | WRITE_DAC
            | WRITE_OWNER
            | DELETE
            | ACCESS_SYSTEM_SECURITY;
        decided |= restore_bits;
        granted |= restore_bits;
        provenance.restore_granted |= restore_bits;
    }

    Ok(PrivilegeGrantState {
        effective_privileges,
        decided,
        granted,
        provenance,
    })
}

/// Applies the `SeTakeOwnershipPrivilege` fallback after earlier mandatory and
/// DACL steps have run.
pub fn apply_take_ownership_fallback(
    scalar: &mut AccessDecisionState,
    object_states: Option<&mut [AccessDecisionState]>,
    normalized: &NormalizedDesiredAccess,
    effective_privileges: u64,
    mandatory_decided: u32,
    provenance: &mut PrivilegeProvenance,
) {
    let write_owner_requested =
        (normalized.mapped & WRITE_OWNER) != 0 || normalized.maximum_allowed;
    if !write_owner_requested {
        return;
    }
    if (effective_privileges & SE_TAKE_OWNERSHIP_PRIVILEGE) == 0 {
        return;
    }
    if (mandatory_decided & WRITE_OWNER) != 0 {
        return;
    }
    if (scalar.granted & WRITE_OWNER) != 0 {
        return;
    }

    scalar.decided |= WRITE_OWNER;
    scalar.granted |= WRITE_OWNER;
    provenance.take_ownership_granted |= WRITE_OWNER;

    if let Some(states) = object_states {
        for state in states.iter_mut() {
            if (state.granted & WRITE_OWNER) == 0 {
                state.decided |= WRITE_OWNER;
                state.granted |= WRITE_OWNER;
            }
        }
    }
}
