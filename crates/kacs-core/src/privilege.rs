use crate::access_mask::{
    GenericMapping, NormalizedDesiredAccess, ACCESS_SYSTEM_SECURITY, DELETE, GENERIC_READ,
    GENERIC_WRITE, WRITE_DAC, WRITE_OWNER,
};
use crate::error::KacsResult;

pub const BACKUP_INTENT: u32 = 0x0000_0001;
pub const RESTORE_INTENT: u32 = 0x0000_0002;

pub const SE_SECURITY_PRIVILEGE: u64 = 1u64 << 8;
pub const SE_TAKE_OWNERSHIP_PRIVILEGE: u64 = 1u64 << 9;
pub const SE_BACKUP_PRIVILEGE: u64 = 1u64 << 17;
pub const SE_RESTORE_PRIVILEGE: u64 = 1u64 << 18;
pub const SE_RELABEL_PRIVILEGE: u64 = 1u64 << 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenPrivileges {
    pub present: u64,
    pub enabled: u64,
    pub enabled_by_default: u64,
    pub used: u64,
}

impl TokenPrivileges {
    pub fn enabled_mask(&self) -> u64 {
        self.present & self.enabled
    }

    pub fn privilege_enabled(&self, privilege: u64) -> bool {
        (self.enabled_mask() & privilege) != 0
    }

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PrivilegeProvenance {
    pub security_granted: u32,
    pub backup_granted: u32,
    pub restore_granted: u32,
    pub take_ownership_granted: u32,
    pub relabel_granted: u32,
}

impl PrivilegeProvenance {
    pub fn privilege_granted(&self) -> u32 {
        self.security_granted
            | self.backup_granted
            | self.restore_granted
            | self.take_ownership_granted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessDecisionState {
    pub decided: u32,
    pub granted: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivilegeGrantState {
    pub effective_privileges: u64,
    pub decided: u32,
    pub granted: u32,
    pub provenance: PrivilegeProvenance,
}

impl PrivilegeGrantState {
    pub fn privilege_granted(&self) -> u32 {
        self.provenance.privilege_granted()
    }
}

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
