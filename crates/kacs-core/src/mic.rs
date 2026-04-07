use crate::access_mask::{
    GenericMapping, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, WRITE_OWNER,
};
use crate::ace::{AceKind, SYSTEM_MANDATORY_LABEL_ACE_TYPE};
use crate::error::{KacsError, KacsResult};
use crate::privilege::{PrivilegeProvenance, SE_RELABEL_PRIVILEGE};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

pub const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 = 0x0000_0001;
pub const TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: u32 = 0x0000_0002;

pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x0000_0001;
pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;
pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x0000_0004;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 4096,
    Medium = 8192,
    High = 12288,
    System = 16384,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryLabel {
    pub integrity_level: IntegrityLevel,
    pub mask: u32,
    pub explicit: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MicEnforcementState {
    pub mandatory_decided: u32,
}

pub fn resolve_mandatory_label(sd: &SecurityDescriptor<'_>) -> KacsResult<MandatoryLabel> {
    let Some(sacl) = sd.sacl() else {
        return Ok(default_mandatory_label());
    };

    for ace in sacl.entries() {
        let ace = ace?;
        if ace.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        let AceKind::SingleSid { mask, sid } = ace.kind() else {
            return Err(KacsError::InvalidMandatoryLabelSid);
        };
        return Ok(MandatoryLabel {
            integrity_level: integrity_level_from_sid(sid)?,
            mask,
            explicit: true,
        });
    }

    Ok(default_mandatory_label())
}

pub fn apply_mic(
    label: MandatoryLabel,
    token_integrity: IntegrityLevel,
    mandatory_policy: u32,
    effective_privileges: u64,
    mapping: &GenericMapping,
    decided: &mut u32,
    provenance: &mut PrivilegeProvenance,
) -> KacsResult<MicEnforcementState> {
    if (mandatory_policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP) == 0 {
        return Ok(MicEnforcementState::default());
    }

    if token_integrity >= label.integrity_level {
        return Ok(MicEnforcementState::default());
    }

    let mut allowed = mapping.map_mask(GENERIC_READ)? | mapping.map_mask(GENERIC_EXECUTE)?;

    if (label.mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP) != 0 {
        allowed &= !mapping.map_mask(GENERIC_READ)?;
    }
    if (label.mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP) != 0 {
        allowed &= !mapping.map_mask(GENERIC_WRITE)?;
    }
    if (label.mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) != 0 {
        allowed &= !mapping.map_mask(GENERIC_EXECUTE)?;
    }

    if (effective_privileges & SE_RELABEL_PRIVILEGE) != 0 {
        allowed |= WRITE_OWNER;
        provenance.relabel_granted |= WRITE_OWNER;
    }

    let all_bits = mapping.map_mask(GENERIC_ALL)?;
    let mandatory_decided = all_bits & !allowed;
    *decided |= mandatory_decided;

    Ok(MicEnforcementState { mandatory_decided })
}

fn default_mandatory_label() -> MandatoryLabel {
    MandatoryLabel {
        integrity_level: IntegrityLevel::Medium,
        mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        explicit: false,
    }
}

fn integrity_level_from_sid(sid: Sid<'_>) -> KacsResult<IntegrityLevel> {
    if sid.identifier_authority() != [0, 0, 0, 0, 0, 16] {
        return Err(KacsError::InvalidMandatoryLabelSid);
    }
    if sid.sub_authority_count() != 1 {
        return Err(KacsError::InvalidMandatoryLabelSid);
    }

    match sid.sub_authority(0) {
        Some(0) => Ok(IntegrityLevel::Untrusted),
        Some(4096) => Ok(IntegrityLevel::Low),
        Some(8192) => Ok(IntegrityLevel::Medium),
        Some(12288) => Ok(IntegrityLevel::High),
        Some(16384) => Ok(IntegrityLevel::System),
        _ => Err(KacsError::InvalidMandatoryLabelSid),
    }
}
