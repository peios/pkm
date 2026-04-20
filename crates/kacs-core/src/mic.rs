use crate::access_mask::{
    GenericMapping, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, WRITE_OWNER,
};
use crate::ace::{AceKind, SYSTEM_MANDATORY_LABEL_ACE_TYPE};
use crate::error::{KacsError, KacsResult};
use crate::privilege::{PrivilegeProvenance, SE_RELABEL_PRIVILEGE};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

const INHERIT_ONLY_ACE: u8 = 0x08;

/// Token mandatory-policy bit enabling NO_WRITE_UP enforcement.
pub const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 = 0x0000_0001;
/// Token mandatory-policy bit enabling NEW_PROCESS_MIN semantics.
pub const TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: u32 = 0x0000_0002;

/// Mandatory-label ACE bit denying read-up.
pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x0000_0001;
/// Mandatory-label ACE bit denying write-up.
pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;
/// Mandatory-label ACE bit denying execute-up.
pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x0000_0004;

/// Integrity levels understood by the slow-track MIC implementation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum IntegrityLevel {
    /// Untrusted integrity.
    Untrusted = 0,
    /// Low integrity.
    Low = 4096,
    /// Medium integrity.
    Medium = 8192,
    /// High integrity.
    High = 12288,
    /// System integrity.
    System = 16384,
}

/// Parsed mandatory label extracted from a descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MandatoryLabel {
    /// Label integrity level.
    pub integrity_level: IntegrityLevel,
    /// Mandatory policy mask from the ACE.
    pub mask: u32,
    /// Whether the label came from an explicit ACE rather than the implicit
    /// default.
    pub explicit: bool,
}

/// Result of applying MIC to the current access state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MicEnforcementState {
    /// Bits decided as denied by MIC.
    pub mandatory_decided: u32,
}

/// Resolves the effective mandatory label for a security descriptor.
pub fn resolve_mandatory_label(sd: &SecurityDescriptor<'_>) -> KacsResult<MandatoryLabel> {
    let Some(sacl) = sd.sacl() else {
        return Ok(default_mandatory_label());
    };

    for ace in sacl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
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

/// Applies MIC to the current decision state and records relabel provenance when
/// `SeRelabelPrivilege` loosens `WRITE_OWNER`.
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
