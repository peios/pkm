use crate::access_mask::{GenericMapping, ACCESS_SYSTEM_SECURITY, GENERIC_ALL};
use crate::ace::{AceKind, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE};
use crate::error::{KacsError, KacsResult};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessTrustLabel {
    pub pip_type: u32,
    pub pip_trust: u32,
    pub mask: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipEnforcementState {
    pub mandatory_decided: u32,
}

pub fn resolve_process_trust_label(
    sd: &SecurityDescriptor<'_>,
) -> KacsResult<Option<ProcessTrustLabel>> {
    let Some(sacl) = sd.sacl() else {
        return Ok(None);
    };

    for ace in sacl.entries() {
        let ace = ace?;
        if ace.ace_type() != SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE {
            continue;
        }
        let AceKind::SingleSid { mask, sid } = ace.kind() else {
            return Err(KacsError::InvalidProcessTrustLabelSid);
        };
        let (pip_type, pip_trust) = pip_axes_from_sid(sid)?;
        return Ok(Some(ProcessTrustLabel {
            pip_type,
            pip_trust,
            mask,
        }));
    }

    Ok(None)
}

pub fn apply_pip(
    label: ProcessTrustLabel,
    pip_type: u32,
    pip_trust: u32,
    mapping: &GenericMapping,
    decided: &mut u32,
    granted: &mut u32,
    privilege_granted: &mut u32,
) -> KacsResult<PipEnforcementState> {
    let caller_dominates = pip_type >= label.pip_type && pip_trust >= label.pip_trust;
    if caller_dominates {
        return Ok(PipEnforcementState::default());
    }

    let allowed = mapping.map_mask(label.mask)?;
    let all_bits = mapping.map_mask(GENERIC_ALL)? | ACCESS_SYSTEM_SECURITY;
    let pip_denied = all_bits & !allowed;

    *decided |= pip_denied;
    *granted &= !pip_denied;
    *privilege_granted &= !pip_denied;

    Ok(PipEnforcementState {
        mandatory_decided: pip_denied,
    })
}

fn pip_axes_from_sid(sid: Sid<'_>) -> KacsResult<(u32, u32)> {
    if sid.identifier_authority() != [0, 0, 0, 0, 0, 19] {
        return Err(KacsError::InvalidProcessTrustLabelSid);
    }
    if sid.sub_authority_count() != 2 {
        return Err(KacsError::InvalidProcessTrustLabelSid);
    }

    let pip_type = sid
        .sub_authority(0)
        .ok_or(KacsError::InvalidProcessTrustLabelSid)?;
    let pip_trust = sid
        .sub_authority(1)
        .ok_or(KacsError::InvalidProcessTrustLabelSid)?;

    Ok((pip_type, pip_trust))
}
