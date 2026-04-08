use crate::access_mask::GenericMapping;
use crate::claims::ClaimAttribute;
use crate::error::KacsResult;
use crate::mic::{apply_mic, resolve_mandatory_label, IntegrityLevel};
use crate::pkm_alloc::Vec;
use crate::pip::{apply_pip, resolve_process_trust_label, PipContext};
use crate::privilege::PrivilegeProvenance;
use crate::sacl::extract_sacl_metadata;
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct PreSaclWalkState<'a> {
    pub decided: u32,
    pub granted: u32,
    pub privilege_granted: u32,
    pub mandatory_decided: u32,
    pub resource_attributes: Vec<ClaimAttribute>,
    pub policy_sids: Vec<Sid<'a>>,
    pub provenance: PrivilegeProvenance,
}

pub fn pre_sacl_walk<'a>(
    sd: &SecurityDescriptor<'a>,
    token_integrity: IntegrityLevel,
    mandatory_policy: u32,
    effective_privileges: u64,
    pip: PipContext,
    mapping: &GenericMapping,
    decided: u32,
    granted: u32,
    privilege_granted: u32,
    provenance: PrivilegeProvenance,
) -> KacsResult<PreSaclWalkState<'a>> {
    let metadata = extract_sacl_metadata(sd)?;
    let label = resolve_mandatory_label(sd)?;
    let trust_label = resolve_process_trust_label(sd)?;

    let mut decided = decided;
    let mut granted = granted;
    let mut privilege_granted = privilege_granted;
    let mut provenance = provenance;
    let mut mandatory_decided = 0u32;

    let mic = apply_mic(
        label,
        token_integrity,
        mandatory_policy,
        effective_privileges,
        mapping,
        &mut decided,
        &mut provenance,
    )?;
    mandatory_decided |= mic.mandatory_decided;

    if let Some(label) = trust_label {
        let pip = apply_pip(
            label,
            pip,
            mapping,
            &mut decided,
            &mut granted,
            &mut privilege_granted,
        )?;
        mandatory_decided |= pip.mandatory_decided;
    }

    Ok(PreSaclWalkState {
        decided,
        granted,
        privilege_granted,
        mandatory_decided,
        resource_attributes: metadata.resource_attributes,
        policy_sids: metadata.policy_sids,
        provenance,
    })
}
