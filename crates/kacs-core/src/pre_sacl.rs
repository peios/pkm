use crate::access_mask::GenericMapping;
use crate::claims::ClaimAttribute;
use crate::error::KacsResult;
use crate::mic::{apply_mic, resolve_mandatory_label, IntegrityLevel};
use crate::pip::{apply_pip, resolve_process_trust_label, PipContext};
use crate::pkm_alloc::Vec;
use crate::privilege::{AccessDecisionState, PrivilegeProvenance};
use crate::sacl::extract_sacl_metadata;
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;

/// Result of the pre-SACL walk after MIC, PIP, claim extraction, and policy-ID
/// extraction have run.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct PreSaclWalkState<'a> {
    /// Decided bits after pre-SACL enforcement.
    pub decided: u32,
    /// Granted bits after pre-SACL enforcement.
    pub granted: u32,
    /// Privilege-granted bits after pre-SACL enforcement.
    pub privilege_granted: u32,
    /// Bits decided by MIC and PIP.
    pub mandatory_decided: u32,
    /// Bits decided specifically by PIP.
    pub pip_decided: u32,
    /// Resource attributes extracted from the SACL.
    pub resource_attributes: Vec<ClaimAttribute>,
    /// Scoped policy SIDs extracted from the SACL.
    pub policy_sids: Vec<Sid<'a>>,
    /// Updated privilege provenance after MIC/PIP adjustments.
    pub provenance: PrivilegeProvenance,
}

/// Inputs for the pre-SACL walk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreSaclWalkInput<'a, 'b> {
    /// Security descriptor being evaluated.
    pub sd: &'b SecurityDescriptor<'a>,
    /// Caller integrity level.
    pub token_integrity: IntegrityLevel,
    /// Caller mandatory policy.
    pub mandatory_policy: u32,
    /// Effective privileges after initial privilege seeding.
    pub effective_privileges: u64,
    /// Caller process-trust label context.
    pub pip: PipContext,
    /// Generic mapping for the protected object type.
    pub mapping: &'b GenericMapping,
    /// Initial decided/granted state entering the pre-SACL walk.
    pub initial_state: AccessDecisionState,
    /// Privilege-granted bits entering the pre-SACL walk.
    pub privilege_granted: u32,
    /// Initial privilege provenance.
    pub provenance: PrivilegeProvenance,
}

/// Runs the pre-SACL portion of AccessCheck and returns the narrowed state plus
/// extracted SACL metadata.
pub fn pre_sacl_walk<'a>(input: PreSaclWalkInput<'a, '_>) -> KacsResult<PreSaclWalkState<'a>> {
    let PreSaclWalkInput {
        sd,
        token_integrity,
        mandatory_policy,
        effective_privileges,
        pip,
        mapping,
        initial_state,
        privilege_granted,
        provenance,
    } = input;
    let metadata = extract_sacl_metadata(sd)?;
    let label = resolve_mandatory_label(sd)?;
    let trust_label = resolve_process_trust_label(sd)?;

    let mut decided = initial_state.decided;
    let mut granted = initial_state.granted;
    let mut privilege_granted = privilege_granted;
    let mut provenance = provenance;
    let mut mandatory_decided = 0u32;
    let mut pip_decided = 0u32;

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
        pip_decided |= pip.mandatory_decided;
    }

    Ok(PreSaclWalkState {
        decided,
        granted,
        privilege_granted,
        mandatory_decided,
        pip_decided,
        resource_attributes: metadata.resource_attributes,
        policy_sids: metadata.policy_sids,
        provenance,
    })
}
