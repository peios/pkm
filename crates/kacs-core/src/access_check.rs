use crate::audit::{evaluate_sacl, AuditEvent};
use crate::caap::{evaluate_caap, CaapPolicyEntry, CaapSaclContribution, CaapSaclPhase};
use crate::condition::ConditionalContext;
use crate::dacl::AccessStatus;
use crate::error::{KacsError, KacsResult};
use crate::evaluate_sd::evaluate_security_descriptor;
use crate::object_tree::ObjectTypeList;
use crate::pip::PipContext;
use crate::pkm_alloc::{slice_to_vec, Vec};
use crate::privilege::{
    PrivilegeProvenance, TokenPrivileges, SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE,
    SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE, SE_TAKE_OWNERSHIP_PRIVILEGE,
};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::{
    AccessCheckToken, AUDIT_POLICY_OBJECT_ACCESS_FAILURE, AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
    AUDIT_POLICY_PRIVILEGE_USE_FAILURE, AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
};
use crate::{Acl, GenericMapping};

/// Selects whether AccessCheck returns a single scalar decision or an
/// object-tree result list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessCheckMode {
    /// Evaluate scalar AccessCheck semantics.
    Scalar,
    /// Evaluate object-tree result-list semantics.
    ResultList,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Records one privilege-use audit decision produced by step 13.
pub struct PrivilegeUseEvent {
    /// Privilege bit responsible for the recorded contribution.
    pub privilege: u64,
    /// Requested bits attributed to that privilege.
    pub requested: u32,
    /// Bits granted by the privilege before later narrowing.
    pub granted: u32,
    /// Bits that survived into the final result.
    pub surviving_bits: u32,
    /// Whether the privilege use counted as success rather than failure.
    pub success: bool,
    /// Optional object-audit context copied into the event.
    pub object_audit_context: Option<Vec<u8>>,
}

/// Classifies one CAAP diagnostic KMES event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaapDiagnosticKind {
    /// A CAAP SACL failed parse or evaluation and its audit contribution was skipped.
    SaclError,
    /// Effective and staged CAAP results differed.
    StagingMismatch,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Durable diagnostic emitted for CAAP policy evaluation issues.
pub struct CaapDiagnosticEvent {
    /// Diagnostic class.
    pub kind: CaapDiagnosticKind,
    /// CAAP SACL phase for SACL diagnostics, or `None` for whole-result diagnostics.
    pub phase: Option<CaapSaclPhase>,
    /// Policy SID for SACL diagnostics.
    pub policy_sid: Option<Vec<u8>>,
    /// Zero-based rule index for SACL diagnostics.
    pub rule_index: Option<u32>,
    /// Stable machine-readable reason string.
    pub reason: &'static str,
    /// Requested access after generic mapping.
    pub requested: u32,
    /// Effective CAAP scalar grant.
    pub effective_granted: u32,
    /// Staged CAAP scalar grant.
    pub staged_granted: u32,
    /// Whether result-list per-node outputs differ.
    pub object_results_differ: bool,
    /// Optional object-audit context copied into the event.
    pub object_audit_context: Option<Vec<u8>>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Full internal AccessCheck state after DACL, CAAP, SACL, and privilege-use
/// processing.
pub struct AccessCheckCoreState<'a> {
    /// Final decided bits.
    pub decided: u32,
    /// Final granted bits.
    pub granted: u32,
    /// Final privilege-granted bits that survived the pipeline.
    pub privilege_granted: u32,
    /// Whether the request ran in `MAXIMUM_ALLOWED` mode.
    pub max_allowed_mode: bool,
    /// Requested access after generic mapping.
    pub mapped_desired: u32,
    /// Continuous-audit mask accumulated from matched SACL ACEs.
    pub continuous_audit_mask: u32,
    /// Whether staged CAAP results differed from effective results.
    pub staging_mismatch: bool,
    /// Bits decided specifically by PIP before DACL/CAAP processing.
    pub pip_decided: u32,
    /// Final per-node granted list when result-list mode is active.
    pub object_granted_list: Option<Vec<u32>>,
    /// Audit/alarm events emitted by step 14.
    pub audit_events: Vec<AuditEvent<'a>>,
    /// Privilege-use audit events emitted by step 13.
    pub privilege_use_events: Vec<PrivilegeUseEvent>,
    /// CAAP policy diagnostics emitted by step 14.
    pub caap_diagnostic_events: Vec<CaapDiagnosticEvent>,
    /// Updated privilege state after successful privilege-use marking.
    pub updated_privileges: TokenPrivileges,
}

/// Public scalar AccessCheck result returned by the convenience wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCheckResult {
    /// Granted scalar access mask.
    pub granted: u32,
    /// Whether the scalar request succeeded.
    pub allowed: bool,
    /// Continuous-audit mask accumulated during SACL evaluation.
    pub continuous_audit_mask: u32,
    /// Whether staged CAAP state differed from effective state.
    pub staging_mismatch: bool,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Public result-list AccessCheck output for object-tree requests.
pub struct AccessCheckResultListState {
    /// Granted bits for each object-tree node.
    pub granted_list: Vec<u32>,
    /// Final status for each object-tree node.
    pub status_list: Vec<AccessStatus>,
    /// Continuous-audit mask accumulated during SACL evaluation.
    pub continuous_audit_mask: u32,
    /// Whether staged CAAP state differed from effective state.
    pub staging_mismatch: bool,
}

#[allow(clippy::too_many_arguments)]
/// Executes the full pure-core AccessCheck pipeline and returns the complete
/// internal state used by the ABI and kernel ingress layers.
pub fn access_check_core<'a>(
    sd: Option<&SecurityDescriptor<'a>>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    mode: AccessCheckMode,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    object_audit_context: Option<&'a [u8]>,
    privilege_intent: u32,
    policies: &[CaapPolicyEntry<'a>],
) -> KacsResult<AccessCheckCoreState<'a>> {
    if mode == AccessCheckMode::ResultList && object_tree.is_none() {
        return Err(KacsError::InvariantViolation(
            "result-list mode requires object tree",
        ));
    }

    let sd = sd.ok_or(KacsError::NullSecurityDescriptor)?;

    let base = evaluate_security_descriptor(
        Some(sd),
        token,
        pip,
        desired_access,
        mapping,
        object_tree,
        conditional_context,
        privilege_intent,
    )?;
    let caap = evaluate_caap(
        sd,
        token,
        pip,
        desired_access,
        mapping,
        object_tree,
        conditional_context,
        &base,
        policies,
    )?;

    let mut staging_mismatch = false;
    let mut object_results_differ = false;
    let mut caap_diagnostic_events = Vec::new();
    if !base.policy_sids.is_empty() {
        if caap.staged_granted != caap.granted {
            staging_mismatch = true;
        }
        object_results_differ = object_grants_differ(
            caap.staged_object_granted_list.as_ref(),
            caap.object_granted_list.as_ref(),
        );
        if object_results_differ {
            staging_mismatch = true;
        }
    }

    let (used_delta, privilege_use_events) = evaluate_privilege_use(
        mode,
        token,
        &base.provenance,
        base.mapped_desired,
        caap.granted,
        caap.object_granted_list.as_deref(),
        base.max_allowed_mode,
        object_audit_context,
    )?;

    let owner = sd
        .owner()
        .ok_or(KacsError::MissingSecurityDescriptorOwner)?;
    let (mut audit_events, continuous_audit_mask) = {
        let mut audit_context = *conditional_context;
        audit_context.resource_claims = base.resource_attributes.as_slice();

        let mut audit_events = Vec::new();
        let mut continuous_audit_mask = 0u32;

        if let Some(sacl) = sd.sacl() {
            let state = evaluate_sacl(
                &sacl,
                &token.subject,
                owner,
                conditional_context.self_sid,
                object_tree,
                base.mapped_desired,
                caap.granted,
                mapping,
                &audit_context,
                object_audit_context,
            )?;
            audit_events.extend(state.audit_events)?;
            continuous_audit_mask |= state.continuous_audit_mask;
        }

        for caap_sacl in &caap.effective_sacls {
            evaluate_caap_sacl_contribution(
                caap_sacl,
                token,
                owner,
                conditional_context.self_sid,
                object_tree,
                base.mapped_desired,
                caap.granted,
                caap.granted,
                caap.staged_granted,
                mapping,
                &audit_context,
                object_audit_context,
                object_results_differ,
                &mut audit_events,
                &mut continuous_audit_mask,
                &mut caap_diagnostic_events,
            )?;
        }

        if !caap.staged_sacls.is_empty() {
            let mut staged_audit_events = Vec::new();
            let mut staged_continuous = 0u32;

            if let Some(sacl) = sd.sacl() {
                let state = evaluate_sacl(
                    &sacl,
                    &token.subject,
                    owner,
                    conditional_context.self_sid,
                    object_tree,
                    base.mapped_desired,
                    caap.staged_granted,
                    mapping,
                    &audit_context,
                    object_audit_context,
                )?;
                staged_audit_events.extend(state.audit_events)?;
                staged_continuous |= state.continuous_audit_mask;
            }

            for caap_sacl in &caap.staged_sacls {
                evaluate_caap_sacl_contribution(
                    caap_sacl,
                    token,
                    owner,
                    conditional_context.self_sid,
                    object_tree,
                    base.mapped_desired,
                    caap.staged_granted,
                    caap.granted,
                    caap.staged_granted,
                    mapping,
                    &audit_context,
                    object_audit_context,
                    object_results_differ,
                    &mut staged_audit_events,
                    &mut staged_continuous,
                    &mut caap_diagnostic_events,
                )?;
            }

            if staged_audit_events != audit_events || staged_continuous != continuous_audit_mask {
                staging_mismatch = true;
            }
        }

        (audit_events, continuous_audit_mask)
    };

    if !base.policy_sids.is_empty() && staging_mismatch {
        caap_diagnostic_events.push(CaapDiagnosticEvent {
            kind: CaapDiagnosticKind::StagingMismatch,
            phase: None,
            policy_sid: None,
            rule_index: None,
            reason: "effective-staged-delta",
            requested: base.mapped_desired,
            effective_granted: caap.granted,
            staged_granted: caap.staged_granted,
            object_results_differ,
            object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
        })?;
    }

    let success =
        (caap.granted & base.mapped_desired) == base.mapped_desired || base.mapped_desired == 0;
    if success && (token.audit_policy & AUDIT_POLICY_OBJECT_ACCESS_SUCCESS) != 0 {
        audit_events.push(AuditEvent {
            ace_bytes: None,
            requested: base.mapped_desired,
            granted: caap.granted,
            success: true,
            policy_forced: true,
            privilege: None,
            object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
        })?;
    }
    if !success && (token.audit_policy & AUDIT_POLICY_OBJECT_ACCESS_FAILURE) != 0 {
        audit_events.push(AuditEvent {
            ace_bytes: None,
            requested: base.mapped_desired,
            granted: caap.granted,
            success: false,
            policy_forced: true,
            privilege: None,
            object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
        })?;
    }

    let mut updated_privileges = token.privileges;
    updated_privileges.used |= used_delta;

    Ok(AccessCheckCoreState {
        decided: base.decided,
        granted: caap.granted,
        privilege_granted: base.privilege_granted & caap.granted,
        max_allowed_mode: base.max_allowed_mode,
        mapped_desired: base.mapped_desired,
        continuous_audit_mask,
        staging_mismatch,
        pip_decided: base.pip_decided,
        object_granted_list: caap.object_granted_list,
        audit_events,
        privilege_use_events,
        caap_diagnostic_events,
        updated_privileges,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_caap_sacl_contribution<'a>(
    contribution: &CaapSaclContribution<'a>,
    token: &AccessCheckToken<'a>,
    owner: Sid<'_>,
    self_sid: Option<Sid<'_>>,
    object_tree: Option<&ObjectTypeList>,
    requested: u32,
    granted_for_phase: u32,
    effective_granted: u32,
    staged_granted: u32,
    mapping: &GenericMapping,
    audit_context: &ConditionalContext<'_>,
    object_audit_context: Option<&[u8]>,
    object_results_differ: bool,
    audit_events: &mut Vec<AuditEvent<'a>>,
    continuous_audit_mask: &mut u32,
    caap_diagnostic_events: &mut Vec<CaapDiagnosticEvent>,
) -> KacsResult<()> {
    let acl = match Acl::parse(contribution.sacl) {
        Ok(acl) => acl,
        Err(_) => {
            push_caap_sacl_error_diagnostic(
                caap_diagnostic_events,
                contribution,
                "invalid-caap-sacl",
                requested,
                effective_granted,
                staged_granted,
                object_results_differ,
                object_audit_context,
            )?;
            return Ok(());
        }
    };

    match evaluate_sacl(
        &acl,
        &token.subject,
        owner,
        self_sid,
        object_tree,
        requested,
        granted_for_phase,
        mapping,
        audit_context,
        object_audit_context,
    ) {
        Ok(state) => {
            audit_events.extend(state.audit_events)?;
            *continuous_audit_mask |= state.continuous_audit_mask;
            Ok(())
        }
        Err(_) => {
            push_caap_sacl_error_diagnostic(
                caap_diagnostic_events,
                contribution,
                "caap-sacl-evaluation-error",
                requested,
                effective_granted,
                staged_granted,
                object_results_differ,
                object_audit_context,
            )?;
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_caap_sacl_error_diagnostic(
    caap_diagnostic_events: &mut Vec<CaapDiagnosticEvent>,
    contribution: &CaapSaclContribution<'_>,
    reason: &'static str,
    requested: u32,
    effective_granted: u32,
    staged_granted: u32,
    object_results_differ: bool,
    object_audit_context: Option<&[u8]>,
) -> KacsResult<()> {
    caap_diagnostic_events.push(CaapDiagnosticEvent {
        kind: CaapDiagnosticKind::SaclError,
        phase: Some(contribution.phase),
        policy_sid: Some(slice_to_vec(contribution.policy_sid.as_bytes())?),
        rule_index: Some(contribution.rule_index),
        reason,
        requested,
        effective_granted,
        staged_granted,
        object_results_differ,
        object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
    })?;
    Ok(())
}

fn object_grants_differ(staged: Option<&Vec<u32>>, effective: Option<&Vec<u32>>) -> bool {
    match (staged, effective) {
        (Some(staged), Some(effective)) => {
            staged.len() != effective.len()
                || staged
                    .iter()
                    .zip(effective.iter())
                    .any(|(staged, effective)| staged != effective)
        }
        (None, None) => false,
        _ => true,
    }
}

#[allow(clippy::too_many_arguments)]
/// Executes scalar AccessCheck and returns the narrowed public scalar result.
pub fn access_check<'a>(
    sd: Option<&SecurityDescriptor<'a>>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    object_audit_context: Option<&'a [u8]>,
    privilege_intent: u32,
    policies: &[CaapPolicyEntry<'a>],
) -> KacsResult<AccessCheckResult> {
    let state = access_check_core(
        sd,
        token,
        pip,
        desired_access,
        mapping,
        AccessCheckMode::Scalar,
        object_tree,
        conditional_context,
        object_audit_context,
        privilege_intent,
        policies,
    )?;

    let granted = state
        .object_granted_list
        .as_ref()
        .and_then(|list| list.first().copied())
        .unwrap_or(state.granted);
    let allowed =
        state.mapped_desired == 0 || (granted & state.mapped_desired) == state.mapped_desired;

    Ok(AccessCheckResult {
        granted,
        allowed,
        continuous_audit_mask: state.continuous_audit_mask,
        staging_mismatch: state.staging_mismatch,
    })
}

#[allow(clippy::too_many_arguments)]
/// Executes result-list AccessCheck and returns the narrowed public list
/// result.
pub fn access_check_result_list<'a>(
    sd: Option<&SecurityDescriptor<'a>>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: &ObjectTypeList,
    conditional_context: &ConditionalContext<'a>,
    object_audit_context: Option<&'a [u8]>,
    privilege_intent: u32,
    policies: &[CaapPolicyEntry<'a>],
) -> KacsResult<AccessCheckResultListState> {
    let state = access_check_core(
        sd,
        token,
        pip,
        desired_access,
        mapping,
        AccessCheckMode::ResultList,
        Some(object_tree),
        conditional_context,
        object_audit_context,
        privilege_intent,
        policies,
    )?;

    let granted_list = state
        .object_granted_list
        .ok_or(KacsError::InvariantViolation(
            "result-list wrapper requires object grants",
        ))?;
    let mut status_list = Vec::with_capacity(granted_list.len())?;
    for granted in &granted_list {
        if state.mapped_desired == 0 || (*granted & state.mapped_desired) == state.mapped_desired {
            status_list.push(AccessStatus::Ok)?;
        } else {
            status_list.push(AccessStatus::AccessDenied)?;
        }
    }

    Ok(AccessCheckResultListState {
        granted_list,
        status_list,
        continuous_audit_mask: state.continuous_audit_mask,
        staging_mismatch: state.staging_mismatch,
    })
}

fn evaluate_privilege_use(
    mode: AccessCheckMode,
    token: &AccessCheckToken<'_>,
    provenance: &PrivilegeProvenance,
    mapped_desired: u32,
    final_granted: u32,
    object_granted_list: Option<&[u32]>,
    max_allowed_mode: bool,
    object_audit_context: Option<&[u8]>,
) -> KacsResult<(u64, Vec<PrivilegeUseEvent>)> {
    if max_allowed_mode {
        return Ok((0, Vec::new()));
    }

    let mut used_delta = 0u64;
    let mut events = Vec::new();
    let provenance_entries = [
        (SE_SECURITY_PRIVILEGE, provenance.security_granted),
        (SE_BACKUP_PRIVILEGE, provenance.backup_granted),
        (SE_RESTORE_PRIVILEGE, provenance.restore_granted),
        (
            SE_TAKE_OWNERSHIP_PRIVILEGE,
            provenance.take_ownership_granted,
        ),
        (SE_RELABEL_PRIVILEGE, provenance.relabel_granted),
    ];

    for (privilege, provenance_mask) in provenance_entries {
        let requested_contribution = provenance_mask & mapped_desired;
        if requested_contribution == 0 {
            continue;
        }

        let surviving_bits = match mode {
            AccessCheckMode::Scalar => requested_contribution & final_granted,
            AccessCheckMode::ResultList => object_granted_list
                .unwrap_or(&[])
                .iter()
                .fold(0u32, |acc, granted| {
                    acc | (requested_contribution & *granted)
                }),
        };

        if surviving_bits != 0 {
            used_delta |= privilege;
            if (token.audit_policy & AUDIT_POLICY_PRIVILEGE_USE_SUCCESS) != 0 {
                events.push(PrivilegeUseEvent {
                    privilege,
                    requested: requested_contribution,
                    granted: requested_contribution,
                    surviving_bits,
                    success: true,
                    object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
                })?;
            }
        } else if (token.audit_policy & AUDIT_POLICY_PRIVILEGE_USE_FAILURE) != 0 {
            events.push(PrivilegeUseEvent {
                privilege,
                requested: requested_contribution,
                granted: requested_contribution,
                surviving_bits: 0,
                success: false,
                object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
            })?;
        }
    }

    Ok((used_delta, events))
}
