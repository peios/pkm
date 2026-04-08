use alloc::vec::Vec;

use crate::audit::{evaluate_sacl, AuditEvent};
use crate::caap::{evaluate_caap, CaapPolicyEntry};
use crate::condition::ConditionalContext;
use crate::dacl::AccessStatus;
use crate::error::{KacsError, KacsResult};
use crate::evaluate_sd::evaluate_security_descriptor;
use crate::object_tree::ObjectTypeList;
use crate::pip::PipContext;
use crate::security_descriptor::SecurityDescriptor;
use crate::token::{
    AccessCheckToken, AUDIT_POLICY_OBJECT_ACCESS_FAILURE, AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
};
use crate::{Acl, GenericMapping};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessCheckCoreState<'a> {
    pub decided: u32,
    pub granted: u32,
    pub privilege_granted: u32,
    pub max_allowed_mode: bool,
    pub mapped_desired: u32,
    pub continuous_audit_mask: u32,
    pub staging_mismatch: bool,
    pub object_granted_list: Option<Vec<u32>>,
    pub audit_events: Vec<AuditEvent<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCheckResult {
    pub granted: u32,
    pub allowed: bool,
    pub continuous_audit_mask: u32,
    pub staging_mismatch: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessCheckResultListState {
    pub granted_list: Vec<u32>,
    pub status_list: Vec<AccessStatus>,
    pub continuous_audit_mask: u32,
    pub staging_mismatch: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn access_check_core<'a>(
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
) -> KacsResult<AccessCheckCoreState<'a>> {
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
    if !base.policy_sids.is_empty() {
        if caap.staged_granted != caap.granted {
            staging_mismatch = true;
        }
        if let (Some(staged), Some(effective)) = (
            caap.staged_object_granted_list.as_ref(),
            caap.object_granted_list.as_ref(),
        ) {
            if staged.iter().zip(effective.iter()).any(|(s, e)| s != e) {
                staging_mismatch = true;
            }
        }
    }

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
            audit_events.extend(state.audit_events);
            continuous_audit_mask |= state.continuous_audit_mask;
        }

        for caap_sacl in &caap.effective_sacls {
            if let Ok(acl) = Acl::parse(caap_sacl) {
                if let Ok(state) = evaluate_sacl(
                    &acl,
                    &token.subject,
                    owner,
                    conditional_context.self_sid,
                    object_tree,
                    base.mapped_desired,
                    caap.granted,
                    mapping,
                    &audit_context,
                    object_audit_context,
                ) {
                    audit_events.extend(state.audit_events);
                    continuous_audit_mask |= state.continuous_audit_mask;
                }
            }
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
                    caap.granted,
                    mapping,
                    &audit_context,
                    object_audit_context,
                )?;
                staged_audit_events.extend(state.audit_events);
                staged_continuous |= state.continuous_audit_mask;
            }

            for caap_sacl in &caap.staged_sacls {
                if let Ok(acl) = Acl::parse(caap_sacl) {
                    if let Ok(state) = evaluate_sacl(
                        &acl,
                        &token.subject,
                        owner,
                        conditional_context.self_sid,
                        object_tree,
                        base.mapped_desired,
                        caap.granted,
                        mapping,
                        &audit_context,
                        object_audit_context,
                    ) {
                        staged_audit_events.extend(state.audit_events);
                        staged_continuous |= state.continuous_audit_mask;
                    }
                }
            }

            if staged_audit_events != audit_events || staged_continuous != continuous_audit_mask {
                staging_mismatch = true;
            }
        }

        (audit_events, continuous_audit_mask)
    };

    let success =
        (caap.granted & base.mapped_desired) == base.mapped_desired || base.mapped_desired == 0;
    if success && (token.audit_policy & AUDIT_POLICY_OBJECT_ACCESS_SUCCESS) != 0 {
        audit_events.push(AuditEvent {
            ace_bytes: None,
            requested: base.mapped_desired,
            granted: caap.granted,
            success: true,
            policy_forced: true,
            object_audit_context: object_audit_context.map(|ctx| ctx.to_vec()),
        });
    }
    if !success && (token.audit_policy & AUDIT_POLICY_OBJECT_ACCESS_FAILURE) != 0 {
        audit_events.push(AuditEvent {
            ace_bytes: None,
            requested: base.mapped_desired,
            granted: caap.granted,
            success: false,
            policy_forced: true,
            object_audit_context: object_audit_context.map(|ctx| ctx.to_vec()),
        });
    }

    Ok(AccessCheckCoreState {
        decided: base.decided,
        granted: caap.granted,
        privilege_granted: base.privilege_granted,
        max_allowed_mode: base.max_allowed_mode,
        mapped_desired: base.mapped_desired,
        continuous_audit_mask,
        staging_mismatch,
        object_granted_list: caap.object_granted_list,
        audit_events,
    })
}

#[allow(clippy::too_many_arguments)]
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
    let mut status_list = Vec::with_capacity(granted_list.len());
    for granted in &granted_list {
        if state.mapped_desired == 0 || (*granted & state.mapped_desired) == state.mapped_desired {
            status_list.push(AccessStatus::Ok);
        } else {
            status_list.push(AccessStatus::AccessDenied);
        }
    }

    Ok(AccessCheckResultListState {
        granted_list,
        status_list,
        continuous_audit_mask: state.continuous_audit_mask,
        staging_mismatch: state.staging_mismatch,
    })
}
