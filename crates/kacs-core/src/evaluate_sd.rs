use alloc::vec::Vec;

use crate::access_mask::GenericMapping;
use crate::claims::ClaimAttribute;
use crate::condition::ConditionalContext;
use crate::dacl::{
    caller_is_owner_normal, confinement_contains, confinement_contains_capability,
    evaluate_dacl_states, merge_absolute_results, merge_restricted_results, restricted_contains,
    sid_matches_token,
};
use crate::error::{KacsError, KacsResult};
use crate::object_tree::ObjectTypeList;
use crate::pre_sacl::pre_sacl_walk;
use crate::privilege::{
    apply_take_ownership_fallback, seed_access_check_privileges, AccessDecisionState,
    PrivilegeProvenance,
};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::{AccessCheckToken, IdentityView, ImpersonationLevel, TokenType};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluateSecurityDescriptorState<'a> {
    pub decided: u32,
    pub granted: u32,
    pub privilege_granted: u32,
    pub max_allowed_mode: bool,
    pub mapped_desired: u32,
    pub resource_attributes: Vec<ClaimAttribute>,
    pub policy_sids: Vec<Sid<'a>>,
    pub provenance: PrivilegeProvenance,
    pub object_granted_list: Option<Vec<u32>>,
}

pub fn evaluate_security_descriptor<'a>(
    sd: Option<&SecurityDescriptor<'a>>,
    token: &AccessCheckToken<'a>,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    privilege_intent: u32,
) -> KacsResult<EvaluateSecurityDescriptorState<'a>> {
    if token.token_type == TokenType::Impersonation
        && token.impersonation_level == ImpersonationLevel::Identification
    {
        return Err(KacsError::AccessDenied);
    }

    let sd = sd.ok_or(KacsError::NullSecurityDescriptor)?;
    if sd.owner().is_none() {
        return Err(KacsError::MissingSecurityDescriptorOwner);
    }
    if sd.group().is_none() {
        return Err(KacsError::MissingSecurityDescriptorGroup);
    }
    if object_tree.is_some_and(ObjectTypeList::is_empty) {
        return Err(KacsError::EmptyObjectTypeList);
    }

    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(crate::GENERIC_ALL)?;

    let privilege_seed =
        seed_access_check_privileges(&token.privileges, mapping, privilege_intent)?;
    let pre_sacl = pre_sacl_walk(
        sd,
        token.integrity_level,
        token.mandatory_policy,
        privilege_seed.effective_privileges,
        token.pip_type,
        token.pip_trust,
        mapping,
        privilege_seed.decided,
        privilege_seed.granted,
        privilege_seed.privilege_granted(),
        privilege_seed.provenance,
    )?;

    let mut provenance = pre_sacl.provenance;
    let mandatory_decided = pre_sacl.mandatory_decided;

    let mut normal_context = *conditional_context;
    normal_context.resource_claims = pre_sacl.resource_attributes.as_slice();

    let caller_is_owner = caller_is_owner_normal(sd, &token.subject);
    let initial_state = AccessDecisionState {
        granted: pre_sacl.granted,
        decided: pre_sacl.decided,
    };
    let mut evaluation = evaluate_dacl_states(
        sd,
        &token.subject,
        normalized,
        valid_rights,
        mapping,
        false,
        normal_context,
        object_tree,
        initial_state,
        caller_is_owner,
        |sid, polarity| sid_matches_token(&token.subject, sid, polarity),
    )?;

    apply_take_ownership_fallback(
        &mut evaluation.root,
        evaluation.object_states.as_deref_mut(),
        &normalized,
        privilege_seed.effective_privileges,
        mandatory_decided,
        &mut provenance,
    );
    let privilege_granted = provenance.privilege_granted();

    if !token.restricted.restricted_sids.is_empty() {
        let mut restricted_context = token.restricted;
        restricted_context.privilege_granted = privilege_granted;

        let restricted_owner = sd
            .owner()
            .is_some_and(|owner| restricted_contains(restricted_context.restricted_sids, owner));
        let mut conditional_restricted = normal_context;
        conditional_restricted.identity = Some(IdentityView {
            user: None,
            user_deny_only: false,
            groups: restricted_context.restricted_sids,
        });
        conditional_restricted.caller_is_owner = restricted_owner;
        if !restricted_context.restricted_device_groups.is_empty() {
            conditional_restricted.device_groups = restricted_context.restricted_device_groups;
        }

        let restricted = evaluate_dacl_states(
            sd,
            &token.subject,
            normalized,
            valid_rights,
            mapping,
            false,
            conditional_restricted,
            object_tree,
            AccessDecisionState {
                granted: 0,
                decided: 0,
            },
            restricted_owner,
            |sid, _| restricted_contains(restricted_context.restricted_sids, sid),
        )?;

        let write_bits = mapping.map_mask(crate::GENERIC_WRITE)?;
        evaluation = merge_restricted_results(
            evaluation,
            &restricted,
            write_bits,
            restricted_context.write_restricted,
            privilege_granted,
        );
    }

    if token.confinement.confinement_sid.is_some() && !token.confinement.confinement_exempt {
        let confinement_owner = sd
            .owner()
            .is_some_and(|owner| confinement_contains(&token.confinement, owner));
        let confinement_self = normal_context
            .self_sid
            .filter(|sid| confinement_contains(&token.confinement, *sid));
        let mut conditional_confinement = normal_context;
        conditional_confinement.self_sid = confinement_self;
        conditional_confinement.principal_self_matches = Some(confinement_self.is_some());
        conditional_confinement.caller_is_owner = confinement_owner;

        let confinement_sid = token
            .confinement
            .confinement_sid
            .expect("checked is_some above");
        let confinement = evaluate_dacl_states(
            sd,
            &token.subject,
            normalized,
            valid_rights,
            mapping,
            true,
            conditional_confinement,
            object_tree,
            AccessDecisionState {
                granted: 0,
                decided: 0,
            },
            confinement_owner,
            |sid, _| {
                sid == confinement_sid || confinement_contains_capability(&token.confinement, sid)
            },
        )?;

        evaluation = merge_absolute_results(evaluation, &confinement);
    }

    let object_granted_list = evaluation.object_states.as_ref().map(|states| {
        states
            .iter()
            .map(|state| state.granted)
            .collect::<Vec<u32>>()
    });

    Ok(EvaluateSecurityDescriptorState {
        decided: evaluation.root.decided,
        granted: evaluation.root.granted,
        privilege_granted,
        max_allowed_mode: normalized.maximum_allowed,
        mapped_desired: normalized.mapped,
        resource_attributes: pre_sacl.resource_attributes,
        policy_sids: pre_sacl.policy_sids,
        provenance,
        object_granted_list,
    })
}
