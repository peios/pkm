use crate::access_mask::GenericMapping;
use crate::claims::ClaimAttribute;
use crate::condition::{ConditionalContext, OwnerMatch};
use crate::dacl::{
    caller_is_owner_normal, confinement_contains, confinement_contains_capability,
    evaluate_dacl_states, merge_absolute_results, merge_restricted_results, restricted_contains,
    sid_matches_token, DaclStateInput,
};
use crate::error::{KacsError, KacsResult};
use crate::object_tree::ObjectTypeList;
use crate::pip::PipContext;
use crate::pkm_alloc::Vec;
use crate::pre_sacl::{pre_sacl_walk, PreSaclWalkInput};
use crate::privilege::{
    apply_take_ownership_fallback, seed_access_check_privileges, AccessDecisionState,
    PrivilegeProvenance,
};
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::{
    validate_access_check_token_invariants, AccessCheckToken, IdentityView, ImpersonationLevel,
    TokenType,
};

/// Output of the full security-descriptor evaluation before CAAP/SACL wrappers
/// further shape the result.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct EvaluateSecurityDescriptorState<'a> {
    /// Final decided scalar bits.
    pub decided: u32,
    /// Final granted scalar bits.
    pub granted: u32,
    /// Final privilege-granted bits.
    pub privilege_granted: u32,
    /// Whether the request ran in `MAXIMUM_ALLOWED` mode.
    pub max_allowed_mode: bool,
    /// Requested access after generic mapping.
    pub mapped_desired: u32,
    /// Resource attributes extracted during the pre-SACL walk.
    pub resource_attributes: Vec<ClaimAttribute>,
    /// Scoped policy SIDs extracted during the pre-SACL walk.
    pub policy_sids: Vec<Sid<'a>>,
    /// Bits decided specifically by PIP.
    pub pip_decided: u32,
    /// Final privilege provenance.
    pub provenance: PrivilegeProvenance,
    /// Final per-node granted list when object-tree mode is active.
    pub object_granted_list: Option<Vec<u32>>,
}

/// Inputs for the full security-descriptor evaluation pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluateSecurityDescriptorInput<'a, 'ctx, 'b> {
    /// Security descriptor being evaluated.
    pub sd: Option<&'b SecurityDescriptor<'a>>,
    /// Caller token.
    pub token: &'b AccessCheckToken<'a>,
    /// Process-trust label context.
    pub pip: PipContext,
    /// Desired access before generic mapping.
    pub desired_access: u32,
    /// Generic mapping for the protected object type.
    pub mapping: &'b GenericMapping,
    /// Optional object-type tree for object-specific access checks.
    pub object_tree: Option<&'b ObjectTypeList>,
    /// Conditional-expression context supplied by the caller.
    pub conditional_context: &'b ConditionalContext<'ctx>,
    /// Privilege intent bits supplied by the caller.
    pub privilege_intent: u32,
}

/// Executes the full security-descriptor evaluation pipeline through MIC, PIP,
/// DACL, restricted pass, and confinement narrowing.
pub fn evaluate_security_descriptor<'a>(
    input: EvaluateSecurityDescriptorInput<'a, '_, '_>,
) -> KacsResult<EvaluateSecurityDescriptorState<'a>> {
    let EvaluateSecurityDescriptorInput {
        sd,
        token,
        pip,
        desired_access,
        mapping,
        object_tree,
        conditional_context,
        privilege_intent,
    } = input;
    validate_access_check_token_invariants(token)?;

    if token.token_type == TokenType::Impersonation
        && token.impersonation_level == ImpersonationLevel::Identification
    {
        return Err(KacsError::AccessDenied);
    }

    let sd = sd.ok_or(KacsError::NullSecurityDescriptor)?;
    if sd.owner().is_none() {
        return Err(KacsError::MissingSecurityDescriptorOwner);
    }
    if object_tree.is_some_and(ObjectTypeList::is_empty) {
        return Err(KacsError::EmptyObjectTypeList);
    }

    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(crate::GENERIC_ALL)?;

    let privilege_seed =
        seed_access_check_privileges(&token.privileges, mapping, privilege_intent)?;
    let pre_sacl = pre_sacl_walk(PreSaclWalkInput {
        sd,
        token_integrity: token.integrity_level,
        mandatory_policy: token.mandatory_policy,
        effective_privileges: privilege_seed.effective_privileges,
        pip,
        mapping,
        initial_state: AccessDecisionState {
            granted: privilege_seed.granted,
            decided: privilege_seed.decided,
        },
        privilege_granted: privilege_seed.privilege_granted(),
        provenance: privilege_seed.provenance,
    })?;

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
        DaclStateInput {
            sd,
            token: &token.subject,
            normalized,
            valid_rights,
            mapping,
            skip_owner_implicit: false,
            conditional_context: normal_context,
            object_tree,
            initial_state,
            caller_is_owner,
        },
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
    let privilege_granted_before_restriction =
        pre_sacl.privilege_granted | provenance.take_ownership_granted;

    if !token.restricted.restricted_sids.is_empty()
        || !token.restricted.restricted_device_groups.is_empty()
    {
        let mut restricted_context = token.restricted;
        restricted_context.privilege_granted = privilege_granted_before_restriction;

        let restricted_owner = sd
            .owner()
            .is_some_and(|owner| restricted_contains(restricted_context.restricted_sids, owner));
        let restricted_self = normal_context
            .self_sid
            .filter(|sid| restricted_contains(restricted_context.restricted_sids, *sid));
        let mut conditional_restricted = normal_context;
        conditional_restricted.self_sid = restricted_self;
        conditional_restricted.principal_self_matches = Some(restricted_self.is_some());
        conditional_restricted.identity = Some(IdentityView {
            user: None,
            user_deny_only: false,
            groups: restricted_context.restricted_sids,
        });
        conditional_restricted.identity_membership_is_presence_based = true;
        conditional_restricted.caller_is_owner = OwnerMatch::presence(restricted_owner);
        conditional_restricted.device_groups = restricted_context.restricted_device_groups;
        conditional_restricted.device_membership_uses_virtual_groups = true;

        let restricted = evaluate_dacl_states(
            DaclStateInput {
                sd,
                token: &token.subject,
                normalized,
                valid_rights,
                mapping,
                skip_owner_implicit: false,
                conditional_context: conditional_restricted,
                object_tree,
                initial_state: AccessDecisionState {
                    granted: 0,
                    decided: 0,
                },
                caller_is_owner: OwnerMatch::presence(restricted_owner),
            },
            |sid, _| restricted_contains(restricted_context.restricted_sids, sid),
        )?;

        let write_bits = mapping.map_mask(crate::GENERIC_WRITE)?;
        evaluation = merge_restricted_results(
            evaluation,
            &restricted,
            write_bits,
            restricted_context.write_restricted,
            privilege_granted_before_restriction,
        );
    }

    if let Some(confinement_sid) = token
        .confinement
        .confinement_sid
        .filter(|_| !token.confinement.confinement_exempt)
    {
        let confinement_owner = sd
            .owner()
            .is_some_and(|owner| confinement_contains(&token.confinement, owner));
        let confinement_self = normal_context
            .self_sid
            .filter(|sid| confinement_contains(&token.confinement, *sid));
        let mut conditional_confinement = normal_context;
        conditional_confinement.self_sid = confinement_self;
        conditional_confinement.principal_self_matches = Some(confinement_self.is_some());
        conditional_confinement.caller_is_owner = OwnerMatch::presence(confinement_owner);
        conditional_confinement.device_membership_uses_virtual_groups = true;

        let confinement = evaluate_dacl_states(
            DaclStateInput {
                sd,
                token: &token.subject,
                normalized,
                valid_rights,
                mapping,
                skip_owner_implicit: true,
                conditional_context: conditional_confinement,
                object_tree,
                initial_state: AccessDecisionState {
                    granted: 0,
                    decided: 0,
                },
                caller_is_owner: OwnerMatch::presence(confinement_owner),
            },
            |sid, _| {
                sid == confinement_sid || confinement_contains_capability(&token.confinement, sid)
            },
        )?;

        evaluation = merge_absolute_results(evaluation, &confinement);
    }

    let privilege_granted = privilege_granted_before_restriction & evaluation.root.granted;

    let object_granted_list = if let Some(states) = evaluation.object_states.as_ref() {
        let mut granted_list = Vec::with_capacity(states.len())?;
        for state in states.iter() {
            granted_list.push(state.granted)?;
        }
        Some(granted_list)
    } else {
        None
    };

    Ok(EvaluateSecurityDescriptorState {
        decided: evaluation.root.decided,
        granted: evaluation.root.granted,
        privilege_granted,
        max_allowed_mode: normalized.maximum_allowed,
        mapped_desired: normalized.mapped,
        resource_attributes: pre_sacl.resource_attributes,
        policy_sids: pre_sacl.policy_sids,
        pip_decided: pre_sacl.pip_decided,
        provenance,
        object_granted_list,
    })
}
