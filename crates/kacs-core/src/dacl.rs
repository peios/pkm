use alloc::vec::Vec;

use crate::access_mask::{
    GenericMapping, NormalizedDesiredAccess, GENERIC_ALL, GENERIC_WRITE, MAXIMUM_ALLOWED,
    READ_CONTROL, WRITE_DAC,
};
use crate::ace::{
    Ace, AceKind, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
};
use crate::condition::{evaluate_conditional_expression, ConditionalContext, ConditionalResult};
use crate::error::{KacsError, KacsResult};
use crate::object_tree::ObjectTypeList;
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::{Sid, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use crate::token::{
    ConfinementTokenContext, IdentityView, RestrictedTokenContext, SidAndAttributes, TokenView,
};

const INHERIT_ONLY_ACE: u8 = 0x08;
const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const PRINCIPAL_SELF_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaclEvaluation {
    pub granted: u32,
    pub decided: u32,
    pub success: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessStatus {
    Ok,
    AccessDenied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDaclResultList {
    pub granted_list: Vec<u32>,
    pub status_list: Vec<AccessStatus>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcePolarity {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AceTarget {
    Global,
    Object([u8; 16]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProjectedDaclAce<'a> {
    polarity: AcePolarity,
    mask: u32,
    sid: Sid<'a>,
    target: AceTarget,
    condition: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeState {
    granted: u32,
    decided: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InternalDaclEvaluation {
    root: NodeState,
    object_states: Option<Vec<NodeState>>,
}

pub fn evaluate_dacl(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
) -> KacsResult<DaclEvaluation> {
    evaluate_dacl_with_context(
        sd,
        token,
        desired_access,
        mapping,
        skip_owner_implicit,
        &ConditionalContext::default(),
    )
}

pub fn evaluate_dacl_with_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    conditional_context: &ConditionalContext<'_>,
) -> KacsResult<DaclEvaluation> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let internal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        None,
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;
    Ok(finalize_scalar(internal.root, &normalized))
}

pub fn evaluate_dacl_with_restricted_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    conditional_context: &ConditionalContext<'_>,
    restricted_context: &RestrictedTokenContext<'_>,
) -> KacsResult<DaclEvaluation> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let normal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        None,
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;

    if restricted_context.restricted_sids.is_empty() {
        return Ok(finalize_scalar(normal.root, &normalized));
    }

    let restricted_owner = sd
        .owner()
        .is_some_and(|owner| restricted_contains(restricted_context.restricted_sids, owner));
    let mut restricted_conditions = *conditional_context;
    restricted_conditions.identity = Some(IdentityView {
        user: None,
        user_deny_only: false,
        groups: restricted_context.restricted_sids,
    });
    restricted_conditions.caller_is_owner = restricted_owner;
    if !restricted_context.restricted_device_groups.is_empty() {
        restricted_conditions.device_groups = restricted_context.restricted_device_groups;
    }

    let restricted = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        restricted_conditions,
        None,
        restricted_owner,
        |sid, _| restricted_contains(restricted_context.restricted_sids, sid),
    )?;

    let write_bits = mapping.map_mask(GENERIC_WRITE)?;
    let merged = merge_restricted_results(
        normal,
        &restricted,
        write_bits,
        restricted_context.write_restricted,
        restricted_context.privilege_granted,
    );
    Ok(finalize_scalar(merged.root, &normalized))
}

pub fn evaluate_dacl_with_confinement_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    conditional_context: &ConditionalContext<'_>,
    confinement_context: &ConfinementTokenContext<'_>,
) -> KacsResult<DaclEvaluation> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let normal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        None,
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;

    let Some(confinement_sid) = confinement_context.confinement_sid else {
        return Ok(finalize_scalar(normal.root, &normalized));
    };
    if confinement_context.confinement_exempt {
        return Ok(finalize_scalar(normal.root, &normalized));
    }

    let confinement_owner = sd
        .owner()
        .is_some_and(|owner| confinement_contains(confinement_context, owner));
    let confinement_self = conditional_context
        .self_sid
        .filter(|sid| confinement_contains(confinement_context, *sid));
    let mut confinement_conditions = *conditional_context;
    confinement_conditions.self_sid = confinement_self;
    confinement_conditions.principal_self_matches = Some(confinement_self.is_some());
    confinement_conditions.caller_is_owner = confinement_owner;

    let confinement = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        true,
        confinement_conditions,
        None,
        confinement_owner,
        |sid, _| {
            sid == confinement_sid || confinement_contains_capability(confinement_context, sid)
        },
    )?;

    let merged = merge_absolute_results(normal, &confinement);
    Ok(finalize_scalar(merged.root, &normalized))
}

pub fn evaluate_dacl_with_self_sid(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    self_sid: Option<Sid<'_>>,
) -> KacsResult<DaclEvaluation> {
    let context = ConditionalContext {
        self_sid,
        ..ConditionalContext::default()
    };
    evaluate_dacl_with_context(
        sd,
        token,
        desired_access,
        mapping,
        skip_owner_implicit,
        &context,
    )
}

pub fn evaluate_dacl_with_object_tree(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    self_sid: Option<Sid<'_>>,
    object_tree: &ObjectTypeList,
) -> KacsResult<DaclEvaluation> {
    let context = ConditionalContext {
        self_sid,
        ..ConditionalContext::default()
    };
    evaluate_dacl_with_object_tree_and_context(
        sd,
        token,
        desired_access,
        mapping,
        skip_owner_implicit,
        object_tree,
        &context,
    )
}

pub fn evaluate_dacl_with_object_tree_and_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    object_tree: &ObjectTypeList,
    conditional_context: &ConditionalContext<'_>,
) -> KacsResult<DaclEvaluation> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let internal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        Some(object_tree),
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;
    Ok(finalize_scalar(internal.root, &normalized))
}

pub fn evaluate_dacl_result_list(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    self_sid: Option<Sid<'_>>,
    object_tree: &ObjectTypeList,
) -> KacsResult<ObjectDaclResultList> {
    let context = ConditionalContext {
        self_sid,
        ..ConditionalContext::default()
    };
    evaluate_dacl_result_list_with_context(
        sd,
        token,
        desired_access,
        mapping,
        skip_owner_implicit,
        object_tree,
        &context,
    )
}

pub fn evaluate_dacl_result_list_with_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    object_tree: &ObjectTypeList,
    conditional_context: &ConditionalContext<'_>,
) -> KacsResult<ObjectDaclResultList> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let internal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        Some(object_tree),
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;
    Ok(finalize_result_list(
        internal
            .object_states
            .as_ref()
            .expect("object-tree evaluation always builds result-list output"),
        &normalized,
    ))
}

pub fn evaluate_dacl_result_list_with_restricted_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    object_tree: &ObjectTypeList,
    conditional_context: &ConditionalContext<'_>,
    restricted_context: &RestrictedTokenContext<'_>,
) -> KacsResult<ObjectDaclResultList> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let normal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        Some(object_tree),
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;

    if restricted_context.restricted_sids.is_empty() {
        return Ok(finalize_result_list(
            normal
                .object_states
                .as_ref()
                .expect("object-tree evaluation always builds result-list output"),
            &normalized,
        ));
    }

    let restricted_owner = sd
        .owner()
        .is_some_and(|owner| restricted_contains(restricted_context.restricted_sids, owner));
    let mut restricted_conditions = *conditional_context;
    restricted_conditions.identity = Some(IdentityView {
        user: None,
        user_deny_only: false,
        groups: restricted_context.restricted_sids,
    });
    restricted_conditions.caller_is_owner = restricted_owner;
    if !restricted_context.restricted_device_groups.is_empty() {
        restricted_conditions.device_groups = restricted_context.restricted_device_groups;
    }

    let restricted = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        restricted_conditions,
        Some(object_tree),
        restricted_owner,
        |sid, _| restricted_contains(restricted_context.restricted_sids, sid),
    )?;

    let write_bits = mapping.map_mask(GENERIC_WRITE)?;
    let merged = merge_restricted_results(
        normal,
        &restricted,
        write_bits,
        restricted_context.write_restricted,
        restricted_context.privilege_granted,
    );
    Ok(finalize_result_list(
        merged
            .object_states
            .as_ref()
            .expect("restricted object-tree evaluation must retain states"),
        &normalized,
    ))
}

pub fn evaluate_dacl_result_list_with_confinement_context(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    desired_access: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    object_tree: &ObjectTypeList,
    conditional_context: &ConditionalContext<'_>,
    confinement_context: &ConfinementTokenContext<'_>,
) -> KacsResult<ObjectDaclResultList> {
    let normalized = mapping.normalize_desired_access(desired_access)?;
    let valid_rights = mapping.map_mask(GENERIC_ALL)?;
    let caller_is_owner = caller_is_owner_normal(sd, token);
    let normal = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        skip_owner_implicit,
        *conditional_context,
        Some(object_tree),
        caller_is_owner,
        |sid, polarity| sid_matches_token(token, sid, polarity),
    )?;

    let Some(confinement_sid) = confinement_context.confinement_sid else {
        return Ok(finalize_result_list(
            normal
                .object_states
                .as_ref()
                .expect("object-tree evaluation always builds result-list output"),
            &normalized,
        ));
    };
    if confinement_context.confinement_exempt {
        return Ok(finalize_result_list(
            normal
                .object_states
                .as_ref()
                .expect("object-tree evaluation always builds result-list output"),
            &normalized,
        ));
    }

    let confinement_owner = sd
        .owner()
        .is_some_and(|owner| confinement_contains(confinement_context, owner));
    let confinement_self = conditional_context
        .self_sid
        .filter(|sid| confinement_contains(confinement_context, *sid));
    let mut confinement_conditions = *conditional_context;
    confinement_conditions.self_sid = confinement_self;
    confinement_conditions.principal_self_matches = Some(confinement_self.is_some());
    confinement_conditions.caller_is_owner = confinement_owner;

    let confinement = evaluate_dacl_states(
        sd,
        token,
        normalized,
        valid_rights,
        mapping,
        true,
        confinement_conditions,
        Some(object_tree),
        confinement_owner,
        |sid, _| {
            sid == confinement_sid || confinement_contains_capability(confinement_context, sid)
        },
    )?;

    let merged = merge_absolute_results(normal, &confinement);
    Ok(finalize_result_list(
        merged
            .object_states
            .as_ref()
            .expect("confinement object-tree evaluation must retain states"),
        &normalized,
    ))
}

fn evaluate_dacl_states<F>(
    sd: &SecurityDescriptor<'_>,
    token: &TokenView<'_>,
    normalized: NormalizedDesiredAccess,
    valid_rights: u32,
    mapping: &GenericMapping,
    skip_owner_implicit: bool,
    conditional_context: ConditionalContext<'_>,
    object_tree: Option<&ObjectTypeList>,
    caller_is_owner: bool,
    sid_matches: F,
) -> KacsResult<InternalDaclEvaluation>
where
    F: Fn(Sid<'_>, AcePolarity) -> bool + Copy,
{
    let relevant_mask = if normalized.maximum_allowed {
        valid_rights
    } else {
        normalized.mapped
    };

    let owner_rights_suppressed = sd
        .dacl()
        .map(|dacl| owner_rights_suppressed(&dacl))
        .transpose()?
        .unwrap_or(false);

    let mut decided = 0u32;
    let mut granted = 0u32;

    if caller_is_owner && !skip_owner_implicit && !owner_rights_suppressed {
        let implicit = (READ_CONTROL | WRITE_DAC) & valid_rights;
        decided |= implicit;
        granted |= implicit;
    }

    let mut object_states =
        object_tree.map(|tree| vec![NodeState { granted, decided }; tree.len()]);

    match sd.dacl() {
        None => {
            if let Some(states) = object_states.as_mut() {
                for state in states.iter_mut() {
                    let null_grant = valid_rights & !state.decided;
                    state.granted |= null_grant;
                    state.decided |= null_grant;
                }
            } else {
                let null_grant = valid_rights & !decided;
                granted |= null_grant;
                decided |= null_grant;
            }
        }
        Some(dacl) => {
            for ace in dacl.entries() {
                let ace = ace?;
                if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
                    continue;
                }

                let Some(projected) = project_dacl_ace(&ace, mapping)? else {
                    continue;
                };

                if !ace_matches_identity(
                    projected.sid,
                    projected.polarity,
                    caller_is_owner,
                    conditional_context.self_sid,
                    sid_matches,
                ) {
                    continue;
                }

                if let Some(condition) = projected.condition {
                    let mut context = conditional_context;
                    context.caller_is_owner = caller_is_owner;
                    let cond_result = evaluate_conditional_expression(
                        condition,
                        token,
                        &context,
                        projected.polarity == AcePolarity::Allow,
                    );
                    if !condition_allows(projected.polarity, cond_result) {
                        continue;
                    }
                }

                let ace_bits = projected.mask & relevant_mask;
                if ace_bits == 0 {
                    continue;
                }

                if let Some(states) = object_states.as_mut() {
                    let tree = object_tree.expect("states only exist with a tree");
                    match projected.target {
                        AceTarget::Global => {
                            apply_global_to_tree(states, ace_bits, projected.polarity)
                        }
                        AceTarget::Object(guid) => {
                            if let Some(index) = tree.find(&guid) {
                                apply_object_ace_to_tree(
                                    tree,
                                    states,
                                    index,
                                    ace_bits,
                                    projected.polarity,
                                );
                            }
                        }
                    }
                } else {
                    let undecided = ace_bits & !decided;
                    if undecided == 0 {
                        continue;
                    }

                    decided |= undecided;
                    if projected.polarity == AcePolarity::Allow {
                        granted |= undecided;
                    }

                    if !normalized.maximum_allowed && (decided & relevant_mask) == relevant_mask {
                        break;
                    }
                }
            }
        }
    }

    if let Some(states) = object_states {
        Ok(InternalDaclEvaluation {
            root: states[0],
            object_states: Some(states),
        })
    } else {
        Ok(InternalDaclEvaluation {
            root: NodeState { granted, decided },
            object_states: None,
        })
    }
}

fn finalize_scalar(root: NodeState, normalized: &NormalizedDesiredAccess) -> DaclEvaluation {
    let specific_request = normalized.requested & !MAXIMUM_ALLOWED;
    let success = if specific_request == 0 {
        true
    } else {
        (normalized.mapped & !root.granted) == 0
    };

    DaclEvaluation {
        granted: root.granted,
        decided: root.decided,
        success,
    }
}

fn finalize_result_list(
    states: &[NodeState],
    normalized: &NormalizedDesiredAccess,
) -> ObjectDaclResultList {
    let mut granted_list = Vec::with_capacity(states.len());
    let mut status_list = Vec::with_capacity(states.len());
    for state in states {
        let status =
            if normalized.mapped == 0 || (state.granted & normalized.mapped) == normalized.mapped {
                AccessStatus::Ok
            } else {
                AccessStatus::AccessDenied
            };
        granted_list.push(state.granted);
        status_list.push(status);
    }

    ObjectDaclResultList {
        granted_list,
        status_list,
    }
}

fn merge_restricted_results(
    mut normal: InternalDaclEvaluation,
    restricted: &InternalDaclEvaluation,
    write_bits: u32,
    write_restricted: bool,
    privilege_granted: u32,
) -> InternalDaclEvaluation {
    normal.root.granted = merge_granted(
        normal.root.granted,
        restricted.root.granted,
        write_bits,
        write_restricted,
        privilege_granted,
    );

    if let Some(states) = normal.object_states.as_mut() {
        let restricted_states = restricted
            .object_states
            .as_ref()
            .expect("restricted merge requires matching object-tree state");
        for (state, restricted_state) in states.iter_mut().zip(restricted_states.iter()) {
            state.granted = merge_granted(
                state.granted,
                restricted_state.granted,
                write_bits,
                write_restricted,
                privilege_granted,
            );
        }
        normal.root = states[0];
    }

    normal
}

fn merge_absolute_results(
    mut normal: InternalDaclEvaluation,
    narrowed: &InternalDaclEvaluation,
) -> InternalDaclEvaluation {
    normal.root.granted &= narrowed.root.granted;

    if let Some(states) = normal.object_states.as_mut() {
        let narrowed_states = narrowed
            .object_states
            .as_ref()
            .expect("absolute merge requires matching object-tree state");
        for (state, narrowed_state) in states.iter_mut().zip(narrowed_states.iter()) {
            state.granted &= narrowed_state.granted;
        }
        normal.root = states[0];
    }

    normal
}

fn merge_granted(
    normal: u32,
    restricted: u32,
    write_bits: u32,
    write_restricted: bool,
    privilege_granted: u32,
) -> u32 {
    let merged = if write_restricted {
        (normal & !write_bits) | (normal & restricted & write_bits)
    } else {
        normal & restricted
    };
    merged | privilege_granted
}

fn caller_is_owner_normal(sd: &SecurityDescriptor<'_>, token: &TokenView<'_>) -> bool {
    sd.owner()
        .is_some_and(|owner| sid_matches_token(token, owner, AcePolarity::Allow))
}

fn restricted_contains(restricted_sids: &[SidAndAttributes<'_>], sid: Sid<'_>) -> bool {
    restricted_sids.iter().any(|entry| entry.sid == sid)
}

fn confinement_contains(confinement: &ConfinementTokenContext<'_>, sid: Sid<'_>) -> bool {
    confinement.confinement_sid == Some(sid) || confinement_contains_capability(confinement, sid)
}

fn confinement_contains_capability(
    confinement: &ConfinementTokenContext<'_>,
    sid: Sid<'_>,
) -> bool {
    confinement
        .confinement_capabilities
        .iter()
        .any(|entry| entry.sid == sid)
}

fn owner_rights_suppressed(dacl: &crate::acl::Acl<'_>) -> KacsResult<bool> {
    for ace in dacl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }

        match ace.kind() {
            AceKind::SingleSid { sid, .. }
            | AceKind::Object { sid, .. }
            | AceKind::Callback { sid, .. }
            | AceKind::CallbackObject { sid, .. } => {
                if sid.as_bytes() == OWNER_RIGHTS_SID_BYTES {
                    match ace.ace_type() {
                        ACCESS_ALLOWED_ACE_TYPE
                        | ACCESS_DENIED_ACE_TYPE
                        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        | ACCESS_DENIED_OBJECT_ACE_TYPE
                        | crate::ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                        | crate::ace::ACCESS_DENIED_CALLBACK_ACE_TYPE
                        | crate::ace::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
                        | crate::ace::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => return Ok(true),
                        _ => {}
                    }
                }
            }
            AceKind::ResourceAttribute { .. } | AceKind::Opaque => {}
        }
    }

    Ok(false)
}

fn project_dacl_ace<'a>(
    ace: &'a Ace<'a>,
    mapping: &GenericMapping,
) -> KacsResult<Option<ProjectedDaclAce<'a>>> {
    match (ace.ace_type(), ace.kind()) {
        (ACCESS_ALLOWED_ACE_TYPE, AceKind::SingleSid { mask, sid }) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Allow,
            mask: mapping.map_mask(mask)?,
            sid,
            target: AceTarget::Global,
            condition: None,
        })),
        (ACCESS_DENIED_ACE_TYPE, AceKind::SingleSid { mask, sid }) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Deny,
            mask: mapping.map_mask(mask)?,
            sid,
            target: AceTarget::Global,
            condition: None,
        })),
        (
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            AceKind::Object {
                mask,
                flags,
                object_type,
                sid,
                ..
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Allow,
            mask: mapping.map_mask(mask)?,
            sid,
            target: project_object_target(flags, object_type)?,
            condition: None,
        })),
        (
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            AceKind::Object {
                mask,
                flags,
                object_type,
                sid,
                ..
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Deny,
            mask: mapping.map_mask(mask)?,
            sid,
            target: project_object_target(flags, object_type)?,
            condition: None,
        })),
        (
            crate::ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            AceKind::Callback {
                mask,
                sid,
                application_data,
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Allow,
            mask: mapping.map_mask(mask)?,
            sid,
            target: AceTarget::Global,
            condition: Some(application_data),
        })),
        (
            crate::ace::ACCESS_DENIED_CALLBACK_ACE_TYPE,
            AceKind::Callback {
                mask,
                sid,
                application_data,
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Deny,
            mask: mapping.map_mask(mask)?,
            sid,
            target: AceTarget::Global,
            condition: Some(application_data),
        })),
        (
            crate::ace::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
            AceKind::CallbackObject {
                mask,
                flags,
                object_type,
                sid,
                application_data,
                ..
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Allow,
            mask: mapping.map_mask(mask)?,
            sid,
            target: project_object_target(flags, object_type)?,
            condition: Some(application_data),
        })),
        (
            crate::ace::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            AceKind::CallbackObject {
                mask,
                flags,
                object_type,
                sid,
                application_data,
                ..
            },
        ) => Ok(Some(ProjectedDaclAce {
            polarity: AcePolarity::Deny,
            mask: mapping.map_mask(mask)?,
            sid,
            target: project_object_target(flags, object_type)?,
            condition: Some(application_data),
        })),
        _ => Ok(None),
    }
}

fn condition_allows(polarity: AcePolarity, result: ConditionalResult) -> bool {
    match (polarity, result) {
        (AcePolarity::Allow, ConditionalResult::True) => true,
        (AcePolarity::Allow, ConditionalResult::False | ConditionalResult::Unknown) => false,
        (AcePolarity::Deny, ConditionalResult::False) => false,
        (AcePolarity::Deny, ConditionalResult::True | ConditionalResult::Unknown) => true,
    }
}

fn project_object_target(flags: u32, object_type: Option<&[u8; 16]>) -> KacsResult<AceTarget> {
    if (flags & ACE_OBJECT_TYPE_PRESENT) == 0 {
        return Ok(AceTarget::Global);
    }

    let guid = object_type.ok_or(KacsError::InvalidObjectAceLayout(
        "object type flag set without object type guid",
    ))?;
    Ok(AceTarget::Object(*guid))
}

fn ace_matches_identity<F>(
    ace_sid: Sid<'_>,
    polarity: AcePolarity,
    caller_is_owner: bool,
    self_sid: Option<Sid<'_>>,
    ordinary_sid_matches: F,
) -> bool
where
    F: Fn(Sid<'_>, AcePolarity) -> bool + Copy,
{
    if ace_sid.as_bytes() == OWNER_RIGHTS_SID_BYTES {
        return caller_is_owner;
    }

    if ace_sid.as_bytes() == PRINCIPAL_SELF_SID_BYTES {
        return self_sid
            .map(|sid| ordinary_sid_matches(sid, polarity))
            .unwrap_or(false);
    }

    ordinary_sid_matches(ace_sid, polarity)
}

fn sid_matches_token(token: &TokenView<'_>, sid: Sid<'_>, polarity: AcePolarity) -> bool {
    if sid == token.user {
        return match polarity {
            AcePolarity::Allow => !token.user_deny_only,
            AcePolarity::Deny => true,
        };
    }

    for group in token.groups {
        if group.sid != sid {
            continue;
        }

        let enabled = (group.attributes & SE_GROUP_ENABLED) != 0;
        let deny_only = (group.attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        match polarity {
            AcePolarity::Allow => {
                if enabled && !deny_only {
                    return true;
                }
            }
            AcePolarity::Deny => {
                if enabled || deny_only {
                    return true;
                }
            }
        }
    }

    false
}

fn apply_global_to_tree(states: &mut [NodeState], bits: u32, polarity: AcePolarity) {
    for state in states.iter_mut() {
        apply_bits(state, bits, polarity);
    }
}

fn apply_object_ace_to_tree(
    tree: &ObjectTypeList,
    states: &mut [NodeState],
    index: usize,
    bits: u32,
    polarity: AcePolarity,
) {
    match polarity {
        AcePolarity::Allow => {
            for node_index in tree.subtree_range(index) {
                apply_bits(&mut states[node_index], bits, AcePolarity::Allow);
            }
            propagate_grants_up(tree, states);
        }
        AcePolarity::Deny => {
            let mut newly_denied = Vec::new();
            for node_index in tree.subtree_range(index) {
                let denied_bits = apply_bits(&mut states[node_index], bits, AcePolarity::Deny);
                if denied_bits != 0 {
                    newly_denied.push((node_index, denied_bits));
                }
            }
            for (node_index, denied_bits) in newly_denied {
                propagate_denials_up(tree, states, node_index, denied_bits);
            }
        }
    }
}

fn apply_bits(state: &mut NodeState, bits: u32, polarity: AcePolarity) -> u32 {
    let undecided = bits & !state.decided;
    if undecided == 0 {
        return 0;
    }

    state.decided |= undecided;
    if polarity == AcePolarity::Allow {
        state.granted |= undecided;
    }

    undecided
}

fn propagate_grants_up(tree: &ObjectTypeList, states: &mut [NodeState]) {
    for index in (0..states.len()).rev() {
        let mut children = tree.direct_children(index);
        let Some(first_child) = children.next() else {
            continue;
        };

        let mut common_granted = states[first_child].granted;
        for child in children {
            common_granted &= states[child].granted;
        }

        let new_bits = common_granted & !states[index].decided;
        if new_bits == 0 {
            continue;
        }

        states[index].decided |= new_bits;
        states[index].granted |= new_bits;
    }
}

fn propagate_denials_up(
    tree: &ObjectTypeList,
    states: &mut [NodeState],
    start_index: usize,
    denied_bits: u32,
) {
    let mut current = tree.parent_of(start_index);
    while let Some(index) = current {
        let newly_denied = denied_bits & !states[index].decided;
        if newly_denied != 0 {
            states[index].decided |= newly_denied;
        }
        current = tree.parent_of(index);
    }
}
