use crate::access_mask::GenericMapping;
use crate::ace::{
    Ace, AceKind, ACE_OBJECT_TYPE_PRESENT, SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE,
};
use crate::acl::Acl;
use crate::condition::{evaluate_conditional_expression, ConditionalContext, ConditionalResult};
use crate::dacl::{sid_matches_token, AcePolarity};
use crate::error::KacsResult;
use crate::object_tree::ObjectTypeList;
use crate::pkm_alloc::{slice_to_vec, Vec};
use crate::sid::Sid;
use crate::token::TokenView;

const INHERIT_ONLY_ACE: u8 = 0x08;
const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const PRINCIPAL_SELF_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0];

/// One audit/alarm event emitted by SACL evaluation or forced policy.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct AuditEvent<'a> {
    /// Optional original ACE bytes responsible for the event.
    pub ace_bytes: Option<&'a [u8]>,
    /// Requested bits considered by the event.
    pub requested: u32,
    /// Granted bits visible when the event fired.
    pub granted: u32,
    /// Whether the event describes a success or failure.
    pub success: bool,
    /// Whether the event was forced by token audit policy rather than by a SACL
    /// ACE.
    pub policy_forced: bool,
    /// Optional privilege bit for privilege-use auditing.
    pub privilege: Option<u64>,
    /// Optional object-audit context blob.
    pub object_audit_context: Option<Vec<u8>>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq)]
/// Output of one `EvaluateSACL` run.
pub struct EvaluateSaclState<'a> {
    /// Audit events collected during the walk.
    pub audit_events: Vec<AuditEvent<'a>>,
    /// Continuous-audit mask collected from matched alarm ACEs.
    pub continuous_audit_mask: u32,
}

#[allow(clippy::too_many_arguments)]
/// Evaluates one SACL against the current access result and returns emitted
/// audit events plus the continuous-audit mask.
pub fn evaluate_sacl<'a>(
    sacl: &Acl<'a>,
    token: &TokenView<'_>,
    owner: Sid<'_>,
    self_sid: Option<Sid<'_>>,
    object_tree: Option<&ObjectTypeList>,
    mapped_desired: u32,
    granted: u32,
    mapping: &GenericMapping,
    conditional_context: &ConditionalContext<'_>,
    object_audit_context: Option<&[u8]>,
) -> KacsResult<EvaluateSaclState<'a>> {
    let caller_is_owner = owner_matches_identity(token, owner);
    let principal_self_matches =
        self_sid.map(|sid| sid_matches_token(token, sid, AcePolarity::Deny));
    let mut context = *conditional_context;
    context.caller_is_owner = caller_is_owner;
    context.principal_self_matches = principal_self_matches;

    let mut state = EvaluateSaclState::default();

    for ace in sacl.entries() {
        let ace = ace?;
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        handle_sacl_ace(
            &ace,
            token,
            self_sid,
            object_tree,
            mapped_desired,
            granted,
            mapping,
            &context,
            object_audit_context,
            &mut state,
        )?;
    }

    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn handle_sacl_ace<'a>(
    ace: &Ace<'a>,
    token: &TokenView<'_>,
    self_sid: Option<Sid<'_>>,
    object_tree: Option<&ObjectTypeList>,
    mapped_desired: u32,
    granted: u32,
    mapping: &GenericMapping,
    conditional_context: &ConditionalContext<'_>,
    object_audit_context: Option<&[u8]>,
    state: &mut EvaluateSaclState<'a>,
) -> KacsResult<()> {
    let ace_mask = mapped_ace_mask(ace, mapping)?;
    match (ace.ace_type(), ace.kind()) {
        (SYSTEM_AUDIT_ACE_TYPE, AceKind::SingleSid { sid, .. })
        | (SYSTEM_AUDIT_OBJECT_ACE_TYPE, AceKind::Object { sid, .. }) => {
            if !audit_sid_matches(token, sid, conditional_context.caller_is_owner, self_sid) {
                return Ok(());
            }
            if !audit_target_matches(ace, object_tree) {
                return Ok(());
            }
            if (ace_mask & mapped_desired) == 0 {
                return Ok(());
            }
            maybe_append_access_audit(ace, mapped_desired, granted, object_audit_context, state)?;
        }
        (
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            AceKind::Callback {
                sid,
                application_data,
                ..
            },
        )
        | (
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
            AceKind::CallbackObject {
                sid,
                application_data,
                ..
            },
        ) => {
            if !audit_sid_matches(token, sid, conditional_context.caller_is_owner, self_sid) {
                return Ok(());
            }
            if !audit_target_matches(ace, object_tree) {
                return Ok(());
            }
            let cond = evaluate_conditional_expression(
                application_data,
                token,
                conditional_context,
                false,
            );
            if cond == ConditionalResult::False {
                return Ok(());
            }
            if (ace_mask & mapped_desired) == 0 {
                return Ok(());
            }
            maybe_append_access_audit(ace, mapped_desired, granted, object_audit_context, state)?;
        }
        (SYSTEM_ALARM_ACE_TYPE, AceKind::SingleSid { sid, .. })
        | (SYSTEM_ALARM_OBJECT_ACE_TYPE, AceKind::Object { sid, .. }) => {
            if !audit_sid_matches(token, sid, conditional_context.caller_is_owner, self_sid) {
                return Ok(());
            }
            if !audit_target_matches(ace, object_tree) {
                return Ok(());
            }
            state.continuous_audit_mask |= ace_mask;
        }
        (
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            AceKind::Callback {
                sid,
                application_data,
                ..
            },
        )
        | (
            SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
            AceKind::CallbackObject {
                sid,
                application_data,
                ..
            },
        ) => {
            if !audit_sid_matches(token, sid, conditional_context.caller_is_owner, self_sid) {
                return Ok(());
            }
            if !audit_target_matches(ace, object_tree) {
                return Ok(());
            }
            let cond = evaluate_conditional_expression(
                application_data,
                token,
                conditional_context,
                false,
            );
            if cond == ConditionalResult::False {
                return Ok(());
            }
            state.continuous_audit_mask |= ace_mask;
        }
        _ => {}
    }

    Ok(())
}

fn maybe_append_access_audit<'a>(
    ace: &Ace<'a>,
    mapped_desired: u32,
    granted: u32,
    object_audit_context: Option<&[u8]>,
    state: &mut EvaluateSaclState<'a>,
) -> KacsResult<()> {
    let success = (granted & mapped_desired) == mapped_desired || mapped_desired == 0;
    if success && (ace.ace_flags() & SUCCESSFUL_ACCESS_ACE_FLAG) != 0 {
        state.audit_events.push(AuditEvent {
            ace_bytes: Some(ace.bytes()),
            requested: mapped_desired,
            granted,
            success: true,
            policy_forced: false,
            privilege: None,
            object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
        })?;
    }
    if !success && (ace.ace_flags() & FAILED_ACCESS_ACE_FLAG) != 0 {
        state.audit_events.push(AuditEvent {
            ace_bytes: Some(ace.bytes()),
            requested: mapped_desired,
            granted,
            success: false,
            policy_forced: false,
            privilege: None,
            object_audit_context: object_audit_context.map(slice_to_vec).transpose()?,
        })?;
    }
    Ok(())
}

fn mapped_ace_mask(ace: &Ace<'_>, mapping: &GenericMapping) -> KacsResult<u32> {
    let mask = match ace.kind() {
        AceKind::SingleSid { mask, .. }
        | AceKind::Object { mask, .. }
        | AceKind::Callback { mask, .. }
        | AceKind::CallbackObject { mask, .. }
        | AceKind::ResourceAttribute { mask, .. } => mask,
        AceKind::Opaque => 0,
    };
    mapping.map_mask(mask)
}

fn audit_target_matches(ace: &Ace<'_>, object_tree: Option<&ObjectTypeList>) -> bool {
    let Some(tree) = object_tree else {
        return true;
    };

    match ace.kind() {
        AceKind::Object {
            flags, object_type, ..
        }
        | AceKind::CallbackObject {
            flags, object_type, ..
        } => {
            if (flags & ACE_OBJECT_TYPE_PRESENT) == 0 {
                return true;
            }
            object_type.is_some_and(|guid| tree.find(guid).is_some())
        }
        _ => true,
    }
}

fn audit_sid_matches(
    token: &TokenView<'_>,
    sid: Sid<'_>,
    caller_is_owner: bool,
    self_sid: Option<Sid<'_>>,
) -> bool {
    if sid.as_bytes() == OWNER_RIGHTS_SID_BYTES {
        return caller_is_owner;
    }
    if sid.as_bytes() == PRINCIPAL_SELF_SID_BYTES {
        return self_sid
            .map(|principal| sid_matches_token(token, principal, AcePolarity::Deny))
            .unwrap_or(false);
    }

    sid_matches_token(token, sid, AcePolarity::Deny)
}

fn owner_matches_identity(token: &TokenView<'_>, sid: Sid<'_>) -> bool {
    sid == token.user || token.groups.iter().any(|group| group.sid == sid)
}
