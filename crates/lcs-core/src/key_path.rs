use crate::config::LcsLimits;
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_key_component_bytes, validate_layer_name_bytes};
use crate::resolution::{
    Guid, PathEntryWriteRequest, PathTarget, ValidatedPathEntryWrite,
    validate_path_entry_write_request,
};
use crate::sequence::SequenceCounter;
use crate::source::NIL_GUID;

/// Namespace metadata stored on an open key fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdNamespaceView<'a> {
    pub resolved_path: &'a [&'a str],
    pub ancestor_guids: &'a [Guid],
    pub orphaned: bool,
}

/// Common key namespace mutation input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPathMutationInput<'a> {
    pub fd: KeyFdNamespaceView<'a>,
    pub layer: &'a str,
}

/// Derived `(parent GUID, child name, layer)` namespace tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedKeyPathMutation<'a> {
    pub parent_guid: Guid,
    pub child_name: &'a str,
    pub layer: &'a str,
}

/// Delete-key input after visible child enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteKeyInput<'a> {
    pub mutation: KeyPathMutationInput<'a>,
    pub visible_child_count: u32,
}

/// Visible-child counts considered before explicit key deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteVisibleChildGateInput {
    pub global_enabled_visible_child_count: u32,
    pub caller_private_visible_child_count: u32,
}

/// Successful visible-child admission for explicit key deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteVisibleChildGatePlan {
    pub visible_child_count_used: u32,
    pub evaluates_global_enabled_layers: bool,
    pub ignores_caller_private_layer_set: bool,
    pub recursive_delete_is_client_side: bool,
}

/// Kernel-side effect contract for explicit key deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyDeleteEffects {
    pub removes_target_layer_path_entry: bool,
    pub preserves_key_data: bool,
    pub preserves_other_layer_path_entries: bool,
}

/// Source-dispatch-ready delete-key plan plus side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedKeyDelete<'a> {
    pub target: DerivedKeyPathMutation<'a>,
    pub updates_parent_last_write_time: bool,
    pub effects: KeyDeleteEffects,
}

/// Hide-key input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HideKeyInput<'a> {
    pub mutation: KeyPathMutationInput<'a>,
}

/// Source-dispatch-ready hide-key plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedKeyHide<'a> {
    pub path_entry: ValidatedPathEntryWrite<'a>,
    pub masks_lower_layers: bool,
}

/// Caller-visible errno class for namespace delete/hide planning failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPathMutationErrno {
    Einval,
    Enoent,
    Enotempty,
}

/// Derives and validates `(parent GUID, child name, layer)` from key fd state.
pub fn derive_key_path_mutation<'a>(
    limits: &LcsLimits,
    input: &KeyPathMutationInput<'a>,
) -> LcsResult<DerivedKeyPathMutation<'a>> {
    if input.fd.orphaned {
        return Err(LcsError::OrphanedKeyNamespaceOperation);
    }

    let path_len = input.fd.resolved_path.len();
    if path_len < 2 {
        return Err(LcsError::HiveRootKeyOperation);
    }
    if input.fd.ancestor_guids.len() != path_len {
        return Err(LcsError::InvalidFdAncestry);
    }

    let parent_guid = input.fd.ancestor_guids[path_len - 2];
    if parent_guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }

    let child_name =
        validate_key_component_bytes(input.fd.resolved_path[path_len - 1].as_bytes(), limits)?;
    let layer = validate_layer_name_bytes(input.layer.as_bytes(), limits)?;

    Ok(DerivedKeyPathMutation {
        parent_guid,
        child_name,
        layer,
    })
}

/// Plans `REG_IOC_DELETE_KEY` after visible child count is known.
pub fn plan_key_delete<'a>(
    limits: &LcsLimits,
    input: &DeleteKeyInput<'a>,
) -> LcsResult<PlannedKeyDelete<'a>> {
    let target = derive_key_path_mutation(limits, &input.mutation)?;
    if input.visible_child_count != 0 {
        return Err(LcsError::KeyHasVisibleChildren {
            count: input.visible_child_count,
        });
    }

    Ok(PlannedKeyDelete {
        target,
        updates_parent_last_write_time: true,
        effects: KeyDeleteEffects {
            removes_target_layer_path_entry: true,
            preserves_key_data: true,
            preserves_other_layer_path_entries: true,
        },
    })
}

/// Applies the visible-child gate for explicit key deletion.
pub fn plan_delete_visible_child_gate(
    input: DeleteVisibleChildGateInput,
) -> LcsResult<DeleteVisibleChildGatePlan> {
    if input.global_enabled_visible_child_count != 0 {
        return Err(LcsError::KeyHasVisibleChildren {
            count: input.global_enabled_visible_child_count,
        });
    }

    Ok(DeleteVisibleChildGatePlan {
        visible_child_count_used: input.global_enabled_visible_child_count,
        evaluates_global_enabled_layers: true,
        ignores_caller_private_layer_set: true,
        recursive_delete_is_client_side: true,
    })
}

/// Plans `REG_IOC_HIDE_KEY` and assigns a HIDDEN path-entry sequence.
pub fn plan_key_hide<'a>(
    limits: &LcsLimits,
    sequence_counter: &mut SequenceCounter,
    input: &HideKeyInput<'a>,
) -> LcsResult<PlannedKeyHide<'a>> {
    let target = derive_key_path_mutation(limits, &input.mutation)?;
    let sequence = sequence_counter.allocate()?;
    let path_entry = validate_path_entry_write_request(
        limits,
        &PathEntryWriteRequest {
            parent_guid: target.parent_guid,
            child_name: target.child_name,
            layer: target.layer,
            sequence,
            target: PathTarget::Hidden,
        },
    )?;

    Ok(PlannedKeyHide {
        path_entry,
        masks_lower_layers: true,
    })
}

/// Maps key namespace mutation planning failures to their PSD-005 errno class.
pub fn key_path_mutation_errno(error: &LcsError) -> Option<KeyPathMutationErrno> {
    match error {
        LcsError::HiveRootKeyOperation => Some(KeyPathMutationErrno::Einval),
        LcsError::OrphanedKeyNamespaceOperation => Some(KeyPathMutationErrno::Enoent),
        LcsError::KeyHasVisibleChildren { .. } => Some(KeyPathMutationErrno::Enotempty),
        _ => None,
    }
}
