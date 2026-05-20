use crate::config::LcsLimits;
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_key_component_bytes, validate_layer_name_bytes};
use crate::resolution::{
    Guid, PathEntryWriteRequest, PathTarget, ValidatedPathEntryWrite,
    validate_path_entry_write_request,
};
use crate::sequence::SequenceCounter;
use crate::source::NIL_GUID;
use crate::transaction::{
    TransactionMutationLogKind, TransactionOperationIndex, TransactionOperationIndexCounter,
};
use crate::watch::{
    WatchAncestryContext, validate_watch_ancestry_context, validate_watch_ancestry_payload,
};

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
    pub parent_watch_context: WatchAncestryContext<'a>,
    pub child_visibility_watch_context: WatchAncestryContext<'a>,
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
    pub parent_watch_context: WatchAncestryContext<'a>,
    pub child_visibility_watch_context: WatchAncestryContext<'a>,
    pub masks_lower_layers: bool,
}

/// Key path transaction mutation-log entry for commit-time kernel effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionKeyPathMutationLogEntry<'a> {
    pub operation_index: TransactionOperationIndex,
    pub kind: TransactionMutationLogKind,
    pub parent_guid: Guid,
    pub parent_watch_context: WatchAncestryContext<'a>,
    pub child_visibility_watch_context: Option<WatchAncestryContext<'a>>,
    pub child_name: &'a str,
    pub layer: &'a str,
    pub target_guid: Option<Guid>,
    pub sequence: Option<u64>,
    pub update_hive_generation_on_commit: bool,
    pub update_parent_last_write_time_on_commit: bool,
    pub recompute_effective_subkey_events_on_commit: bool,
    pub evaluate_orphaning_on_commit: bool,
    pub publish_new_key_guid_on_commit: bool,
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
    let (parent_watch_context, child_visibility_watch_context) =
        derive_key_path_watch_contexts(limits, input.mutation.fd, target)?;

    Ok(PlannedKeyDelete {
        target,
        parent_watch_context,
        child_visibility_watch_context,
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
    let (parent_watch_context, child_visibility_watch_context) =
        derive_key_path_watch_contexts(limits, input.mutation.fd, target)?;
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
        parent_watch_context,
        child_visibility_watch_context,
        masks_lower_layers: true,
    })
}

/// Plans a transaction mutation-log entry for a validated DELETE_KEY operation.
pub fn plan_key_delete_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &PlannedKeyDelete<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionKeyPathMutationLogEntry<'a>> {
    validate_planned_key_delete_for_log(limits, planned)?;
    Ok(TransactionKeyPathMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::DeleteKey,
        parent_guid: planned.target.parent_guid,
        parent_watch_context: planned.parent_watch_context,
        child_visibility_watch_context: Some(planned.child_visibility_watch_context),
        child_name: planned.target.child_name,
        layer: planned.target.layer,
        target_guid: None,
        sequence: None,
        update_hive_generation_on_commit: true,
        update_parent_last_write_time_on_commit: true,
        recompute_effective_subkey_events_on_commit: true,
        evaluate_orphaning_on_commit: true,
        publish_new_key_guid_on_commit: false,
    })
}

/// Plans a transaction mutation-log entry for a validated HIDE_KEY operation.
pub fn plan_key_hide_transaction_log_entry<'a>(
    limits: &LcsLimits,
    planned: &PlannedKeyHide<'a>,
    counter: &mut TransactionOperationIndexCounter,
) -> LcsResult<TransactionKeyPathMutationLogEntry<'a>> {
    validate_planned_key_hide_for_log(limits, planned)?;
    Ok(TransactionKeyPathMutationLogEntry {
        operation_index: counter.allocate()?,
        kind: TransactionMutationLogKind::HideKey,
        parent_guid: planned.path_entry.parent_guid,
        parent_watch_context: planned.parent_watch_context,
        child_visibility_watch_context: Some(planned.child_visibility_watch_context),
        child_name: planned.path_entry.child_name,
        layer: planned.path_entry.layer,
        target_guid: None,
        sequence: Some(planned.path_entry.sequence),
        update_hive_generation_on_commit: true,
        update_parent_last_write_time_on_commit: false,
        recompute_effective_subkey_events_on_commit: true,
        evaluate_orphaning_on_commit: false,
        publish_new_key_guid_on_commit: false,
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

fn validate_planned_key_delete_for_log(
    limits: &LcsLimits,
    planned: &PlannedKeyDelete<'_>,
) -> LcsResult<()> {
    validate_derived_key_path_mutation(limits, planned.target)?;
    if !planned.updates_parent_last_write_time {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "updates_parent_last_write_time",
        });
    }
    if !planned.effects.removes_target_layer_path_entry
        || !planned.effects.preserves_key_data
        || !planned.effects.preserves_other_layer_path_entries
    {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "delete_key.effects",
        });
    }
    Ok(())
}

fn validate_planned_key_hide_for_log(
    limits: &LcsLimits,
    planned: &PlannedKeyHide<'_>,
) -> LcsResult<()> {
    validate_path_entry_write_request(
        limits,
        &PathEntryWriteRequest {
            parent_guid: planned.path_entry.parent_guid,
            child_name: planned.path_entry.child_name,
            layer: planned.path_entry.layer,
            sequence: planned.path_entry.sequence,
            target: planned.path_entry.target,
        },
    )?;
    if planned.path_entry.target != PathTarget::Hidden {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "path_entry.target",
        });
    }
    if !planned.masks_lower_layers {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "masks_lower_layers",
        });
    }
    Ok(())
}

pub(crate) fn validate_derived_key_path_mutation(
    limits: &LcsLimits,
    target: DerivedKeyPathMutation<'_>,
) -> LcsResult<()> {
    if target.parent_guid == NIL_GUID {
        return Err(LcsError::NilParentGuid);
    }
    validate_key_component_bytes(target.child_name.as_bytes(), limits)?;
    validate_layer_name_bytes(target.layer.as_bytes(), limits)?;
    Ok(())
}

pub(crate) fn validate_parent_watch_context(
    parent_guid: Guid,
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_context(context)?;
    if context.changed_key_guid != parent_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.parent_watch_context.changed_key_guid",
        });
    }
    Ok(())
}

pub(crate) fn validate_parent_watch_context_for_log(
    limits: &LcsLimits,
    parent_guid: Guid,
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_payload(limits, "key_path.parent_watch_context", context)?;
    if context.changed_key_guid != parent_guid {
        return Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "key_path.parent_watch_context.changed_key_guid",
        });
    }
    Ok(())
}

pub(crate) fn validate_child_visibility_watch_context(
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_context(context)?;
    Ok(())
}

fn validate_child_visibility_watch_context_for_log(
    limits: &LcsLimits,
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_payload(limits, "key_path.child_visibility_watch_context", context)?;
    Ok(())
}

fn derive_key_path_watch_contexts<'a>(
    limits: &LcsLimits,
    fd: KeyFdNamespaceView<'a>,
    target: DerivedKeyPathMutation<'a>,
) -> LcsResult<(WatchAncestryContext<'a>, WatchAncestryContext<'a>)> {
    let path_len = fd.resolved_path.len();
    let parent_watch_context = WatchAncestryContext {
        changed_key_guid: target.parent_guid,
        ancestor_guids: &fd.ancestor_guids[..path_len - 1],
        path_components: &fd.resolved_path[..path_len - 1],
    };
    let child_visibility_watch_context = WatchAncestryContext {
        changed_key_guid: fd.ancestor_guids[path_len - 1],
        ancestor_guids: fd.ancestor_guids,
        path_components: fd.resolved_path,
    };
    validate_parent_watch_context_for_log(limits, target.parent_guid, &parent_watch_context)?;
    validate_child_visibility_watch_context_for_log(limits, &child_visibility_watch_context)?;
    Ok((parent_watch_context, child_visibility_watch_context))
}
