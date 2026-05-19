use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::{
    REG_NOTIFY_ALL, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE, REG_WATCH_KEY_DELETED,
    REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET,
};
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_layer_name_bytes, validate_value_name_bytes};
use crate::resolution::{EnumeratedValue, Guid};
use crate::source::NIL_GUID;
use crate::value::validate_value_data_len;

const DIRECT_WATCH_EVENT_HEADER_LEN: usize = 8;
const SUBTREE_WATCH_EVENT_DEPTH_LEN: usize = 2;
const WATCH_COMPONENT_LEN_FIELD: usize = 2;

/// Kernel watch state stored on a key fd before `REG_IOC_NOTIFY`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyWatchState {
    pub armed: bool,
    pub orphaned: bool,
}

/// Copied and shape-checked `reg_notify_args`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchNotifyArgs {
    pub filter: u32,
    pub subtree: u8,
    pub reserved: [u8; 3],
}

/// Planned watch state transition for `REG_IOC_NOTIFY`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchNotifyPlan {
    Arm {
        filter: u32,
        subtree: bool,
        replaces_existing: bool,
    },
    Disarm {
        discard_pending_events: bool,
    },
}

/// Event-filter category used by §4.2 dispatch matching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchEventCategory {
    Value,
    Subkey,
    SecurityDescriptor,
    Always,
}

/// Requested watch event record shape before byte serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchEventRecordRequest<'a> {
    pub event_type: u32,
    pub name: &'a str,
    pub subtree: bool,
    pub path_components: &'a [&'a str],
}

/// Serializable watch event record metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchEventRecordShape {
    pub total_len: u32,
    pub name_len: u16,
    pub path_depth: Option<u16>,
}

/// Watch event record decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchEventRecordPlan {
    Record(WatchEventRecordShape),
    OverflowInstead,
}

/// Pending event length stored in a watch queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedWatchEvent {
    pub total_len: u32,
}

/// Watch read batching decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchReadBatchPlan {
    WouldBlock,
    Ready { event_count: usize, bytes: usize },
}

/// Minimal queue snapshot needed for overflow planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueueState {
    pub queued_events: usize,
    pub contains_overflow: bool,
}

/// Queue insertion policy for one incoming watch event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchQueueInsertPlan {
    QueueEvent,
    DropOldestAndQueueOverflow,
    DropOldestPreservingOverflowAndQueueEvent,
}

/// One armed watcher considered during dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatcherView {
    pub watched_guid: Guid,
    pub filter: u32,
    pub subtree: bool,
}

/// Captured ancestry for the key being mutated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchMutationContext<'a> {
    pub changed_key_guid: Guid,
    pub ancestor_guids: &'a [Guid],
    pub path_components: &'a [&'a str],
    pub event_type: u32,
}

/// A watch event delivery selected by dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchDelivery<'a> {
    pub event_type: u32,
    pub subtree_record: bool,
    pub relative_path_components: &'a [&'a str],
}

/// Dispatch decision for one watcher and one mutation event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchDispatchDecision<'a> {
    Deliver(WatchDelivery<'a>),
    NoMatch,
    SuppressedByDepthLimit { depth: usize, max: usize },
}

/// Per-watcher event-generation policy for one transaction commit batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionWatchBurstPlan {
    NoEvents,
    EmitIndividualEvents {
        event_count: usize,
    },
    EmitOverflowOnly {
        attempted_event_count: usize,
        max_event_burst: usize,
    },
}

/// Value-level effective-state watch event selected by snapshot diffing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveValueWatchEvent<'a> {
    ValueSet { name: &'a str },
    ValueDeleted { name: &'a str },
}

impl EffectiveValueWatchEvent<'_> {
    pub fn event_type(self) -> u32 {
        match self {
            Self::ValueSet { .. } => REG_WATCH_VALUE_SET,
            Self::ValueDeleted { .. } => REG_WATCH_VALUE_DELETED,
        }
    }
}

/// Internal LCS watcher target for self-configuration and layer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalWatchTarget {
    SelfConfiguration,
    LayerMetadata,
    MachineRootFallback,
}

/// Kernel-internal watch registration shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalWatchRegistration {
    pub watched_guid: Guid,
    pub target: InternalWatchTarget,
    pub subtree: bool,
    pub has_fd: bool,
    pub has_granted_access_mask: bool,
    pub has_filter: bool,
    pub receives_all_event_types: bool,
    pub subject_to_notification_queue_limit: bool,
}

/// Resolved GUIDs needed to arm LCS self-watch registrations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalSelfWatchRoots {
    pub machine_root_guid: Guid,
    pub registry_guid: Option<Guid>,
    pub layers_guid: Option<Guid>,
}

/// Registration plan for the LCS internal self-watch mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalSelfWatchPlan {
    Targeted {
        registry: InternalWatchRegistration,
        layers: InternalWatchRegistration,
    },
    MachineRootFallback {
        root: InternalWatchRegistration,
    },
}

/// Dirty path classified by live internal watch dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalWatchDirtyPath<'a> {
    SelfConfigurationValue {
        value_name: &'a str,
    },
    LayerMetadata {
        layer_name: &'a str,
    },
    LayerSubkey {
        event_type: u32,
        layer_name: &'a str,
    },
    RegistrySubtreeAvailable,
}

/// Action selected for one internal watch callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalWatchCallbackPlan<'a> {
    RefreshSelfConfiguration {
        dirty_value_name: &'a str,
    },
    RefreshLayerMetadata {
        dirty_layer_name: &'a str,
        publish_only_complete_entry: bool,
    },
    AddLayer {
        layer_name: &'a str,
        publish_only_complete_entry: bool,
    },
    DeleteLayer {
        layer_name: &'a str,
    },
    ResolveAndRearmTargetedWatches,
}

/// Validates the REG_IOC_NOTIFY filter bitmask.
pub fn validate_notify_filter(filter: u32) -> LcsResult<u32> {
    let unknown = filter & !REG_NOTIFY_ALL;
    if unknown != 0 {
        return Err(LcsError::UnknownNotifyFilterFlags {
            flags: filter,
            unknown,
        });
    }
    Ok(filter)
}

/// Validates a one-byte ABI boolean field.
pub fn validate_abi_bool(field: &'static str, value: u8) -> LcsResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(LcsError::InvalidBooleanFlag { field, value }),
    }
}

/// Validates that reserved REG_IOC_NOTIFY padding bytes are zero.
pub fn validate_notify_reserved(reserved: [u8; 3]) -> LcsResult<()> {
    if reserved.iter().any(|byte| *byte != 0) {
        return Err(LcsError::NonZeroReservedBytes {
            field: "reg_notify_args._pad",
        });
    }
    Ok(())
}

/// Plans `REG_IOC_NOTIFY` arm, replace, or disarm behavior for a key fd.
pub fn plan_watch_notify(
    state: KeyWatchState,
    args: &WatchNotifyArgs,
) -> LcsResult<WatchNotifyPlan> {
    let filter = validate_notify_filter(args.filter)?;
    let subtree = validate_abi_bool("reg_notify_args.subtree", args.subtree)?;
    validate_notify_reserved(args.reserved)?;

    if filter == 0 {
        return Ok(WatchNotifyPlan::Disarm {
            discard_pending_events: state.armed,
        });
    }

    if state.orphaned && !state.armed {
        return Err(LcsError::OrphanedWatchArm);
    }

    Ok(WatchNotifyPlan::Arm {
        filter,
        subtree,
        replaces_existing: state.armed,
    })
}

/// Classifies a PSD-005 watch event type into its notify-filter category.
pub fn watch_event_category(event_type: u32) -> LcsResult<WatchEventCategory> {
    match event_type {
        REG_WATCH_VALUE_SET | REG_WATCH_VALUE_DELETED => Ok(WatchEventCategory::Value),
        REG_WATCH_SUBKEY_CREATED | REG_WATCH_SUBKEY_DELETED => Ok(WatchEventCategory::Subkey),
        REG_WATCH_SD_CHANGED => Ok(WatchEventCategory::SecurityDescriptor),
        REG_WATCH_KEY_DELETED | REG_WATCH_OVERFLOW => Ok(WatchEventCategory::Always),
        _ => Err(LcsError::UnknownWatchEventType(event_type)),
    }
}

/// Returns whether an event must be queued for a watch with this filter.
pub fn watch_event_matches_filter(event_type: u32, filter: u32) -> LcsResult<bool> {
    validate_notify_filter(filter)?;
    match watch_event_category(event_type)? {
        WatchEventCategory::Value => Ok((filter & REG_NOTIFY_VALUE) != 0),
        WatchEventCategory::Subkey => Ok((filter & REG_NOTIFY_SUBKEY) != 0),
        WatchEventCategory::SecurityDescriptor => Ok((filter & REG_NOTIFY_SD) != 0),
        WatchEventCategory::Always => Ok(true),
    }
}

/// Computes the record metadata for a direct or subtree watch event.
pub fn plan_watch_event_record(
    request: &WatchEventRecordRequest<'_>,
) -> LcsResult<WatchEventRecordPlan> {
    let category = watch_event_category(request.event_type)?;
    if matches!(
        category,
        WatchEventCategory::SecurityDescriptor | WatchEventCategory::Always
    ) && !request.name.is_empty()
    {
        return Err(LcsError::WatchNoNameEventCarriedName {
            event_type: request.event_type,
        });
    }
    if !request.subtree && !request.path_components.is_empty() {
        return Err(LcsError::DirectWatchEventHasPath);
    }

    let name_len = match u16::try_from(request.name.len()) {
        Ok(len) => len,
        Err(_) => return Ok(WatchEventRecordPlan::OverflowInstead),
    };
    let mut total_len = match DIRECT_WATCH_EVENT_HEADER_LEN.checked_add(request.name.len()) {
        Some(len) => len,
        None => return Ok(WatchEventRecordPlan::OverflowInstead),
    };

    let path_depth = if request.subtree {
        let path_depth = match u16::try_from(request.path_components.len()) {
            Ok(depth) => depth,
            Err(_) => return Ok(WatchEventRecordPlan::OverflowInstead),
        };
        total_len = match total_len.checked_add(SUBTREE_WATCH_EVENT_DEPTH_LEN) {
            Some(len) => len,
            None => return Ok(WatchEventRecordPlan::OverflowInstead),
        };
        for component in request.path_components {
            if u16::try_from(component.len()).is_err() {
                return Ok(WatchEventRecordPlan::OverflowInstead);
            }
            total_len = match total_len
                .checked_add(WATCH_COMPONENT_LEN_FIELD)
                .and_then(|len| len.checked_add(component.len()))
            {
                Some(len) => len,
                None => return Ok(WatchEventRecordPlan::OverflowInstead),
            };
        }
        Some(path_depth)
    } else {
        None
    };

    let total_len = match u32::try_from(total_len) {
        Ok(len) => len,
        Err(_) => return Ok(WatchEventRecordPlan::OverflowInstead),
    };
    Ok(WatchEventRecordPlan::Record(WatchEventRecordShape {
        total_len,
        name_len,
        path_depth,
    }))
}

/// Plans one read() batch without splitting variable-length watch records.
pub fn plan_watch_read_batch(
    pending: &[QueuedWatchEvent],
    buffer_len: usize,
) -> LcsResult<WatchReadBatchPlan> {
    let Some(first) = pending.first() else {
        return Ok(WatchReadBatchPlan::WouldBlock);
    };
    let first_len = validate_queued_event_len(*first)?;
    if buffer_len < first_len {
        return Err(LcsError::WatchReadBufferTooSmall {
            buffer_len,
            first_event_len: first_len,
        });
    }

    let mut event_count = 0;
    let mut bytes = 0usize;
    for event in pending {
        let event_len = validate_queued_event_len(*event)?;
        let Some(next_bytes) = bytes.checked_add(event_len) else {
            break;
        };
        if next_bytes > buffer_len {
            break;
        }
        event_count += 1;
        bytes = next_bytes;
    }

    Ok(WatchReadBatchPlan::Ready { event_count, bytes })
}

fn validate_queued_event_len(event: QueuedWatchEvent) -> LcsResult<usize> {
    let total_len = event.total_len as usize;
    if total_len < DIRECT_WATCH_EVENT_HEADER_LEN {
        return Err(LcsError::InvalidWatchEventLength(event.total_len));
    }
    Ok(total_len)
}

/// Plans queue insertion when a watch event arrives.
pub fn plan_watch_queue_insert(
    queue_limit: usize,
    state: WatchQueueState,
) -> LcsResult<WatchQueueInsertPlan> {
    if queue_limit == 0 {
        return Err(LcsError::InvalidWatchQueueLimit);
    }
    if state.queued_events > queue_limit || (state.contains_overflow && state.queued_events == 0) {
        return Err(LcsError::InvalidWatchQueueState);
    }
    if state.queued_events < queue_limit {
        return Ok(WatchQueueInsertPlan::QueueEvent);
    }
    if state.contains_overflow {
        Ok(WatchQueueInsertPlan::DropOldestPreservingOverflowAndQueueEvent)
    } else {
        Ok(WatchQueueInsertPlan::DropOldestAndQueueOverflow)
    }
}

/// Selects whether a watcher receives a mutation event using captured ancestry.
pub fn plan_watch_dispatch<'a>(
    limits: &LcsLimits,
    watcher: WatcherView,
    mutation: &WatchMutationContext<'a>,
) -> LcsResult<WatchDispatchDecision<'a>> {
    validate_watch_mutation_context(mutation)?;
    if !watch_event_matches_filter(mutation.event_type, watcher.filter)? {
        return Ok(WatchDispatchDecision::NoMatch);
    }

    let changed_index = mutation.ancestor_guids.len() - 1;
    if watcher.watched_guid == mutation.changed_key_guid {
        return Ok(WatchDispatchDecision::Deliver(WatchDelivery {
            event_type: mutation.event_type,
            subtree_record: watcher.subtree,
            relative_path_components: &mutation.path_components[changed_index + 1..],
        }));
    }

    if !watcher.subtree {
        return Ok(WatchDispatchDecision::NoMatch);
    }

    let Some(watched_index) = mutation
        .ancestor_guids
        .iter()
        .position(|guid| *guid == watcher.watched_guid)
    else {
        return Ok(WatchDispatchDecision::NoMatch);
    };
    if watched_index == changed_index {
        return Ok(WatchDispatchDecision::NoMatch);
    }

    let depth = changed_index - watched_index;
    if limits.max_subtree_watch_depth != 0 && depth > limits.max_subtree_watch_depth {
        return Ok(WatchDispatchDecision::SuppressedByDepthLimit {
            depth,
            max: limits.max_subtree_watch_depth,
        });
    }

    Ok(WatchDispatchDecision::Deliver(WatchDelivery {
        event_type: mutation.event_type,
        subtree_record: true,
        relative_path_components: &mutation.path_components[watched_index + 1..=changed_index],
    }))
}

/// Plans transaction commit watch emission after per-watcher event counting.
pub fn plan_transaction_watch_burst(
    limits: &LcsLimits,
    event_count: usize,
) -> LcsResult<TransactionWatchBurstPlan> {
    let max_event_burst = limits.max_transaction_watch_event_burst;
    if max_event_burst == 0 {
        return Err(LcsError::InvalidTransactionWatchBurstLimit);
    }
    if event_count == 0 {
        return Ok(TransactionWatchBurstPlan::NoEvents);
    }
    if event_count > max_event_burst {
        return Ok(TransactionWatchBurstPlan::EmitOverflowOnly {
            attempted_event_count: event_count,
            max_event_burst,
        });
    }
    Ok(TransactionWatchBurstPlan::EmitIndividualEvents { event_count })
}

/// Emits value watch events for the caller-visible effective-state difference.
pub fn for_each_effective_value_watch_event<'a, F>(
    limits: &LcsLimits,
    before: &'a [EnumeratedValue<'a>],
    after: &'a [EnumeratedValue<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(EffectiveValueWatchEvent<'a>) -> LcsResult<()>,
{
    validate_effective_value_snapshot(limits, "before", before)?;
    validate_effective_value_snapshot(limits, "after", after)?;

    let mut emitted = 0usize;
    for before_value in before {
        let Some(after_value) = find_effective_value(after, before_value.name) else {
            emit(EffectiveValueWatchEvent::ValueDeleted {
                name: before_value.name,
            })?;
            emitted += 1;
            continue;
        };
        if !same_effective_value(before_value, after_value) {
            emit(EffectiveValueWatchEvent::ValueSet {
                name: after_value.name,
            })?;
            emitted += 1;
        }
    }

    for after_value in after {
        if find_effective_value(before, after_value.name).is_none() {
            emit(EffectiveValueWatchEvent::ValueSet {
                name: after_value.name,
            })?;
            emitted += 1;
        }
    }

    Ok(emitted)
}

/// Plans internal LCS self-watch registrations after source registration.
pub fn plan_internal_self_watch(roots: InternalSelfWatchRoots) -> LcsResult<InternalSelfWatchPlan> {
    validate_internal_watch_guid(roots.machine_root_guid)?;

    match (roots.registry_guid, roots.layers_guid) {
        (Some(registry_guid), Some(layers_guid)) => {
            validate_internal_watch_guid(registry_guid)?;
            validate_internal_watch_guid(layers_guid)?;
            Ok(InternalSelfWatchPlan::Targeted {
                registry: internal_watch_registration(
                    registry_guid,
                    InternalWatchTarget::SelfConfiguration,
                ),
                layers: internal_watch_registration(
                    layers_guid,
                    InternalWatchTarget::LayerMetadata,
                ),
            })
        }
        (Some(registry_guid), None) => {
            validate_internal_watch_guid(registry_guid)?;
            Ok(InternalSelfWatchPlan::MachineRootFallback {
                root: internal_watch_registration(
                    roots.machine_root_guid,
                    InternalWatchTarget::MachineRootFallback,
                ),
            })
        }
        (None, Some(layers_guid)) => {
            validate_internal_watch_guid(layers_guid)?;
            Ok(InternalSelfWatchPlan::MachineRootFallback {
                root: internal_watch_registration(
                    roots.machine_root_guid,
                    InternalWatchTarget::MachineRootFallback,
                ),
            })
        }
        (None, None) => Ok(InternalSelfWatchPlan::MachineRootFallback {
            root: internal_watch_registration(
                roots.machine_root_guid,
                InternalWatchTarget::MachineRootFallback,
            ),
        }),
    }
}

/// Plans the synchronous callback action for an internal self-watch event.
pub fn plan_internal_watch_callback<'a>(
    limits: &LcsLimits,
    dirty_path: InternalWatchDirtyPath<'a>,
) -> LcsResult<InternalWatchCallbackPlan<'a>> {
    match dirty_path {
        InternalWatchDirtyPath::SelfConfigurationValue { value_name } => {
            let value_name = validate_value_name_bytes(value_name.as_bytes(), limits)?;
            Ok(InternalWatchCallbackPlan::RefreshSelfConfiguration {
                dirty_value_name: value_name,
            })
        }
        InternalWatchDirtyPath::LayerMetadata { layer_name } => {
            let layer_name = validate_layer_name_bytes(layer_name.as_bytes(), limits)?;
            Ok(InternalWatchCallbackPlan::RefreshLayerMetadata {
                dirty_layer_name: layer_name,
                publish_only_complete_entry: true,
            })
        }
        InternalWatchDirtyPath::LayerSubkey {
            event_type,
            layer_name,
        } => {
            let layer_name = validate_layer_name_bytes(layer_name.as_bytes(), limits)?;
            match event_type {
                REG_WATCH_SUBKEY_CREATED => Ok(InternalWatchCallbackPlan::AddLayer {
                    layer_name,
                    publish_only_complete_entry: true,
                }),
                REG_WATCH_SUBKEY_DELETED => {
                    Ok(InternalWatchCallbackPlan::DeleteLayer { layer_name })
                }
                _ => {
                    watch_event_category(event_type)?;
                    Err(LcsError::UnexpectedInternalWatchEvent { event_type })
                }
            }
        }
        InternalWatchDirtyPath::RegistrySubtreeAvailable => {
            Ok(InternalWatchCallbackPlan::ResolveAndRearmTargetedWatches)
        }
    }
}

fn internal_watch_registration(
    watched_guid: Guid,
    target: InternalWatchTarget,
) -> InternalWatchRegistration {
    InternalWatchRegistration {
        watched_guid,
        target,
        subtree: true,
        has_fd: false,
        has_granted_access_mask: false,
        has_filter: false,
        receives_all_event_types: true,
        subject_to_notification_queue_limit: false,
    }
}

fn validate_internal_watch_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}

fn validate_effective_value_snapshot(
    limits: &LcsLimits,
    snapshot: &'static str,
    values: &[EnumeratedValue<'_>],
) -> LcsResult<()> {
    for (index, value) in values.iter().enumerate() {
        validate_value_name_bytes(value.name.as_bytes(), limits)?;
        validate_layer_name_bytes(value.value.layer.as_bytes(), limits)?;
        validate_value_data_len(value.value.data.len(), limits)?;
        if effective_value_seen_before(limits, values, index, value.name)? {
            return Err(LcsError::DuplicateEffectiveWatchValueName { snapshot, index });
        }
    }
    Ok(())
}

fn effective_value_seen_before(
    limits: &LcsLimits,
    values: &[EnumeratedValue<'_>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    let current_name = validate_value_name_bytes(current_name.as_bytes(), limits)?;
    for previous in &values[..index] {
        let previous_name = validate_value_name_bytes(previous.name.as_bytes(), limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn find_effective_value<'a>(
    values: &'a [EnumeratedValue<'a>],
    name: &str,
) -> Option<&'a EnumeratedValue<'a>> {
    values
        .iter()
        .find(|candidate| casefold_eq(candidate.name, name))
}

fn same_effective_value(before: &EnumeratedValue<'_>, after: &EnumeratedValue<'_>) -> bool {
    before.name == after.name
        && before.value.value_type == after.value.value_type
        && before.value.data == after.value.data
        && before.value.layer == after.value.layer
        && before.value.sequence == after.value.sequence
}

fn validate_watch_mutation_context(mutation: &WatchMutationContext<'_>) -> LcsResult<()> {
    if mutation.ancestor_guids.is_empty()
        || mutation.ancestor_guids.len() != mutation.path_components.len()
    {
        return Err(LcsError::InvalidWatchAncestry);
    }
    if mutation.ancestor_guids[mutation.ancestor_guids.len() - 1] != mutation.changed_key_guid {
        return Err(LcsError::WatchChangedKeyNotLastAncestor);
    }
    watch_event_category(mutation.event_type)?;
    Ok(())
}
