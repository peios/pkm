use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::{
    REG_NOTIFY_ALL, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE, REG_WATCH_KEY_DELETED,
    REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET,
};
use crate::error::{LcsError, LcsResult};
use crate::path::{
    validate_key_component_bytes, validate_layer_name_bytes, validate_value_name_bytes,
};
use crate::resolution::{EnumeratedSubkey, EnumeratedValue, Guid, ResolvedPathEntry};
use crate::source::NIL_GUID;
use crate::validate_abi_reserved_zero;
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

/// Byte-serialization result for a watch event record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchEventRecordWritePlan {
    Written { bytes: usize },
    OverflowInstead,
}

/// Pending event length stored in a watch queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedWatchEvent {
    pub total_len: u32,
}

/// Runtime watch queue entry retained until a key fd read drains it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueueEntry {
    pub event_type: u32,
    pub total_len: u32,
}

/// Watch read batching decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchReadBatchPlan {
    WouldBlock,
    Ready { event_count: usize, bytes: usize },
}

/// Watch fd poll readiness bits expressed without platform poll constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueuePollPlan {
    pub readable: bool,
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

/// Applied queue mutation outcome for one incoming watch event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchQueuePushEffect {
    QueuedEvent,
    DropOldestAndQueueOverflow,
    DropOldestPreservingOverflowAndQueueEvent,
    PreservedExistingOverflow,
}

/// Summary returned after mutating caller-provided watch queue storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueueMutationSummary {
    pub queued_events: usize,
    pub contains_overflow: bool,
    pub effect: WatchQueuePushEffect,
}

/// Summary returned after clearing a watch queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueueClearSummary {
    pub queued_events: usize,
    pub contains_overflow: bool,
}

/// Applied read-drain outcome for one key-fd watch queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchQueueDrainSummary {
    pub queued_events: usize,
    pub contains_overflow: bool,
    pub event_count: usize,
    pub bytes: usize,
    pub drained_overflow: bool,
}

/// Watch queue read-drain decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchQueueReadDrainPlan {
    WouldBlock,
    Drained(WatchQueueDrainSummary),
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
pub struct WatchAncestryContext<'a> {
    pub changed_key_guid: Guid,
    pub ancestor_guids: &'a [Guid],
    pub path_components: &'a [&'a str],
}

impl<'a> WatchAncestryContext<'a> {
    pub const fn with_event(self, event_type: u32) -> WatchMutationContext<'a> {
        WatchMutationContext {
            changed_key_guid: self.changed_key_guid,
            ancestor_guids: self.ancestor_guids,
            path_components: self.path_components,
            event_type,
        }
    }
}

/// Captured ancestry plus the concrete event being dispatched.
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

/// Per-watcher event count generated by one operation in a transaction log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionWatchBatchMember {
    pub operation_index: u64,
    pub event_count: usize,
}

/// Per-watcher watch delivery plan for a committed transaction batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionWatchBatchPlan {
    pub operation_count: usize,
    pub total_event_count: usize,
    pub delivery: TransactionWatchBurstPlan,
    pub dispatch_without_interleaving: bool,
}

/// Applied transaction watch-batch queue effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionWatchQueueApplySummary {
    pub queued_events: usize,
    pub contains_overflow: bool,
    pub attempted_event_count: usize,
    pub queued_individual_events: usize,
    pub queued_overflow_only: bool,
    pub dispatch_without_interleaving: bool,
}

/// Transaction watch-batch queue application decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionWatchQueueApplyPlan {
    NoEvents(WatchQueueState),
    Applied(TransactionWatchQueueApplySummary),
}

/// Source-restart watch overflow queue application decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRestartWatchQueueApplyPlan {
    Unaffected(WatchQueueState),
    Applied(WatchQueueMutationSummary),
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

/// Subkey-level effective-state watch event selected by snapshot diffing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveSubkeyWatchEvent<'a> {
    SubkeyCreated { name: &'a str },
    SubkeyDeleted { name: &'a str },
}

impl EffectiveSubkeyWatchEvent<'_> {
    pub fn event_type(self) -> u32 {
        match self {
            Self::SubkeyCreated { .. } => REG_WATCH_SUBKEY_CREATED,
            Self::SubkeyDeleted { .. } => REG_WATCH_SUBKEY_DELETED,
        }
    }
}

/// Visibility event for a GUID-bound watched key object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchedKeyVisibilityEvent {
    KeyDeleted,
}

impl WatchedKeyVisibilityEvent {
    pub fn event_type(self) -> u32 {
        match self {
            Self::KeyDeleted => REG_WATCH_KEY_DELETED,
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

/// Reason a layer metadata refresh needs source I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalLayerMetadataRefreshReason {
    MetadataChanged,
    LayerCreated,
}

/// Lock-discipline plan for layer metadata refresh source I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InternalLayerMetadataRefreshLockPlan<'a> {
    pub layer_name: &'a str,
    pub reason: InternalLayerMetadataRefreshReason,
    pub release_watch_map_lock_before_source_round_trip: bool,
    pub release_layer_publication_lock_before_source_round_trip: bool,
    pub acquire_layer_publication_lock_only_for_atomic_publish: bool,
    pub publish_only_complete_entry: bool,
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
    validate_abi_reserved_zero("reg_notify_args._pad", &reserved)
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

/// Serializes a direct or subtree watch event record into PSD-005's raw byte
/// layout without writing partial output.
pub fn write_watch_event_record(
    request: &WatchEventRecordRequest<'_>,
    output: &mut [u8],
) -> LcsResult<WatchEventRecordWritePlan> {
    let shape = match plan_watch_event_record(request)? {
        WatchEventRecordPlan::Record(shape) => shape,
        WatchEventRecordPlan::OverflowInstead => {
            return Ok(WatchEventRecordWritePlan::OverflowInstead);
        }
    };
    let total_len = shape.total_len as usize;
    if output.len() < total_len {
        return Err(LcsError::WatchEventOutputBufferTooSmall {
            buffer_len: output.len(),
            required_len: total_len,
        });
    }

    output[..4].copy_from_slice(&shape.total_len.to_le_bytes());
    output[4..6].copy_from_slice(&(request.event_type as u16).to_le_bytes());
    output[6..8].copy_from_slice(&shape.name_len.to_le_bytes());
    let mut offset = DIRECT_WATCH_EVENT_HEADER_LEN;
    output[offset..offset + request.name.len()].copy_from_slice(request.name.as_bytes());
    offset += request.name.len();

    if let Some(path_depth) = shape.path_depth {
        output[offset..offset + 2].copy_from_slice(&path_depth.to_le_bytes());
        offset += SUBTREE_WATCH_EVENT_DEPTH_LEN;
        for component in request.path_components {
            let component_len = component.len() as u16;
            output[offset..offset + 2].copy_from_slice(&component_len.to_le_bytes());
            offset += WATCH_COMPONENT_LEN_FIELD;
            output[offset..offset + component.len()].copy_from_slice(component.as_bytes());
            offset += component.len();
        }
    }

    Ok(WatchEventRecordWritePlan::Written { bytes: total_len })
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

/// Computes and validates a runtime queue snapshot from retained entries.
pub fn watch_queue_snapshot(
    queue: &[WatchQueueEntry],
    queued_events: usize,
) -> LcsResult<WatchQueueState> {
    if queued_events > queue.len() {
        return Err(LcsError::InvalidWatchQueueState);
    }

    let mut overflow_count = 0usize;
    for entry in &queue[..queued_events] {
        validate_watch_queue_entry(*entry)?;
        if entry.event_type == REG_WATCH_OVERFLOW {
            overflow_count += 1;
            if overflow_count > 1 {
                return Err(LcsError::DuplicateWatchOverflowEvent);
            }
        }
    }

    Ok(WatchQueueState {
        queued_events,
        contains_overflow: overflow_count != 0,
    })
}

/// Applies PSD-005 watch queue overflow/drop rules to fixed queue storage.
pub fn push_watch_queue_event(
    queue_limit: usize,
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
    event: WatchQueueEntry,
) -> LcsResult<WatchQueueMutationSummary> {
    validate_watch_queue_storage(queue_limit, queue.len())?;
    validate_watch_queue_entry(event)?;

    let state = watch_queue_snapshot(queue, queued_events)?;
    let plan = plan_watch_queue_insert(queue_limit, state)?;

    if event.event_type == REG_WATCH_OVERFLOW && state.contains_overflow {
        return Ok(WatchQueueMutationSummary {
            queued_events,
            contains_overflow: true,
            effect: WatchQueuePushEffect::PreservedExistingOverflow,
        });
    }

    match plan {
        WatchQueueInsertPlan::QueueEvent => {
            queue[queued_events] = event;
            Ok(WatchQueueMutationSummary {
                queued_events: queued_events + 1,
                contains_overflow: state.contains_overflow
                    || event.event_type == REG_WATCH_OVERFLOW,
                effect: WatchQueuePushEffect::QueuedEvent,
            })
        }
        WatchQueueInsertPlan::DropOldestAndQueueOverflow => {
            drop_oldest(queue, queue_limit);
            queue[queue_limit - 1] = overflow_queue_entry();
            Ok(WatchQueueMutationSummary {
                queued_events: queue_limit,
                contains_overflow: true,
                effect: WatchQueuePushEffect::DropOldestAndQueueOverflow,
            })
        }
        WatchQueueInsertPlan::DropOldestPreservingOverflowAndQueueEvent => {
            drop_oldest_preserving_overflow(queue, queue_limit)?;
            queue[queue_limit - 1] = event;
            Ok(WatchQueueMutationSummary {
                queued_events: queue_limit,
                contains_overflow: true,
                effect: WatchQueuePushEffect::DropOldestPreservingOverflowAndQueueEvent,
            })
        }
    }
}

/// Clears all retained watch events for disarm or fd-close cleanup.
pub fn clear_watch_queue(
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
) -> LcsResult<WatchQueueClearSummary> {
    watch_queue_snapshot(queue, queued_events)?;
    Ok(WatchQueueClearSummary {
        queued_events: 0,
        contains_overflow: false,
    })
}

/// Plans poll readiness for an armed key-fd watch queue.
pub fn plan_watch_queue_poll(
    queue: &[WatchQueueEntry],
    queued_events: usize,
) -> LcsResult<WatchQueuePollPlan> {
    watch_queue_snapshot(queue, queued_events)?;
    Ok(WatchQueuePollPlan {
        readable: queued_events != 0,
    })
}

/// Drains as many complete watch events as fit in one key-fd read buffer.
pub fn drain_watch_queue_read_batch(
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
    buffer_len: usize,
) -> LcsResult<WatchQueueReadDrainPlan> {
    let state = watch_queue_snapshot(queue, queued_events)?;
    if queued_events == 0 {
        return Ok(WatchQueueReadDrainPlan::WouldBlock);
    }

    let first_len = validate_watch_queue_entry_len(queue[0])?;
    if buffer_len < first_len {
        return Err(LcsError::WatchReadBufferTooSmall {
            buffer_len,
            first_event_len: first_len,
        });
    }

    let mut event_count = 0usize;
    let mut bytes = 0usize;
    let mut drained_overflow = false;
    for entry in &queue[..queued_events] {
        let event_len = validate_watch_queue_entry_len(*entry)?;
        let Some(next_bytes) = bytes.checked_add(event_len) else {
            break;
        };
        if next_bytes > buffer_len {
            break;
        }
        if entry.event_type == REG_WATCH_OVERFLOW {
            drained_overflow = true;
        }
        event_count += 1;
        bytes = next_bytes;
    }

    let remaining_events = queued_events - event_count;
    for index in 0..remaining_events {
        queue[index] = queue[event_count + index];
    }

    Ok(WatchQueueReadDrainPlan::Drained(WatchQueueDrainSummary {
        queued_events: remaining_events,
        contains_overflow: state.contains_overflow && !drained_overflow,
        event_count,
        bytes,
        drained_overflow,
    }))
}

pub(crate) fn validate_watch_queue_storage(
    queue_limit: usize,
    storage_len: usize,
) -> LcsResult<()> {
    if queue_limit == 0 {
        return Err(LcsError::InvalidWatchQueueLimit);
    }
    if storage_len < queue_limit {
        return Err(LcsError::WatchQueueStorageTooSmall {
            storage_len,
            queue_limit,
        });
    }
    Ok(())
}

fn validate_watch_queue_entry(entry: WatchQueueEntry) -> LcsResult<()> {
    validate_watch_queue_entry_len(entry)?;
    Ok(())
}

fn validate_watch_queue_entry_len(entry: WatchQueueEntry) -> LcsResult<usize> {
    watch_event_category(entry.event_type)?;
    validate_queued_event_len(QueuedWatchEvent {
        total_len: entry.total_len,
    })
}

pub(crate) fn overflow_queue_entry() -> WatchQueueEntry {
    WatchQueueEntry {
        event_type: REG_WATCH_OVERFLOW,
        total_len: DIRECT_WATCH_EVENT_HEADER_LEN as u32,
    }
}

fn drop_oldest(queue: &mut [WatchQueueEntry], len: usize) {
    for index in 1..len {
        queue[index - 1] = queue[index];
    }
}

fn drop_oldest_preserving_overflow(queue: &mut [WatchQueueEntry], len: usize) -> LcsResult<()> {
    if len <= 1 {
        return Err(LcsError::InvalidWatchQueueState);
    }

    let drop_index = if queue[0].event_type == REG_WATCH_OVERFLOW {
        1
    } else {
        0
    };
    for index in drop_index + 1..len {
        queue[index - 1] = queue[index];
    }
    Ok(())
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

/// Plans per-watcher delivery for a committed transaction mutation-log batch.
pub fn plan_transaction_watch_batch(
    limits: &LcsLimits,
    members: &[TransactionWatchBatchMember],
) -> LcsResult<TransactionWatchBatchPlan> {
    let mut previous_operation_index = None;
    let mut total_event_count = 0usize;

    for (index, member) in members.iter().enumerate() {
        if let Some(previous) = previous_operation_index {
            if member.operation_index <= previous {
                return Err(LcsError::InvalidTransactionWatchBatchOrder { index });
            }
        }
        previous_operation_index = Some(member.operation_index);
        total_event_count = total_event_count
            .checked_add(member.event_count)
            .ok_or(LcsError::TransactionWatchBatchEventCountOverflow)?;
    }

    let delivery = plan_transaction_watch_burst(limits, total_event_count)?;
    Ok(TransactionWatchBatchPlan {
        operation_count: members.len(),
        total_event_count,
        delivery,
        dispatch_without_interleaving: total_event_count != 0,
    })
}

/// Applies a committed transaction watch batch to fixed watch queue storage.
pub fn apply_transaction_watch_queue_batch(
    limits: &LcsLimits,
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
    members: &[TransactionWatchBatchMember],
    events: &[WatchQueueEntry],
) -> LcsResult<TransactionWatchQueueApplyPlan> {
    validate_watch_queue_storage(limits.notification_queue_size, queue.len())?;
    let initial_state = watch_queue_snapshot(queue, queued_events)?;
    let batch = plan_transaction_watch_batch(limits, members)?;

    match batch.delivery {
        TransactionWatchBurstPlan::NoEvents => {
            require_transaction_watch_event_count(0, events.len())?;
            Ok(TransactionWatchQueueApplyPlan::NoEvents(initial_state))
        }
        TransactionWatchBurstPlan::EmitIndividualEvents { event_count } => {
            require_transaction_watch_event_count(event_count, events.len())?;
            for event in events {
                validate_watch_queue_entry(*event)?;
            }

            let mut current_queued_events = queued_events;
            let mut contains_overflow = initial_state.contains_overflow;
            for event in events {
                let summary = push_watch_queue_event(
                    limits.notification_queue_size,
                    queue,
                    current_queued_events,
                    *event,
                )?;
                current_queued_events = summary.queued_events;
                contains_overflow = summary.contains_overflow;
            }

            Ok(TransactionWatchQueueApplyPlan::Applied(
                TransactionWatchQueueApplySummary {
                    queued_events: current_queued_events,
                    contains_overflow,
                    attempted_event_count: batch.total_event_count,
                    queued_individual_events: event_count,
                    queued_overflow_only: false,
                    dispatch_without_interleaving: batch.dispatch_without_interleaving,
                },
            ))
        }
        TransactionWatchBurstPlan::EmitOverflowOnly {
            attempted_event_count,
            ..
        } => {
            require_transaction_watch_event_count(0, events.len())?;
            let summary = push_watch_queue_event(
                limits.notification_queue_size,
                queue,
                queued_events,
                overflow_queue_entry(),
            )?;

            Ok(TransactionWatchQueueApplyPlan::Applied(
                TransactionWatchQueueApplySummary {
                    queued_events: summary.queued_events,
                    contains_overflow: summary.contains_overflow,
                    attempted_event_count,
                    queued_individual_events: 0,
                    queued_overflow_only: true,
                    dispatch_without_interleaving: batch.dispatch_without_interleaving,
                },
            ))
        }
    }
}

fn require_transaction_watch_event_count(expected: usize, actual: usize) -> LcsResult<()> {
    if actual != expected {
        return Err(LcsError::TransactionWatchEventCountMismatch { expected, actual });
    }
    Ok(())
}

/// Applies source-restart overflow delivery to one watch queue.
pub fn apply_source_restart_watch_overflow(
    limits: &LcsLimits,
    queue: &mut [WatchQueueEntry],
    queued_events: usize,
    enqueue_overflow: bool,
) -> LcsResult<SourceRestartWatchQueueApplyPlan> {
    validate_watch_queue_storage(limits.notification_queue_size, queue.len())?;
    if !enqueue_overflow {
        return Ok(SourceRestartWatchQueueApplyPlan::Unaffected(
            watch_queue_snapshot(queue, queued_events)?,
        ));
    }

    let summary = push_watch_queue_event(
        limits.notification_queue_size,
        queue,
        queued_events,
        overflow_queue_entry(),
    )?;
    Ok(SourceRestartWatchQueueApplyPlan::Applied(summary))
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

/// Emits subkey watch events for the effective child-visibility difference.
pub fn for_each_effective_subkey_watch_event<'a, F>(
    limits: &LcsLimits,
    before: &'a [EnumeratedSubkey<'a>],
    after: &'a [EnumeratedSubkey<'a>],
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(EffectiveSubkeyWatchEvent<'a>) -> LcsResult<()>,
{
    validate_effective_subkey_snapshot(limits, "before", before)?;
    validate_effective_subkey_snapshot(limits, "after", after)?;

    let mut emitted = 0usize;
    for before_subkey in before {
        let Some(after_subkey) = find_effective_subkey(after, before_subkey.child_name) else {
            emit(EffectiveSubkeyWatchEvent::SubkeyDeleted {
                name: before_subkey.child_name,
            })?;
            emitted += 1;
            continue;
        };
        if before_subkey.path.guid != after_subkey.path.guid {
            emit(EffectiveSubkeyWatchEvent::SubkeyDeleted {
                name: before_subkey.child_name,
            })?;
            emit(EffectiveSubkeyWatchEvent::SubkeyCreated {
                name: after_subkey.child_name,
            })?;
            emitted += 2;
        }
    }

    for after_subkey in after {
        if find_effective_subkey(before, after_subkey.child_name).is_none() {
            emit(EffectiveSubkeyWatchEvent::SubkeyCreated {
                name: after_subkey.child_name,
            })?;
            emitted += 1;
        }
    }

    Ok(emitted)
}

/// Selects the direct `KEY_DELETED` event for a GUID-bound watched key object.
pub fn plan_watched_key_visibility_event(
    limits: &LcsLimits,
    watched_guid: Guid,
    before: Option<ResolvedPathEntry<'_>>,
    after: Option<ResolvedPathEntry<'_>>,
) -> LcsResult<Option<WatchedKeyVisibilityEvent>> {
    validate_watch_key_guid(watched_guid)?;
    if let Some(before) = before {
        validate_resolved_path_entry(limits, before)?;
    }
    if let Some(after) = after {
        validate_resolved_path_entry(limits, after)?;
    }

    let was_visible = before.is_some_and(|entry| entry.guid == watched_guid);
    let still_visible = after.is_some_and(|entry| entry.guid == watched_guid);
    if was_visible && !still_visible {
        Ok(Some(WatchedKeyVisibilityEvent::KeyDeleted))
    } else {
        Ok(None)
    }
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

/// Plans source-I/O lock discipline for layer metadata internal callbacks.
pub fn plan_internal_layer_metadata_refresh_locking<'a>(
    callback: InternalWatchCallbackPlan<'a>,
) -> Option<InternalLayerMetadataRefreshLockPlan<'a>> {
    let (layer_name, reason, publish_only_complete_entry) = match callback {
        InternalWatchCallbackPlan::RefreshLayerMetadata {
            dirty_layer_name,
            publish_only_complete_entry,
        } => (
            dirty_layer_name,
            InternalLayerMetadataRefreshReason::MetadataChanged,
            publish_only_complete_entry,
        ),
        InternalWatchCallbackPlan::AddLayer {
            layer_name,
            publish_only_complete_entry,
        } => (
            layer_name,
            InternalLayerMetadataRefreshReason::LayerCreated,
            publish_only_complete_entry,
        ),
        InternalWatchCallbackPlan::RefreshSelfConfiguration { .. }
        | InternalWatchCallbackPlan::DeleteLayer { .. }
        | InternalWatchCallbackPlan::ResolveAndRearmTargetedWatches => return None,
    };

    Some(InternalLayerMetadataRefreshLockPlan {
        layer_name,
        reason,
        release_watch_map_lock_before_source_round_trip: true,
        release_layer_publication_lock_before_source_round_trip: true,
        acquire_layer_publication_lock_only_for_atomic_publish: true,
        publish_only_complete_entry,
    })
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

fn validate_effective_subkey_snapshot(
    limits: &LcsLimits,
    snapshot: &'static str,
    subkeys: &[EnumeratedSubkey<'_>],
) -> LcsResult<()> {
    for (index, subkey) in subkeys.iter().enumerate() {
        validate_key_component_bytes(subkey.child_name.as_bytes(), limits)?;
        validate_resolved_path_entry(limits, subkey.path)?;
        if effective_subkey_seen_before(limits, subkeys, index, subkey.child_name)? {
            return Err(LcsError::DuplicateEffectiveWatchSubkeyName { snapshot, index });
        }
    }
    Ok(())
}

fn effective_subkey_seen_before(
    limits: &LcsLimits,
    subkeys: &[EnumeratedSubkey<'_>],
    index: usize,
    current_name: &str,
) -> LcsResult<bool> {
    let current_name = validate_key_component_bytes(current_name.as_bytes(), limits)?;
    for previous in &subkeys[..index] {
        let previous_name = validate_key_component_bytes(previous.child_name.as_bytes(), limits)?;
        if casefold_eq(previous_name, current_name) {
            return Ok(true);
        }
    }
    Ok(false)
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

fn find_effective_subkey<'a>(
    subkeys: &'a [EnumeratedSubkey<'a>],
    name: &str,
) -> Option<&'a EnumeratedSubkey<'a>> {
    subkeys
        .iter()
        .find(|candidate| casefold_eq(candidate.child_name, name))
}

fn validate_resolved_path_entry(limits: &LcsLimits, entry: ResolvedPathEntry<'_>) -> LcsResult<()> {
    validate_watch_key_guid(entry.guid)?;
    validate_layer_name_bytes(entry.layer.as_bytes(), limits)?;
    Ok(())
}

fn validate_watch_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}

pub(crate) fn validate_watch_mutation_context(
    mutation: &WatchMutationContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_context(&WatchAncestryContext {
        changed_key_guid: mutation.changed_key_guid,
        ancestor_guids: mutation.ancestor_guids,
        path_components: mutation.path_components,
    })?;
    watch_event_category(mutation.event_type)?;
    Ok(())
}

pub(crate) fn validate_watch_ancestry_context(context: &WatchAncestryContext<'_>) -> LcsResult<()> {
    if context.ancestor_guids.is_empty()
        || context.ancestor_guids.len() != context.path_components.len()
    {
        return Err(LcsError::InvalidWatchAncestry);
    }
    if context.ancestor_guids[context.ancestor_guids.len() - 1] != context.changed_key_guid {
        return Err(LcsError::WatchChangedKeyNotLastAncestor);
    }
    Ok(())
}

pub(crate) fn validate_watch_ancestry_payload(
    limits: &LcsLimits,
    field: &'static str,
    context: &WatchAncestryContext<'_>,
) -> LcsResult<()> {
    validate_watch_ancestry_context(context)
        .map_err(|_| LcsError::InvalidTransactionMutationLogEntry { field })?;
    if context.changed_key_guid == NIL_GUID {
        return Err(LcsError::InvalidTransactionMutationLogEntry { field });
    }
    for guid in context.ancestor_guids {
        if *guid == NIL_GUID {
            return Err(LcsError::InvalidTransactionMutationLogEntry { field });
        }
    }
    for path_component in context.path_components {
        validate_key_component_bytes(path_component.as_bytes(), limits)?;
    }
    Ok(())
}
