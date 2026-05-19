use crate::constants::{
    REG_NOTIFY_ALL, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE, REG_WATCH_KEY_DELETED,
    REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET,
};
use crate::error::{LcsError, LcsResult};

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
