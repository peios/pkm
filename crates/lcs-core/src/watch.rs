use crate::constants::{
    REG_NOTIFY_ALL, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE, REG_WATCH_KEY_DELETED,
    REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET,
};
use crate::error::{LcsError, LcsResult};

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
