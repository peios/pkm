use lcs_core::{
    KeyWatchState, LcsError, REG_NOTIFY_SD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE,
    REG_WATCH_KEY_DELETED, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, WatchEventCategory, WatchNotifyArgs,
    WatchNotifyPlan, plan_watch_notify, validate_notify_filter, watch_event_category,
    watch_event_matches_filter,
};

fn notify_args(filter: u32, subtree: u8) -> WatchNotifyArgs {
    WatchNotifyArgs {
        filter,
        subtree,
        reserved: [0; 3],
    }
}

#[test]
fn notify_plan_arms_replaces_and_disarms_key_fd_watch_state() {
    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: false,
                orphaned: false,
            },
            &notify_args(REG_NOTIFY_VALUE | REG_NOTIFY_SUBKEY, 1),
        ),
        Ok(WatchNotifyPlan::Arm {
            filter: REG_NOTIFY_VALUE | REG_NOTIFY_SUBKEY,
            subtree: true,
            replaces_existing: false,
        })
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: true,
                orphaned: false,
            },
            &notify_args(REG_NOTIFY_SD, 0),
        ),
        Ok(WatchNotifyPlan::Arm {
            filter: REG_NOTIFY_SD,
            subtree: false,
            replaces_existing: true,
        })
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: true,
                orphaned: false,
            },
            &notify_args(0, 0),
        ),
        Ok(WatchNotifyPlan::Disarm {
            discard_pending_events: true,
        })
    );
}

#[test]
fn notify_plan_rejects_new_orphaned_arms_but_allows_existing_watch_updates() {
    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: false,
                orphaned: true,
            },
            &notify_args(REG_NOTIFY_VALUE, 0),
        ),
        Err(LcsError::OrphanedWatchArm)
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: true,
                orphaned: true,
            },
            &notify_args(REG_NOTIFY_SUBKEY, 1),
        ),
        Ok(WatchNotifyPlan::Arm {
            filter: REG_NOTIFY_SUBKEY,
            subtree: true,
            replaces_existing: true,
        })
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: false,
                orphaned: true,
            },
            &notify_args(0, 0),
        ),
        Ok(WatchNotifyPlan::Disarm {
            discard_pending_events: false,
        })
    );
}

#[test]
fn notify_args_fail_closed_on_unknown_filters_boolean_and_padding() {
    assert_eq!(
        validate_notify_filter(REG_NOTIFY_VALUE | 0x80),
        Err(LcsError::UnknownNotifyFilterFlags {
            flags: REG_NOTIFY_VALUE | 0x80,
            unknown: 0x80,
        })
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: false,
                orphaned: false,
            },
            &notify_args(REG_NOTIFY_VALUE, 2),
        ),
        Err(LcsError::InvalidBooleanFlag {
            field: "reg_notify_args.subtree",
            value: 2,
        })
    );

    assert_eq!(
        plan_watch_notify(
            KeyWatchState {
                armed: false,
                orphaned: false,
            },
            &WatchNotifyArgs {
                filter: REG_NOTIFY_VALUE,
                subtree: 0,
                reserved: [0, 1, 0],
            },
        ),
        Err(LcsError::NonZeroReservedBytes {
            field: "reg_notify_args._pad",
        })
    );
}

#[test]
fn watch_event_categories_match_notify_filter_groups() {
    assert_eq!(
        watch_event_category(REG_WATCH_VALUE_SET),
        Ok(WatchEventCategory::Value)
    );
    assert_eq!(
        watch_event_category(REG_WATCH_VALUE_DELETED),
        Ok(WatchEventCategory::Value)
    );
    assert_eq!(
        watch_event_category(REG_WATCH_SUBKEY_CREATED),
        Ok(WatchEventCategory::Subkey)
    );
    assert_eq!(
        watch_event_category(REG_WATCH_SD_CHANGED),
        Ok(WatchEventCategory::SecurityDescriptor)
    );
    assert_eq!(
        watch_event_category(REG_WATCH_KEY_DELETED),
        Ok(WatchEventCategory::Always)
    );
    assert_eq!(
        watch_event_category(REG_WATCH_OVERFLOW),
        Ok(WatchEventCategory::Always)
    );
    assert_eq!(
        watch_event_category(99),
        Err(LcsError::UnknownWatchEventType(99))
    );
}

#[test]
fn key_deleted_and_overflow_bypass_filters_but_other_events_do_not() {
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_VALUE_SET, REG_NOTIFY_VALUE),
        Ok(true)
    );
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_VALUE_SET, REG_NOTIFY_SUBKEY),
        Ok(false)
    );
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_SUBKEY_CREATED, REG_NOTIFY_SUBKEY),
        Ok(true)
    );
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_SD_CHANGED, REG_NOTIFY_VALUE | REG_NOTIFY_SD),
        Ok(true)
    );
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_KEY_DELETED, 0),
        Ok(true)
    );
    assert_eq!(watch_event_matches_filter(REG_WATCH_OVERFLOW, 0), Ok(true));
    assert_eq!(
        watch_event_matches_filter(REG_WATCH_OVERFLOW, 0x80),
        Err(LcsError::UnknownNotifyFilterFlags {
            flags: 0x80,
            unknown: 0x80,
        })
    );
}
