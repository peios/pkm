use lcs_core::{
    LcsError, LcsLimits, REG_NOTIFY_SD, REG_NOTIFY_VALUE, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, TransactionReplayWatchDispatchSummary,
    TransactionReplayWatchEvent, TransactionWatchBatchMember, TransactionWatchQueueApplyPlan,
    TransactionWatchQueueApplySummary, WatchAncestryContext, WatchQueueEntry, WatcherView,
    apply_transaction_watch_queue_batch, for_each_transaction_replay_watch_dispatch,
    summarize_transaction_replay_watch_dispatch,
};

const ROOT_GUID: [u8; 16] = [0x10; 16];
const PARENT_GUID: [u8; 16] = [0x20; 16];
const CHILD_GUID: [u8; 16] = [0x30; 16];
const KEY_GUID: [u8; 16] = [0x40; 16];
const KEY_ANCESTORS: [[u8; 16]; 2] = [ROOT_GUID, KEY_GUID];
const KEY_PATH: [&str; 2] = ["Machine", "Policy"];
const CHILD_ANCESTORS: [[u8; 16]; 3] = [ROOT_GUID, PARENT_GUID, CHILD_GUID];
const CHILD_PATH: [&str; 3] = ["Machine", "Parent", "Child"];

fn key_context(event_type: u32) -> lcs_core::WatchMutationContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &KEY_ANCESTORS,
        path_components: &KEY_PATH,
    }
    .with_event(event_type)
}

fn child_context(event_type: u32) -> lcs_core::WatchMutationContext<'static> {
    WatchAncestryContext {
        changed_key_guid: CHILD_GUID,
        ancestor_guids: &CHILD_ANCESTORS,
        path_components: &CHILD_PATH,
    }
    .with_event(event_type)
}

fn collect_dispatch<'a>(
    limits: &LcsLimits,
    watcher: WatcherView,
    events: &'a [TransactionReplayWatchEvent<'a>],
) -> Result<
    (
        TransactionReplayWatchDispatchSummary,
        Vec<TransactionWatchBatchMember>,
        Vec<WatchQueueEntry>,
    ),
    LcsError,
> {
    let mut members = Vec::new();
    let mut entries = Vec::new();
    let summary = for_each_transaction_replay_watch_dispatch(
        limits,
        watcher,
        events,
        |member| {
            members.push(member);
            Ok(())
        },
        |entry| {
            entries.push(entry);
            Ok(())
        },
    )?;
    Ok((summary, members, entries))
}

#[test]
fn replay_dispatch_groups_delivered_events_by_operation_for_one_watcher() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 4;
    limits.notification_queue_size = 4;
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: false,
    };
    let events = [
        TransactionReplayWatchEvent {
            operation_index: 10,
            mutation: key_context(REG_WATCH_VALUE_SET),
            name: "A",
        },
        TransactionReplayWatchEvent {
            operation_index: 10,
            mutation: key_context(REG_WATCH_VALUE_DELETED),
            name: "B",
        },
        TransactionReplayWatchEvent {
            operation_index: 11,
            mutation: key_context(REG_WATCH_SD_CHANGED),
            name: "",
        },
    ];

    let (summary, members, entries) = collect_dispatch(&limits, watcher, &events).unwrap();

    assert_eq!(
        summary,
        TransactionReplayWatchDispatchSummary {
            operation_count: 2,
            delivered_event_count: 2,
            suppressed_event_count: 1,
            overflow_substitution_count: 0,
        }
    );
    assert_eq!(
        members,
        vec![
            TransactionWatchBatchMember {
                operation_index: 10,
                event_count: 2,
            },
            TransactionWatchBatchMember {
                operation_index: 11,
                event_count: 0,
            },
        ]
    );
    assert_eq!(
        entries,
        vec![
            WatchQueueEntry {
                event_type: REG_WATCH_VALUE_SET,
                total_len: 9,
            },
            WatchQueueEntry {
                event_type: REG_WATCH_VALUE_DELETED,
                total_len: 9,
            },
        ]
    );

    let mut queue = [WatchQueueEntry {
        event_type: 0,
        total_len: 0,
    }; 4];
    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 0, &members, &entries),
        Ok(TransactionWatchQueueApplyPlan::Applied(
            TransactionWatchQueueApplySummary {
                queued_events: 2,
                contains_overflow: false,
                attempted_event_count: 2,
                queued_individual_events: 2,
                queued_overflow_only: false,
                dispatch_without_interleaving: true,
            },
        ))
    );
}

#[test]
fn replay_dispatch_shapes_subtree_records_from_captured_ancestry() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: PARENT_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: true,
    };
    let events = [TransactionReplayWatchEvent {
        operation_index: 12,
        mutation: child_context(REG_WATCH_VALUE_SET),
        name: "Setting",
    }];

    let (summary, members, entries) = collect_dispatch(&limits, watcher, &events).unwrap();

    assert_eq!(
        summary,
        TransactionReplayWatchDispatchSummary {
            operation_count: 1,
            delivered_event_count: 1,
            suppressed_event_count: 0,
            overflow_substitution_count: 0,
        }
    );
    assert_eq!(
        members,
        vec![TransactionWatchBatchMember {
            operation_index: 12,
            event_count: 1,
        }]
    );
    assert_eq!(
        entries,
        vec![WatchQueueEntry {
            event_type: REG_WATCH_VALUE_SET,
            total_len: 24,
        }]
    );
}

#[test]
fn replay_dispatch_substitutes_overflow_for_unrepresentable_record() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: false,
    };
    let long_name = "x".repeat(u16::MAX as usize + 1);
    let events = [TransactionReplayWatchEvent {
        operation_index: 13,
        mutation: key_context(REG_WATCH_VALUE_SET),
        name: &long_name,
    }];

    let (summary, members, entries) = collect_dispatch(&limits, watcher, &events).unwrap();

    assert_eq!(
        summary,
        TransactionReplayWatchDispatchSummary {
            operation_count: 1,
            delivered_event_count: 1,
            suppressed_event_count: 0,
            overflow_substitution_count: 1,
        }
    );
    assert_eq!(
        members,
        vec![TransactionWatchBatchMember {
            operation_index: 13,
            event_count: 1,
        }]
    );
    assert_eq!(
        entries,
        vec![WatchQueueEntry {
            event_type: REG_WATCH_OVERFLOW,
            total_len: 8,
        }]
    );
}

#[test]
fn replay_dispatch_summary_matches_emitted_counts_without_side_effects() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: false,
    };
    let events = [
        TransactionReplayWatchEvent {
            operation_index: 14,
            mutation: key_context(REG_WATCH_VALUE_SET),
            name: "A",
        },
        TransactionReplayWatchEvent {
            operation_index: 15,
            mutation: key_context(REG_WATCH_SD_CHANGED),
            name: "",
        },
    ];

    assert_eq!(
        summarize_transaction_replay_watch_dispatch(&limits, watcher, &events),
        Ok(TransactionReplayWatchDispatchSummary {
            operation_count: 2,
            delivered_event_count: 1,
            suppressed_event_count: 1,
            overflow_substitution_count: 0,
        })
    );
}

#[test]
fn replay_dispatch_fails_closed_on_descending_operation_order_before_emit() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: false,
    };
    let events = [
        TransactionReplayWatchEvent {
            operation_index: 2,
            mutation: key_context(REG_WATCH_VALUE_SET),
            name: "A",
        },
        TransactionReplayWatchEvent {
            operation_index: 1,
            mutation: key_context(REG_WATCH_VALUE_SET),
            name: "B",
        },
    ];
    let mut members = Vec::new();
    let mut entries = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_dispatch(
            &limits,
            watcher,
            &events,
            |member| {
                members.push(member);
                Ok(())
            },
            |entry| {
                entries.push(entry);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionWatchBatchOrder { index: 1 })
    );
    assert!(members.is_empty());
    assert!(entries.is_empty());
}

#[test]
fn replay_dispatch_fails_closed_on_zero_operation_index_before_emit() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_VALUE,
        subtree: false,
    };
    let events = [TransactionReplayWatchEvent {
        operation_index: 0,
        mutation: key_context(REG_WATCH_VALUE_SET),
        name: "A",
    }];
    let mut members = Vec::new();
    let mut entries = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_dispatch(
            &limits,
            watcher,
            &events,
            |member| {
                members.push(member);
                Ok(())
            },
            |entry| {
                entries.push(entry);
                Ok(())
            },
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "watch_replay.operation_index",
        })
    );
    assert!(members.is_empty());
    assert!(entries.is_empty());
}

#[test]
fn replay_dispatch_fails_closed_on_malformed_event_record_before_emit() {
    let limits = LcsLimits::default();
    let watcher = WatcherView {
        watched_guid: KEY_GUID,
        filter: REG_NOTIFY_SD,
        subtree: false,
    };
    let events = [TransactionReplayWatchEvent {
        operation_index: 16,
        mutation: key_context(REG_WATCH_SD_CHANGED),
        name: "illegal",
    }];
    let mut members = Vec::new();
    let mut entries = Vec::new();

    assert_eq!(
        for_each_transaction_replay_watch_dispatch(
            &limits,
            watcher,
            &events,
            |member| {
                members.push(member);
                Ok(())
            },
            |entry| {
                entries.push(entry);
                Ok(())
            },
        ),
        Err(LcsError::WatchNoNameEventCarriedName {
            event_type: REG_WATCH_SD_CHANGED,
        })
    );
    assert!(members.is_empty());
    assert!(entries.is_empty());
}
