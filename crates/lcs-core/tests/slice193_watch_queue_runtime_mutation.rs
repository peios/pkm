use lcs_core::{
    LcsError, REG_WATCH_OVERFLOW, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, WatchQueueClearSummary, WatchQueueEntry,
    WatchQueueMutationSummary, WatchQueuePushEffect, WatchQueueState, clear_watch_queue,
    push_watch_queue_event, watch_queue_snapshot,
};

fn entry(event_type: u32, total_len: u32) -> WatchQueueEntry {
    WatchQueueEntry {
        event_type,
        total_len,
    }
}

fn event_types(queue: &[WatchQueueEntry], len: usize) -> Vec<u32> {
    queue[..len].iter().map(|entry| entry.event_type).collect()
}

#[test]
fn watch_queue_push_appends_under_capacity_preserving_order() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
        entry(REG_WATCH_VALUE_DELETED, 16),
    ];

    let summary =
        push_watch_queue_event(3, &mut queue, 2, entry(REG_WATCH_VALUE_DELETED, 16)).unwrap();

    assert_eq!(
        summary,
        WatchQueueMutationSummary {
            queued_events: 3,
            contains_overflow: false,
            effect: WatchQueuePushEffect::QueuedEvent,
        }
    );
    assert_eq!(
        event_types(&queue, summary.queued_events),
        vec![
            REG_WATCH_VALUE_SET,
            REG_WATCH_SUBKEY_CREATED,
            REG_WATCH_VALUE_DELETED,
        ]
    );
}

#[test]
fn full_watch_queue_without_overflow_drops_oldest_and_queues_overflow() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
    ];

    let summary =
        push_watch_queue_event(2, &mut queue, 2, entry(REG_WATCH_VALUE_DELETED, 16)).unwrap();

    assert_eq!(
        summary,
        WatchQueueMutationSummary {
            queued_events: 2,
            contains_overflow: true,
            effect: WatchQueuePushEffect::DropOldestAndQueueOverflow,
        }
    );
    assert_eq!(
        event_types(&queue, summary.queued_events),
        vec![REG_WATCH_SUBKEY_CREATED, REG_WATCH_OVERFLOW]
    );
    assert_eq!(queue[1].total_len, 8);
}

#[test]
fn full_watch_queue_preserves_existing_overflow_and_queues_later_events() {
    let mut queue = [
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
    ];

    let summary =
        push_watch_queue_event(3, &mut queue, 3, entry(REG_WATCH_SUBKEY_DELETED, 16)).unwrap();

    assert_eq!(
        summary,
        WatchQueueMutationSummary {
            queued_events: 3,
            contains_overflow: true,
            effect: WatchQueuePushEffect::DropOldestPreservingOverflowAndQueueEvent,
        }
    );
    assert_eq!(
        event_types(&queue, summary.queued_events),
        vec![
            REG_WATCH_OVERFLOW,
            REG_WATCH_SUBKEY_CREATED,
            REG_WATCH_SUBKEY_DELETED,
        ]
    );
}

#[test]
fn incoming_overflow_is_coalesced_when_overflow_is_already_pending() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
    ];
    let before = queue;

    let summary = push_watch_queue_event(3, &mut queue, 3, entry(REG_WATCH_OVERFLOW, 8)).unwrap();

    assert_eq!(
        summary,
        WatchQueueMutationSummary {
            queued_events: 3,
            contains_overflow: true,
            effect: WatchQueuePushEffect::PreservedExistingOverflow,
        }
    );
    assert_eq!(queue, before);
}

#[test]
fn watch_queue_clear_discards_pending_events_for_disarm_or_close() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
    ];

    assert_eq!(
        clear_watch_queue(&mut queue, 3),
        Ok(WatchQueueClearSummary {
            queued_events: 0,
            contains_overflow: false,
        })
    );
}

#[test]
fn watch_queue_runtime_state_fails_closed_on_corrupt_snapshots() {
    let duplicate_overflow = [entry(REG_WATCH_OVERFLOW, 8), entry(REG_WATCH_OVERFLOW, 8)];
    assert_eq!(
        watch_queue_snapshot(&duplicate_overflow, 2),
        Err(LcsError::DuplicateWatchOverflowEvent)
    );

    let short_event = [entry(REG_WATCH_VALUE_SET, 7)];
    assert_eq!(
        watch_queue_snapshot(&short_event, 1),
        Err(LcsError::InvalidWatchEventLength(7))
    );

    let unknown_event = [entry(99, 8)];
    assert_eq!(
        watch_queue_snapshot(&unknown_event, 1),
        Err(LcsError::UnknownWatchEventType(99))
    );

    let mut queue = [entry(REG_WATCH_VALUE_SET, 12)];
    assert_eq!(
        push_watch_queue_event(2, &mut queue, 0, entry(REG_WATCH_VALUE_DELETED, 12)),
        Err(LcsError::WatchQueueStorageTooSmall {
            storage_len: 1,
            queue_limit: 2,
        })
    );
    assert_eq!(
        push_watch_queue_event(1, &mut queue, 2, entry(REG_WATCH_VALUE_DELETED, 12)),
        Err(LcsError::InvalidWatchQueueState)
    );
}

#[test]
fn watch_queue_snapshot_reports_overflow_presence() {
    let queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
    ];

    assert_eq!(
        watch_queue_snapshot(&queue, 3),
        Ok(WatchQueueState {
            queued_events: 3,
            contains_overflow: true,
        })
    );
}
