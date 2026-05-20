use lcs_core::{
    LcsError, LcsLimits, REG_NOTIFY_SD, REG_NOTIFY_VALUE, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, TransactionReplayWatchEvent,
    TransactionWatchQueueApplyPlan, TransactionWatchQueueApplySummary, WatchAncestryContext,
    WatchQueueEntry, WatchQueueState, WatcherView, apply_transaction_replay_watch_queue,
};

const ROOT_GUID: [u8; 16] = [0x10; 16];
const KEY_GUID: [u8; 16] = [0x40; 16];
const KEY_ANCESTORS: [[u8; 16]; 2] = [ROOT_GUID, KEY_GUID];
const KEY_PATH: [&str; 2] = ["Machine", "Policy"];

fn entry(event_type: u32, total_len: u32) -> WatchQueueEntry {
    WatchQueueEntry {
        event_type,
        total_len,
    }
}

fn event_types(queue: &[WatchQueueEntry], len: usize) -> Vec<u32> {
    queue[..len].iter().map(|entry| entry.event_type).collect()
}

fn key_context(event_type: u32) -> lcs_core::WatchMutationContext<'static> {
    WatchAncestryContext {
        changed_key_guid: KEY_GUID,
        ancestor_guids: &KEY_ANCESTORS,
        path_components: &KEY_PATH,
    }
    .with_event(event_type)
}

fn value_event(operation_index: u64, name: &'static str) -> TransactionReplayWatchEvent<'static> {
    TransactionReplayWatchEvent {
        operation_index,
        mutation: key_context(REG_WATCH_VALUE_SET),
        name,
    }
}

fn watcher(filter: u32) -> WatcherView {
    WatcherView {
        watched_guid: KEY_GUID,
        filter,
        subtree: false,
    }
}

fn limits(queue_size: usize, burst: usize) -> LcsLimits {
    let mut limits = LcsLimits::default();
    limits.notification_queue_size = queue_size;
    limits.max_transaction_watch_event_burst = burst;
    limits
}

#[test]
fn replay_watch_queue_applies_individual_in_limit_events() {
    let limits = limits(4, 4);
    let events = [
        value_event(10, "A"),
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
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 0),
        entry(0, 0),
        entry(0, 0),
    ];

    assert_eq!(
        apply_transaction_replay_watch_queue(
            &limits,
            watcher(REG_NOTIFY_VALUE),
            &mut queue,
            1,
            &events
        ),
        Ok(TransactionWatchQueueApplyPlan::Applied(
            TransactionWatchQueueApplySummary {
                queued_events: 3,
                contains_overflow: false,
                attempted_event_count: 2,
                queued_individual_events: 2,
                queued_overflow_only: false,
                dispatch_without_interleaving: true,
            },
        ))
    );
    assert_eq!(
        event_types(&queue, 3),
        vec![
            REG_WATCH_SD_CHANGED,
            REG_WATCH_VALUE_SET,
            REG_WATCH_VALUE_DELETED,
        ]
    );
}

#[test]
fn replay_watch_queue_over_burst_applies_single_overflow_only() {
    let limits = limits(4, 1);
    let events = [value_event(12, "A"), value_event(13, "B")];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 0),
        entry(0, 0),
        entry(0, 0),
    ];

    assert_eq!(
        apply_transaction_replay_watch_queue(
            &limits,
            watcher(REG_NOTIFY_VALUE),
            &mut queue,
            1,
            &events
        ),
        Ok(TransactionWatchQueueApplyPlan::Applied(
            TransactionWatchQueueApplySummary {
                queued_events: 2,
                contains_overflow: true,
                attempted_event_count: 2,
                queued_individual_events: 0,
                queued_overflow_only: true,
                dispatch_without_interleaving: true,
            },
        ))
    );
    assert_eq!(
        event_types(&queue, 2),
        vec![REG_WATCH_SD_CHANGED, REG_WATCH_OVERFLOW]
    );
}

#[test]
fn replay_watch_queue_no_matching_events_preserves_queue() {
    let limits = limits(2, 2);
    let events = [value_event(14, "A")];
    let mut queue = [entry(REG_WATCH_SD_CHANGED, 8), entry(0, 0)];
    let before = queue;

    assert_eq!(
        apply_transaction_replay_watch_queue(
            &limits,
            watcher(REG_NOTIFY_SD),
            &mut queue,
            1,
            &events
        ),
        Ok(TransactionWatchQueueApplyPlan::NoEvents(WatchQueueState {
            queued_events: 1,
            contains_overflow: false,
        }))
    );
    assert_eq!(queue, before);
}

#[test]
fn replay_watch_queue_validation_failures_do_not_mutate_queue() {
    let limits = limits(4, 4);
    let events = [value_event(2, "A"), value_event(1, "B")];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 0),
        entry(0, 0),
        entry(0, 0),
    ];
    let before = queue;

    assert_eq!(
        apply_transaction_replay_watch_queue(
            &limits,
            watcher(REG_NOTIFY_VALUE),
            &mut queue,
            1,
            &events
        ),
        Err(LcsError::InvalidTransactionWatchBatchOrder { index: 1 })
    );
    assert_eq!(queue, before);
}

#[test]
fn replay_watch_queue_validates_storage_even_for_no_event_outcomes() {
    let limits = limits(2, 2);
    let events = [value_event(15, "A")];
    let mut queue = [entry(REG_WATCH_SD_CHANGED, 8)];

    assert_eq!(
        apply_transaction_replay_watch_queue(
            &limits,
            watcher(REG_NOTIFY_SD),
            &mut queue,
            1,
            &events
        ),
        Err(LcsError::WatchQueueStorageTooSmall {
            storage_len: 1,
            queue_limit: 2,
        })
    );
}
