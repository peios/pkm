use lcs_core::{
    LcsError, LcsLimits, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, TransactionWatchBatchMember,
    TransactionWatchQueueApplyPlan, TransactionWatchQueueApplySummary, WatchQueueEntry,
    WatchQueueState, apply_transaction_watch_queue_batch,
};

fn entry(event_type: u32, total_len: u32) -> WatchQueueEntry {
    WatchQueueEntry {
        event_type,
        total_len,
    }
}

fn limits(queue_size: usize, burst: usize) -> LcsLimits {
    let mut limits = LcsLimits::default();
    limits.notification_queue_size = queue_size;
    limits.max_transaction_watch_event_burst = burst;
    limits
}

fn event_types(queue: &[WatchQueueEntry], len: usize) -> Vec<u32> {
    queue[..len].iter().map(|entry| entry.event_type).collect()
}

#[test]
fn transaction_watch_batch_queues_individual_events_without_interleaving() {
    let limits = limits(4, 4);
    let members = [
        TransactionWatchBatchMember {
            operation_index: 10,
            event_count: 1,
        },
        TransactionWatchBatchMember {
            operation_index: 11,
            event_count: 2,
        },
    ];
    let events = [
        entry(REG_WATCH_SUBKEY_CREATED, 12),
        entry(REG_WATCH_VALUE_DELETED, 14),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(0, 8),
        entry(0, 8),
        entry(0, 8),
    ];

    let plan =
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &events).unwrap();

    assert_eq!(
        plan,
        TransactionWatchQueueApplyPlan::Applied(TransactionWatchQueueApplySummary {
            queued_events: 4,
            contains_overflow: false,
            attempted_event_count: 3,
            queued_individual_events: 3,
            queued_overflow_only: false,
            dispatch_without_interleaving: true,
        })
    );
    assert_eq!(
        event_types(&queue, 4),
        vec![
            REG_WATCH_VALUE_SET,
            REG_WATCH_SUBKEY_CREATED,
            REG_WATCH_VALUE_DELETED,
            REG_WATCH_SD_CHANGED,
        ]
    );
}

#[test]
fn over_limit_transaction_watch_batch_queues_single_overflow() {
    let limits = limits(3, 2);
    let members = [TransactionWatchBatchMember {
        operation_index: 1,
        event_count: 3,
    }];
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12), entry(0, 8), entry(0, 8)];

    let plan = apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &[]).unwrap();

    assert_eq!(
        plan,
        TransactionWatchQueueApplyPlan::Applied(TransactionWatchQueueApplySummary {
            queued_events: 2,
            contains_overflow: true,
            attempted_event_count: 3,
            queued_individual_events: 0,
            queued_overflow_only: true,
            dispatch_without_interleaving: true,
        })
    );
    assert_eq!(
        event_types(&queue, 2),
        vec![REG_WATCH_VALUE_SET, REG_WATCH_OVERFLOW]
    );
}

#[test]
fn transaction_watch_batch_empty_batch_leaves_queue_unchanged() {
    let limits = limits(2, 2);
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12), entry(0, 8)];
    let before = queue;

    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &[], &[]),
        Ok(TransactionWatchQueueApplyPlan::NoEvents(WatchQueueState {
            queued_events: 1,
            contains_overflow: false,
        }))
    );
    assert_eq!(queue, before);
}

#[test]
fn transaction_watch_batch_rejects_event_count_mismatch_without_mutation() {
    let limits = limits(4, 4);
    let members = [TransactionWatchBatchMember {
        operation_index: 1,
        event_count: 2,
    }];
    let events = [entry(REG_WATCH_VALUE_SET, 12)];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 8),
        entry(0, 8),
        entry(0, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &events),
        Err(LcsError::TransactionWatchEventCountMismatch {
            expected: 2,
            actual: 1,
        })
    );
    assert_eq!(queue, before);
}

#[test]
fn over_limit_transaction_watch_batch_rejects_prebuilt_individual_events() {
    let limits = limits(4, 1);
    let members = [TransactionWatchBatchMember {
        operation_index: 1,
        event_count: 2,
    }];
    let events = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_VALUE_DELETED, 12),
    ];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 8),
        entry(0, 8),
        entry(0, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &events),
        Err(LcsError::TransactionWatchEventCountMismatch {
            expected: 0,
            actual: 2,
        })
    );
    assert_eq!(queue, before);
}

#[test]
fn transaction_watch_batch_prevalidates_events_before_queue_mutation() {
    let limits = limits(4, 4);
    let members = [TransactionWatchBatchMember {
        operation_index: 1,
        event_count: 2,
    }];
    let events = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_VALUE_DELETED, 7),
    ];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 8),
        entry(0, 8),
        entry(0, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &events),
        Err(LcsError::InvalidWatchEventLength(7))
    );
    assert_eq!(queue, before);
}

#[test]
fn transaction_watch_batch_rejects_invalid_order_before_queue_mutation() {
    let limits = limits(4, 4);
    let members = [
        TransactionWatchBatchMember {
            operation_index: 2,
            event_count: 1,
        },
        TransactionWatchBatchMember {
            operation_index: 1,
            event_count: 1,
        },
    ];
    let events = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_VALUE_DELETED, 12),
    ];
    let mut queue = [
        entry(REG_WATCH_SD_CHANGED, 8),
        entry(0, 8),
        entry(0, 8),
        entry(0, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_transaction_watch_queue_batch(&limits, &mut queue, 1, &members, &events),
        Err(LcsError::InvalidTransactionWatchBatchOrder { index: 1 })
    );
    assert_eq!(queue, before);
}
