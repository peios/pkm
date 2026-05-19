use lcs_core::{
    LcsError, LcsLimits, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, SourceRestartWatchQueueApplyPlan,
    WatchQueueEntry, WatchQueueMutationSummary, WatchQueuePushEffect, WatchQueueState,
    apply_source_restart_watch_overflow, plan_source_restart_watch_overflow,
};

fn entry(event_type: u32, total_len: u32) -> WatchQueueEntry {
    WatchQueueEntry {
        event_type,
        total_len,
    }
}

fn limits(queue_size: usize) -> LcsLimits {
    let mut limits = LcsLimits::default();
    limits.notification_queue_size = queue_size;
    limits
}

fn event_types(queue: &[WatchQueueEntry], len: usize) -> Vec<u32> {
    queue[..len].iter().map(|entry| entry.event_type).collect()
}

#[test]
fn source_restart_overflow_is_queued_for_affected_watch() {
    let limits = limits(3);
    let selection = plan_source_restart_watch_overflow(7, 7);
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12), entry(0, 8), entry(0, 8)];

    let plan =
        apply_source_restart_watch_overflow(&limits, &mut queue, 1, selection.enqueue_overflow)
            .unwrap();

    assert_eq!(
        plan,
        SourceRestartWatchQueueApplyPlan::Applied(WatchQueueMutationSummary {
            queued_events: 2,
            contains_overflow: true,
            effect: WatchQueuePushEffect::QueuedEvent,
        })
    );
    assert_eq!(
        event_types(&queue, 2),
        vec![REG_WATCH_VALUE_SET, REG_WATCH_OVERFLOW]
    );
}

#[test]
fn source_restart_does_not_mutate_unaffected_watch_queue() {
    let limits = limits(3);
    let selection = plan_source_restart_watch_overflow(7, 8);
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 14),
        entry(0, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_source_restart_watch_overflow(&limits, &mut queue, 2, selection.enqueue_overflow,),
        Ok(SourceRestartWatchQueueApplyPlan::Unaffected(
            WatchQueueState {
                queued_events: 2,
                contains_overflow: false,
            }
        ))
    );
    assert_eq!(queue, before);
}

#[test]
fn source_restart_overflow_uses_normal_full_queue_policy() {
    let limits = limits(2);
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_VALUE_DELETED, 12),
    ];

    let plan = apply_source_restart_watch_overflow(&limits, &mut queue, 2, true).unwrap();

    assert_eq!(
        plan,
        SourceRestartWatchQueueApplyPlan::Applied(WatchQueueMutationSummary {
            queued_events: 2,
            contains_overflow: true,
            effect: WatchQueuePushEffect::DropOldestAndQueueOverflow,
        })
    );
    assert_eq!(
        event_types(&queue, 2),
        vec![REG_WATCH_VALUE_DELETED, REG_WATCH_OVERFLOW]
    );
}

#[test]
fn source_restart_preserves_existing_pending_overflow() {
    let limits = limits(3);
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];
    let before = queue;

    assert_eq!(
        apply_source_restart_watch_overflow(&limits, &mut queue, 3, true),
        Ok(SourceRestartWatchQueueApplyPlan::Applied(
            WatchQueueMutationSummary {
                queued_events: 3,
                contains_overflow: true,
                effect: WatchQueuePushEffect::PreservedExistingOverflow,
            },
        ))
    );
    assert_eq!(queue, before);
}

#[test]
fn source_restart_overflow_fails_closed_on_corrupt_queue_state() {
    let limits = limits(3);
    let mut duplicate_overflow = [
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(0, 8),
    ];
    let before = duplicate_overflow;

    assert_eq!(
        apply_source_restart_watch_overflow(&limits, &mut duplicate_overflow, 2, true),
        Err(LcsError::DuplicateWatchOverflowEvent)
    );
    assert_eq!(duplicate_overflow, before);

    let mut short_event = [entry(REG_WATCH_VALUE_SET, 7)];
    assert_eq!(
        apply_source_restart_watch_overflow(&limits, &mut short_event, 1, false),
        Err(LcsError::WatchQueueStorageTooSmall {
            storage_len: 1,
            queue_limit: 3,
        })
    );
}
