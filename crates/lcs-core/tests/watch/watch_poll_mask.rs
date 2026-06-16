use lcs_core::{
    LINUX_POLLIN, LcsError, REG_WATCH_KEY_DELETED, REG_WATCH_OVERFLOW, REG_WATCH_VALUE_SET,
    WatchQueueEntry, WatchQueuePollPlan, plan_watch_queue_poll_mask, watch_queue_poll_plan_mask,
};

fn entry(event_type: u32, total_len: u32) -> WatchQueueEntry {
    WatchQueueEntry {
        event_type,
        total_len,
    }
}

#[test]
fn watch_poll_mask_reports_pollin_for_pending_events() {
    assert_eq!(
        watch_queue_poll_plan_mask(WatchQueuePollPlan { readable: true }),
        LINUX_POLLIN
    );

    let queue = [entry(REG_WATCH_VALUE_SET, 12)];
    assert_eq!(plan_watch_queue_poll_mask(&queue, 1), Ok(LINUX_POLLIN));
}

#[test]
fn watch_poll_mask_is_empty_for_empty_queues() {
    assert_eq!(
        watch_queue_poll_plan_mask(WatchQueuePollPlan { readable: false }),
        0
    );

    let queue = [entry(REG_WATCH_VALUE_SET, 12)];
    assert_eq!(plan_watch_queue_poll_mask(&queue, 0), Ok(0));
}

#[test]
fn key_deleted_and_overflow_events_are_readable_queue_records() {
    let queue = [
        entry(REG_WATCH_KEY_DELETED, 8),
        entry(REG_WATCH_OVERFLOW, 8),
    ];

    assert_eq!(plan_watch_queue_poll_mask(&queue, 2), Ok(LINUX_POLLIN));
}

#[test]
fn corrupt_watch_queue_fails_before_poll_mask_projection() {
    let duplicate_overflow = [entry(REG_WATCH_OVERFLOW, 8), entry(REG_WATCH_OVERFLOW, 8)];
    assert_eq!(
        plan_watch_queue_poll_mask(&duplicate_overflow, 2),
        Err(LcsError::DuplicateWatchOverflowEvent)
    );

    let short_event = [entry(REG_WATCH_VALUE_SET, 7)];
    assert_eq!(
        plan_watch_queue_poll_mask(&short_event, 1),
        Err(LcsError::InvalidWatchEventLength(7))
    );
}
