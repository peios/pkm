use lcs_core::{
    LcsError, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_SUBKEY_CREATED,
    REG_WATCH_VALUE_DELETED, REG_WATCH_VALUE_SET, WatchQueueDrainSummary, WatchQueueEntry,
    WatchQueuePollPlan, WatchQueueReadDrainPlan, drain_watch_queue_read_batch,
    plan_watch_queue_poll,
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
fn watch_queue_poll_reports_readable_only_for_pending_events() {
    let queue = [entry(REG_WATCH_VALUE_SET, 12)];

    assert_eq!(
        plan_watch_queue_poll(&queue, 0),
        Ok(WatchQueuePollPlan { readable: false })
    );
    assert_eq!(
        plan_watch_queue_poll(&queue, 1),
        Ok(WatchQueuePollPlan { readable: true })
    );
}

#[test]
fn watch_queue_read_drains_complete_fitting_records_and_shifts_remainder() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 20),
        entry(REG_WATCH_VALUE_DELETED, 16),
    ];

    let plan = drain_watch_queue_read_batch(&mut queue, 3, 40).unwrap();

    assert_eq!(
        plan,
        WatchQueueReadDrainPlan::Drained(WatchQueueDrainSummary {
            queued_events: 1,
            contains_overflow: false,
            event_count: 2,
            bytes: 32,
            drained_overflow: false,
        })
    );
    assert_eq!(event_types(&queue, 1), vec![REG_WATCH_VALUE_DELETED]);
}

#[test]
fn watch_queue_read_too_small_first_buffer_fails_without_mutation() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SUBKEY_CREATED, 20),
    ];
    let before = queue;

    assert_eq!(
        drain_watch_queue_read_batch(&mut queue, 2, 11),
        Err(LcsError::WatchReadBufferTooSmall {
            buffer_len: 11,
            first_event_len: 12,
        })
    );
    assert_eq!(queue, before);
}

#[test]
fn watch_queue_read_empty_queue_would_block_without_mutation() {
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12)];
    let before = queue;

    assert_eq!(
        drain_watch_queue_read_batch(&mut queue, 0, 128),
        Ok(WatchQueueReadDrainPlan::WouldBlock)
    );
    assert_eq!(queue, before);
}

#[test]
fn watch_queue_read_recomputes_overflow_presence_after_drain() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];

    let plan = drain_watch_queue_read_batch(&mut queue, 3, 20).unwrap();

    assert_eq!(
        plan,
        WatchQueueReadDrainPlan::Drained(WatchQueueDrainSummary {
            queued_events: 1,
            contains_overflow: false,
            event_count: 2,
            bytes: 20,
            drained_overflow: true,
        })
    );
    assert_eq!(event_types(&queue, 1), vec![REG_WATCH_SD_CHANGED]);
}

#[test]
fn watch_queue_read_preserves_undrained_overflow_marker() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];

    let plan = drain_watch_queue_read_batch(&mut queue, 3, 12).unwrap();

    assert_eq!(
        plan,
        WatchQueueReadDrainPlan::Drained(WatchQueueDrainSummary {
            queued_events: 2,
            contains_overflow: true,
            event_count: 1,
            bytes: 12,
            drained_overflow: false,
        })
    );
    assert_eq!(
        event_types(&queue, 2),
        vec![REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED]
    );
}

#[test]
fn watch_queue_read_and_poll_fail_closed_on_corrupt_snapshots() {
    let duplicate_overflow = [entry(REG_WATCH_OVERFLOW, 8), entry(REG_WATCH_OVERFLOW, 8)];
    assert_eq!(
        plan_watch_queue_poll(&duplicate_overflow, 2),
        Err(LcsError::DuplicateWatchOverflowEvent)
    );

    let mut short_event = [
        entry(REG_WATCH_VALUE_SET, 7),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];
    let before = short_event;
    assert_eq!(
        drain_watch_queue_read_batch(&mut short_event, 2, 128),
        Err(LcsError::InvalidWatchEventLength(7))
    );
    assert_eq!(short_event, before);

    let mut unknown_event = [entry(99, 8)];
    assert_eq!(
        drain_watch_queue_read_batch(&mut unknown_event, 1, 128),
        Err(LcsError::UnknownWatchEventType(99))
    );
}
