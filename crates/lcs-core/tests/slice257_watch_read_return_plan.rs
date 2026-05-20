use lcs_core::{
    LcsError, LinuxErrno, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED, REG_WATCH_VALUE_DELETED,
    REG_WATCH_VALUE_SET, WatchQueueDrainSummary, WatchQueueEntry, WatchQueueReadReturnPlan,
    plan_watch_queue_read_return,
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
fn nonblocking_empty_watch_read_returns_eagain_without_mutation() {
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12)];
    let before = queue;

    assert_eq!(
        plan_watch_queue_read_return(&mut queue, 0, 128, true),
        Ok(WatchQueueReadReturnPlan::ReturnErrno(LinuxErrno::Eagain))
    );
    assert_eq!(queue, before);
}

#[test]
fn blocking_empty_watch_read_waits_without_zero_byte_success() {
    let mut queue = [entry(REG_WATCH_VALUE_SET, 12)];
    let before = queue;

    assert_eq!(
        plan_watch_queue_read_return(&mut queue, 0, 128, false),
        Ok(WatchQueueReadReturnPlan::WaitForEvent)
    );
    assert_eq!(queue, before);
}

#[test]
fn too_small_first_event_buffer_returns_einval_without_mutation() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_SD_CHANGED, 8),
    ];
    let before = queue;

    assert_eq!(
        plan_watch_queue_read_return(&mut queue, 2, 11, true),
        Ok(WatchQueueReadReturnPlan::ReturnErrno(LinuxErrno::Einval))
    );
    assert_eq!(queue, before);
}

#[test]
fn pending_watch_read_drains_complete_records_and_shifts_queue() {
    let mut queue = [
        entry(REG_WATCH_VALUE_SET, 12),
        entry(REG_WATCH_OVERFLOW, 8),
        entry(REG_WATCH_VALUE_DELETED, 16),
    ];

    assert_eq!(
        plan_watch_queue_read_return(&mut queue, 3, 20, true),
        Ok(WatchQueueReadReturnPlan::Drained(WatchQueueDrainSummary {
            queued_events: 1,
            contains_overflow: false,
            event_count: 2,
            bytes: 20,
            drained_overflow: true,
        }))
    );
    assert_eq!(event_types(&queue, 1), vec![REG_WATCH_VALUE_DELETED]);
}

#[test]
fn corrupt_watch_queue_fails_before_return_projection() {
    let mut duplicate_overflow = [entry(REG_WATCH_OVERFLOW, 8), entry(REG_WATCH_OVERFLOW, 8)];
    let before = duplicate_overflow;

    assert_eq!(
        plan_watch_queue_read_return(&mut duplicate_overflow, 2, 128, true),
        Err(LcsError::DuplicateWatchOverflowEvent)
    );
    assert_eq!(duplicate_overflow, before);
}
