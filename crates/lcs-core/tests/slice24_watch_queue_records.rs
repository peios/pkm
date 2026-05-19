use lcs_core::{
    LcsError, QueuedWatchEvent, REG_WATCH_KEY_DELETED, REG_WATCH_OVERFLOW, REG_WATCH_SD_CHANGED,
    REG_WATCH_SUBKEY_CREATED, REG_WATCH_VALUE_SET, WatchEventRecordPlan, WatchEventRecordRequest,
    WatchEventRecordShape, WatchQueueInsertPlan, WatchQueueState, WatchReadBatchPlan,
    plan_watch_event_record, plan_watch_queue_insert, plan_watch_read_batch,
};

#[test]
fn watch_event_record_shapes_direct_and_subtree_records() {
    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_VALUE_SET,
            name: "Setting",
            subtree: false,
            path_components: &[],
        }),
        Ok(WatchEventRecordPlan::Record(WatchEventRecordShape {
            total_len: 15,
            name_len: 7,
            path_depth: None,
        }))
    );

    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_SUBKEY_CREATED,
            name: "Child",
            subtree: true,
            path_components: &["Services", "Child"],
        }),
        Ok(WatchEventRecordPlan::Record(WatchEventRecordShape {
            total_len: 32,
            name_len: 5,
            path_depth: Some(2),
        }))
    );

    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_SD_CHANGED,
            name: "",
            subtree: true,
            path_components: &[],
        }),
        Ok(WatchEventRecordPlan::Record(WatchEventRecordShape {
            total_len: 10,
            name_len: 0,
            path_depth: Some(0),
        }))
    );
}

#[test]
fn watch_event_record_uses_overflow_for_unrepresentable_lengths() {
    let oversized_name = "x".repeat(u16::MAX as usize + 1);
    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_VALUE_SET,
            name: &oversized_name,
            subtree: false,
            path_components: &[],
        }),
        Ok(WatchEventRecordPlan::OverflowInstead)
    );

    let oversized_component = "y".repeat(u16::MAX as usize + 1);
    let components = [oversized_component.as_str()];
    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_SUBKEY_CREATED,
            name: "Child",
            subtree: true,
            path_components: &components,
        }),
        Ok(WatchEventRecordPlan::OverflowInstead)
    );
}

#[test]
fn watch_event_record_rejects_malformed_internal_requests() {
    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_KEY_DELETED,
            name: "not-empty",
            subtree: false,
            path_components: &[],
        }),
        Err(LcsError::WatchNoNameEventCarriedName {
            event_type: REG_WATCH_KEY_DELETED,
        })
    );

    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_VALUE_SET,
            name: "Setting",
            subtree: false,
            path_components: &["Child"],
        }),
        Err(LcsError::DirectWatchEventHasPath)
    );
}

#[test]
fn watch_read_batch_never_splits_records_and_reports_too_small_first_buffer() {
    let pending = [
        QueuedWatchEvent { total_len: 12 },
        QueuedWatchEvent { total_len: 20 },
        QueuedWatchEvent { total_len: 16 },
    ];

    assert_eq!(
        plan_watch_read_batch(&pending, 40),
        Ok(WatchReadBatchPlan::Ready {
            event_count: 2,
            bytes: 32,
        })
    );
    assert_eq!(
        plan_watch_read_batch(&pending, 11),
        Err(LcsError::WatchReadBufferTooSmall {
            buffer_len: 11,
            first_event_len: 12,
        })
    );
    assert_eq!(
        plan_watch_read_batch(&[], 128),
        Ok(WatchReadBatchPlan::WouldBlock)
    );
    assert_eq!(
        plan_watch_read_batch(&[QueuedWatchEvent { total_len: 7 }], 128),
        Err(LcsError::InvalidWatchEventLength(7))
    );
}

#[test]
fn watch_queue_insert_plans_overflow_and_preserves_existing_overflow() {
    assert_eq!(
        plan_watch_queue_insert(
            16,
            WatchQueueState {
                queued_events: 15,
                contains_overflow: false,
            },
        ),
        Ok(WatchQueueInsertPlan::QueueEvent)
    );
    assert_eq!(
        plan_watch_queue_insert(
            16,
            WatchQueueState {
                queued_events: 16,
                contains_overflow: false,
            },
        ),
        Ok(WatchQueueInsertPlan::DropOldestAndQueueOverflow)
    );
    assert_eq!(
        plan_watch_queue_insert(
            16,
            WatchQueueState {
                queued_events: 16,
                contains_overflow: true,
            },
        ),
        Ok(WatchQueueInsertPlan::DropOldestPreservingOverflowAndQueueEvent)
    );
    assert_eq!(
        plan_watch_queue_insert(
            0,
            WatchQueueState {
                queued_events: 0,
                contains_overflow: false,
            },
        ),
        Err(LcsError::InvalidWatchQueueLimit)
    );
    assert_eq!(
        plan_watch_queue_insert(
            16,
            WatchQueueState {
                queued_events: 0,
                contains_overflow: true,
            },
        ),
        Err(LcsError::InvalidWatchQueueState)
    );
}

#[test]
fn overflow_event_itself_has_minimum_no_name_record_shape() {
    assert_eq!(
        plan_watch_event_record(&WatchEventRecordRequest {
            event_type: REG_WATCH_OVERFLOW,
            name: "",
            subtree: false,
            path_components: &[],
        }),
        Ok(WatchEventRecordPlan::Record(WatchEventRecordShape {
            total_len: 8,
            name_len: 0,
            path_depth: None,
        }))
    );
}
