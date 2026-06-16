use lcs_core::{
    Guid, LcsError, LcsLimits, RSI_ENUM_CHILDREN, RSI_QUERY_VALUES, RsiRequestIdCounter,
    RsiTransactionReplaySnapshotBatchScheduleStop,
    RsiTransactionReplaySnapshotBatchScheduleSummary,
    RsiTransactionReplaySnapshotRequestTableSummary, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplayValueWatchScope, find_transaction_replay_snapshot_request_record,
    parse_rsi_request_header, reserve_and_schedule_transaction_replay_snapshot_query_batch,
    retain_transaction_replay_snapshot_request,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x45; 16];
const PARENT_GUID: Guid = [0x25; 16];

fn limits() -> LcsLimits {
    LcsLimits {
        request_timeout_ms: 1_000,
        max_concurrent_rsi_requests: 2,
        ..LcsLimits::default()
    }
}

fn value_query(op: u64, name: &'static str) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name },
        },
    }
}

fn subkey_query(op: u64) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
        },
    }
}

#[test]
fn batch_schedules_all_queries_when_slots_and_storage_are_available() {
    let queries = [value_query(1, "A"), subkey_query(2)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(700);
    let mut storage = [None; 3];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 96];

    let summary = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            250,
            &mut storage,
            &mut frames,
            &queries,
        )
        .expect("batch scheduled")
    };

    assert_eq!(
        summary,
        RsiTransactionReplaySnapshotBatchScheduleSummary {
            planned_queries: 2,
            scheduled_requests: 2,
            request_summary: RsiTransactionReplaySnapshotRequestTableSummary {
                entries: 2,
                capacity: 3,
                full: false,
            },
            in_flight_after_schedule: 2,
            stop: RsiTransactionReplaySnapshotBatchScheduleStop::AllScheduled,
        },
    );
    assert_eq!(counter.next_request_id(), 702);
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 700)
            .expect("first request")
            .query,
        queries[0],
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 701)
            .expect("second request")
            .query,
        queries[1],
    );
    assert_eq!(
        parse_rsi_request_header(&frame0[..44])
            .expect("first header")
            .op_code,
        RSI_QUERY_VALUES,
    );
    assert_eq!(
        parse_rsi_request_header(&frame1[..38])
            .expect("second header")
            .op_code,
        RSI_ENUM_CHILDREN,
    );
}

#[test]
fn batch_schedules_available_prefix_and_reports_wait_for_remaining_queries() {
    let queries = [value_query(1, "A"), subkey_query(2), value_query(3, "B")];
    let mut counter = RsiRequestIdCounter::from_next_request_id(710);
    let mut storage = [None; 3];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 96];

    let summary = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
        .expect("prefix scheduled")
    };

    assert_eq!(summary.planned_queries, 3);
    assert_eq!(summary.scheduled_requests, 2);
    assert_eq!(summary.in_flight_after_schedule, 2);
    assert_eq!(
        summary.stop,
        RsiTransactionReplaySnapshotBatchScheduleStop::WaitForSlot {
            remaining_timeout_ms: 900,
        },
    );
    assert_eq!(counter.next_request_id(), 712);
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage)
            .expect("dense table")
            .entries,
        2,
    );
}

#[test]
fn batch_waits_without_allocating_when_in_flight_limit_is_already_full() {
    let queries = [subkey_query(4)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(720);
    let mut storage = [None; 1];

    let summary = reserve_and_schedule_transaction_replay_snapshot_query_batch(
        &limits(),
        &mut counter,
        2,
        250,
        &mut storage,
        &mut [],
        &queries,
    )
    .expect("wait plan");

    assert_eq!(
        summary.stop,
        RsiTransactionReplaySnapshotBatchScheduleStop::WaitForSlot {
            remaining_timeout_ms: 750,
        },
    );
    assert_eq!(summary.scheduled_requests, 0);
    assert_eq!(counter.next_request_id(), 720);
    assert_eq!(storage, [None]);
}

#[test]
fn batch_timeout_before_dispatch_allocates_no_request_ids() {
    let queries = [subkey_query(5)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(730);
    let mut storage = [None; 1];

    let summary = reserve_and_schedule_transaction_replay_snapshot_query_batch(
        &limits(),
        &mut counter,
        0,
        1_000,
        &mut storage,
        &mut [],
        &queries,
    )
    .expect("timeout plan");

    assert_eq!(
        summary.stop,
        RsiTransactionReplaySnapshotBatchScheduleStop::TimeoutBeforeDispatchNoRequest,
    );
    assert_eq!(summary.scheduled_requests, 0);
    assert_eq!(counter.next_request_id(), 730);
    assert_eq!(storage, [None]);
}

#[test]
fn too_few_frame_slots_rejects_before_partial_batch_mutation() {
    let queries = [value_query(6, "A"), subkey_query(7)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(740);
    let mut storage = [None; 2];
    let mut frame0 = [0xaa; 96];
    let original_frame0 = frame0;

    let result = {
        let mut frames: [&mut [u8]; 1] = [&mut frame0];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
    };

    assert_eq!(
        result,
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "transaction_replay_snapshot_request_frames",
            required: 2,
            capacity: 1,
        }),
    );
    assert_eq!(counter.next_request_id(), 740);
    assert_eq!(storage, [None, None]);
    assert_eq!(frame0, original_frame0);
}

#[test]
fn short_later_frame_rejects_before_partial_batch_mutation() {
    let queries = [value_query(8, "A"), subkey_query(9)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(750);
    let mut storage = [None; 2];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 1];
    let original_frame0 = frame0;
    let original_frame1 = frame1;

    let result = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
    };

    assert_eq!(
        result,
        Err(LcsError::RsiFrameBufferTooSmall {
            len: 1,
            required: 38,
        }),
    );
    assert_eq!(counter.next_request_id(), 750);
    assert_eq!(storage, [None, None]);
    assert_eq!(frame0, original_frame0);
    assert_eq!(frame1, original_frame1);
}

#[test]
fn insufficient_request_table_capacity_rejects_before_partial_batch_mutation() {
    let existing = retain_transaction_replay_snapshot_request(759, value_query(10, "Existing"));
    let queries = [value_query(11, "A"), subkey_query(12)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(760);
    let mut storage = [Some(existing), None];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 96];
    let original_frame0 = frame0;
    let original_frame1 = frame1;

    let result = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
    };

    assert_eq!(
        result,
        Err(LcsError::TransactionReplaySnapshotRequestTableFull { capacity: 2 }),
    );
    assert_eq!(counter.next_request_id(), 760);
    assert_eq!(storage, [Some(existing), None]);
    assert_eq!(frame0, original_frame0);
    assert_eq!(frame1, original_frame1);
}

#[test]
fn request_id_overflow_rejects_entire_batch_before_mutation() {
    let queries = [value_query(13, "A"), subkey_query(14)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(u64::MAX - 1);
    let mut storage = [None; 2];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 96];
    let original_frame0 = frame0;
    let original_frame1 = frame1;

    let result = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
    };

    assert_eq!(result, Err(LcsError::RsiRequestIdOverflow));
    assert_eq!(counter.next_request_id(), u64::MAX - 1);
    assert_eq!(storage, [None, None]);
    assert_eq!(frame0, original_frame0);
    assert_eq!(frame1, original_frame1);
}

#[test]
fn stale_batch_request_id_duplicate_rejects_before_mutation() {
    let existing = retain_transaction_replay_snapshot_request(770, value_query(15, "Existing"));
    let queries = [value_query(16, "A"), subkey_query(17)];
    let mut counter = RsiRequestIdCounter::from_next_request_id(770);
    let mut storage = [Some(existing), None, None];
    let mut frame0 = [0xaa; 96];
    let mut frame1 = [0xbb; 96];
    let original_frame0 = frame0;
    let original_frame1 = frame1;

    let result = {
        let mut frames: [&mut [u8]; 2] = [&mut frame0, &mut frame1];
        reserve_and_schedule_transaction_replay_snapshot_query_batch(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frames,
            &queries,
        )
    };

    assert_eq!(
        result,
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 770 }),
    );
    assert_eq!(counter.next_request_id(), 770);
    assert_eq!(storage, [Some(existing), None, None]);
    assert_eq!(frame0, original_frame0);
    assert_eq!(frame1, original_frame1);
}
