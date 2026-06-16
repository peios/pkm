use lcs_core::{
    Guid, LcsError, LcsLimits, RSI_QUERY_VALUES, RSI_REQUEST_HEADER_LEN, RsiBuiltRequest,
    RsiRequestIdCounter, RsiRetainedRequest, RsiTransactionReplaySnapshotReservationPlan,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotQuery,
    TransactionReplaySnapshotQueryKind, TransactionReplayValueWatchScope,
    find_transaction_replay_snapshot_request_record, parse_rsi_query_values_request_payload,
    parse_rsi_request_header, reserve_and_schedule_transaction_replay_snapshot_query_request,
    retain_transaction_replay_snapshot_request,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x44; 16];
const PARENT_GUID: Guid = [0x22; 16];

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
fn dispatch_admission_allocates_id_writes_frame_and_retains_record() {
    let query = value_query(1, "Setting");
    let mut counter = RsiRequestIdCounter::from_next_request_id(500);
    let mut storage = [None; 2];
    let mut frame = [0xaa; 96];

    let plan = reserve_and_schedule_transaction_replay_snapshot_query_request(
        &limits(),
        &mut counter,
        1,
        250,
        &mut storage,
        &mut frame,
        query,
    )
    .expect("dispatch admitted");

    let RsiTransactionReplaySnapshotReservationPlan::DispatchNow {
        scheduled,
        remaining_timeout_ms,
        in_flight_after_dispatch,
    } = plan
    else {
        panic!("expected dispatch");
    };

    assert_eq!(remaining_timeout_ms, 750);
    assert_eq!(in_flight_after_dispatch, 2);
    assert_eq!(counter.next_request_id(), 501);
    assert_eq!(
        scheduled.built,
        RsiBuiltRequest {
            len: 50,
            retained: RsiRetainedRequest {
                request_id: 500,
                op_code: RSI_QUERY_VALUES,
            },
        },
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 500).expect("retained request"),
        scheduled.record,
    );

    let header = parse_rsi_request_header(&frame[..scheduled.built.len]).expect("header");
    let payload = &frame[RSI_REQUEST_HEADER_LEN..scheduled.built.len];
    let parsed = parse_rsi_query_values_request_payload(payload).expect("payload");
    assert_eq!(header.request_id, 500);
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    assert_eq!(header.txn_id, 0);
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.value_name.data, b"Setting");
    assert!(!parsed.query_all);
}

#[test]
fn full_in_flight_limit_waits_without_allocating_or_mutating() {
    let mut counter = RsiRequestIdCounter::from_next_request_id(501);
    let mut storage = [None; 1];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            2,
            100,
            &mut storage,
            &mut frame,
            subkey_query(2),
        ),
        Ok(RsiTransactionReplaySnapshotReservationPlan::WaitForSlot {
            remaining_timeout_ms: 900,
        }),
    );
    assert_eq!(counter.next_request_id(), 501);
    assert_eq!(storage, [None]);
    assert_eq!(frame, original_frame);
}

#[test]
fn timeout_before_dispatch_sends_no_request_and_allocates_no_id() {
    let mut counter = RsiRequestIdCounter::from_next_request_id(502);
    let mut storage = [None; 1];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            0,
            1_000,
            &mut storage,
            &mut frame,
            subkey_query(3),
        ),
        Ok(RsiTransactionReplaySnapshotReservationPlan::TimeoutBeforeDispatchNoRequest),
    );
    assert_eq!(counter.next_request_id(), 502);
    assert_eq!(storage, [None]);
    assert_eq!(frame, original_frame);
}

#[test]
fn full_request_table_rejects_before_allocating_request_id() {
    let existing = retain_transaction_replay_snapshot_request(503, value_query(4, "Existing"));
    let mut counter = RsiRequestIdCounter::from_next_request_id(504);
    let mut storage = [Some(existing)];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frame,
            subkey_query(5),
        ),
        Err(LcsError::TransactionReplaySnapshotRequestTableFull { capacity: 1 }),
    );
    assert_eq!(counter.next_request_id(), 504);
    assert_eq!(storage, [Some(existing)]);
    assert_eq!(frame, original_frame);
}

#[test]
fn short_frame_buffer_rejects_before_allocating_request_id() {
    let mut counter = RsiRequestIdCounter::from_next_request_id(505);
    let mut storage = [None; 1];
    let mut frame = [0xaa; 1];

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frame,
            subkey_query(6),
        ),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: 1,
            required: 38,
        }),
    );
    assert_eq!(counter.next_request_id(), 505);
    assert_eq!(frame, [0xaa; 1]);
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage)
            .expect("empty table remains valid")
            .entries,
        0,
    );
}

#[test]
fn stale_request_id_counter_duplicate_fails_without_frame_mutation() {
    let existing = retain_transaction_replay_snapshot_request(506, value_query(7, "Existing"));
    let mut counter = RsiRequestIdCounter::from_next_request_id(506);
    let mut storage = [Some(existing), None];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            1,
            100,
            &mut storage,
            &mut frame,
            subkey_query(8),
        ),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 506 }),
    );
    assert_eq!(counter.next_request_id(), 507);
    assert_eq!(storage, [Some(existing), None]);
    assert_eq!(frame, original_frame);
}

#[test]
fn request_id_overflow_rejects_without_frame_or_table_mutation() {
    let mut counter = RsiRequestIdCounter::from_next_request_id(u64::MAX);
    let mut storage = [None; 1];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        reserve_and_schedule_transaction_replay_snapshot_query_request(
            &limits(),
            &mut counter,
            0,
            100,
            &mut storage,
            &mut frame,
            subkey_query(9),
        ),
        Err(LcsError::RsiRequestIdOverflow),
    );
    assert_eq!(counter.next_request_id(), u64::MAX);
    assert_eq!(storage, [None]);
    assert_eq!(frame, original_frame);
}
