use lcs_core::{
    Guid, LcsError, RSI_QUERY_VALUES, RSI_REQUEST_HEADER_LEN, RsiBuiltRequest, RsiRetainedRequest,
    RsiTransactionReplaySnapshotRequestTableSummary, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplayValueWatchScope, find_transaction_replay_snapshot_request_record,
    insert_transaction_replay_snapshot_request_record, parse_rsi_query_values_request_payload,
    parse_rsi_request_header, retain_transaction_replay_snapshot_request,
    schedule_transaction_replay_snapshot_query_request,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];

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
fn schedule_writes_frame_and_retains_matching_request_record() {
    let query = value_query(1, "Setting");
    let mut storage = [None; 2];
    let mut frame = [0xaa; 96];

    let scheduled =
        schedule_transaction_replay_snapshot_query_request(&mut storage, &mut frame, 1200, query)
            .expect("scheduled request");

    assert_eq!(
        scheduled.built,
        RsiBuiltRequest {
            len: 50,
            retained: RsiRetainedRequest {
                request_id: 1200,
                op_code: RSI_QUERY_VALUES,
            },
        },
    );
    assert_eq!(
        scheduled.request_summary,
        RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 1,
            capacity: 2,
            full: false,
        },
    );
    assert_eq!(scheduled.record.query, query);
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 1200).expect("retained request"),
        scheduled.record,
    );

    let header = parse_rsi_request_header(&frame[..scheduled.built.len]).expect("header");
    let payload = &frame[RSI_REQUEST_HEADER_LEN..scheduled.built.len];
    let parsed = parse_rsi_query_values_request_payload(payload).expect("payload");
    assert_eq!(header.request_id, 1200);
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    assert_eq!(header.txn_id, 0);
    assert_eq!(parsed.guid, KEY_GUID);
    assert_eq!(parsed.value_name.data, b"Setting");
    assert!(!parsed.query_all);
}

#[test]
fn duplicate_request_id_rejects_before_frame_mutation() {
    let existing = retain_transaction_replay_snapshot_request(1201, value_query(2, "Existing"));
    let mut storage = [None; 2];
    insert_transaction_replay_snapshot_request_record(&mut storage, existing)
        .expect("insert existing");
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        schedule_transaction_replay_snapshot_query_request(
            &mut storage,
            &mut frame,
            1201,
            subkey_query(3),
        ),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 1201 }),
    );
    assert_eq!(frame, original_frame);
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 1201),
        Ok(existing),
    );
}

#[test]
fn full_request_table_rejects_before_frame_mutation() {
    let existing = retain_transaction_replay_snapshot_request(1202, value_query(4, "Existing"));
    let mut storage = [Some(existing)];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        schedule_transaction_replay_snapshot_query_request(
            &mut storage,
            &mut frame,
            1203,
            subkey_query(5),
        ),
        Err(LcsError::TransactionReplaySnapshotRequestTableFull { capacity: 1 }),
    );
    assert_eq!(frame, original_frame);
    assert_eq!(storage, [Some(existing)]);
}

#[test]
fn short_frame_buffer_rejects_without_retaining_request() {
    let mut storage = [None; 1];
    let mut frame = [0xaa; 1];

    assert_eq!(
        schedule_transaction_replay_snapshot_query_request(
            &mut storage,
            &mut frame,
            1204,
            subkey_query(6),
        ),
        Err(LcsError::RsiFrameBufferTooSmall {
            len: 1,
            required: 38,
        }),
    );
    assert_eq!(frame, [0xaa; 1]);
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage)
            .expect("empty table remains valid")
            .entries,
        0,
    );
}

#[test]
fn corrupt_existing_request_table_rejects_before_frame_mutation() {
    let duplicate = retain_transaction_replay_snapshot_request(1205, value_query(7, "Dup"));
    let mut storage = [Some(duplicate), Some(duplicate)];
    let mut frame = [0xaa; 96];
    let original_frame = frame;

    assert_eq!(
        schedule_transaction_replay_snapshot_query_request(
            &mut storage,
            &mut frame,
            1206,
            value_query(8, "New"),
        ),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 1205 }),
    );
    assert_eq!(frame, original_frame);
    assert_eq!(storage, [Some(duplicate), Some(duplicate)]);
}
