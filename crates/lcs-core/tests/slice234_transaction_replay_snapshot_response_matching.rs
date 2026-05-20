use lcs_core::{
    Guid, LcsError, RSI_ENUM_CHILDREN, RSI_MIN_RESPONSE_LEN, RSI_QUERY_VALUES, RsiStatus,
    RsiTransactionReplaySnapshotRequestRecord, RsiTransactionReplaySnapshotRequestTableSummary,
    RsiTransactionReplaySnapshotResponseMatch, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplayValueWatchScope, find_transaction_replay_snapshot_request_record,
    insert_transaction_replay_snapshot_request_record,
    match_transaction_replay_snapshot_response_record, retain_transaction_replay_snapshot_request,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];
const RESPONSE_BIT: u16 = 0x8000;

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

fn record(
    request_id: u64,
    query: TransactionReplaySnapshotQuery<'static>,
) -> RsiTransactionReplaySnapshotRequestRecord<'static> {
    retain_transaction_replay_snapshot_request(request_id, query)
}

fn response_frame(
    request_id: u64,
    request_op_code: u16,
    status: u32,
) -> [u8; RSI_MIN_RESPONSE_LEN] {
    let mut frame = [0u8; RSI_MIN_RESPONSE_LEN];
    frame[0..4].copy_from_slice(&(RSI_MIN_RESPONSE_LEN as u32).to_le_bytes());
    frame[4..12].copy_from_slice(&request_id.to_le_bytes());
    frame[12..14].copy_from_slice(&(request_op_code | RESPONSE_BIT).to_le_bytes());
    frame[14..18].copy_from_slice(&status.to_le_bytes());
    frame
}

#[test]
fn response_match_validates_without_releasing_request_record() {
    let query = value_query(1, "Setting");
    let retained = record(70, query);
    let mut storage = [None; 2];
    insert_transaction_replay_snapshot_request_record(&mut storage, retained)
        .expect("insert retained record");
    let frame = response_frame(70, RSI_QUERY_VALUES, 0);

    assert_eq!(
        match_transaction_replay_snapshot_response_record(&storage, &frame),
        Ok(RsiTransactionReplaySnapshotResponseMatch {
            record: retained,
            response: lcs_core::RsiValidatedResponse {
                header: lcs_core::RsiResponseHeader {
                    total_len: RSI_MIN_RESPONSE_LEN as u32,
                    request_id: 70,
                    op_code: RSI_QUERY_VALUES | RESPONSE_BIT,
                },
                status: RsiStatus::Ok,
            },
        })
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 70)
            .expect("matching must not release before payload validation")
            .query,
        query
    );
}

#[test]
fn response_match_rejects_unknown_request_id_without_releasing_other_records() {
    let retained = record(71, value_query(2, "Setting"));
    let mut storage = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut storage, retained)
        .expect("insert retained record");
    let frame = response_frame(72, RSI_QUERY_VALUES, 0);

    assert_eq!(
        match_transaction_replay_snapshot_response_record(&storage, &frame),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 72 })
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 71)
            .expect("unknown response must not mutate retained records"),
        retained
    );
}

#[test]
fn response_match_rejects_opcode_mismatch_without_releasing_record() {
    let retained = record(73, value_query(3, "Setting"));
    let mut storage = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut storage, retained)
        .expect("insert retained record");
    let frame = response_frame(73, RSI_ENUM_CHILDREN, 0);

    assert_eq!(
        match_transaction_replay_snapshot_response_record(&storage, &frame),
        Err(LcsError::RsiResponseOpcodeMismatch {
            expected: RSI_QUERY_VALUES | RESPONSE_BIT,
            actual: RSI_ENUM_CHILDREN | RESPONSE_BIT,
        })
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&storage, 73)
            .expect("mismatched response must not consume record"),
        retained
    );
}

#[test]
fn response_match_rejects_corrupt_duplicate_table_before_matching() {
    let duplicate = record(74, subkey_query(4));
    let storage = [Some(duplicate), Some(duplicate)];
    let frame = response_frame(74, RSI_ENUM_CHILDREN, 0);

    assert_eq!(
        match_transaction_replay_snapshot_response_record(&storage, &frame),
        Err(LcsError::DuplicateTransactionReplaySnapshotRequest { request_id: 74 })
    );
}

#[test]
fn response_match_rejects_malformed_frame_without_mutating_records() {
    let retained = record(75, value_query(5, "Setting"));
    let mut storage = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut storage, retained)
        .expect("insert retained record");
    let frame = [0u8; RSI_MIN_RESPONSE_LEN - 1];

    assert_eq!(
        match_transaction_replay_snapshot_response_record(&storage, &frame),
        Err(LcsError::RsiMessageTooShort {
            len: RSI_MIN_RESPONSE_LEN - 1,
            min: RSI_MIN_RESPONSE_LEN,
        })
    );
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&storage),
        Ok(RsiTransactionReplaySnapshotRequestTableSummary {
            entries: 1,
            capacity: 1,
            full: true,
        })
    );
}
