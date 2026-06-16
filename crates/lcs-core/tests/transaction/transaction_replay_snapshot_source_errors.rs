use lcs_core::{
    Guid, LcsError, RSI_MIN_RESPONSE_LEN, RSI_OK, RSI_QUERY_VALUES, RSI_STORAGE_ERROR,
    RsiMappedErrno, RsiStatus, RsiTransactionReplaySnapshotSourceErrorResponse,
    RsiValidatedResponse, TransactionReplaySnapshotPhase, TransactionReplaySnapshotQuery,
    TransactionReplaySnapshotQueryKind, TransactionReplayValueWatchScope,
    find_transaction_replay_snapshot_request_record,
    insert_transaction_replay_snapshot_request_record,
    process_transaction_replay_snapshot_source_error_response,
    retain_transaction_replay_snapshot_request, rsi_response_op_code,
    summarize_transaction_replay_snapshot_request_table,
};

const KEY_GUID: Guid = [0x40; 16];

fn value_query(op: u64) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
            key_guid: KEY_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
        },
    }
}

fn response_frame(request_id: u64, request_op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&(RSI_MIN_RESPONSE_LEN as u32).to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&rsi_response_op_code(request_op_code).unwrap().to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

#[test]
fn source_error_response_releases_request_without_snapshot_result() {
    let retained = retain_transaction_replay_snapshot_request(110, value_query(1));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let frame = response_frame(110, RSI_QUERY_VALUES, RSI_STORAGE_ERROR);

    assert_eq!(
        process_transaction_replay_snapshot_source_error_response(&mut request_table, &frame),
        Ok(RsiTransactionReplaySnapshotSourceErrorResponse {
            response: RsiValidatedResponse {
                header: lcs_core::RsiResponseHeader {
                    total_len: RSI_MIN_RESPONSE_LEN as u32,
                    request_id: 110,
                    op_code: rsi_response_op_code(RSI_QUERY_VALUES).unwrap(),
                },
                status: RsiStatus::StorageError,
            },
            released_record: retained,
            source_errno: RsiMappedErrno::Eio,
        }),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 110),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 110 }),
    );
}

#[test]
fn source_error_response_with_payload_is_rejected_before_release() {
    let retained = retain_transaction_replay_snapshot_request(111, value_query(2));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let mut frame = response_frame(111, RSI_QUERY_VALUES, RSI_STORAGE_ERROR);
    frame.extend_from_slice(&0xaaaa_u32.to_le_bytes());
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());

    assert_eq!(
        process_transaction_replay_snapshot_source_error_response(&mut request_table, &frame),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_QUERY_VALUES,
            extra_len: 4,
        }),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 111),
        Ok(retained),
    );
}

#[test]
fn ok_status_is_not_accepted_by_source_error_path() {
    let retained = retain_transaction_replay_snapshot_request(112, value_query(3));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let frame = response_frame(112, RSI_QUERY_VALUES, RSI_OK);

    assert_eq!(
        process_transaction_replay_snapshot_source_error_response(&mut request_table, &frame),
        Err(LcsError::RsiResponseRequiresPayloadParser(RSI_QUERY_VALUES)),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 112),
        Ok(retained),
    );
}

#[test]
fn unknown_status_is_rejected_before_release() {
    let retained = retain_transaction_replay_snapshot_request(113, value_query(4));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let frame = response_frame(113, RSI_QUERY_VALUES, 0xffff_ffff);

    assert_eq!(
        process_transaction_replay_snapshot_source_error_response(&mut request_table, &frame),
        Err(LcsError::UnknownRsiStatus(0xffff_ffff)),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 113),
        Ok(retained),
    );
}

#[test]
fn unknown_request_id_leaves_other_records_retained() {
    let retained = retain_transaction_replay_snapshot_request(114, value_query(5));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let frame = response_frame(115, RSI_QUERY_VALUES, RSI_STORAGE_ERROR);

    assert_eq!(
        process_transaction_replay_snapshot_source_error_response(&mut request_table, &frame),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 115 }),
    );
    assert_eq!(
        summarize_transaction_replay_snapshot_request_table(&request_table)
            .expect("request table remains valid")
            .entries,
        1,
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 114),
        Ok(retained),
    );
}
