use crate::common::{finish_total_len};
use lcs_core::{
    Guid, LcsError, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN, RSI_NOT_FOUND, RSI_OK,
    RSI_QUERY_VALUES, RsiRetainedRequest, RsiStatus, RsiTransactionReplaySnapshotParsedResponse,
    RsiTransactionReplaySnapshotRequestRecord, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplayValueWatchScope, insert_transaction_replay_snapshot_request_record,
    match_transaction_replay_snapshot_response_record,
    parse_transaction_replay_snapshot_response_payload, retain_transaction_replay_snapshot_request,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];
const RESPONSE_BIT: u16 = 0x8000;

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

fn subkey_query(op: u64) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
            parent_guid: PARENT_GUID,
        },
    }
}

fn child_query(op: u64) -> TransactionReplaySnapshotQuery<'static> {
    TransactionReplaySnapshotQuery {
        phase: TransactionReplaySnapshotPhase::AfterCommit,
        operation_index: op,
        kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
            parent_guid: PARENT_GUID,
            child_name: "Child",
        },
    }
}

fn record(
    request_id: u64,
    query: TransactionReplaySnapshotQuery<'static>,
) -> RsiTransactionReplaySnapshotRequestRecord<'static> {
    retain_transaction_replay_snapshot_request(request_id, query)
}

fn response_frame(request_id: u64, request_op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&(request_op_code | RESPONSE_BIT).to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}


fn matched_payload<'a>(
    retained: RsiTransactionReplaySnapshotRequestRecord<'static>,
    frame: &'a [u8],
) -> lcs_core::LcsResult<RsiTransactionReplaySnapshotParsedResponse<'static, 'a>> {
    let mut storage = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut storage, retained)
        .expect("insert retained record");
    let matched =
        match_transaction_replay_snapshot_response_record(&storage, frame).expect("matched frame");
    parse_transaction_replay_snapshot_response_payload(matched, frame)
}

#[test]
fn matched_effective_value_response_parses_query_values_payload() {
    let retained = record(80, value_query(1));
    let mut frame = response_frame(80, RSI_QUERY_VALUES, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    match matched_payload(retained, &frame).expect("parsed payload") {
        RsiTransactionReplaySnapshotParsedResponse::EffectiveValue { record, payload } => {
            assert_eq!(record, retained);
            assert_eq!(payload.response.status, RsiStatus::Ok);
            assert_eq!(payload.entry_count, 0);
            assert_eq!(payload.blanket_count, 0);
        }
        other => panic!("unexpected payload variant: {other:?}"),
    }
}

#[test]
fn matched_effective_subkey_response_parses_enum_children_payload() {
    let retained = record(81, subkey_query(2));
    let mut frame = response_frame(81, RSI_ENUM_CHILDREN, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    match matched_payload(retained, &frame).expect("parsed payload") {
        RsiTransactionReplaySnapshotParsedResponse::EffectiveSubkeys { record, payload } => {
            assert_eq!(record, retained);
            assert_eq!(payload.response.header.request_id, 81);
            assert_eq!(payload.child_count, 0);
            assert_eq!(payload.metadata_count, 0);
        }
        other => panic!("unexpected payload variant: {other:?}"),
    }
}

#[test]
fn matched_child_visibility_response_parses_lookup_payload() {
    let retained = record(82, child_query(3));
    let mut frame = response_frame(82, RSI_LOOKUP, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    match matched_payload(retained, &frame).expect("parsed payload") {
        RsiTransactionReplaySnapshotParsedResponse::ChildVisibility { record, payload } => {
            assert_eq!(record, retained);
            assert_eq!(payload.response.header.request_id, 82);
            assert_eq!(payload.entry_count, 0);
            assert_eq!(payload.metadata_count, 0);
        }
        other => panic!("unexpected payload variant: {other:?}"),
    }
}

#[test]
fn matched_source_error_response_does_not_parse_success_payload() {
    let retained = record(83, value_query(4));
    let mut frame = response_frame(83, RSI_QUERY_VALUES, RSI_NOT_FOUND);
    finish_total_len(&mut frame);

    assert_eq!(
        matched_payload(retained, &frame),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND))
    );
}

#[test]
fn parser_rejects_record_query_kind_and_retained_opcode_mismatch() {
    let query = subkey_query(5);
    let retained = RsiTransactionReplaySnapshotRequestRecord {
        request_id: 84,
        query,
        retained: RsiRetainedRequest {
            request_id: 84,
            op_code: RSI_QUERY_VALUES,
        },
    };
    let mut frame = response_frame(84, RSI_QUERY_VALUES, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    assert_eq!(
        matched_payload(retained, &frame),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_ENUM_CHILDREN,
            actual: RSI_QUERY_VALUES,
        })
    );
    assert!(frame.len() >= RSI_MIN_RESPONSE_LEN);
}
