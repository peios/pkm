use lcs_core::{
    Guid, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_QUERY_VALUES, RSI_REQUEST_HEADER_LEN,
    TransactionReplaySnapshotPhase, TransactionReplaySnapshotQuery,
    TransactionReplaySnapshotQueryKind, TransactionReplayValueWatchScope,
    parse_rsi_enum_children_request_payload, parse_rsi_lookup_request_payload,
    parse_rsi_query_values_request_payload, parse_rsi_request_header,
    write_transaction_replay_snapshot_query_request_frame,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];

fn payload(frame: &[u8], len: usize) -> &[u8] {
    &frame[RSI_REQUEST_HEADER_LEN..len]
}

#[test]
fn named_value_snapshot_query_writes_query_values_without_transaction_context() {
    let mut frame = [0xaa; 96];
    let built = write_transaction_replay_snapshot_query_request_frame(
        &mut frame,
        701,
        TransactionReplaySnapshotQuery {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 2,
            kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            },
        },
    )
    .expect("snapshot query frame");
    let header = parse_rsi_request_header(&frame[..built.len]).expect("header");
    let request = parse_rsi_query_values_request_payload(payload(&frame, built.len))
        .expect("query-values payload");

    assert_eq!(header.request_id, 701);
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    assert_eq!(header.txn_id, 0);
    assert_eq!(request.guid, KEY_GUID);
    assert_eq!(request.value_name.data, b"Setting");
    assert!(!request.query_all);
}

#[test]
fn all_values_snapshot_query_writes_query_values_all_sentinel() {
    let mut frame = [0xaa; 96];
    let built = write_transaction_replay_snapshot_query_request_frame(
        &mut frame,
        702,
        TransactionReplaySnapshotQuery {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 3,
            kind: TransactionReplaySnapshotQueryKind::EffectiveValue {
                key_guid: KEY_GUID,
                scope: TransactionReplayValueWatchScope::AllValues,
            },
        },
    )
    .expect("snapshot query frame");
    let header = parse_rsi_request_header(&frame[..built.len]).expect("header");
    let request = parse_rsi_query_values_request_payload(payload(&frame, built.len))
        .expect("query-values payload");

    assert_eq!(header.request_id, 702);
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    assert_eq!(header.txn_id, 0);
    assert_eq!(request.guid, KEY_GUID);
    assert_eq!(request.value_name.data, b"");
    assert!(request.query_all);
}

#[test]
fn effective_subkey_snapshot_query_writes_enum_children_without_transaction_context() {
    let mut frame = [0xaa; 96];
    let built = write_transaction_replay_snapshot_query_request_frame(
        &mut frame,
        703,
        TransactionReplaySnapshotQuery {
            phase: TransactionReplaySnapshotPhase::BeforeCommit,
            operation_index: 4,
            kind: TransactionReplaySnapshotQueryKind::EffectiveSubkeys {
                parent_guid: PARENT_GUID,
            },
        },
    )
    .expect("snapshot query frame");
    let header = parse_rsi_request_header(&frame[..built.len]).expect("header");
    let request = parse_rsi_enum_children_request_payload(payload(&frame, built.len))
        .expect("enum-children payload");

    assert_eq!(header.request_id, 703);
    assert_eq!(header.op_code, RSI_ENUM_CHILDREN);
    assert_eq!(header.txn_id, 0);
    assert_eq!(request.parent_guid, PARENT_GUID);
}

#[test]
fn child_visibility_snapshot_query_writes_lookup_without_transaction_context() {
    let mut frame = [0xaa; 96];
    let built = write_transaction_replay_snapshot_query_request_frame(
        &mut frame,
        704,
        TransactionReplaySnapshotQuery {
            phase: TransactionReplaySnapshotPhase::AfterCommit,
            operation_index: 5,
            kind: TransactionReplaySnapshotQueryKind::ChildVisibility {
                parent_guid: PARENT_GUID,
                child_name: "Child",
            },
        },
    )
    .expect("snapshot query frame");
    let header = parse_rsi_request_header(&frame[..built.len]).expect("header");
    let request =
        parse_rsi_lookup_request_payload(payload(&frame, built.len)).expect("lookup payload");

    assert_eq!(header.request_id, 704);
    assert_eq!(header.op_code, RSI_LOOKUP);
    assert_eq!(header.txn_id, 0);
    assert_eq!(request.parent_guid, PARENT_GUID);
    assert_eq!(request.child_name.data, b"Child");
}
