use crate::common::{finish_total_len, push_len_prefixed};
use lcs_core::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, LcsError, LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry, PathTarget, REG_SZ,
    RSI_ENUM_CHILDREN, RSI_NOT_FOUND, RSI_OK, RSI_QUERY_VALUES, RegistryValueType,
    ResolvedPathEntry, ResolvedValueEntry, RsiTransactionReplaySnapshotMaterializedResponse,
    RsiTransactionReplaySnapshotRequestRecord, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplaySnapshotResultKind, TransactionReplaySnapshotResultTableSummary,
    TransactionReplayValueWatchScope, ValueEntry, find_transaction_replay_snapshot_request_record,
    insert_transaction_replay_snapshot_request_record, insert_transaction_replay_snapshot_result,
    process_transaction_replay_snapshot_success_response,
    retain_transaction_replay_snapshot_request, rsi_response_op_code,
    summarize_transaction_replay_snapshot_result_table,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];
const OTHER_GUID: Guid = [0x30; 16];
const LAYERS: [LayerView<'static>; 2] = [
    LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    },
    LayerView {
        name: "policy",
        precedence: 10,
        enabled: true,
    },
];

fn context(limits: &LcsLimits) -> LayerResolutionContext<'_> {
    LayerResolutionContext {
        layers: &LAYERS,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

fn dummy_value_entry() -> NamedValueEntry<'static> {
    NamedValueEntry {
        name: "",
        entry: ValueEntry {
            layer: "base",
            sequence: 1,
            value_type: REG_SZ,
            data: b"",
        },
    }
}

fn dummy_blanket_entry() -> BlanketTombstoneEntry<'static> {
    BlanketTombstoneEntry {
        layer: "base",
        sequence: 1,
    }
}

fn dummy_path_entry() -> NamedPathEntry<'static> {
    NamedPathEntry {
        child_name: "dummy",
        entry: PathEntry {
            layer: "base",
            sequence: 1,
            target: PathTarget::Hidden,
        },
    }
}

fn dummy_value_result() -> EnumeratedValue<'static> {
    EnumeratedValue {
        name: "",
        value: ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"",
            layer: "base",
            precedence: 0,
            sequence: 1,
        },
    }
}

fn dummy_subkey_result() -> EnumeratedSubkey<'static> {
    EnumeratedSubkey {
        child_name: "",
        path: ResolvedPathEntry {
            guid: OTHER_GUID,
            layer: "base",
            precedence: 0,
            sequence: 1,
        },
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
    frame.extend_from_slice(&rsi_response_op_code(request_op_code).unwrap().to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}


fn push_value_entry(
    frame: &mut Vec<u8>,
    value_name: &[u8],
    layer_name: &[u8],
    data: &[u8],
    sequence: u64,
) {
    push_len_prefixed(frame, value_name);
    push_len_prefixed(frame, layer_name);
    frame.extend_from_slice(&REG_SZ.to_le_bytes());
    push_len_prefixed(frame, data);
    frame.extend_from_slice(&sequence.to_le_bytes());
}


#[test]
fn successful_effective_value_response_is_stored_then_released() {
    let retained = record(100, value_query(1, "Setting"));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let mut result_table = [None; 2];
    let mut frame = response_frame(100, RSI_QUERY_VALUES, RSI_OK);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"Setting", b"base", b"old", 10);
    push_value_entry(&mut frame, b"Setting", b"policy", b"new", 11);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 4];
    let mut blankets = [dummy_blanket_entry(); 2];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 4];
    let mut subkeys = [dummy_subkey_result(); 1];

    let processed = process_transaction_replay_snapshot_success_response(
        &mut request_table,
        &mut result_table,
        &frame,
        &context(&limits),
        &mut value_entries,
        &mut blankets,
        &mut paths,
        &mut values,
        &mut subkeys,
    )
    .expect("processed response");

    assert_eq!(processed.response.status, lcs_core::RsiStatus::Ok);
    assert_eq!(processed.released_record, retained);
    assert_eq!(
        processed.result_summary,
        TransactionReplaySnapshotResultTableSummary {
            entries: 1,
            capacity: 2,
            effective_value_results: 1,
            effective_subkey_results: 0,
            child_visibility_results: 0,
        }
    );
    match processed.materialized {
        RsiTransactionReplaySnapshotMaterializedResponse::EffectiveValue { result, summary } => {
            assert_eq!(summary.emitted_values, 1);
            let TransactionReplaySnapshotResultKind::EffectiveValue {
                key_guid,
                scope,
                values,
            } = result.kind
            else {
                panic!("unexpected result kind: {:?}", result.kind);
            };
            assert_eq!(key_guid, KEY_GUID);
            assert_eq!(
                scope,
                TransactionReplayValueWatchScope::NamedValue { name: "Setting" },
            );
            assert_eq!(
                values,
                &[EnumeratedValue {
                    name: "Setting",
                    value: ResolvedValueEntry {
                        value_type: RegistryValueType::Sz,
                        data: b"new",
                        layer: "policy",
                        precedence: 10,
                        sequence: 11,
                    },
                }],
            );
        }
        other => panic!("unexpected materialized response: {other:?}"),
    }
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 100),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 100 }),
    );
    assert_eq!(
        result_table[0].expect("stored result").phase,
        retained.query.phase
    );
}

#[test]
fn successful_effective_subkey_response_uses_same_store_release_path() {
    let retained = record(101, subkey_query(2));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let mut result_table = [None; 1];
    let mut frame = response_frame(101, RSI_ENUM_CHILDREN, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    let processed = process_transaction_replay_snapshot_success_response(
        &mut request_table,
        &mut result_table,
        &frame,
        &context(&limits),
        &mut value_entries,
        &mut blankets,
        &mut paths,
        &mut values,
        &mut subkeys,
    )
    .expect("processed response");

    assert_eq!(processed.released_record, retained);
    assert_eq!(processed.result_summary.effective_subkey_results, 1);
    match processed.materialized {
        RsiTransactionReplaySnapshotMaterializedResponse::EffectiveSubkeys { result, summary } => {
            assert_eq!(summary.emitted_subkeys, 0);
            let TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid,
                children,
            } = result.kind
            else {
                panic!("unexpected result kind: {:?}", result.kind);
            };
            assert_eq!(parent_guid, PARENT_GUID);
            assert!(children.is_empty());
        }
        other => panic!("unexpected materialized response: {other:?}"),
    }
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 101),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 101 }),
    );
}

#[test]
fn source_error_status_keeps_request_record_and_stores_no_result() {
    let retained = record(102, value_query(3, "Setting"));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let mut result_table = [None; 1];
    let mut frame = response_frame(102, RSI_QUERY_VALUES, RSI_NOT_FOUND);
    finish_total_len(&mut frame);
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    assert_eq!(
        process_transaction_replay_snapshot_success_response(
            &mut request_table,
            &mut result_table,
            &frame,
            &context(&limits),
            &mut value_entries,
            &mut blankets,
            &mut paths,
            &mut values,
            &mut subkeys,
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND)),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 102),
        Ok(retained),
    );
    assert_eq!(
        summarize_transaction_replay_snapshot_result_table(&result_table)
            .expect("valid empty result table")
            .entries,
        0,
    );
}

#[test]
fn full_result_table_keeps_request_record_after_success_payload_validation() {
    let retained = record(103, value_query(4, "Setting"));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let existing = lcs_core::TransactionReplaySnapshotResult {
        phase: TransactionReplaySnapshotPhase::BeforeCommit,
        operation_index: 99,
        kind: TransactionReplaySnapshotResultKind::EffectiveValue {
            key_guid: OTHER_GUID,
            scope: TransactionReplayValueWatchScope::NamedValue { name: "Other" },
            values: &[],
        },
    };
    let mut result_table = [None; 1];
    insert_transaction_replay_snapshot_result(&mut result_table, existing)
        .expect("fill result table");
    let mut frame = response_frame(103, RSI_QUERY_VALUES, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    assert_eq!(
        process_transaction_replay_snapshot_success_response(
            &mut request_table,
            &mut result_table,
            &frame,
            &context(&limits),
            &mut value_entries,
            &mut blankets,
            &mut paths,
            &mut values,
            &mut subkeys,
        ),
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "replay_snapshot.results",
            required: 2,
            capacity: 1,
        }),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 103),
        Ok(retained),
    );
    assert_eq!(result_table[0], Some(existing));
}

#[test]
fn unknown_request_id_keeps_other_records_and_stores_no_result() {
    let retained = record(104, value_query(5, "Setting"));
    let mut request_table = [None; 1];
    insert_transaction_replay_snapshot_request_record(&mut request_table, retained)
        .expect("insert request");
    let mut result_table = [None; 1];
    let mut frame = response_frame(105, RSI_QUERY_VALUES, RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    assert_eq!(
        process_transaction_replay_snapshot_success_response(
            &mut request_table,
            &mut result_table,
            &frame,
            &context(&limits),
            &mut value_entries,
            &mut blankets,
            &mut paths,
            &mut values,
            &mut subkeys,
        ),
        Err(LcsError::TransactionReplaySnapshotRequestNotFound { request_id: 105 }),
    );
    assert_eq!(
        find_transaction_replay_snapshot_request_record(&request_table, 104),
        Ok(retained),
    );
    assert_eq!(result_table, [None; 1]);
}
