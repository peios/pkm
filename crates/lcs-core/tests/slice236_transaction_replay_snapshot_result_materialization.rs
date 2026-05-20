use lcs_core::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, LcsError, LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry, PathTarget, REG_SZ,
    RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN,
    RSI_QUERY_VALUES, RegistryValueType, ResolvedPathEntry, ResolvedValueEntry, RsiRetainedRequest,
    RsiTransactionReplaySnapshotMaterializedResponse, RsiTransactionReplaySnapshotParsedResponse,
    RsiTransactionReplaySnapshotRequestRecord, TransactionReplaySnapshotPhase,
    TransactionReplaySnapshotQuery, TransactionReplaySnapshotQueryKind,
    TransactionReplaySnapshotResultKind, TransactionReplayValueWatchScope, ValueEntry,
    insert_transaction_replay_snapshot_request_record,
    match_transaction_replay_snapshot_response_record,
    materialize_transaction_replay_snapshot_response,
    parse_rsi_query_values_success_response_payload,
    parse_transaction_replay_snapshot_response_payload, retain_transaction_replay_snapshot_request,
    rsi_response_op_code,
};

const KEY_GUID: Guid = [0x40; 16];
const PARENT_GUID: Guid = [0x20; 16];
const CHILD_GUID: Guid = [0x30; 16];
const OTHER_GUID: Guid = [0x31; 16];
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

fn response_frame(request_id: u64, request_op_code: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&rsi_response_op_code(request_op_code).unwrap().to_le_bytes());
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}

fn push_len_prefixed(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
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

fn push_path_entry(
    frame: &mut Vec<u8>,
    layer_name: &[u8],
    target_type: u8,
    target_guid: Guid,
    sequence: u64,
) {
    push_len_prefixed(frame, layer_name);
    frame.push(target_type);
    frame.extend_from_slice(&target_guid);
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

fn parsed_response<'a>(
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
fn effective_value_payload_materializes_retained_snapshot_result() {
    let retained = record(90, value_query(1));
    let mut frame = response_frame(90, RSI_QUERY_VALUES);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"Setting", b"base", b"old", 10);
    push_value_entry(&mut frame, b"Setting", b"policy", b"new", 11);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let parsed = parsed_response(retained, &frame).expect("parsed response");
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 4];
    let mut blankets = [dummy_blanket_entry(); 2];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 4];
    let mut subkeys = [dummy_subkey_result(); 1];

    match materialize_transaction_replay_snapshot_response(
        &context(&limits),
        parsed,
        &mut value_entries,
        &mut blankets,
        &mut paths,
        &mut values,
        &mut subkeys,
    )
    .expect("materialized response")
    {
        RsiTransactionReplaySnapshotMaterializedResponse::EffectiveValue { result, summary } => {
            assert_eq!(summary.source_value_entries, 2);
            assert_eq!(summary.source_blanket_entries, 0);
            assert_eq!(summary.emitted_values, 1);
            assert_eq!(result.phase, TransactionReplaySnapshotPhase::BeforeCommit);
            assert_eq!(result.operation_index, 1);
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
                TransactionReplayValueWatchScope::NamedValue { name: "Setting" }
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
}

#[test]
fn effective_subkey_payload_materializes_retained_snapshot_result() {
    let retained = record(91, subkey_query(2));
    let mut frame = response_frame(91, RSI_ENUM_CHILDREN);
    frame.extend_from_slice(&3u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Alpha");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, CHILD_GUID, 20);
    push_len_prefixed(&mut frame, b"Beta");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"policy", RSI_PATH_TARGET_GUID, OTHER_GUID, 21);
    push_len_prefixed(&mut frame, b"Alpha");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"policy", RSI_PATH_TARGET_HIDDEN, [0; 16], 22);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let parsed = parsed_response(retained, &frame).expect("parsed response");
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 4];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 3];

    match materialize_transaction_replay_snapshot_response(
        &context(&limits),
        parsed,
        &mut value_entries,
        &mut blankets,
        &mut paths,
        &mut values,
        &mut subkeys,
    )
    .expect("materialized response")
    {
        RsiTransactionReplaySnapshotMaterializedResponse::EffectiveSubkeys { result, summary } => {
            assert_eq!(summary.source_path_entries, 3);
            assert_eq!(summary.emitted_subkeys, 1);
            assert_eq!(result.phase, TransactionReplaySnapshotPhase::AfterCommit);
            assert_eq!(result.operation_index, 2);
            let TransactionReplaySnapshotResultKind::EffectiveSubkeys {
                parent_guid,
                children,
            } = result.kind
            else {
                panic!("unexpected result kind: {:?}", result.kind);
            };
            assert_eq!(parent_guid, PARENT_GUID);
            assert_eq!(
                children,
                &[EnumeratedSubkey {
                    child_name: "Beta",
                    path: ResolvedPathEntry {
                        guid: OTHER_GUID,
                        layer: "policy",
                        precedence: 10,
                        sequence: 21,
                    },
                }],
            );
        }
        other => panic!("unexpected materialized response: {other:?}"),
    }
}

#[test]
fn child_visibility_payload_materializes_retained_snapshot_result() {
    let retained = record(92, child_query(3));
    let mut frame = response_frame(92, RSI_LOOKUP);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, CHILD_GUID, 30);
    push_path_entry(&mut frame, b"policy", RSI_PATH_TARGET_HIDDEN, [0; 16], 31);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let parsed = parsed_response(retained, &frame).expect("parsed response");
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 2];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    match materialize_transaction_replay_snapshot_response(
        &context(&limits),
        parsed,
        &mut value_entries,
        &mut blankets,
        &mut paths,
        &mut values,
        &mut subkeys,
    )
    .expect("materialized response")
    {
        RsiTransactionReplaySnapshotMaterializedResponse::ChildVisibility { result, summary } => {
            assert_eq!(summary.source_path_entries, 2);
            assert_eq!(summary.resolved, None);
            let TransactionReplaySnapshotResultKind::ChildVisibility {
                parent_guid,
                child_name,
                child,
            } = result.kind
            else {
                panic!("unexpected result kind: {:?}", result.kind);
            };
            assert_eq!(parent_guid, PARENT_GUID);
            assert_eq!(child_name, "Child");
            assert_eq!(child, None);
        }
        other => panic!("unexpected materialized response: {other:?}"),
    }
}

#[test]
fn materialization_rejects_too_small_effective_value_result_storage_before_emit() {
    let retained = record(93, value_query(4));
    let mut frame = response_frame(93, RSI_QUERY_VALUES);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"One", b"base", b"one", 40);
    push_value_entry(&mut frame, b"Two", b"base", b"two", 41);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let parsed = parsed_response(retained, &frame).expect("parsed response");
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 2];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    assert_eq!(
        materialize_transaction_replay_snapshot_response(
            &context(&limits),
            parsed,
            &mut value_entries,
            &mut blankets,
            &mut paths,
            &mut values,
            &mut subkeys,
        ),
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "query_values.effective_values",
            required: 2,
            capacity: 1,
        }),
    );
}

#[test]
fn materialization_rejects_corrupt_parsed_variant_query_kind_pair() {
    let query = subkey_query(5);
    let retained = RsiTransactionReplaySnapshotRequestRecord {
        request_id: 94,
        query,
        retained: RsiRetainedRequest {
            request_id: 94,
            op_code: RSI_QUERY_VALUES,
        },
    };
    let mut frame = response_frame(94, RSI_QUERY_VALUES);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_query_values_success_response_payload(&frame, retained.retained)
        .expect("query-values payload");
    let parsed = RsiTransactionReplaySnapshotParsedResponse::EffectiveValue {
        record: retained,
        payload,
    };
    let limits = LcsLimits::default();
    let mut value_entries = [dummy_value_entry(); 1];
    let mut blankets = [dummy_blanket_entry(); 1];
    let mut paths = [dummy_path_entry(); 1];
    let mut values = [dummy_value_result(); 1];
    let mut subkeys = [dummy_subkey_result(); 1];

    assert_eq!(
        materialize_transaction_replay_snapshot_response(
            &context(&limits),
            parsed,
            &mut value_entries,
            &mut blankets,
            &mut paths,
            &mut values,
            &mut subkeys,
        ),
        Err(LcsError::InvalidTransactionMutationLogEntry {
            field: "replay_snapshot.query_kind",
        }),
    );
}
