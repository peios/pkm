use lcs_core::{
    BlanketTombstoneEntry, EnumeratedSubkey, EnumeratedValue, Guid, LayerResolutionContext,
    LayerView, LcsError, LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry, PathTarget, REG_SZ,
    RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN,
    RSI_QUERY_VALUES, RegistryValueType, ResolvedPathEntry, RsiRetainedRequest, ValueEntry,
    for_each_rsi_enum_children_effective_subkey_snapshot_entry,
    for_each_rsi_query_values_effective_snapshot_entry,
    parse_rsi_enum_children_success_response_payload, parse_rsi_lookup_success_response_payload,
    parse_rsi_query_values_success_response_payload, resolve_rsi_lookup_child_visibility_snapshot,
    rsi_response_op_code,
};

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

fn response_frame(request_id: u64, op_code: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
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
    value_type: u32,
    data: &[u8],
    sequence: u64,
) {
    push_len_prefixed(frame, value_name);
    push_len_prefixed(frame, layer_name);
    frame.extend_from_slice(&value_type.to_le_bytes());
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

#[test]
fn query_values_snapshot_resolution_emits_effective_values() {
    let mut frame = response_frame(901, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"Setting", b"base", REG_SZ, b"old", 10);
    push_value_entry(&mut frame, b"Setting", b"policy", REG_SZ, b"new", 11);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_query_values_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 901,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .expect("query-values payload");
    let limits = LcsLimits::default();
    let mut value_storage = [dummy_value_entry(); 4];
    let mut blanket_storage = [dummy_blanket_entry(); 2];
    let mut emitted = Vec::new();

    let summary = for_each_rsi_query_values_effective_snapshot_entry(
        &context(&limits),
        &payload,
        &mut value_storage,
        &mut blanket_storage,
        |entry| {
            emitted.push(entry);
            Ok(())
        },
    )
    .expect("effective values");

    assert_eq!(summary.source_value_entries, 2);
    assert_eq!(summary.source_blanket_entries, 0);
    assert_eq!(summary.emitted_values, 1);
    assert_eq!(
        emitted,
        vec![EnumeratedValue {
            name: "Setting",
            value: lcs_core::ResolvedValueEntry {
                value_type: RegistryValueType::Sz,
                data: b"new",
                layer: "policy",
                precedence: 10,
                sequence: 11,
            },
        }],
    );
}

#[test]
fn snapshot_resolution_capacity_failure_happens_before_effective_emit() {
    let mut frame = response_frame(902, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"One", b"base", REG_SZ, b"one", 10);
    push_value_entry(&mut frame, b"Two", b"base", REG_SZ, b"two", 11);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_query_values_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 902,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .expect("query-values payload");
    let limits = LcsLimits::default();
    let mut value_storage = [dummy_value_entry(); 1];
    let mut blanket_storage = [dummy_blanket_entry(); 1];
    let mut emitted = Vec::new();

    assert_eq!(
        for_each_rsi_query_values_effective_snapshot_entry(
            &context(&limits),
            &payload,
            &mut value_storage,
            &mut blanket_storage,
            |entry| {
                emitted.push(entry);
                Ok(())
            },
        ),
        Err(LcsError::TransactionReplaySnapshotStorageFull {
            field: "query_values.value_entries",
            required: 2,
            capacity: 1,
        }),
    );
    assert!(emitted.is_empty());
}

#[test]
fn enum_children_snapshot_resolution_emits_effective_subkeys() {
    let mut frame = response_frame(903, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
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
    let payload = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 903,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .expect("enum-children payload");
    let limits = LcsLimits::default();
    let mut path_storage = [dummy_path_entry(); 4];
    let mut emitted = Vec::new();

    let summary = for_each_rsi_enum_children_effective_subkey_snapshot_entry(
        &context(&limits),
        &payload,
        &mut path_storage,
        |entry| {
            emitted.push(entry);
            Ok(())
        },
    )
    .expect("effective subkeys");

    assert_eq!(summary.source_path_entries, 3);
    assert_eq!(summary.emitted_subkeys, 1);
    assert_eq!(
        emitted,
        vec![EnumeratedSubkey {
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

#[test]
fn lookup_snapshot_resolution_materializes_child_visibility() {
    let mut frame = response_frame(904, rsi_response_op_code(RSI_LOOKUP).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, CHILD_GUID, 30);
    push_path_entry(&mut frame, b"policy", RSI_PATH_TARGET_HIDDEN, [0; 16], 31);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 904,
            op_code: RSI_LOOKUP,
        },
    )
    .expect("lookup payload");
    let limits = LcsLimits::default();
    let mut path_storage = [dummy_path_entry(); 2];

    let snapshot = resolve_rsi_lookup_child_visibility_snapshot(
        &context(&limits),
        &payload,
        "Child",
        &mut path_storage,
    )
    .expect("child visibility");

    assert_eq!(snapshot.source_path_entries, 2);
    assert_eq!(snapshot.path_capacity, 2);
    assert_eq!(snapshot.resolved, None);
}
