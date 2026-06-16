use crate::common::{finish_total_len, push_len_prefixed, response_frame};
use lcs_core::{
    BlanketTombstoneEntry, Guid, LcsError, LcsLimits, NamedPathEntry, NamedValueEntry, PathEntry,
    PathTarget, REG_BINARY, REG_SZ, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_PATH_TARGET_GUID,
    RSI_PATH_TARGET_HIDDEN, RSI_QUERY_VALUES, RsiRetainedRequest, ValueEntry,
    for_each_rsi_enum_children_source_path_entry, for_each_rsi_lookup_source_path_entry,
    for_each_rsi_query_values_source_blanket_entry, for_each_rsi_query_values_source_value_entry,
    parse_rsi_enum_children_success_response_payload, parse_rsi_lookup_success_response_payload,
    parse_rsi_query_values_success_response_payload, rsi_response_op_code,
};

const CHILD_GUID: Guid = [0x30; 16];



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

fn push_blanket(frame: &mut Vec<u8>, layer_name: &[u8], sequence: u64) {
    push_len_prefixed(frame, layer_name);
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


fn query_values_payload(
    frame: &[u8],
    request_id: u64,
) -> lcs_core::RsiQueryValuesSuccessResponsePayload<'_> {
    parse_rsi_query_values_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .expect("query-values payload")
}

#[test]
fn query_values_snapshot_response_projects_value_and_blanket_resolution_entries() {
    let mut frame = response_frame(801, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"Alpha", b"base", REG_SZ, b"one", 10);
    push_value_entry(&mut frame, b"Beta", b"policy", REG_BINARY, b"\x01\x02", 11);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_blanket(&mut frame, b"mask", 12);
    finish_total_len(&mut frame);
    let payload = query_values_payload(&frame, 801);

    let mut values = Vec::new();
    assert_eq!(
        for_each_rsi_query_values_source_value_entry(&payload, &LcsLimits::default(), |entry| {
            values.push(entry);
            Ok(())
        },),
        Ok(2),
    );
    assert_eq!(
        values,
        vec![
            NamedValueEntry {
                name: "Alpha",
                entry: ValueEntry {
                    layer: "base",
                    sequence: 10,
                    value_type: REG_SZ,
                    data: b"one",
                },
            },
            NamedValueEntry {
                name: "Beta",
                entry: ValueEntry {
                    layer: "policy",
                    sequence: 11,
                    value_type: REG_BINARY,
                    data: b"\x01\x02",
                },
            },
        ],
    );

    let mut blankets = Vec::new();
    assert_eq!(
        for_each_rsi_query_values_source_blanket_entry(&payload, &LcsLimits::default(), |entry| {
            blankets.push(entry);
            Ok(())
        },),
        Ok(1),
    );
    assert_eq!(
        blankets,
        vec![BlanketTombstoneEntry {
            layer: "mask",
            sequence: 12,
        }],
    );
}

#[test]
fn lookup_snapshot_response_projects_queried_child_path_entries() {
    let mut frame = response_frame(802, rsi_response_op_code(RSI_LOOKUP).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, CHILD_GUID, 20);
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, [0; 16], 21);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 802,
            op_code: RSI_LOOKUP,
        },
    )
    .expect("lookup payload");

    let mut entries = Vec::new();
    assert_eq!(
        for_each_rsi_lookup_source_path_entry(&payload, &LcsLimits::default(), "Child", |entry| {
            entries.push(entry);
            Ok(())
        },),
        Ok(2),
    );
    assert_eq!(
        entries,
        vec![
            NamedPathEntry {
                child_name: "Child",
                entry: PathEntry {
                    layer: "base",
                    sequence: 20,
                    target: PathTarget::Guid(CHILD_GUID),
                },
            },
            NamedPathEntry {
                child_name: "Child",
                entry: PathEntry {
                    layer: "mask",
                    sequence: 21,
                    target: PathTarget::Hidden,
                },
            },
        ],
    );
}

#[test]
fn enum_children_snapshot_response_projects_flattened_child_path_entries() {
    let mut frame = response_frame(803, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Alpha");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, CHILD_GUID, 30);
    push_len_prefixed(&mut frame, b"Beta");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, [0; 16], 31);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 803,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .expect("enum-children payload");

    let mut entries = Vec::new();
    assert_eq!(
        for_each_rsi_enum_children_source_path_entry(&payload, &LcsLimits::default(), |entry| {
            entries.push(entry);
            Ok(())
        },),
        Ok(2),
    );
    assert_eq!(
        entries,
        vec![
            NamedPathEntry {
                child_name: "Alpha",
                entry: PathEntry {
                    layer: "base",
                    sequence: 30,
                    target: PathTarget::Guid(CHILD_GUID),
                },
            },
            NamedPathEntry {
                child_name: "Beta",
                entry: PathEntry {
                    layer: "mask",
                    sequence: 31,
                    target: PathTarget::Hidden,
                },
            },
        ],
    );
}

#[test]
fn snapshot_response_projection_fails_before_emitting_invalid_names() {
    let mut frame = response_frame(804, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_value_entry(&mut frame, b"Bad\0Name", b"base", REG_SZ, b"one", 40);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);
    let payload = query_values_payload(&frame, 804);
    let mut values = Vec::new();

    assert_eq!(
        for_each_rsi_query_values_source_value_entry(&payload, &LcsLimits::default(), |entry| {
            values.push(entry);
            Ok(())
        },),
        Err(LcsError::NullByte {
            field: "value_name",
        }),
    );
    assert!(values.is_empty());
}
