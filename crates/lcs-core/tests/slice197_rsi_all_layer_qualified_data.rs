use lcs_core::{
    REG_BINARY, REG_SZ, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_PATH_TARGET_GUID,
    RSI_PATH_TARGET_HIDDEN, RSI_QUERY_VALUES, RSI_REQUEST_HEADER_LEN, RsiLengthPrefixedField,
    RsiLookupPathEntry, RsiPathTargetType, RsiQueryValueResponseEntry,
    RsiQueryValuesBlanketResponseEntry, RsiRetainedRequest,
    parse_rsi_enum_children_success_response_payload, parse_rsi_lookup_request_payload,
    parse_rsi_lookup_success_response_payload, parse_rsi_query_values_request_payload,
    parse_rsi_query_values_success_response_payload, parse_rsi_request_header,
    rsi_response_op_code, write_rsi_enum_children_request_frame, write_rsi_lookup_request_frame,
    write_rsi_query_values_request_frame,
};

const PARENT_GUID: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KEY_GUID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const USER_GUID: [u8; 16] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

fn field(data: &[u8]) -> RsiLengthPrefixedField<'_> {
    RsiLengthPrefixedField {
        len: data.len() as u32,
        data,
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

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

fn push_len_prefixed(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
}

fn push_path_entry(frame: &mut Vec<u8>, layer: &[u8], target_type: u8, guid: &[u8; 16], seq: u64) {
    push_len_prefixed(frame, layer);
    frame.push(target_type);
    frame.extend_from_slice(guid);
    frame.extend_from_slice(&seq.to_le_bytes());
}

fn push_metadata(frame: &mut Vec<u8>, guid: &[u8; 16]) {
    frame.extend_from_slice(guid);
    push_len_prefixed(frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&0u64.to_le_bytes());
}

fn push_value_entry(
    frame: &mut Vec<u8>,
    value_name: &[u8],
    layer: &[u8],
    value_type: u32,
    data: &[u8],
    seq: u64,
) {
    push_len_prefixed(frame, value_name);
    push_len_prefixed(frame, layer);
    frame.extend_from_slice(&value_type.to_le_bytes());
    push_len_prefixed(frame, data);
    frame.extend_from_slice(&seq.to_le_bytes());
}

fn push_blanket(frame: &mut Vec<u8>, layer: &[u8], seq: u64) {
    push_len_prefixed(frame, layer);
    frame.extend_from_slice(&seq.to_le_bytes());
}

#[test]
fn layer_qualified_read_requests_do_not_include_layer_filters() {
    let mut lookup = [0xcc; 96];
    let built =
        write_rsi_lookup_request_frame(&mut lookup, 7001, 11, PARENT_GUID, b"Child").unwrap();
    let header = parse_rsi_request_header(&lookup[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_LOOKUP);
    let payload =
        parse_rsi_lookup_request_payload(&lookup[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.child_name, field(b"Child"));
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut enum_children = [0xcc; 64];
    let built =
        write_rsi_enum_children_request_frame(&mut enum_children, 7002, 12, PARENT_GUID).unwrap();
    let header = parse_rsi_request_header(&enum_children[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_ENUM_CHILDREN);
    assert_eq!(built.len, RSI_REQUEST_HEADER_LEN + 16);

    let mut query_one = [0xcc; 96];
    let built =
        write_rsi_query_values_request_frame(&mut query_one, 7003, 13, KEY_GUID, b"Value", false)
            .unwrap();
    let header = parse_rsi_request_header(&query_one[..built.len]).unwrap();
    assert_eq!(header.op_code, RSI_QUERY_VALUES);
    let payload =
        parse_rsi_query_values_request_payload(&query_one[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b"Value"));
    assert!(!payload.query_all);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);

    let mut query_all = [0xcc; 96];
    let built = write_rsi_query_values_request_frame(&mut query_all, 7004, 14, KEY_GUID, b"", true)
        .unwrap();
    let payload =
        parse_rsi_query_values_request_payload(&query_all[RSI_REQUEST_HEADER_LEN..built.len])
            .unwrap();
    assert_eq!(payload.guid, KEY_GUID);
    assert_eq!(payload.value_name, field(b""));
    assert!(payload.query_all);
    assert_eq!(payload.trailing.ignored_trailing_len, 0);
}

#[test]
fn lookup_response_preserves_every_returned_layer_entry() {
    let mut frame = response_frame(7010, rsi_response_op_code(RSI_LOOKUP).unwrap());
    frame.extend_from_slice(&3u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &KEY_GUID, 10);
    push_path_entry(&mut frame, b"user", RSI_PATH_TARGET_GUID, &USER_GUID, 11);
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, &[0; 16], 12);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_metadata(&mut frame, &KEY_GUID);
    push_metadata(&mut frame, &USER_GUID);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 7010,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();

    let mut entries = Vec::new();
    parsed
        .for_each_path_entry(|entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        entries,
        vec![
            RsiLookupPathEntry {
                layer_name: field(b"base"),
                target_type: RsiPathTargetType::Guid,
                target_guid: KEY_GUID,
                sequence: 10,
            },
            RsiLookupPathEntry {
                layer_name: field(b"user"),
                target_type: RsiPathTargetType::Guid,
                target_guid: USER_GUID,
                sequence: 11,
            },
            RsiLookupPathEntry {
                layer_name: field(b"mask"),
                target_type: RsiPathTargetType::Hidden,
                target_guid: [0; 16],
                sequence: 12,
            },
        ]
    );
}

#[test]
fn enum_children_response_preserves_all_layers_per_child() {
    let mut frame = response_frame(7020, rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Child");
    frame.extend_from_slice(&3u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &KEY_GUID, 20);
    push_path_entry(&mut frame, b"user", RSI_PATH_TARGET_GUID, &USER_GUID, 21);
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, &[0; 16], 22);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_metadata(&mut frame, &KEY_GUID);
    push_metadata(&mut frame, &USER_GUID);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 7020,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();

    let mut children = Vec::new();
    parsed
        .for_each_child(|child| {
            children.push(child);
            Ok(())
        })
        .unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].child_name, field(b"Child"));

    let mut entries = Vec::new();
    children[0]
        .for_each_path_entry(|entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].layer_name, field(b"base"));
    assert_eq!(entries[1].layer_name, field(b"user"));
    assert_eq!(entries[2].layer_name, field(b"mask"));
}

#[test]
fn query_values_response_preserves_all_value_and_blanket_layers() {
    let mut frame = response_frame(7030, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&3u32.to_le_bytes());
    push_value_entry(&mut frame, b"Value", b"base", REG_SZ, b"base-data", 30);
    push_value_entry(&mut frame, b"Value", b"user", REG_BINARY, b"user-data", 31);
    push_value_entry(&mut frame, b"Other", b"policy", REG_SZ, b"other-data", 32);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_blanket(&mut frame, b"base", 33);
    push_blanket(&mut frame, b"user", 34);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_query_values_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 7030,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();

    let mut values = Vec::new();
    parsed
        .for_each_value_entry(|entry| {
            values.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        values,
        vec![
            RsiQueryValueResponseEntry {
                value_name: field(b"Value"),
                layer_name: field(b"base"),
                value_type: REG_SZ,
                data: field(b"base-data"),
                sequence: 30,
            },
            RsiQueryValueResponseEntry {
                value_name: field(b"Value"),
                layer_name: field(b"user"),
                value_type: REG_BINARY,
                data: field(b"user-data"),
                sequence: 31,
            },
            RsiQueryValueResponseEntry {
                value_name: field(b"Other"),
                layer_name: field(b"policy"),
                value_type: REG_SZ,
                data: field(b"other-data"),
                sequence: 32,
            },
        ]
    );

    let mut blankets = Vec::new();
    parsed
        .for_each_blanket_entry(|entry| {
            blankets.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        blankets,
        vec![
            RsiQueryValuesBlanketResponseEntry {
                layer_name: field(b"base"),
                sequence: 33,
            },
            RsiQueryValuesBlanketResponseEntry {
                layer_name: field(b"user"),
                sequence: 34,
            },
        ]
    );
}
