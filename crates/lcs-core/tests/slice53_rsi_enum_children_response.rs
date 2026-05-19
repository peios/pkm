use lcs_core::{
    LcsError, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_NOT_FOUND, RSI_OK, RSI_PATH_TARGET_GUID,
    RSI_PATH_TARGET_HIDDEN, RsiKeyMetadataResponseEntry, RsiLengthPrefixedField,
    RsiLookupPathEntry, RsiPathTargetType, RsiRetainedRequest,
    parse_rsi_enum_children_success_response_payload, rsi_response_op_code,
};

fn response_frame(request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

fn push_len_prefixed(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
}

fn push_path_entry(
    frame: &mut Vec<u8>,
    layer_name: &[u8],
    target_type: u8,
    target_guid: &[u8; 16],
    sequence: u64,
) {
    push_len_prefixed(frame, layer_name);
    frame.push(target_type);
    frame.extend_from_slice(target_guid);
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn push_metadata(
    frame: &mut Vec<u8>,
    guid: &[u8; 16],
    sd: &[u8],
    volatile: u8,
    symlink: u8,
    last_write_time: u64,
) {
    frame.extend_from_slice(guid);
    push_len_prefixed(frame, sd);
    frame.push(volatile);
    frame.push(symlink);
    frame.extend_from_slice(&last_write_time.to_le_bytes());
}

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

#[test]
fn enum_children_success_response_parses_children_entries_and_metadata() {
    let alpha_guid = [0x42; 16];
    let mut frame = response_frame(
        201,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Alpha");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &alpha_guid, 700);
    push_len_prefixed(&mut frame, b"Beta");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, b"mask", RSI_PATH_TARGET_HIDDEN, &[0; 16], 701);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame, &alpha_guid, b"alpha-sd", 1, 0, 702);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 201,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();

    assert_eq!(parsed.child_count, 2);
    assert_eq!(parsed.metadata_count, 1);

    let mut children = Vec::new();
    parsed
        .for_each_child(|child| {
            children.push(child);
            Ok(())
        })
        .unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(
        children[0].child_name,
        RsiLengthPrefixedField {
            len: 5,
            data: b"Alpha",
        }
    );
    assert_eq!(children[0].path_entry_count, 1);
    assert_eq!(
        children[1].child_name,
        RsiLengthPrefixedField {
            len: 4,
            data: b"Beta",
        }
    );
    assert_eq!(children[1].path_entry_count, 1);

    let mut alpha_entries = Vec::new();
    children[0]
        .for_each_path_entry(|entry| {
            alpha_entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        alpha_entries,
        vec![RsiLookupPathEntry {
            layer_name: RsiLengthPrefixedField {
                len: 4,
                data: b"base",
            },
            target_type: RsiPathTargetType::Guid,
            target_guid: alpha_guid,
            sequence: 700,
        }]
    );

    let mut beta_entries = Vec::new();
    children[1]
        .for_each_path_entry(|entry| {
            beta_entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        beta_entries,
        vec![RsiLookupPathEntry {
            layer_name: RsiLengthPrefixedField {
                len: 4,
                data: b"mask",
            },
            target_type: RsiPathTargetType::Hidden,
            target_guid: [0; 16],
            sequence: 701,
        }]
    );

    let mut metadata = Vec::new();
    parsed
        .for_each_key_metadata(|entry| {
            metadata.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        metadata,
        vec![RsiKeyMetadataResponseEntry {
            guid: alpha_guid,
            sd: RsiLengthPrefixedField {
                len: 8,
                data: b"alpha-sd",
            },
            volatile: true,
            symlink: false,
            last_write_time: 702,
        }]
    );
}

#[test]
fn enum_children_success_response_accepts_empty_child_and_metadata_sets() {
    let mut frame = response_frame(
        202,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_rsi_enum_children_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 202,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();

    assert_eq!(parsed.child_count, 0);
    assert_eq!(parsed.metadata_count, 0);
    parsed.for_each_child(|_| unreachable!()).unwrap();
    parsed.for_each_key_metadata(|_| unreachable!()).unwrap();
}

#[test]
fn enum_children_success_response_rejects_non_success_status_and_wrong_parser_operation() {
    let mut failed = response_frame(
        203,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_NOT_FOUND,
    );
    finish_total_len(&mut failed);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &failed,
            RsiRetainedRequest {
                request_id: 203,
                op_code: RSI_ENUM_CHILDREN,
            }
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND))
    );

    let mut wrong_op = response_frame(204, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    finish_total_len(&mut wrong_op);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &wrong_op,
            RsiRetainedRequest {
                request_id: 204,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_ENUM_CHILDREN,
            actual: RSI_LOOKUP,
        })
    );
}

#[test]
fn enum_children_success_response_rejects_nested_path_entry_errors() {
    let guid = [0x55; 16];
    let mut bad_type = response_frame(
        205,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    bad_type.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut bad_type, b"BadType");
    bad_type.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut bad_type, b"base", 9, &guid, 800);
    finish_total_len(&mut bad_type);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &bad_type,
            RsiRetainedRequest {
                request_id: 205,
                op_code: RSI_ENUM_CHILDREN,
            }
        ),
        Err(LcsError::InvalidRsiPathTargetType(9))
    );

    let mut bad_hidden = response_frame(
        206,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    bad_hidden.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut bad_hidden, b"BadHidden");
    bad_hidden.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut bad_hidden, b"mask", RSI_PATH_TARGET_HIDDEN, &guid, 801);
    finish_total_len(&mut bad_hidden);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &bad_hidden,
            RsiRetainedRequest {
                request_id: 206,
                op_code: RSI_ENUM_CHILDREN,
            }
        ),
        Err(LcsError::RsiHiddenPathTargetGuidNotZero)
    );
}

#[test]
fn enum_children_success_response_rejects_metadata_boolean_errors_and_extra_bytes() {
    let guid = [0x66; 16];
    let mut bad_bool = response_frame(
        207,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    bad_bool.extend_from_slice(&0u32.to_le_bytes());
    bad_bool.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut bad_bool, &guid, b"sd", 0, 2, 900);
    finish_total_len(&mut bad_bool);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &bad_bool,
            RsiRetainedRequest {
                request_id: 207,
                op_code: RSI_ENUM_CHILDREN,
            }
        ),
        Err(LcsError::InvalidBooleanFlag {
            field: "key_metadata.symlink",
            value: 2,
        })
    );

    let mut extra = response_frame(
        208,
        rsi_response_op_code(RSI_ENUM_CHILDREN).unwrap(),
        RSI_OK,
    );
    extra.extend_from_slice(&0u32.to_le_bytes());
    extra.extend_from_slice(&0u32.to_le_bytes());
    extra.push(0xee);
    finish_total_len(&mut extra);
    assert_eq!(
        parse_rsi_enum_children_success_response_payload(
            &extra,
            RsiRetainedRequest {
                request_id: 208,
                op_code: RSI_ENUM_CHILDREN,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_ENUM_CHILDREN,
            extra_len: 1,
        })
    );
}
