use lcs_core::{
    LcsError, RSI_LOOKUP, RSI_NOT_FOUND, RSI_OK, RSI_PATH_TARGET_GUID, RSI_PATH_TARGET_HIDDEN,
    RSI_QUERY_VALUES, RsiKeyMetadataResponseEntry, RsiLengthPrefixedField, RsiLookupPathEntry,
    RsiPathTargetType, RsiRetainedRequest, parse_rsi_lookup_success_response_payload,
    rsi_response_op_code,
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
fn lookup_success_response_parses_entries_and_metadata() {
    let guid = [0x21; 16];
    let hidden_guid = [0; 16];
    let mut frame = response_frame(101, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_path_entry(&mut frame, b"base", RSI_PATH_TARGET_GUID, &guid, 20);
    push_path_entry(
        &mut frame,
        b"mask",
        RSI_PATH_TARGET_HIDDEN,
        &hidden_guid,
        21,
    );
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame, &guid, b"sd", 1, 0, 22);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 101,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();

    assert_eq!(parsed.entry_count, 2);
    assert_eq!(parsed.metadata_count, 1);

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
                layer_name: RsiLengthPrefixedField {
                    len: 4,
                    data: b"base",
                },
                target_type: RsiPathTargetType::Guid,
                target_guid: guid,
                sequence: 20,
            },
            RsiLookupPathEntry {
                layer_name: RsiLengthPrefixedField {
                    len: 4,
                    data: b"mask",
                },
                target_type: RsiPathTargetType::Hidden,
                target_guid: [0; 16],
                sequence: 21,
            },
        ]
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
            guid,
            sd: RsiLengthPrefixedField {
                len: 2,
                data: b"sd",
            },
            volatile: true,
            symlink: false,
            last_write_time: 22,
        }]
    );
}

#[test]
fn lookup_success_response_accepts_empty_entry_and_metadata_sets() {
    let mut frame = response_frame(102, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_rsi_lookup_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 102,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();

    assert_eq!(parsed.entry_count, 0);
    assert_eq!(parsed.metadata_count, 0);
    parsed.for_each_path_entry(|_| unreachable!()).unwrap();
    parsed.for_each_key_metadata(|_| unreachable!()).unwrap();
}

#[test]
fn lookup_success_response_rejects_non_success_status_and_wrong_parser_operation() {
    let mut failed = response_frame(
        103,
        rsi_response_op_code(RSI_LOOKUP).unwrap(),
        RSI_NOT_FOUND,
    );
    finish_total_len(&mut failed);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &failed,
            RsiRetainedRequest {
                request_id: 103,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND))
    );

    let mut wrong_op = response_frame(104, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    finish_total_len(&mut wrong_op);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &wrong_op,
            RsiRetainedRequest {
                request_id: 104,
                op_code: RSI_QUERY_VALUES,
            }
        ),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_LOOKUP,
            actual: RSI_QUERY_VALUES,
        })
    );
}

#[test]
fn lookup_success_response_rejects_invalid_target_type_and_hidden_guid_shape() {
    let guid = [0x22; 16];
    let mut bad_type = response_frame(105, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    bad_type.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut bad_type, b"base", 9, &guid, 30);
    finish_total_len(&mut bad_type);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &bad_type,
            RsiRetainedRequest {
                request_id: 105,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::InvalidRsiPathTargetType(9))
    );

    let mut bad_hidden = response_frame(106, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    bad_hidden.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut bad_hidden, b"mask", RSI_PATH_TARGET_HIDDEN, &guid, 31);
    finish_total_len(&mut bad_hidden);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &bad_hidden,
            RsiRetainedRequest {
                request_id: 106,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::RsiHiddenPathTargetGuidNotZero)
    );
}

#[test]
fn lookup_success_response_rejects_metadata_boolean_errors_and_extra_bytes() {
    let guid = [0x33; 16];
    let mut bad_bool = response_frame(107, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    bad_bool.extend_from_slice(&0u32.to_le_bytes());
    bad_bool.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut bad_bool, &guid, b"sd", 2, 0, 40);
    finish_total_len(&mut bad_bool);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &bad_bool,
            RsiRetainedRequest {
                request_id: 107,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::InvalidBooleanFlag {
            field: "key_metadata.volatile",
            value: 2,
        })
    );

    let mut extra = response_frame(108, rsi_response_op_code(RSI_LOOKUP).unwrap(), RSI_OK);
    extra.extend_from_slice(&0u32.to_le_bytes());
    extra.extend_from_slice(&0u32.to_le_bytes());
    extra.push(0xee);
    finish_total_len(&mut extra);
    assert_eq!(
        parse_rsi_lookup_success_response_payload(
            &extra,
            RsiRetainedRequest {
                request_id: 108,
                op_code: RSI_LOOKUP,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_LOOKUP,
            extra_len: 1,
        })
    );
}
