use crate::common::{finish_total_len, push_len_prefixed};
use lcs_core::{
    LcsError, REG_BINARY, REG_SZ, RSI_NOT_FOUND, RSI_OK, RSI_QUERY_VALUES, RSI_READ_KEY,
    RsiLengthPrefixedField, RsiQueryValueResponseEntry, RsiQueryValuesBlanketResponseEntry,
    RsiRetainedRequest, parse_rsi_query_values_success_response_payload, rsi_response_op_code,
};

fn response_frame(request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
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

fn push_blanket(frame: &mut Vec<u8>, layer_name: &[u8], sequence: u64) {
    push_len_prefixed(frame, layer_name);
    frame.extend_from_slice(&sequence.to_le_bytes());
}


#[test]
fn query_values_success_response_parses_value_entries_and_blankets() {
    let mut frame = response_frame(91, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_value_entry(&mut frame, b"Alpha", b"base", REG_SZ, b"one", 10);
    push_value_entry(&mut frame, b"Beta", b"feature", REG_BINARY, b"\x01\x02", 11);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_blanket(&mut frame, b"mask", 12);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_query_values_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 91,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();

    assert_eq!(parsed.entry_count, 2);
    assert_eq!(parsed.blanket_count, 1);

    let mut entries = Vec::new();
    parsed
        .for_each_value_entry(|entry| {
            entries.push(entry);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        entries,
        vec![
            RsiQueryValueResponseEntry {
                value_name: RsiLengthPrefixedField {
                    len: 5,
                    data: b"Alpha",
                },
                layer_name: RsiLengthPrefixedField {
                    len: 4,
                    data: b"base",
                },
                value_type: REG_SZ,
                data: RsiLengthPrefixedField {
                    len: 3,
                    data: b"one",
                },
                sequence: 10,
            },
            RsiQueryValueResponseEntry {
                value_name: RsiLengthPrefixedField {
                    len: 4,
                    data: b"Beta",
                },
                layer_name: RsiLengthPrefixedField {
                    len: 7,
                    data: b"feature",
                },
                value_type: REG_BINARY,
                data: RsiLengthPrefixedField {
                    len: 2,
                    data: b"\x01\x02",
                },
                sequence: 11,
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
        vec![RsiQueryValuesBlanketResponseEntry {
            layer_name: RsiLengthPrefixedField {
                len: 4,
                data: b"mask",
            },
            sequence: 12,
        }]
    );
}

#[test]
fn query_values_success_response_accepts_empty_entry_and_blanket_sets() {
    let mut frame = response_frame(92, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_rsi_query_values_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 92,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();

    assert_eq!(parsed.entry_count, 0);
    assert_eq!(parsed.blanket_count, 0);
    parsed.for_each_value_entry(|_| unreachable!()).unwrap();
    parsed.for_each_blanket_entry(|_| unreachable!()).unwrap();
}

#[test]
fn query_values_success_response_rejects_non_success_status_and_wrong_parser_operation() {
    let mut failed = response_frame(
        93,
        rsi_response_op_code(RSI_QUERY_VALUES).unwrap(),
        RSI_NOT_FOUND,
    );
    finish_total_len(&mut failed);
    assert_eq!(
        parse_rsi_query_values_success_response_payload(
            &failed,
            RsiRetainedRequest {
                request_id: 93,
                op_code: RSI_QUERY_VALUES,
            }
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND))
    );

    let mut wrong_op = response_frame(94, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    finish_total_len(&mut wrong_op);
    assert_eq!(
        parse_rsi_query_values_success_response_payload(
            &wrong_op,
            RsiRetainedRequest {
                request_id: 94,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_QUERY_VALUES,
            actual: RSI_READ_KEY,
        })
    );
}

#[test]
fn query_values_success_response_rejects_truncated_entries_and_missing_blanket_count() {
    let mut missing_blanket_count =
        response_frame(95, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    missing_blanket_count.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut missing_blanket_count);
    assert_eq!(
        parse_rsi_query_values_success_response_payload(
            &missing_blanket_count,
            RsiRetainedRequest {
                request_id: 95,
                op_code: RSI_QUERY_VALUES,
            }
        ),
        Err(LcsError::RsiMessageTooShort { len: 4, min: 8 })
    );

    let mut truncated_entry =
        response_frame(96, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    truncated_entry.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut truncated_entry, b"Name");
    finish_total_len(&mut truncated_entry);
    assert_eq!(
        parse_rsi_query_values_success_response_payload(
            &truncated_entry,
            RsiRetainedRequest {
                request_id: 96,
                op_code: RSI_QUERY_VALUES,
            }
        ),
        Err(LcsError::RsiMessageTooShort { len: 12, min: 16 })
    );
}

#[test]
fn query_values_success_response_rejects_extra_response_bytes() {
    let mut frame = response_frame(97, rsi_response_op_code(RSI_QUERY_VALUES).unwrap(), RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.push(0xee);
    finish_total_len(&mut frame);

    assert_eq!(
        parse_rsi_query_values_success_response_payload(
            &frame,
            RsiRetainedRequest {
                request_id: 97,
                op_code: RSI_QUERY_VALUES,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_QUERY_VALUES,
            extra_len: 1,
        })
    );
}
