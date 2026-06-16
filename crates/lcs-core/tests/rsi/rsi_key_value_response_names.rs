use crate::common::{finish_total_len, push_len_prefixed, response_frame};
use lcs_core::{
    LcsError, LcsLimits, RSI_QUERY_VALUES, RSI_READ_KEY, RsiRetainedRequest,
    parse_rsi_query_values_success_response_payload, parse_rsi_read_key_success_response_payload,
    rsi_response_op_code, validate_rsi_query_values_response_names,
    validate_rsi_read_key_response_names,
};



fn push_read_key_body(frame: &mut Vec<u8>, name: &[u8]) {
    push_len_prefixed(frame, name);
    frame.extend_from_slice(&[0x51; 16]);
    push_len_prefixed(frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1u64.to_le_bytes());
}

fn push_query_value_entry(
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


fn parse_read_key_frame(
    request_id: u64,
    frame: &[u8],
) -> lcs_core::RsiReadKeySuccessResponsePayload<'_> {
    parse_rsi_read_key_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_READ_KEY,
        },
    )
    .unwrap()
}

fn parse_query_values_frame(
    request_id: u64,
    frame: &[u8],
) -> lcs_core::RsiQueryValuesSuccessResponsePayload<'_> {
    parse_rsi_query_values_success_response_payload(
        frame,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap()
}

#[test]
fn read_key_response_names_validate_key_component() {
    let limits = LcsLimits::DEFAULT;
    let mut frame = response_frame(501, rsi_response_op_code(RSI_READ_KEY).unwrap());
    push_read_key_body(&mut frame, b"Child");
    finish_total_len(&mut frame);

    let parsed = parse_read_key_frame(501, &frame);
    validate_rsi_read_key_response_names(&parsed, &limits).unwrap();
}

#[test]
fn read_key_response_names_reject_invalid_key_component() {
    let limits = LcsLimits::DEFAULT;

    let mut separator = response_frame(502, rsi_response_op_code(RSI_READ_KEY).unwrap());
    push_read_key_body(&mut separator, b"bad/child");
    finish_total_len(&mut separator);
    let parsed = parse_read_key_frame(502, &separator);
    assert_eq!(
        validate_rsi_read_key_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let mut empty = response_frame(503, rsi_response_op_code(RSI_READ_KEY).unwrap());
    push_read_key_body(&mut empty, b"");
    finish_total_len(&mut empty);
    let parsed = parse_read_key_frame(503, &empty);
    assert_eq!(
        validate_rsi_read_key_response_names(&parsed, &limits),
        Err(LcsError::EmptyString {
            field: "key_component",
        })
    );
}

#[test]
fn query_values_response_names_validate_value_and_layer_names() {
    let limits = LcsLimits::DEFAULT;
    let mut frame = response_frame(504, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut frame, b"Path\\Like/Value", b"base", 1, b"data", 10);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_blanket(&mut frame, b"policy", 11);
    finish_total_len(&mut frame);

    let parsed = parse_query_values_frame(504, &frame);
    validate_rsi_query_values_response_names(&parsed, &limits).unwrap();
}

#[test]
fn query_values_response_names_reject_invalid_value_and_layer_names() {
    let limits = LcsLimits::DEFAULT;

    let mut bad_value = response_frame(505, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    bad_value.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut bad_value, b"bad\0value", b"base", 1, b"data", 20);
    bad_value.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut bad_value);
    let parsed = parse_query_values_frame(505, &bad_value);
    assert_eq!(
        validate_rsi_query_values_response_names(&parsed, &limits),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );

    let mut bad_entry_layer = response_frame(506, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    bad_entry_layer.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut bad_entry_layer, b"Value", b"bad/layer", 1, b"data", 21);
    bad_entry_layer.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut bad_entry_layer);
    let parsed = parse_query_values_frame(506, &bad_entry_layer);
    assert_eq!(
        validate_rsi_query_values_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    let mut bad_blanket_layer =
        response_frame(507, rsi_response_op_code(RSI_QUERY_VALUES).unwrap());
    bad_blanket_layer.extend_from_slice(&0u32.to_le_bytes());
    bad_blanket_layer.extend_from_slice(&1u32.to_le_bytes());
    push_blanket(&mut bad_blanket_layer, b"bad\\layer", 22);
    finish_total_len(&mut bad_blanket_layer);
    let parsed = parse_query_values_frame(507, &bad_blanket_layer);
    assert_eq!(
        validate_rsi_query_values_response_names(&parsed, &limits),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
