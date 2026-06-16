use crate::common::{finish_total_len, push_len_prefixed};
use lcs_core::{
    LcsError, REG_SZ, RSI_ENUM_CHILDREN, RSI_LOOKUP, RSI_OK, RSI_PATH_TARGET_GUID,
    RSI_QUERY_VALUES, RsiRetainedRequest, parse_rsi_enum_children_success_response_payload,
    parse_rsi_lookup_success_response_payload, parse_rsi_query_values_success_response_payload,
    rsi_response_op_code, validate_rsi_enum_children_path_response_sequences,
    validate_rsi_lookup_path_response_sequences, validate_rsi_query_values_response_sequences,
};

fn response_frame(request_id: u64, request_op_code: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&rsi_response_op_code(request_op_code).unwrap().to_le_bytes());
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}


fn push_path_entry(frame: &mut Vec<u8>, sequence: u64) {
    push_len_prefixed(frame, b"base");
    frame.push(RSI_PATH_TARGET_GUID);
    frame.extend_from_slice(&[0x11; 16]);
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn push_query_value_entry(frame: &mut Vec<u8>, sequence: u64) {
    push_len_prefixed(frame, b"Value");
    push_len_prefixed(frame, b"base");
    frame.extend_from_slice(&REG_SZ.to_le_bytes());
    push_len_prefixed(frame, b"data");
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn push_blanket_entry(frame: &mut Vec<u8>, sequence: u64) {
    push_len_prefixed(frame, b"base");
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn push_metadata(frame: &mut Vec<u8>) {
    frame.extend_from_slice(&[0x11; 16]);
    push_len_prefixed(frame, b"sd");
    frame.push(0);
    frame.push(0);
    frame.extend_from_slice(&1000u64.to_le_bytes());
}


fn lookup_frame(request_id: u64, sequence: u64) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_LOOKUP);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, sequence);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame);
    finish_total_len(&mut frame);
    frame
}

fn enum_children_frame(request_id: u64, sequence: u64) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_ENUM_CHILDREN);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_len_prefixed(&mut frame, b"Child");
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_path_entry(&mut frame, sequence);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_metadata(&mut frame);
    finish_total_len(&mut frame);
    frame
}

fn query_values_frame(request_id: u64, value_sequence: u64, blanket_sequence: u64) -> Vec<u8> {
    let mut frame = response_frame(request_id, RSI_QUERY_VALUES);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut frame, value_sequence);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_blanket_entry(&mut frame, blanket_sequence);
    finish_total_len(&mut frame);
    frame
}

#[test]
fn rsi_response_sequence_validation_accepts_past_entries() {
    let lookup = lookup_frame(901, 99);
    let parsed_lookup = parse_rsi_lookup_success_response_payload(
        &lookup,
        RsiRetainedRequest {
            request_id: 901,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();
    validate_rsi_lookup_path_response_sequences(&parsed_lookup, 100).unwrap();

    let enum_children = enum_children_frame(902, 98);
    let parsed_enum = parse_rsi_enum_children_success_response_payload(
        &enum_children,
        RsiRetainedRequest {
            request_id: 902,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();
    validate_rsi_enum_children_path_response_sequences(&parsed_enum, 100).unwrap();

    let query_values = query_values_frame(903, 97, 96);
    let parsed_values = parse_rsi_query_values_success_response_payload(
        &query_values,
        RsiRetainedRequest {
            request_id: 903,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();
    validate_rsi_query_values_response_sequences(&parsed_values, 100).unwrap();
}

#[test]
fn rsi_path_response_sequence_validation_rejects_current_or_future_entries() {
    let lookup = lookup_frame(904, 100);
    let parsed_lookup = parse_rsi_lookup_success_response_payload(
        &lookup,
        RsiRetainedRequest {
            request_id: 904,
            op_code: RSI_LOOKUP,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_lookup_path_response_sequences(&parsed_lookup, 100),
        Err(LcsError::FutureSequence {
            sequence: 100,
            next_sequence: 100,
        })
    );

    let enum_children = enum_children_frame(905, 101);
    let parsed_enum = parse_rsi_enum_children_success_response_payload(
        &enum_children,
        RsiRetainedRequest {
            request_id: 905,
            op_code: RSI_ENUM_CHILDREN,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_enum_children_path_response_sequences(&parsed_enum, 100),
        Err(LcsError::FutureSequence {
            sequence: 101,
            next_sequence: 100,
        })
    );
}

#[test]
fn rsi_query_values_sequence_validation_rejects_future_values_and_blankets() {
    let value_future = query_values_frame(906, 100, 99);
    let parsed = parse_rsi_query_values_success_response_payload(
        &value_future,
        RsiRetainedRequest {
            request_id: 906,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_query_values_response_sequences(&parsed, 100),
        Err(LcsError::FutureSequence {
            sequence: 100,
            next_sequence: 100,
        })
    );

    let blanket_future = query_values_frame(907, 99, 100);
    let parsed = parse_rsi_query_values_success_response_payload(
        &blanket_future,
        RsiRetainedRequest {
            request_id: 907,
            op_code: RSI_QUERY_VALUES,
        },
    )
    .unwrap();
    assert_eq!(
        validate_rsi_query_values_response_sequences(&parsed, 100),
        Err(LcsError::FutureSequence {
            sequence: 100,
            next_sequence: 100,
        })
    );
}
