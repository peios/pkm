use lcs_core::{
    LcsError, LcsLimits, REG_SZ, REG_TOMBSTONE, RSI_OK, RSI_QUERY_VALUES, RsiRetainedRequest,
    parse_rsi_query_values_success_response_payload, rsi_response_op_code,
    validate_rsi_query_values_response_value_payloads,
};

fn response_frame(request_id: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(
        &rsi_response_op_code(RSI_QUERY_VALUES)
            .unwrap()
            .to_le_bytes(),
    );
    frame.extend_from_slice(&RSI_OK.to_le_bytes());
    frame
}

fn push_len_prefixed(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(bytes);
}

fn push_query_value_entry(frame: &mut Vec<u8>, value_type: u32, data: &[u8], sequence: u64) {
    push_len_prefixed(frame, b"Value");
    push_len_prefixed(frame, b"base");
    frame.extend_from_slice(&value_type.to_le_bytes());
    push_len_prefixed(frame, data);
    frame.extend_from_slice(&sequence.to_le_bytes());
}

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

fn parse_frame(
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
fn query_values_value_payloads_accept_normal_values_and_tombstones() {
    let limits = LcsLimits::DEFAULT;
    let mut frame = response_frame(601);
    frame.extend_from_slice(&2u32.to_le_bytes());
    push_query_value_entry(&mut frame, REG_SZ, b"data", 10);
    push_query_value_entry(&mut frame, REG_TOMBSTONE, b"", 11);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_frame(601, &frame);
    validate_rsi_query_values_response_value_payloads(&parsed, &limits).unwrap();
}

#[test]
fn query_values_value_payloads_reject_unknown_types_and_malformed_tombstones() {
    let limits = LcsLimits::DEFAULT;

    let mut unknown = response_frame(602);
    unknown.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut unknown, 0xffff_fffe, b"data", 20);
    unknown.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut unknown);
    let parsed = parse_frame(602, &unknown);
    assert_eq!(
        validate_rsi_query_values_response_value_payloads(&parsed, &limits),
        Err(LcsError::UnknownValueType(0xffff_fffe))
    );

    let mut tombstone_data = response_frame(603);
    tombstone_data.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut tombstone_data, REG_TOMBSTONE, b"not-empty", 21);
    tombstone_data.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut tombstone_data);
    let parsed = parse_frame(603, &tombstone_data);
    assert_eq!(
        validate_rsi_query_values_response_value_payloads(&parsed, &limits),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 9 })
    );
}

#[test]
fn query_values_value_payloads_enforce_configured_value_size_limit() {
    let limits = LcsLimits {
        max_value_size: 3,
        ..LcsLimits::DEFAULT
    };
    let mut frame = response_frame(604);
    frame.extend_from_slice(&1u32.to_le_bytes());
    push_query_value_entry(&mut frame, REG_SZ, b"data", 30);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_frame(604, &frame);
    assert_eq!(
        validate_rsi_query_values_response_value_payloads(&parsed, &limits),
        Err(LcsError::ValueDataTooLarge { len: 4, max: 3 })
    );
}
