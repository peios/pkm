use lcs_core::{
    LcsError, RSI_CREATE_KEY, RSI_INVALID, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN, RSI_NOT_FOUND, RSI_OK,
    RSI_REQUEST_HEADER_LEN, RSI_RESPONSE_BIT, RsiRequestHeader, RsiRequestIdCounter,
    RsiResponseHeader, RsiRetainedRequest, RsiStatus, RsiValidatedResponse,
    parse_rsi_request_header, parse_rsi_response_header, rsi_response_op_code,
    validate_rsi_request_op_code, validate_rsi_response_for_request,
};

fn request_frame(total_len: u32, request_id: u64, op_code: u16, txn_id: u64) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&txn_id.to_le_bytes());
    frame
}

fn response_frame(total_len: u32, request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

#[test]
fn rsi_request_headers_are_fixed_size_little_endian_and_validate_opcodes() {
    let frame = request_frame(
        RSI_REQUEST_HEADER_LEN as u32,
        0x0807_0605_0403_0201,
        RSI_LOOKUP,
        0x1817_1615_1413_1211,
    );

    assert_eq!(
        parse_rsi_request_header(&frame),
        Ok(RsiRequestHeader {
            total_len: RSI_REQUEST_HEADER_LEN as u32,
            request_id: 0x0807_0605_0403_0201,
            op_code: RSI_LOOKUP,
            txn_id: 0x1817_1615_1413_1211,
        })
    );
    assert_eq!(
        validate_rsi_request_op_code(RSI_CREATE_KEY),
        Ok(RSI_CREATE_KEY)
    );
}

#[test]
fn rsi_request_header_rejects_short_mismatched_and_response_op_frames() {
    assert_eq!(
        parse_rsi_request_header(&[0; RSI_REQUEST_HEADER_LEN - 1]),
        Err(LcsError::RsiMessageTooShort {
            len: RSI_REQUEST_HEADER_LEN - 1,
            min: RSI_REQUEST_HEADER_LEN,
        })
    );

    let frame = request_frame(99, 7, RSI_LOOKUP, 0);
    assert_eq!(
        parse_rsi_request_header(&frame),
        Err(LcsError::RsiMessageLengthMismatch {
            total_len: 99,
            actual_len: RSI_REQUEST_HEADER_LEN,
        })
    );

    let frame = request_frame(
        RSI_REQUEST_HEADER_LEN as u32,
        7,
        RSI_LOOKUP | RSI_RESPONSE_BIT,
        0,
    );
    assert_eq!(
        parse_rsi_request_header(&frame),
        Err(LcsError::UnknownRsiOpcode(RSI_LOOKUP | RSI_RESPONSE_BIT))
    );
}

#[test]
fn rsi_request_ids_are_monotonic_per_source_connection() {
    let mut counter = RsiRequestIdCounter::new();
    assert_eq!(counter.allocate(), Ok(0));
    assert_eq!(counter.allocate(), Ok(1));
    assert_eq!(counter.next_request_id(), 2);

    let mut exhausted = RsiRequestIdCounter::from_next_request_id(u64::MAX);
    assert_eq!(exhausted.allocate(), Err(LcsError::RsiRequestIdOverflow));
}

#[test]
fn rsi_response_headers_are_fixed_size_and_status_is_first_payload_field() {
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        44,
        rsi_response_op_code(RSI_LOOKUP).unwrap(),
        RSI_NOT_FOUND,
    );
    let retained = RsiRetainedRequest {
        request_id: 44,
        op_code: RSI_LOOKUP,
    };

    assert_eq!(
        parse_rsi_response_header(&frame),
        Ok(RsiResponseHeader {
            total_len: RSI_MIN_RESPONSE_LEN as u32,
            request_id: 44,
            op_code: RSI_LOOKUP | RSI_RESPONSE_BIT,
        })
    );
    assert_eq!(
        validate_rsi_response_for_request(&frame, retained),
        Ok(RsiValidatedResponse {
            header: RsiResponseHeader {
                total_len: RSI_MIN_RESPONSE_LEN as u32,
                request_id: 44,
                op_code: RSI_LOOKUP | RSI_RESPONSE_BIT,
            },
            status: RsiStatus::NotFound,
        })
    );
}

#[test]
fn rsi_response_validation_rejects_short_id_opcode_and_unknown_status() {
    let retained = RsiRetainedRequest {
        request_id: 44,
        op_code: RSI_LOOKUP,
    };

    let short = vec![0; RSI_MIN_RESPONSE_LEN - 1];
    assert_eq!(
        validate_rsi_response_for_request(&short, retained),
        Err(LcsError::RsiMessageTooShort {
            len: RSI_MIN_RESPONSE_LEN - 1,
            min: RSI_MIN_RESPONSE_LEN,
        })
    );

    let wrong_id = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        45,
        rsi_response_op_code(RSI_LOOKUP).unwrap(),
        RSI_OK,
    );
    assert_eq!(
        validate_rsi_response_for_request(&wrong_id, retained),
        Err(LcsError::RsiRequestIdMismatch {
            expected: 44,
            actual: 45,
        })
    );

    let wrong_opcode = response_frame(RSI_MIN_RESPONSE_LEN as u32, 44, RSI_LOOKUP, RSI_OK);
    assert_eq!(
        validate_rsi_response_for_request(&wrong_opcode, retained),
        Err(LcsError::RsiResponseOpcodeMismatch {
            expected: RSI_LOOKUP | RSI_RESPONSE_BIT,
            actual: RSI_LOOKUP,
        })
    );

    let unknown_status = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        44,
        rsi_response_op_code(RSI_LOOKUP).unwrap(),
        RSI_INVALID + 3,
    );
    assert_eq!(
        validate_rsi_response_for_request(&unknown_status, retained),
        Err(LcsError::UnknownRsiStatus(RSI_INVALID + 3))
    );
}

#[test]
fn response_opcode_helper_rejects_unknown_request_opcodes() {
    assert_eq!(
        rsi_response_op_code(RSI_LOOKUP),
        Ok(RSI_LOOKUP | RSI_RESPONSE_BIT)
    );
    assert_eq!(
        rsi_response_op_code(0x7777),
        Err(LcsError::UnknownRsiOpcode(0x7777))
    );
}
