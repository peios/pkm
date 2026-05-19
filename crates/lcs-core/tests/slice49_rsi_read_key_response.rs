use lcs_core::{
    LcsError, RSI_CREATE_KEY, RSI_NOT_FOUND, RSI_OK, RSI_READ_KEY, RsiLengthPrefixedField,
    RsiReadKeySuccessResponsePayload, RsiResponseHeader, RsiRetainedRequest, RsiStatus,
    RsiValidatedResponse, parse_rsi_read_key_success_response_payload, rsi_response_op_code,
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

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

#[test]
fn read_key_success_response_payload_matches_psd_005_wire_order() {
    let parent_guid = [0x33; 16];
    let name = b"ChildKey";
    let sd = b"self-relative-sd";
    let mut frame = response_frame(71, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    push_len_prefixed(&mut frame, name);
    frame.extend_from_slice(&parent_guid);
    push_len_prefixed(&mut frame, sd);
    frame.push(1);
    frame.push(0);
    frame.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    finish_total_len(&mut frame);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &frame,
            RsiRetainedRequest {
                request_id: 71,
                op_code: RSI_READ_KEY,
            }
        ),
        Ok(RsiReadKeySuccessResponsePayload {
            response: RsiValidatedResponse {
                header: RsiResponseHeader {
                    total_len: frame.len() as u32,
                    request_id: 71,
                    op_code: rsi_response_op_code(RSI_READ_KEY).unwrap(),
                },
                status: RsiStatus::Ok,
            },
            name: RsiLengthPrefixedField {
                len: name.len() as u32,
                data: name,
            },
            parent_guid,
            sd: RsiLengthPrefixedField {
                len: sd.len() as u32,
                data: sd,
            },
            volatile: true,
            symlink: false,
            last_write_time: 0x0102_0304_0506_0708,
        })
    );
}

#[test]
fn read_key_success_response_payload_rejects_non_success_status_before_body_parse() {
    let mut frame = response_frame(
        72,
        rsi_response_op_code(RSI_READ_KEY).unwrap(),
        RSI_NOT_FOUND,
    );
    finish_total_len(&mut frame);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &frame,
            RsiRetainedRequest {
                request_id: 72,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_FOUND))
    );
}

#[test]
fn read_key_success_response_payload_rejects_wrong_parser_operation() {
    let mut frame = response_frame(73, rsi_response_op_code(RSI_CREATE_KEY).unwrap(), RSI_OK);
    finish_total_len(&mut frame);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &frame,
            RsiRetainedRequest {
                request_id: 73,
                op_code: RSI_CREATE_KEY,
            }
        ),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_READ_KEY,
            actual: RSI_CREATE_KEY,
        })
    );
}

#[test]
fn read_key_success_response_payload_rejects_truncation_and_invalid_booleans() {
    let mut truncated = response_frame(74, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    push_len_prefixed(&mut truncated, b"name");
    finish_total_len(&mut truncated);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &truncated,
            RsiRetainedRequest {
                request_id: 74,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::RsiMessageTooShort { len: 8, min: 24 })
    );

    let mut invalid_bool = response_frame(75, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    push_len_prefixed(&mut invalid_bool, b"name");
    invalid_bool.extend_from_slice(&[0x44; 16]);
    push_len_prefixed(&mut invalid_bool, b"sd");
    invalid_bool.push(2);
    invalid_bool.push(0);
    invalid_bool.extend_from_slice(&0u64.to_le_bytes());
    finish_total_len(&mut invalid_bool);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &invalid_bool,
            RsiRetainedRequest {
                request_id: 75,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::InvalidBooleanFlag {
            field: "read_key.volatile",
            value: 2,
        })
    );
}

#[test]
fn read_key_success_response_payload_rejects_extra_response_bytes() {
    let mut frame = response_frame(76, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    push_len_prefixed(&mut frame, b"name");
    frame.extend_from_slice(&[0x55; 16]);
    push_len_prefixed(&mut frame, b"sd");
    frame.push(0);
    frame.push(1);
    frame.extend_from_slice(&55u64.to_le_bytes());
    frame.push(0xaa);
    frame.push(0xbb);
    finish_total_len(&mut frame);

    assert_eq!(
        parse_rsi_read_key_success_response_payload(
            &frame,
            RsiRetainedRequest {
                request_id: 76,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_READ_KEY,
            extra_len: 2,
        })
    );
}
