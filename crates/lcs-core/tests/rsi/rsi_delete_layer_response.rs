use lcs_core::{
    LcsError, RSI_DELETE_LAYER, RSI_MIN_RESPONSE_LEN, RSI_NOT_EMPTY, RSI_OK, RSI_READ_KEY,
    RsiGuidArray, RsiResponseHeader, RsiRetainedRequest, RsiStatus, RsiValidatedResponse,
    parse_rsi_delete_layer_success_response_payload, rsi_response_op_code,
};

fn response_frame(request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

fn finish_total_len(frame: &mut [u8]) {
    let total_len = frame.len() as u32;
    frame[..4].copy_from_slice(&total_len.to_le_bytes());
}

#[test]
fn delete_layer_success_response_parses_count_prefixed_orphan_guid_array() {
    let guid_a = [0xa1; 16];
    let guid_b = [0xb2; 16];
    let mut frame = response_frame(81, rsi_response_op_code(RSI_DELETE_LAYER).unwrap(), RSI_OK);
    frame.extend_from_slice(&2u32.to_le_bytes());
    frame.extend_from_slice(&guid_a);
    frame.extend_from_slice(&guid_b);
    finish_total_len(&mut frame);

    let parsed = parse_rsi_delete_layer_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 81,
            op_code: RSI_DELETE_LAYER,
        },
    )
    .unwrap();

    assert_eq!(
        parsed.response,
        RsiValidatedResponse {
            header: RsiResponseHeader {
                total_len: frame.len() as u32,
                request_id: 81,
                op_code: rsi_response_op_code(RSI_DELETE_LAYER).unwrap(),
            },
            status: RsiStatus::Ok,
        }
    );
    assert_eq!(
        parsed.orphaned_guids,
        RsiGuidArray {
            count: 2,
            bytes: &frame[RSI_MIN_RESPONSE_LEN + 4..],
        }
    );
    assert_eq!(parsed.orphaned_guids.guid_at(0), Some(guid_a));
    assert_eq!(parsed.orphaned_guids.guid_at(1), Some(guid_b));
    assert_eq!(parsed.orphaned_guids.guid_at(2), None);
}

#[test]
fn delete_layer_success_response_accepts_empty_orphan_guid_array() {
    let mut frame = response_frame(82, rsi_response_op_code(RSI_DELETE_LAYER).unwrap(), RSI_OK);
    frame.extend_from_slice(&0u32.to_le_bytes());
    finish_total_len(&mut frame);

    let parsed = parse_rsi_delete_layer_success_response_payload(
        &frame,
        RsiRetainedRequest {
            request_id: 82,
            op_code: RSI_DELETE_LAYER,
        },
    )
    .unwrap();

    assert_eq!(parsed.orphaned_guids.count, 0);
    assert_eq!(parsed.orphaned_guids.bytes, &[]);
    assert_eq!(parsed.orphaned_guids.guid_at(0), None);
}

#[test]
fn delete_layer_success_response_rejects_non_success_status_and_wrong_parser_operation() {
    let mut failed = response_frame(
        83,
        rsi_response_op_code(RSI_DELETE_LAYER).unwrap(),
        RSI_NOT_EMPTY,
    );
    finish_total_len(&mut failed);
    assert_eq!(
        parse_rsi_delete_layer_success_response_payload(
            &failed,
            RsiRetainedRequest {
                request_id: 83,
                op_code: RSI_DELETE_LAYER,
            }
        ),
        Err(LcsError::RsiResponseStatusNotOk(RSI_NOT_EMPTY))
    );

    let mut wrong_op = response_frame(84, rsi_response_op_code(RSI_READ_KEY).unwrap(), RSI_OK);
    finish_total_len(&mut wrong_op);
    assert_eq!(
        parse_rsi_delete_layer_success_response_payload(
            &wrong_op,
            RsiRetainedRequest {
                request_id: 84,
                op_code: RSI_READ_KEY,
            }
        ),
        Err(LcsError::RsiResponsePayloadParserMismatch {
            expected: RSI_DELETE_LAYER,
            actual: RSI_READ_KEY,
        })
    );
}

#[test]
fn delete_layer_success_response_rejects_truncated_and_extra_guid_bytes() {
    let mut truncated = response_frame(85, rsi_response_op_code(RSI_DELETE_LAYER).unwrap(), RSI_OK);
    frame_extend_count_and_one_guid(&mut truncated, 2);
    finish_total_len(&mut truncated);

    assert_eq!(
        parse_rsi_delete_layer_success_response_payload(
            &truncated,
            RsiRetainedRequest {
                request_id: 85,
                op_code: RSI_DELETE_LAYER,
            }
        ),
        Err(LcsError::RsiMessageTooShort { len: 20, min: 36 })
    );

    let mut extra = response_frame(86, rsi_response_op_code(RSI_DELETE_LAYER).unwrap(), RSI_OK);
    frame_extend_count_and_one_guid(&mut extra, 1);
    extra.push(0xee);
    finish_total_len(&mut extra);

    assert_eq!(
        parse_rsi_delete_layer_success_response_payload(
            &extra,
            RsiRetainedRequest {
                request_id: 86,
                op_code: RSI_DELETE_LAYER,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code: RSI_DELETE_LAYER,
            extra_len: 1,
        })
    );
}

fn frame_extend_count_and_one_guid(frame: &mut Vec<u8>, count: u32) {
    frame.extend_from_slice(&count.to_le_bytes());
    frame.extend_from_slice(&[0xc3; 16]);
}
