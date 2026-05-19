use lcs_core::{
    LcsError, RSI_ABORT_TRANSACTION, RSI_BEGIN_TRANSACTION, RSI_CAS_FAILED, RSI_COMMIT_TRANSACTION,
    RSI_CREATE_ENTRY, RSI_CREATE_KEY, RSI_DELETE_ENTRY, RSI_DELETE_LAYER, RSI_DELETE_VALUE_ENTRY,
    RSI_DROP_KEY, RSI_ENUM_CHILDREN, RSI_FLUSH, RSI_HIDE_ENTRY, RSI_LOOKUP, RSI_MIN_RESPONSE_LEN,
    RSI_OK, RSI_QUERY_VALUES, RSI_READ_KEY, RSI_SET_BLANKET_TOMBSTONE, RSI_SET_VALUE,
    RSI_WRITE_KEY, RsiResponseHeader, RsiRetainedRequest, RsiStatus, RsiValidatedResponse,
    rsi_request_has_status_only_response, rsi_response_op_code,
    validate_rsi_status_only_response_for_request,
};

fn response_frame(total_len: u32, request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

#[test]
fn status_only_response_ops_are_classified_from_psd_005_layouts() {
    for op_code in [
        RSI_CREATE_ENTRY,
        RSI_HIDE_ENTRY,
        RSI_DELETE_ENTRY,
        RSI_CREATE_KEY,
        RSI_WRITE_KEY,
        RSI_DROP_KEY,
        RSI_SET_VALUE,
        RSI_DELETE_VALUE_ENTRY,
        RSI_SET_BLANKET_TOMBSTONE,
        RSI_BEGIN_TRANSACTION,
        RSI_COMMIT_TRANSACTION,
        RSI_ABORT_TRANSACTION,
        RSI_FLUSH,
    ] {
        assert_eq!(rsi_request_has_status_only_response(op_code), Ok(true));
    }

    for op_code in [
        RSI_LOOKUP,
        RSI_ENUM_CHILDREN,
        RSI_READ_KEY,
        RSI_QUERY_VALUES,
        RSI_DELETE_LAYER,
    ] {
        assert_eq!(rsi_request_has_status_only_response(op_code), Ok(false));
    }

    assert_eq!(
        rsi_request_has_status_only_response(0x7777),
        Err(LcsError::UnknownRsiOpcode(0x7777))
    );
}

#[test]
fn status_only_response_validation_accepts_exact_status_success() {
    let op_code = RSI_CREATE_KEY;
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        91,
        rsi_response_op_code(op_code).unwrap(),
        RSI_OK,
    );

    assert_eq!(
        validate_rsi_status_only_response_for_request(
            &frame,
            RsiRetainedRequest {
                request_id: 91,
                op_code,
            }
        ),
        Ok(RsiValidatedResponse {
            header: RsiResponseHeader {
                total_len: RSI_MIN_RESPONSE_LEN as u32,
                request_id: 91,
                op_code: rsi_response_op_code(op_code).unwrap(),
            },
            status: RsiStatus::Ok,
        })
    );
}

#[test]
fn status_only_response_validation_accepts_exact_status_failures() {
    let op_code = RSI_SET_VALUE;
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        92,
        rsi_response_op_code(op_code).unwrap(),
        RSI_CAS_FAILED,
    );

    assert_eq!(
        validate_rsi_status_only_response_for_request(
            &frame,
            RsiRetainedRequest {
                request_id: 92,
                op_code,
            }
        )
        .map(|response| response.status),
        Ok(RsiStatus::CasFailed)
    );
}

#[test]
fn status_only_response_validation_rejects_extra_payload_bytes() {
    let op_code = RSI_FLUSH;
    let mut frame = response_frame(
        (RSI_MIN_RESPONSE_LEN + 2) as u32,
        93,
        rsi_response_op_code(op_code).unwrap(),
        RSI_OK,
    );
    frame.extend_from_slice(&[0xaa, 0xbb]);

    assert_eq!(
        validate_rsi_status_only_response_for_request(
            &frame,
            RsiRetainedRequest {
                request_id: 93,
                op_code,
            }
        ),
        Err(LcsError::RsiUnexpectedResponsePayload {
            op_code,
            extra_len: 2,
        })
    );
}

#[test]
fn status_only_response_validation_rejects_data_bearing_success_ops() {
    let op_code = RSI_LOOKUP;
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        94,
        rsi_response_op_code(op_code).unwrap(),
        RSI_OK,
    );

    assert_eq!(
        validate_rsi_status_only_response_for_request(
            &frame,
            RsiRetainedRequest {
                request_id: 94,
                op_code,
            }
        ),
        Err(LcsError::RsiResponseRequiresPayloadParser(op_code))
    );
}
