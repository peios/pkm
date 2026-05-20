use lcs_core::{
    LcsSourceValidationClass, RSI_MIN_RESPONSE_LEN, RSI_OK, RSI_RESPONSE_BIT, RSI_WRITE_KEY,
    RsiInFlightRequestRecord, RsiMalformedSourceDataPlan, RsiMappedErrno, RsiResponseHeader,
    RsiRetainedRequest, RsiSourceDataValidationFailure, RsiSourceWriteFailClosedReason,
    RsiSourceWriteRejectReason, RsiSourceWriteResponseMatch, RsiSourceWriteResponsePlan, RsiStatus,
    RsiValidatedResponse, plan_rsi_source_write_response,
};

const SOURCE_A: u64 = 11;
const SOURCE_B: u64 = 12;
const UNKNOWN_RSI_STATUS: u32 = 10;

fn retained(request_id: u64, op_code: u16) -> RsiRetainedRequest {
    RsiRetainedRequest {
        request_id,
        op_code,
    }
}

fn record(source_connection_id: u64, request_id: u64, op_code: u16) -> RsiInFlightRequestRecord {
    RsiInFlightRequestRecord {
        source_connection_id,
        retained: retained(request_id, op_code),
    }
}

fn response_frame(total_len: u32, request_id: u64, op_code: u16, status: u32) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&op_code.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

fn reject(reason: RsiSourceWriteRejectReason) -> RsiSourceWriteResponsePlan {
    RsiSourceWriteResponsePlan::RejectSourceWrite {
        reason,
        source_write_errno: RsiMappedErrno::Einval,
        release_request_record: false,
        tear_down_source: false,
        mark_source_down: false,
    }
}

#[test]
fn valid_source_write_response_is_accepted_without_mutation() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &frame),
        RsiSourceWriteResponsePlan::AcceptResponse {
            matched: RsiSourceWriteResponseMatch {
                record: source_a_req10,
                response: RsiValidatedResponse {
                    header: RsiResponseHeader {
                        total_len: RSI_MIN_RESPONSE_LEN as u32,
                        request_id: 10,
                        op_code: RSI_WRITE_KEY | RSI_RESPONSE_BIT,
                    },
                    status: RsiStatus::Ok,
                },
            },
        },
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn enumerated_source_write_validation_failures_are_einval_without_teardown() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let short = [0u8; RSI_MIN_RESPONSE_LEN - 1];
    let length_mismatch = response_frame(99, 10, RSI_WRITE_KEY | RSI_RESPONSE_BIT, RSI_OK);
    let unknown_request_id = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        99,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );
    let wrong_opcode = response_frame(RSI_MIN_RESPONSE_LEN as u32, 10, RSI_WRITE_KEY, RSI_OK);

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &short),
        reject(RsiSourceWriteRejectReason::ShortResponse {
            len: RSI_MIN_RESPONSE_LEN - 1,
            min: RSI_MIN_RESPONSE_LEN,
        }),
    );
    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &length_mismatch),
        reject(RsiSourceWriteRejectReason::LengthMismatch {
            total_len: 99,
            actual_len: RSI_MIN_RESPONSE_LEN,
        }),
    );
    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &unknown_request_id),
        reject(RsiSourceWriteRejectReason::UnknownOrDuplicateRequestId {
            source_connection_id: SOURCE_A,
            request_id: 99,
        }),
    );
    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &wrong_opcode),
        reject(RsiSourceWriteRejectReason::ResponseOpcodeMismatch {
            expected: RSI_WRITE_KEY | RSI_RESPONSE_BIT,
            actual: RSI_WRITE_KEY,
        }),
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn response_for_another_source_connection_is_einval_without_consuming_record() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_B, &frame),
        reject(
            RsiSourceWriteRejectReason::ResponseForAnotherSourceConnection {
                request_id: 10,
                expected_source_connection_id: SOURCE_B,
                actual_source_connection_id: SOURCE_A,
            },
        ),
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn unknown_status_code_is_malformed_data_and_releases_the_matched_record() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        UNKNOWN_RSI_STATUS,
    );

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &frame),
        RsiSourceWriteResponsePlan::MalformedSourceData {
            record: source_a_req10,
            plan: RsiMalformedSourceDataPlan {
                failure: RsiSourceDataValidationFailure::UnknownRsiStatusCode,
                caller_errno: RsiMappedErrno::Eio,
                emit_audit: true,
                keep_source_alive: true,
                retain_previous_layer_metadata_sd: false,
            },
            release_request_record: true,
        },
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::UnknownRsiStatusCode)
            .as_str(),
        "unknown_rsi_status_code",
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn corrupt_in_flight_state_fails_closed_instead_of_einval() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10), Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &frame),
        RsiSourceWriteResponsePlan::FailClosed {
            reason: RsiSourceWriteFailClosedReason::DuplicateInFlightRequestRecord {
                source_connection_id: SOURCE_A,
                request_id: 10,
            },
            source_write_errno: RsiMappedErrno::Eio,
            tear_down_source: true,
            mark_source_down: true,
            release_in_flight_table: true,
        },
    );
}

#[test]
fn invalid_retained_request_opcode_fails_closed_instead_of_einval() {
    let invalid_op_code = 0x7fff;
    let table = [Some(record(SOURCE_A, 10, invalid_op_code))];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        invalid_op_code | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        plan_rsi_source_write_response(&table, SOURCE_A, &frame),
        RsiSourceWriteResponsePlan::FailClosed {
            reason: RsiSourceWriteFailClosedReason::InvalidRetainedRequestOpcode {
                op_code: invalid_op_code,
            },
            source_write_errno: RsiMappedErrno::Eio,
            tear_down_source: true,
            mark_source_down: true,
            release_in_flight_table: true,
        },
    );
}
