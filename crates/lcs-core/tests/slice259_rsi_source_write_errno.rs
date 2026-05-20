use lcs_core::{
    LinuxErrno, RSI_MIN_RESPONSE_LEN, RSI_OK, RSI_RESPONSE_BIT, RSI_WRITE_KEY,
    RsiInFlightRequestRecord, RsiMalformedSourceDataPlan, RsiMappedErrno, RsiResponseHeader,
    RsiRetainedRequest, RsiSourceDataValidationFailure, RsiSourceWriteFailClosedReason,
    RsiSourceWriteRejectReason, RsiSourceWriteResponseMatch, RsiSourceWriteResponsePlan, RsiStatus,
    RsiValidatedResponse, plan_rsi_source_write_response, rsi_source_write_response_errno,
};

const SOURCE_A: u64 = 11;

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

#[test]
fn source_write_validation_rejects_project_to_linux_einval() {
    let short = [0u8; RSI_MIN_RESPONSE_LEN - 1];
    let plan = plan_rsi_source_write_response(&[], SOURCE_A, &short);

    assert_eq!(
        plan,
        RsiSourceWriteResponsePlan::RejectSourceWrite {
            reason: RsiSourceWriteRejectReason::ShortResponse {
                len: RSI_MIN_RESPONSE_LEN - 1,
                min: RSI_MIN_RESPONSE_LEN,
            },
            source_write_errno: RsiMappedErrno::Einval,
            release_request_record: false,
            tear_down_source: false,
            mark_source_down: false,
        }
    );
    assert_eq!(
        rsi_source_write_response_errno(&plan),
        Some(LinuxErrno::Einval)
    );
}

#[test]
fn accepted_source_write_responses_have_no_write_errno() {
    let record = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let plan = RsiSourceWriteResponsePlan::AcceptResponse {
        matched: RsiSourceWriteResponseMatch {
            record,
            response: RsiValidatedResponse {
                header: RsiResponseHeader {
                    total_len: RSI_MIN_RESPONSE_LEN as u32,
                    request_id: 10,
                    op_code: RSI_WRITE_KEY | RSI_RESPONSE_BIT,
                },
                status: RsiStatus::Ok,
            },
        },
    };

    assert_eq!(rsi_source_write_response_errno(&plan), None);
}

#[test]
fn matched_malformed_source_data_has_no_source_write_errno() {
    let plan = RsiSourceWriteResponsePlan::MalformedSourceData {
        record: record(SOURCE_A, 10, RSI_WRITE_KEY),
        plan: RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::UnknownRsiStatusCode,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        },
        release_request_record: true,
    };

    assert_eq!(rsi_source_write_response_errno(&plan), None);
}

#[test]
fn fail_closed_source_write_plans_project_retained_symbolic_errno() {
    let plan = RsiSourceWriteResponsePlan::FailClosed {
        reason: RsiSourceWriteFailClosedReason::InvalidRetainedRequestOpcode { op_code: 0x7fff },
        source_write_errno: RsiMappedErrno::Eio,
        tear_down_source: true,
        mark_source_down: true,
        release_in_flight_table: true,
    };

    assert_eq!(
        rsi_source_write_response_errno(&plan),
        Some(LinuxErrno::Eio)
    );
}

#[test]
fn concrete_valid_response_still_projects_no_source_write_errno() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );
    let plan = plan_rsi_source_write_response(&table, SOURCE_A, &frame);

    assert_eq!(rsi_source_write_response_errno(&plan), None);
}
