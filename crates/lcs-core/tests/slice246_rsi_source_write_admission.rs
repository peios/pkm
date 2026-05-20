use lcs_core::{
    LcsError, RSI_MIN_RESPONSE_LEN, RSI_OK, RSI_RESPONSE_BIT, RSI_WRITE_KEY,
    RsiInFlightRequestRecord, RsiInFlightRequestTableSummary, RsiResponseHeader,
    RsiRetainedRequest, RsiSourceWriteResponseMatch, RsiStatus, RsiValidatedResponse,
    match_rsi_source_write_response_record, release_rsi_in_flight_request_record,
    summarize_rsi_in_flight_request_table,
};

const SOURCE_A: u64 = 7;
const SOURCE_B: u64 = 8;
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

#[test]
fn source_write_match_validates_common_response_without_releasing_record() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let source_b_req10 = record(SOURCE_B, 10, RSI_WRITE_KEY);
    let source_a_req11 = record(SOURCE_A, 11, RSI_WRITE_KEY);
    let table = [
        Some(source_a_req10),
        Some(source_b_req10),
        Some(source_a_req11),
    ];
    let original = table;
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        summarize_rsi_in_flight_request_table(&table),
        Ok(RsiInFlightRequestTableSummary {
            entries: 3,
            capacity: 3,
            full: true,
        }),
    );
    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &frame),
        Ok(RsiSourceWriteResponseMatch {
            record: source_a_req10,
            response: RsiValidatedResponse {
                header: RsiResponseHeader {
                    total_len: RSI_MIN_RESPONSE_LEN as u32,
                    request_id: 10,
                    op_code: RSI_WRITE_KEY | RSI_RESPONSE_BIT,
                },
                status: RsiStatus::Ok,
            },
        }),
    );
    assert_eq!(table, original);
}

#[test]
fn processed_response_release_removes_exact_matching_connection_record_only() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let source_b_req10 = record(SOURCE_B, 10, RSI_WRITE_KEY);
    let mut table = [Some(source_a_req10), Some(source_b_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );
    let matched = match_rsi_source_write_response_record(&table, SOURCE_A, &frame).unwrap();

    assert_eq!(
        release_rsi_in_flight_request_record(&mut table, matched.record),
        Ok(source_a_req10),
    );
    assert_eq!(table, [None, Some(source_b_req10)]);
    assert_eq!(
        summarize_rsi_in_flight_request_table(&table),
        Ok(RsiInFlightRequestTableSummary {
            entries: 1,
            capacity: 2,
            full: false,
        }),
    );
}

#[test]
fn duplicate_response_after_release_is_not_accepted() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let mut table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );
    let matched = match_rsi_source_write_response_record(&table, SOURCE_A, &frame).unwrap();
    release_rsi_in_flight_request_record(&mut table, matched.record).unwrap();

    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &frame),
        Err(LcsError::RsiInFlightRequestNotFound {
            source_connection_id: SOURCE_A,
            request_id: 10,
        }),
    );
    assert_eq!(table, [None]);
}

#[test]
fn response_for_another_source_connection_cannot_consume_record() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_B, &frame),
        Err(LcsError::RsiSourceConnectionMismatch {
            request_id: 10,
            expected_source_connection_id: SOURCE_B,
            actual_source_connection_id: SOURCE_A,
        }),
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn unknown_request_id_is_rejected_without_mutating_table() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        99,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &frame),
        Err(LcsError::RsiInFlightRequestNotFound {
            source_connection_id: SOURCE_A,
            request_id: 99,
        }),
    );
    assert_eq!(table, [Some(source_a_req10)]);
}

#[test]
fn duplicate_in_flight_records_for_same_connection_fail_closed() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10), Some(source_a_req10)];
    let frame = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        RSI_OK,
    );

    assert_eq!(
        summarize_rsi_in_flight_request_table(&table),
        Err(LcsError::DuplicateRsiInFlightRequestRecord {
            source_connection_id: SOURCE_A,
            request_id: 10,
        }),
    );
    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &frame),
        Err(LcsError::DuplicateRsiInFlightRequestRecord {
            source_connection_id: SOURCE_A,
            request_id: 10,
        }),
    );
}

#[test]
fn malformed_response_frames_are_rejected_without_mutating_table() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let table = [Some(source_a_req10)];
    let short = [0u8; RSI_MIN_RESPONSE_LEN - 1];
    let length_mismatch = response_frame(99, 10, RSI_WRITE_KEY | RSI_RESPONSE_BIT, RSI_OK);
    let wrong_opcode = response_frame(RSI_MIN_RESPONSE_LEN as u32, 10, RSI_WRITE_KEY, RSI_OK);
    let unknown_status = response_frame(
        RSI_MIN_RESPONSE_LEN as u32,
        10,
        RSI_WRITE_KEY | RSI_RESPONSE_BIT,
        UNKNOWN_RSI_STATUS,
    );

    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &short),
        Err(LcsError::RsiMessageTooShort {
            len: RSI_MIN_RESPONSE_LEN - 1,
            min: RSI_MIN_RESPONSE_LEN,
        }),
    );
    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &length_mismatch),
        Err(LcsError::RsiMessageLengthMismatch {
            total_len: 99,
            actual_len: RSI_MIN_RESPONSE_LEN,
        }),
    );
    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &wrong_opcode),
        Err(LcsError::RsiResponseOpcodeMismatch {
            expected: RSI_WRITE_KEY | RSI_RESPONSE_BIT,
            actual: RSI_WRITE_KEY,
        }),
    );
    assert_eq!(
        match_rsi_source_write_response_record(&table, SOURCE_A, &unknown_status),
        Err(LcsError::UnknownRsiStatus(UNKNOWN_RSI_STATUS)),
    );
    assert_eq!(table, [Some(source_a_req10)]);
}
