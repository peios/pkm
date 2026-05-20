use lcs_core::{
    LcsError, RSI_READ_KEY, RSI_WRITE_KEY, RsiInFlightRequestRecord,
    RsiInFlightRequestTeardownReleaseSummary, RsiRetainedRequest,
    release_rsi_in_flight_request_records_for_source,
};

const SOURCE_A: u64 = 7;
const SOURCE_B: u64 = 8;

fn record(source_connection_id: u64, request_id: u64, op_code: u16) -> RsiInFlightRequestRecord {
    RsiInFlightRequestRecord {
        source_connection_id,
        retained: RsiRetainedRequest {
            request_id,
            op_code,
        },
    }
}

#[test]
fn source_teardown_releases_all_records_for_that_connection_only() {
    let source_a_req10 = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let source_b_req10 = record(SOURCE_B, 10, RSI_WRITE_KEY);
    let source_a_req11 = record(SOURCE_A, 11, RSI_READ_KEY);
    let mut table = [
        Some(source_a_req10),
        Some(source_b_req10),
        None,
        Some(source_a_req11),
    ];

    assert_eq!(
        release_rsi_in_flight_request_records_for_source(&mut table, SOURCE_A),
        Ok(RsiInFlightRequestTeardownReleaseSummary {
            released: 2,
            remaining: 1,
            capacity: 4,
        }),
    );
    assert_eq!(table, [None, Some(source_b_req10), None, None]);
}

#[test]
fn source_teardown_without_matching_records_is_noop_after_validation() {
    let source_b_req10 = record(SOURCE_B, 10, RSI_WRITE_KEY);
    let mut table = [None, Some(source_b_req10)];

    assert_eq!(
        release_rsi_in_flight_request_records_for_source(&mut table, SOURCE_A),
        Ok(RsiInFlightRequestTeardownReleaseSummary {
            released: 0,
            remaining: 1,
            capacity: 2,
        }),
    );
    assert_eq!(table, [None, Some(source_b_req10)]);
}

#[test]
fn corrupt_duplicate_table_fails_without_partial_release() {
    let duplicate = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let mut table = [Some(duplicate), Some(duplicate)];
    let original = table;

    assert_eq!(
        release_rsi_in_flight_request_records_for_source(&mut table, SOURCE_A),
        Err(LcsError::DuplicateRsiInFlightRequestRecord {
            source_connection_id: SOURCE_A,
            request_id: 10,
        }),
    );
    assert_eq!(table, original);
}

#[test]
fn malformed_retained_record_fails_without_partial_release() {
    let valid = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let invalid = record(SOURCE_A, 11, 0x7777);
    let mut table = [Some(valid), Some(invalid)];
    let original = table;

    assert_eq!(
        release_rsi_in_flight_request_records_for_source(&mut table, SOURCE_A),
        Err(LcsError::UnknownRsiOpcode(0x7777)),
    );
    assert_eq!(table, original);
}
