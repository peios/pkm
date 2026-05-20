use lcs_core::{
    LcsError, RSI_READ_KEY, RSI_WRITE_KEY, RsiInFlightRequestRecord,
    RsiInFlightRequestTableSummary, RsiRetainedRequest, insert_rsi_in_flight_request_record,
    summarize_rsi_in_flight_request_table,
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
fn insert_places_dispatched_record_in_first_free_slot_and_updates_summary() {
    let existing = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let inserted = record(SOURCE_A, 11, RSI_READ_KEY);
    let mut table = [Some(existing), None, None];

    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, inserted),
        Ok(RsiInFlightRequestTableSummary {
            entries: 2,
            capacity: 3,
            full: false,
        }),
    );
    assert_eq!(table, [Some(existing), Some(inserted), None]);
}

#[test]
fn sparse_storage_remains_valid_and_insert_uses_hole_left_by_release() {
    let left = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let right = record(SOURCE_A, 12, RSI_READ_KEY);
    let inserted = record(SOURCE_A, 11, RSI_WRITE_KEY);
    let mut table = [Some(left), None, Some(right)];

    assert_eq!(
        summarize_rsi_in_flight_request_table(&table),
        Ok(RsiInFlightRequestTableSummary {
            entries: 2,
            capacity: 3,
            full: false,
        }),
    );
    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, inserted),
        Ok(RsiInFlightRequestTableSummary {
            entries: 3,
            capacity: 3,
            full: true,
        }),
    );
    assert_eq!(table, [Some(left), Some(inserted), Some(right)]);
}

#[test]
fn full_table_rejects_new_record_without_mutation() {
    let left = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let right = record(SOURCE_A, 11, RSI_READ_KEY);
    let mut table = [Some(left), Some(right)];
    let original = table;

    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, record(SOURCE_A, 12, RSI_WRITE_KEY)),
        Err(LcsError::RsiInFlightRequestTableFull { capacity: 2 }),
    );
    assert_eq!(table, original);
}

#[test]
fn duplicate_request_id_for_same_source_connection_fails_without_mutation() {
    let existing = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let duplicate = record(SOURCE_A, 10, RSI_READ_KEY);
    let mut table = [Some(existing), None];
    let original = table;

    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, duplicate),
        Err(LcsError::DuplicateRsiInFlightRequestRecord {
            source_connection_id: SOURCE_A,
            request_id: 10,
        }),
    );
    assert_eq!(table, original);
}

#[test]
fn same_request_id_is_allowed_for_different_source_connections() {
    let source_a = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let source_b = record(SOURCE_B, 10, RSI_READ_KEY);
    let mut table = [Some(source_a), None];

    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, source_b),
        Ok(RsiInFlightRequestTableSummary {
            entries: 2,
            capacity: 2,
            full: true,
        }),
    );
    assert_eq!(table, [Some(source_a), Some(source_b)]);
}

#[test]
fn malformed_retained_opcode_fails_before_mutation() {
    let existing = record(SOURCE_A, 10, RSI_WRITE_KEY);
    let invalid = record(SOURCE_A, 11, 0x7777);
    let mut table = [Some(existing), None];
    let original = table;

    assert_eq!(
        insert_rsi_in_flight_request_record(&mut table, invalid),
        Err(LcsError::UnknownRsiOpcode(0x7777)),
    );
    assert_eq!(table, original);
}
