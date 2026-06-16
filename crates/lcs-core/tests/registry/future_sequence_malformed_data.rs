use lcs_core::{
    LcsError, RsiMalformedSourceDataPlan, RsiMappedErrno, RsiSourceDataValidationFailure,
    SequenceCounter, plan_rsi_malformed_source_data,
};

fn future_sequence_failure(sequence: u64, next_sequence: u64) -> RsiSourceDataValidationFailure {
    let counter = SequenceCounter::new(next_sequence);
    let err = counter
        .validate_source_entry_sequence(sequence)
        .unwrap_err();

    assert_eq!(
        err,
        LcsError::FutureSequence {
            sequence,
            next_sequence,
        }
    );

    match err {
        LcsError::FutureSequence { .. } => RsiSourceDataValidationFailure::FutureSequenceNumber,
        other => panic!("unexpected source sequence validation result: {other:?}"),
    }
}

fn assert_future_sequence_malformed_data_plan(failure: RsiSourceDataValidationFailure) {
    assert_eq!(
        plan_rsi_malformed_source_data(failure),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::FutureSequenceNumber,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
}

#[test]
fn source_entry_sequence_equal_to_next_sequence_maps_to_malformed_data_eio_and_audit_policy() {
    let failure = future_sequence_failure(100, 100);

    assert_future_sequence_malformed_data_plan(failure);
}

#[test]
fn source_entry_sequence_above_next_sequence_uses_same_malformed_data_policy() {
    let failure = future_sequence_failure(101, 100);

    assert_future_sequence_malformed_data_plan(failure);
}

#[test]
fn past_source_entry_sequence_does_not_enter_malformed_data_path() {
    let counter = SequenceCounter::new(100);

    assert_eq!(counter.validate_source_entry_sequence(99), Ok(()));
}
