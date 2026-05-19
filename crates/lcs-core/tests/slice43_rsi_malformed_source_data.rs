use lcs_core::{
    RsiMalformedSourceDataPlan, RsiMappedErrno, RsiSourceDataValidationFailure,
    plan_rsi_malformed_source_data,
};

fn expected(
    failure: RsiSourceDataValidationFailure,
    retain_previous_layer_metadata_sd: bool,
) -> RsiMalformedSourceDataPlan {
    RsiMalformedSourceDataPlan {
        failure,
        caller_errno: RsiMappedErrno::Eio,
        emit_audit: true,
        keep_source_alive: true,
        retain_previous_layer_metadata_sd,
    }
}

#[test]
fn malformed_sd_data_returns_eio_audits_and_keeps_source_alive() {
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::MalformedSecurityDescriptor),
        expected(
            RsiSourceDataValidationFailure::MalformedSecurityDescriptor,
            false
        )
    );
}

#[test]
fn future_sequences_and_duplicate_winning_ties_are_malformed_data() {
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::FutureSequenceNumber),
        expected(RsiSourceDataValidationFailure::FutureSequenceNumber, false)
    );
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::DuplicateWinningSequenceTie),
        expected(
            RsiSourceDataValidationFailure::DuplicateWinningSequenceTie,
            false
        )
    );
}

#[test]
fn malformed_layer_metadata_sd_retains_previous_known_good_cache() {
    assert_eq!(
        plan_rsi_malformed_source_data(
            RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor,
        ),
        expected(
            RsiSourceDataValidationFailure::MalformedLayerMetadataSecurityDescriptor,
            true,
        )
    );
}
