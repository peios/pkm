use lcs_core::{
    RsiLateMutatingKernelEffects, RsiLateResponseEffectPlan, RsiLateResponseTearDownReason,
    RsiLateResponseValidationOutcome, RsiMappedErrno, RsiSourceDataValidationFailure,
    TransactionKernelEffectsPlan, plan_rsi_late_response_effects,
};

#[test]
fn late_source_error_releases_record_without_normal_effects() {
    assert_eq!(
        plan_rsi_late_response_effects(RsiLateResponseValidationOutcome::SourceError(
            RsiMappedErrno::Eio,
        )),
        RsiLateResponseEffectPlan::ReleaseRecordNoNormalEffects {
            source_errno: Some(RsiMappedErrno::Eio),
            release_request_record: true,
        }
    );
}

#[test]
fn late_read_only_success_is_validated_and_discarded() {
    assert_eq!(
        plan_rsi_late_response_effects(RsiLateResponseValidationOutcome::SuccessReadOnly),
        RsiLateResponseEffectPlan::DiscardValidatedReadOnlyResponse {
            release_request_record: true,
        }
    );
}

#[test]
fn late_mutating_success_applies_supplied_kernel_side_effects() {
    let effects = RsiLateMutatingKernelEffects {
        update_hive_generation: true,
        dispatch_watch_events: true,
        refresh_layer_cache: true,
        track_orphans: true,
        transaction_commit_effects: Some(
            TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
        ),
    };

    assert_eq!(
        plan_rsi_late_response_effects(RsiLateResponseValidationOutcome::SuccessMutating(effects)),
        RsiLateResponseEffectPlan::ApplyMutatingKernelEffects {
            effects,
            release_request_record: true,
        }
    );
}

#[test]
fn late_malformed_data_follows_source_data_policy_without_teardown() {
    let plan = plan_rsi_late_response_effects(RsiLateResponseValidationOutcome::MalformedData(
        RsiSourceDataValidationFailure::FutureSequenceNumber,
    ));

    let RsiLateResponseEffectPlan::MalformedData {
        plan,
        release_request_record,
    } = plan
    else {
        panic!("expected malformed-data plan");
    };

    assert_eq!(
        plan.failure,
        RsiSourceDataValidationFailure::FutureSequenceNumber
    );
    assert_eq!(plan.caller_errno, RsiMappedErrno::Eio);
    assert!(plan.emit_audit);
    assert!(plan.keep_source_alive);
    assert!(!plan.retain_previous_layer_metadata_sd);
    assert!(release_request_record);
}

#[test]
fn late_malformed_protocol_tears_down_source() {
    assert_eq!(
        plan_rsi_late_response_effects(RsiLateResponseValidationOutcome::MalformedProtocol),
        RsiLateResponseEffectPlan::MalformedProtocolTearDown {
            reason: RsiLateResponseTearDownReason::MalformedProtocol,
            tear_down_source: true,
            mark_source_down: true,
            release_in_flight_table: true,
        }
    );
}

#[test]
fn missing_mutation_metadata_tears_down_instead_of_ignoring_late_response() {
    assert_eq!(
        plan_rsi_late_response_effects(
            RsiLateResponseValidationOutcome::MissingOrInvalidKernelMetadata,
        ),
        RsiLateResponseEffectPlan::MalformedProtocolTearDown {
            reason: RsiLateResponseTearDownReason::MissingOrInvalidKernelMetadata,
            tear_down_source: true,
            mark_source_down: true,
            release_in_flight_table: true,
        }
    );
}
