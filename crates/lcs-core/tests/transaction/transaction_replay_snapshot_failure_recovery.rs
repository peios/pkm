use lcs_core::{
    RsiMappedErrno, RsiSourceDataValidationFailure, TransactionReplaySnapshotFailureKind,
    TransactionReplaySnapshotFailureRecoveryPlan,
    TransactionReplaySnapshotRecoveryRequestDisposition,
    TransactionReplaySnapshotRecoverySourcePolicy, plan_rsi_malformed_source_data,
    plan_transaction_replay_snapshot_failure_recovery,
};

fn common_success_overflow_invariants(plan: TransactionReplaySnapshotFailureRecoveryPlan) {
    assert!(plan.commit_remains_successful);
    assert_eq!(plan.caller_errno, None);
    assert!(!plan.emit_normal_watch_events);
    assert!(plan.queue_overflow_for_affected_watches);
    assert!(plan.release_transaction_replay_state);
    assert!(plan.late_response_must_not_resurrect_normal_events);
}

#[test]
fn source_error_preserves_commit_and_overflows_affected_watchers() {
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::SourceError {
            source_errno: RsiMappedErrno::Eio,
        },
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, Some(RsiMappedErrno::Eio));
    assert_eq!(plan.malformed_data_plan, None);
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseFailedRequestRecord,
    );
}

#[test]
fn timeout_before_dispatch_has_no_request_to_retain_or_release() {
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::TimeoutBeforeDispatch,
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, None);
    assert_eq!(plan.malformed_data_plan, None);
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::NoRequestSent,
    );
}

#[test]
fn timeout_after_dispatch_retains_in_flight_record_for_late_validation() {
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::TimeoutAfterDispatch { request_id: 77 },
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, None);
    assert_eq!(plan.malformed_data_plan, None);
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::RetainTimedOutInFlightRequest {
            request_id: 77,
        },
    );
}

#[test]
fn malformed_source_data_uses_existing_audit_and_source_alive_policy() {
    let failure = RsiSourceDataValidationFailure::FutureSequenceNumber;
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::MalformedData { failure },
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, None);
    assert_eq!(
        plan.malformed_data_plan,
        Some(plan_rsi_malformed_source_data(failure)),
    );
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::KeepSourceAlive,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseFailedRequestRecord,
    );
}

#[test]
fn malformed_protocol_tears_down_source_and_releases_in_flight_table() {
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::MalformedProtocol,
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, None);
    assert_eq!(plan.malformed_data_plan, None);
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::TearDownAndMarkSourceDown,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseInFlightTableOnSourceTeardown,
    );
}

#[test]
fn source_teardown_releases_replay_state_without_normal_events() {
    let plan = plan_transaction_replay_snapshot_failure_recovery(
        TransactionReplaySnapshotFailureKind::SourceConnectionTornDown,
    );

    common_success_overflow_invariants(plan);
    assert_eq!(plan.source_errno, None);
    assert_eq!(plan.malformed_data_plan, None);
    assert_eq!(
        plan.source_policy,
        TransactionReplaySnapshotRecoverySourcePolicy::SourceAlreadyTornDown,
    );
    assert_eq!(
        plan.request_disposition,
        TransactionReplaySnapshotRecoveryRequestDisposition::ReleaseInFlightTableOnSourceTeardown,
    );
}
