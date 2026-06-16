use lcs_core::{
    LcsError, LcsLimits, TransactionCompletionEvent, TransactionKernelEffectsPlan,
    TransactionWatchBurstPlan, plan_transaction_completion_effects, plan_transaction_watch_burst,
};

#[test]
fn committed_transactions_apply_mutation_log_for_kernel_effects() {
    assert_eq!(
        plan_transaction_completion_effects(TransactionCompletionEvent::CommitSucceeded),
        TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects
    );
    assert_eq!(
        plan_transaction_completion_effects(TransactionCompletionEvent::LateCommitSucceeded),
        TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects
    );
}

#[test]
fn aborted_or_failed_transactions_discard_log_without_watch_events() {
    for event in [
        TransactionCompletionEvent::ExplicitAbort,
        TransactionCompletionEvent::TimeoutBeforeCommitDispatch,
        TransactionCompletionEvent::SourceDownCancellation,
        TransactionCompletionEvent::LateCommitFailed,
        TransactionCompletionEvent::SourceConnectionTornDownAfterCommitTimeout,
    ] {
        assert_eq!(
            plan_transaction_completion_effects(event),
            TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents
        );
    }
}

#[test]
fn commit_timeout_after_dispatch_retains_log_for_late_response() {
    assert_eq!(
        plan_transaction_completion_effects(
            TransactionCompletionEvent::CommitRequestTimedOutAfterDispatch,
        ),
        TransactionKernelEffectsPlan::RetainMutationLogForLateResponse
    );
}

#[test]
fn transaction_watch_burst_boundary_emits_individual_events_up_to_limit() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 3;

    assert_eq!(
        plan_transaction_watch_burst(&limits, 0),
        Ok(TransactionWatchBurstPlan::NoEvents)
    );
    assert_eq!(
        plan_transaction_watch_burst(&limits, 1),
        Ok(TransactionWatchBurstPlan::EmitIndividualEvents { event_count: 1 })
    );
    assert_eq!(
        plan_transaction_watch_burst(&limits, 3),
        Ok(TransactionWatchBurstPlan::EmitIndividualEvents { event_count: 3 })
    );
}

#[test]
fn transaction_watch_burst_over_limit_forces_single_overflow() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 3;

    assert_eq!(
        plan_transaction_watch_burst(&limits, 4),
        Ok(TransactionWatchBurstPlan::EmitOverflowOnly {
            attempted_event_count: 4,
            max_event_burst: 3,
        })
    );
}

#[test]
fn transaction_watch_burst_zero_limit_fails_closed() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 0;

    assert_eq!(
        plan_transaction_watch_burst(&limits, 1),
        Err(LcsError::InvalidTransactionWatchBurstLimit)
    );
}
