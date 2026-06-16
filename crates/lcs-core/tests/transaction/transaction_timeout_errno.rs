use lcs_core::{
    LcsLimits, TransactionBinding, TransactionKernelEffectsPlan, TransactionPollPlan,
    TransactionRuntimeTransitionPlan, TransactionState, TransactionTimeoutErrno,
    TransactionUseFailure, plan_transaction_poll, plan_transaction_timeout,
    transaction_terminal_failure, transaction_timeout_errno,
};

const ROOT_GUID: [u8; 16] = [0x48; 16];

fn binding() -> TransactionBinding<'static> {
    TransactionBinding {
        source_id: 17,
        hive_name: "Machine",
        hive_root_guid: ROOT_GUID,
    }
}

#[test]
fn transaction_timeout_future_operations_report_etimedout() {
    let plan = plan_transaction_timeout(
        &LcsLimits::default(),
        TransactionState::ActiveUnbound,
        false,
    )
    .unwrap();

    assert_eq!(
        plan,
        TransactionRuntimeTransitionPlan {
            final_state: TransactionState::TimedOut,
            binding: None,
            state_changed: true,
            wake_poll_waiters: true,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::TimedOut),
            dispatch_source_abort: false,
            kernel_effects: Some(TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents),
        }
    );
    assert_eq!(
        transaction_timeout_errno(plan.future_operation_failure.unwrap()),
        Some(TransactionTimeoutErrno::Etimedout)
    );
}

#[test]
fn bound_timeout_abort_policy_preserves_etimedout_failure() {
    let binding = binding();
    let plan = plan_transaction_timeout(
        &LcsLimits::default(),
        TransactionState::ActiveBound(binding),
        false,
    )
    .unwrap();

    assert_eq!(plan.final_state, TransactionState::TimedOut);
    assert_eq!(plan.binding, Some(binding));
    assert!(plan.wake_poll_waiters);
    assert!(plan.fd_remains_present);
    assert!(plan.dispatch_source_abort);
    assert_eq!(
        plan.kernel_effects,
        Some(TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents)
    );
    assert_eq!(
        transaction_timeout_errno(plan.future_operation_failure.unwrap()),
        Some(TransactionTimeoutErrno::Etimedout)
    );
}

#[test]
fn in_flight_commit_timeout_retains_late_commit_uncertainty() {
    let binding = binding();
    let plan = plan_transaction_timeout(
        &LcsLimits::default(),
        TransactionState::ActiveBound(binding),
        true,
    )
    .unwrap();

    assert_eq!(plan.final_state, TransactionState::TimedOut);
    assert_eq!(plan.binding, Some(binding));
    assert!(plan.wake_poll_waiters);
    assert!(plan.fd_remains_present);
    assert!(!plan.dispatch_source_abort);
    assert_eq!(
        plan.kernel_effects,
        Some(TransactionKernelEffectsPlan::RetainMutationLogForLateResponse)
    );
    assert_eq!(
        transaction_timeout_errno(plan.future_operation_failure.unwrap()),
        Some(TransactionTimeoutErrno::Etimedout)
    );
}

#[test]
fn timed_out_terminal_state_poll_and_failure_class_remain_consistent() {
    assert_eq!(
        plan_transaction_poll(TransactionState::TimedOut),
        TransactionPollPlan {
            readable: false,
            writable: false,
            hangup: true,
            error: true,
        }
    );
    assert_eq!(
        transaction_terminal_failure(TransactionState::TimedOut),
        Some(TransactionUseFailure::TimedOut)
    );
    assert_eq!(
        transaction_timeout_errno(TransactionUseFailure::TimedOut),
        Some(TransactionTimeoutErrno::Etimedout)
    );
}

#[test]
fn non_timeout_transaction_failures_do_not_claim_etimedout() {
    for failure in [
        TransactionUseFailure::Invalid,
        TransactionUseFailure::SourceDown,
        TransactionUseFailure::CrossHive,
        TransactionUseFailure::Busy,
        TransactionUseFailure::NotSupported,
    ] {
        assert_eq!(transaction_timeout_errno(failure), None);
    }
}
