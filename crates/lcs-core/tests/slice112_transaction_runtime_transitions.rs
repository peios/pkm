use lcs_core::{
    LcsError, LcsLimits, TransactionBinding, TransactionKernelEffectsPlan,
    TransactionRuntimeTransitionPlan, TransactionState, TransactionUseFailure,
    plan_transaction_bound_source_down, plan_transaction_timeout,
};

const ROOT_GUID: [u8; 16] = [0x44; 16];

fn binding() -> TransactionBinding<'static> {
    TransactionBinding {
        source_id: 17,
        hive_name: "Machine",
        hive_root_guid: ROOT_GUID,
    }
}

#[test]
fn timeout_marks_unbound_transaction_timed_out_without_source_abort() {
    assert_eq!(
        plan_transaction_timeout(
            &LcsLimits::default(),
            TransactionState::ActiveUnbound,
            false
        ),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::TimedOut,
            binding: None,
            state_changed: true,
            wake_poll_waiters: true,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::TimedOut),
            dispatch_source_abort: false,
            kernel_effects: Some(TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents),
        })
    );
}

#[test]
fn timeout_aborts_bound_transaction_when_commit_is_not_in_flight() {
    let binding = binding();

    assert_eq!(
        plan_transaction_timeout(
            &LcsLimits::default(),
            TransactionState::ActiveBound(binding),
            false,
        ),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::TimedOut,
            binding: Some(binding),
            state_changed: true,
            wake_poll_waiters: true,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::TimedOut),
            dispatch_source_abort: true,
            kernel_effects: Some(TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents),
        })
    );
}

#[test]
fn timeout_with_in_flight_commit_retains_log_for_late_response() {
    let binding = binding();

    assert_eq!(
        plan_transaction_timeout(
            &LcsLimits::default(),
            TransactionState::ActiveBound(binding),
            true,
        ),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::TimedOut,
            binding: Some(binding),
            state_changed: true,
            wake_poll_waiters: true,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::TimedOut),
            dispatch_source_abort: false,
            kernel_effects: Some(TransactionKernelEffectsPlan::RetainMutationLogForLateResponse),
        })
    );
}

#[test]
fn timeout_callback_is_noop_after_terminal_transition() {
    assert_eq!(
        plan_transaction_timeout(&LcsLimits::default(), TransactionState::Committed, false),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::Committed,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::Invalid),
            dispatch_source_abort: false,
            kernel_effects: None,
        })
    );
}

#[test]
fn source_down_marks_bound_transaction_source_down_and_discards_log() {
    let binding = binding();

    assert_eq!(
        plan_transaction_bound_source_down(
            &LcsLimits::default(),
            TransactionState::ActiveBound(binding),
        ),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::SourceDown,
            binding: Some(binding),
            state_changed: true,
            wake_poll_waiters: true,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::SourceDown),
            dispatch_source_abort: false,
            kernel_effects: Some(TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents),
        })
    );
}

#[test]
fn source_down_does_not_affect_unbound_or_terminal_transactions() {
    assert_eq!(
        plan_transaction_bound_source_down(&LcsLimits::default(), TransactionState::ActiveUnbound),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::ActiveUnbound,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: None,
            dispatch_source_abort: false,
            kernel_effects: None,
        })
    );
    assert_eq!(
        plan_transaction_bound_source_down(&LcsLimits::default(), TransactionState::TimedOut),
        Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::TimedOut,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: Some(TransactionUseFailure::TimedOut),
            dispatch_source_abort: false,
            kernel_effects: None,
        })
    );
}

#[test]
fn runtime_transitions_fail_closed_on_corrupt_bound_state() {
    let corrupt = TransactionBinding {
        source_id: 17,
        hive_name: "Machine",
        hive_root_guid: [0; 16],
    };

    assert_eq!(
        plan_transaction_timeout(
            &LcsLimits::default(),
            TransactionState::ActiveBound(corrupt),
            false,
        ),
        Err(LcsError::NilHiveRootGuid)
    );
    assert_eq!(
        plan_transaction_bound_source_down(
            &LcsLimits::default(),
            TransactionState::ActiveBound(corrupt),
        ),
        Err(LcsError::NilHiveRootGuid)
    );
    assert_eq!(
        plan_transaction_timeout(&LcsLimits::default(), TransactionState::ActiveUnbound, true),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}
