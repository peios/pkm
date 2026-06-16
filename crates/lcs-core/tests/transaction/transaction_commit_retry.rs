use lcs_core::{
    LcsError, LcsLimits, TransactionBinding, TransactionCommitResponsePlan,
    TransactionCommitReturnStatus, TransactionCommitSourceResponse, TransactionKernelEffectsPlan,
    TransactionState, plan_transaction_commit_response,
};

const HIVE_ROOT: [u8; 16] = [0x44; 16];

fn binding() -> TransactionBinding<'static> {
    TransactionBinding {
        source_id: 7,
        hive_name: "Machine",
        hive_root_guid: HIVE_ROOT,
    }
}

#[test]
fn successful_commit_response_enters_terminal_committed_state() {
    assert_eq!(
        plan_transaction_commit_response(
            &LcsLimits::default(),
            TransactionState::ActiveBound(binding()),
            TransactionCommitSourceResponse::Committed,
        ),
        Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::Committed,
            state_changed: true,
            wake_poll_waiters: true,
            return_status: TransactionCommitReturnStatus::Success,
            kernel_effects: TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
        })
    );
}

#[test]
fn retryable_busy_commit_response_keeps_transaction_open_and_retains_log() {
    let tx_binding = binding();

    assert_eq!(
        plan_transaction_commit_response(
            &LcsLimits::default(),
            TransactionState::ActiveBound(tx_binding),
            TransactionCommitSourceResponse::SourceBusy,
        ),
        Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::ActiveBound(tx_binding),
            state_changed: false,
            wake_poll_waiters: false,
            return_status: TransactionCommitReturnStatus::Busy,
            kernel_effects: TransactionKernelEffectsPlan::RetainMutationLogForOpenTransaction,
        })
    );
}

#[test]
fn synchronous_failed_commit_response_keeps_transaction_open_and_retains_log() {
    let tx_binding = binding();

    assert_eq!(
        plan_transaction_commit_response(
            &LcsLimits::default(),
            TransactionState::ActiveBound(tx_binding),
            TransactionCommitSourceResponse::SourceFailed,
        ),
        Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::ActiveBound(tx_binding),
            state_changed: false,
            wake_poll_waiters: false,
            return_status: TransactionCommitReturnStatus::Io,
            kernel_effects: TransactionKernelEffectsPlan::RetainMutationLogForOpenTransaction,
        })
    );
}

#[test]
fn commit_response_on_non_active_bound_state_fails_closed() {
    for state in [
        TransactionState::ActiveUnbound,
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ] {
        assert_eq!(
            plan_transaction_commit_response(
                &LcsLimits::default(),
                state,
                TransactionCommitSourceResponse::Committed,
            ),
            Err(LcsError::InvalidTransactionRuntimeState)
        );
    }
}

#[test]
fn corrupt_commit_response_binding_fails_closed() {
    assert_eq!(
        plan_transaction_commit_response(
            &LcsLimits::default(),
            TransactionState::ActiveBound(TransactionBinding {
                source_id: 7,
                hive_name: "Machine",
                hive_root_guid: [0; 16],
            }),
            TransactionCommitSourceResponse::Committed,
        ),
        Err(LcsError::NilHiveRootGuid)
    );
}
