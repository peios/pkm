use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::constants::{
    REG_TXN_ABORTED, REG_TXN_ACTIVE_BOUND, REG_TXN_ACTIVE_UNBOUND, REG_TXN_COMMITTED,
    REG_TXN_SOURCE_DOWN, REG_TXN_TIMED_OUT,
};
use crate::error::{LcsError, LcsResult};
use crate::hives::SourceId;
use crate::path::validate_hive_name_bytes;
use crate::resolution::Guid;
use crate::source::NIL_GUID;

/// Kernel-internal transaction identifier.
pub type TransactionId = u64;

/// Source/hive binding selected by the first mutating operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBinding<'a> {
    pub source_id: SourceId,
    pub hive_name: &'a str,
    pub hive_root_guid: Guid,
}

/// LCS-visible transaction state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState<'a> {
    ActiveUnbound,
    ActiveBound(TransactionBinding<'a>),
    Committed,
    Aborted,
    TimedOut,
    SourceDown,
}

/// Terminal errno class reported by REG_IOC_TXN_STATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionTerminalErrno {
    None,
    Invalid,
    TimedOut,
    Io,
}

/// Result payload for REG_IOC_TXN_STATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionStatusResult {
    pub state_code: u32,
    pub terminal_errno: TransactionTerminalErrno,
}

/// Transaction fd poll readiness bits expressed without platform poll constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionPollPlan {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    pub error: bool,
}

/// Pre-dispatch failure class for operations using a transaction fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionUseFailure {
    Invalid,
    TimedOut,
    SourceDown,
    CrossHive,
    Busy,
    NotSupported,
}

/// Source-dispatch-ready commit precheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionCommitPlan<'a> {
    pub binding: TransactionBinding<'a>,
}

/// Binding decision for a mutating operation using a transaction fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionMutationBindingPlan<'a> {
    BindNew(TransactionBinding<'a>),
    UseExisting(TransactionBinding<'a>),
}

/// Read context selected for a read ioctl with an optional transaction fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionReadPlan<'a> {
    NonTransactional,
    Transactional(TransactionBinding<'a>),
}

/// Transaction lifetime event that determines mutation-log side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionCompletionEvent {
    CommitSucceeded,
    ExplicitAbort,
    TimeoutBeforeCommitDispatch,
    SourceDownCancellation,
    CommitRequestTimedOutAfterDispatch,
    LateCommitSucceeded,
    LateCommitFailed,
    SourceConnectionTornDownAfterCommitTimeout,
}

/// Kernel-owned transaction mutation-log disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionKernelEffectsPlan {
    ApplyMutationLogAndEmitCommitEffects,
    DiscardMutationLogWithoutEvents,
    RetainMutationLogForOpenTransaction,
    RetainMutationLogForLateResponse,
}

/// Synchronous source response to an in-flight REG_IOC_COMMIT request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionCommitSourceResponse {
    Committed,
    SourceBusy,
    SourceFailed,
}

/// Caller-visible result class for a synchronous REG_IOC_COMMIT source response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionCommitReturnStatus {
    Success,
    Busy,
    Io,
}

/// Planned transaction object effects for a synchronous source commit response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionCommitResponsePlan<'a> {
    pub final_state: TransactionState<'a>,
    pub state_changed: bool,
    pub wake_poll_waiters: bool,
    pub return_status: TransactionCommitReturnStatus,
    pub kernel_effects: TransactionKernelEffectsPlan,
}

/// Monotonic non-zero transaction ID allocator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionIdCounter {
    next_id: TransactionId,
}

impl TransactionIdCounter {
    pub const fn new() -> Self {
        Self { next_id: 1 }
    }

    pub fn from_next_id(next_id: TransactionId) -> LcsResult<Self> {
        if next_id == 0 {
            return Err(LcsError::InvalidTransactionId);
        }
        Ok(Self { next_id })
    }

    pub const fn next_id(&self) -> TransactionId {
        self.next_id
    }

    pub fn allocate(&mut self) -> LcsResult<TransactionId> {
        if self.next_id == TransactionId::MAX {
            return Err(LcsError::TransactionIdOverflow);
        }
        let allocated = self.next_id;
        self.next_id += 1;
        Ok(allocated)
    }
}

impl Default for TransactionIdCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Planned result of reg_begin_transaction before anonymous fd publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartedTransaction {
    pub transaction_id: TransactionId,
    pub state: TransactionState<'static>,
    pub timeout_ms: u32,
    pub start_timeout_timer: bool,
}

/// Planned transaction fd publication for `reg_begin_transaction`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFdPublicationPlan {
    pub transaction_id: TransactionId,
    pub initial_state: TransactionState<'static>,
    pub timeout_ms: u32,
    pub publish_anonymous_fd: bool,
    pub start_timeout_timer: bool,
    pub source_contact_required: bool,
    pub close_without_commit_aborts: bool,
}

/// Planned cleanup when a transaction fd is closed by normal Linux fd teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFdClosePlan<'a> {
    pub final_state: TransactionState<'a>,
    pub binding: Option<TransactionBinding<'a>>,
    pub dispatch_source_abort: bool,
    pub discard_mutation_log: bool,
    pub wake_poll_waiters: bool,
    pub release_fd_object: bool,
}

/// Planned effects when a transaction runtime event changes or observes state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionRuntimeTransitionPlan<'a> {
    pub final_state: TransactionState<'a>,
    pub binding: Option<TransactionBinding<'a>>,
    pub state_changed: bool,
    pub wake_poll_waiters: bool,
    pub fd_remains_present: bool,
    pub future_operation_failure: Option<TransactionUseFailure>,
    pub dispatch_source_abort: bool,
    pub kernel_effects: Option<TransactionKernelEffectsPlan>,
}

/// Per-source bound-transaction counter mutation selected by live state code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionBoundCounterUpdate {
    NoChange,
    Increment,
    Decrement,
}

/// Planned per-source bound-transaction counter result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBoundCounterPlan {
    pub update: TransactionBoundCounterUpdate,
    pub previous_count: usize,
    pub next_count: usize,
}

/// Planned counter mutation selected from a transaction state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBoundCounterTransitionPlan<'a> {
    pub affected_binding: Option<TransactionBinding<'a>>,
    pub counter: TransactionBoundCounterPlan,
}

/// Plans reg_begin_transaction without selecting a source.
pub fn plan_begin_transaction(
    limits: &LcsLimits,
    counter: &mut TransactionIdCounter,
) -> LcsResult<StartedTransaction> {
    Ok(StartedTransaction {
        transaction_id: counter.allocate()?,
        state: TransactionState::ActiveUnbound,
        timeout_ms: limits.transaction_timeout_ms,
        start_timeout_timer: true,
    })
}

/// Plans the full semantic fd publication result of `reg_begin_transaction`.
pub fn plan_begin_transaction_fd(
    limits: &LcsLimits,
    counter: &mut TransactionIdCounter,
) -> LcsResult<TransactionFdPublicationPlan> {
    let started = plan_begin_transaction(limits, counter)?;
    Ok(TransactionFdPublicationPlan {
        transaction_id: started.transaction_id,
        initial_state: started.state,
        timeout_ms: started.timeout_ms,
        publish_anonymous_fd: true,
        start_timeout_timer: started.start_timeout_timer,
        source_contact_required: false,
        close_without_commit_aborts: true,
    })
}

/// Plans transaction-fd release side effects for close(), close-on-exec, or process exit.
pub fn plan_transaction_fd_close<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
) -> LcsResult<TransactionFdClosePlan<'a>> {
    match state {
        TransactionState::ActiveUnbound => Ok(TransactionFdClosePlan {
            final_state: TransactionState::Aborted,
            binding: None,
            dispatch_source_abort: false,
            discard_mutation_log: true,
            wake_poll_waiters: true,
            release_fd_object: true,
        }),
        TransactionState::ActiveBound(binding) => {
            validate_transaction_binding(limits, binding)?;
            Ok(TransactionFdClosePlan {
                final_state: TransactionState::Aborted,
                binding: Some(binding),
                dispatch_source_abort: true,
                discard_mutation_log: true,
                wake_poll_waiters: true,
                release_fd_object: true,
            })
        }
        terminal @ (TransactionState::Committed
        | TransactionState::Aborted
        | TransactionState::TimedOut
        | TransactionState::SourceDown) => Ok(TransactionFdClosePlan {
            final_state: terminal,
            binding: None,
            dispatch_source_abort: false,
            discard_mutation_log: false,
            wake_poll_waiters: false,
            release_fd_object: true,
        }),
    }
}

/// Shapes the REG_IOC_TXN_STATUS output payload from stored state.
pub fn transaction_status(state: TransactionState<'_>) -> TransactionStatusResult {
    match state {
        TransactionState::ActiveUnbound => TransactionStatusResult {
            state_code: REG_TXN_ACTIVE_UNBOUND,
            terminal_errno: TransactionTerminalErrno::None,
        },
        TransactionState::ActiveBound(_) => TransactionStatusResult {
            state_code: REG_TXN_ACTIVE_BOUND,
            terminal_errno: TransactionTerminalErrno::None,
        },
        TransactionState::Committed => TransactionStatusResult {
            state_code: REG_TXN_COMMITTED,
            terminal_errno: TransactionTerminalErrno::None,
        },
        TransactionState::Aborted => TransactionStatusResult {
            state_code: REG_TXN_ABORTED,
            terminal_errno: TransactionTerminalErrno::Invalid,
        },
        TransactionState::TimedOut => TransactionStatusResult {
            state_code: REG_TXN_TIMED_OUT,
            terminal_errno: TransactionTerminalErrno::TimedOut,
        },
        TransactionState::SourceDown => TransactionStatusResult {
            state_code: REG_TXN_SOURCE_DOWN,
            terminal_errno: TransactionTerminalErrno::Io,
        },
    }
}

/// Returns the failure future read/mutating operations must report for a state.
pub fn transaction_terminal_failure(state: TransactionState<'_>) -> Option<TransactionUseFailure> {
    match state {
        TransactionState::ActiveUnbound | TransactionState::ActiveBound(_) => None,
        TransactionState::Committed | TransactionState::Aborted => {
            Some(TransactionUseFailure::Invalid)
        }
        TransactionState::TimedOut => Some(TransactionUseFailure::TimedOut),
        TransactionState::SourceDown => Some(TransactionUseFailure::SourceDown),
    }
}

/// Plans transaction-fd poll readiness from the transaction state.
pub fn plan_transaction_poll(state: TransactionState<'_>) -> TransactionPollPlan {
    match state {
        TransactionState::ActiveUnbound | TransactionState::ActiveBound(_) => TransactionPollPlan {
            readable: false,
            writable: false,
            hangup: false,
            error: false,
        },
        TransactionState::Committed
        | TransactionState::Aborted
        | TransactionState::TimedOut
        | TransactionState::SourceDown => TransactionPollPlan {
            readable: false,
            writable: false,
            hangup: true,
            error: true,
        },
    }
}

/// Prechecks REG_IOC_COMMIT before dispatching to the bound source.
pub fn plan_transaction_commit(
    state: TransactionState<'_>,
) -> Result<TransactionCommitPlan<'_>, TransactionUseFailure> {
    match state {
        TransactionState::ActiveBound(binding) => Ok(TransactionCommitPlan { binding }),
        TransactionState::TimedOut => Err(TransactionUseFailure::TimedOut),
        TransactionState::SourceDown => Err(TransactionUseFailure::SourceDown),
        TransactionState::ActiveUnbound
        | TransactionState::Committed
        | TransactionState::Aborted => Err(TransactionUseFailure::Invalid),
    }
}

/// Plans first-bind or existing-bind behavior for transactional mutations.
pub fn plan_transaction_mutation_binding<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
    target: TransactionBinding<'a>,
    source_supports_transactions: bool,
    current_bound_transactions_for_source: usize,
) -> Result<TransactionMutationBindingPlan<'a>, TransactionUseFailure> {
    validate_transaction_binding(limits, target).map_err(|_| TransactionUseFailure::Invalid)?;
    match state {
        TransactionState::ActiveUnbound => {
            if !source_supports_transactions {
                return Err(TransactionUseFailure::NotSupported);
            }
            if current_bound_transactions_for_source >= limits.max_bound_transactions_per_source {
                return Err(TransactionUseFailure::Busy);
            }
            Ok(TransactionMutationBindingPlan::BindNew(target))
        }
        TransactionState::ActiveBound(existing) => {
            if same_transaction_binding(limits, existing, target)
                .map_err(|_| TransactionUseFailure::Invalid)?
            {
                Ok(TransactionMutationBindingPlan::UseExisting(existing))
            } else {
                Err(TransactionUseFailure::CrossHive)
            }
        }
        TransactionState::Committed | TransactionState::Aborted => {
            Err(TransactionUseFailure::Invalid)
        }
        TransactionState::TimedOut => Err(TransactionUseFailure::TimedOut),
        TransactionState::SourceDown => Err(TransactionUseFailure::SourceDown),
    }
}

/// Plans read behavior when a read ioctl is supplied a transaction fd.
pub fn plan_transaction_read<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
    target: TransactionBinding<'a>,
) -> Result<TransactionReadPlan<'a>, TransactionUseFailure> {
    validate_transaction_binding(limits, target).map_err(|_| TransactionUseFailure::Invalid)?;
    match state {
        TransactionState::ActiveUnbound => Ok(TransactionReadPlan::NonTransactional),
        TransactionState::ActiveBound(existing) => {
            if same_transaction_binding(limits, existing, target)
                .map_err(|_| TransactionUseFailure::Invalid)?
            {
                Ok(TransactionReadPlan::Transactional(existing))
            } else {
                Err(TransactionUseFailure::CrossHive)
            }
        }
        TransactionState::Committed | TransactionState::Aborted => {
            Err(TransactionUseFailure::Invalid)
        }
        TransactionState::TimedOut => Err(TransactionUseFailure::TimedOut),
        TransactionState::SourceDown => Err(TransactionUseFailure::SourceDown),
    }
}

/// Plans transaction mutation-log effects after a terminal or pending commit event.
pub fn plan_transaction_completion_effects(
    event: TransactionCompletionEvent,
) -> TransactionKernelEffectsPlan {
    match event {
        TransactionCompletionEvent::CommitSucceeded
        | TransactionCompletionEvent::LateCommitSucceeded => {
            TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects
        }
        TransactionCompletionEvent::CommitRequestTimedOutAfterDispatch => {
            TransactionKernelEffectsPlan::RetainMutationLogForLateResponse
        }
        TransactionCompletionEvent::ExplicitAbort
        | TransactionCompletionEvent::TimeoutBeforeCommitDispatch
        | TransactionCompletionEvent::SourceDownCancellation
        | TransactionCompletionEvent::LateCommitFailed
        | TransactionCompletionEvent::SourceConnectionTornDownAfterCommitTimeout => {
            TransactionKernelEffectsPlan::DiscardMutationLogWithoutEvents
        }
    }
}

/// Plans the synchronous response path for REG_IOC_COMMIT after source dispatch.
pub fn plan_transaction_commit_response<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
    response: TransactionCommitSourceResponse,
) -> LcsResult<TransactionCommitResponsePlan<'a>> {
    let TransactionState::ActiveBound(binding) = state else {
        return Err(LcsError::InvalidTransactionRuntimeState);
    };
    validate_transaction_binding(limits, binding)?;

    match response {
        TransactionCommitSourceResponse::Committed => Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::Committed,
            state_changed: true,
            wake_poll_waiters: true,
            return_status: TransactionCommitReturnStatus::Success,
            kernel_effects: TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
        }),
        TransactionCommitSourceResponse::SourceBusy => Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::ActiveBound(binding),
            state_changed: false,
            wake_poll_waiters: false,
            return_status: TransactionCommitReturnStatus::Busy,
            kernel_effects: TransactionKernelEffectsPlan::RetainMutationLogForOpenTransaction,
        }),
        TransactionCommitSourceResponse::SourceFailed => Ok(TransactionCommitResponsePlan {
            final_state: TransactionState::ActiveBound(binding),
            state_changed: false,
            wake_poll_waiters: false,
            return_status: TransactionCommitReturnStatus::Io,
            kernel_effects: TransactionKernelEffectsPlan::RetainMutationLogForOpenTransaction,
        }),
    }
}

/// Plans the transaction lifetime timer firing for an active or terminal fd object.
pub fn plan_transaction_timeout<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
    commit_in_flight: bool,
) -> LcsResult<TransactionRuntimeTransitionPlan<'a>> {
    match state {
        TransactionState::ActiveUnbound => {
            if commit_in_flight {
                return Err(LcsError::InvalidTransactionRuntimeState);
            }
            Ok(TransactionRuntimeTransitionPlan {
                final_state: TransactionState::TimedOut,
                binding: None,
                state_changed: true,
                wake_poll_waiters: true,
                fd_remains_present: true,
                future_operation_failure: Some(TransactionUseFailure::TimedOut),
                dispatch_source_abort: false,
                kernel_effects: Some(plan_transaction_completion_effects(
                    TransactionCompletionEvent::TimeoutBeforeCommitDispatch,
                )),
            })
        }
        TransactionState::ActiveBound(binding) => {
            validate_transaction_binding(limits, binding)?;
            Ok(TransactionRuntimeTransitionPlan {
                final_state: TransactionState::TimedOut,
                binding: Some(binding),
                state_changed: true,
                wake_poll_waiters: true,
                fd_remains_present: true,
                future_operation_failure: Some(TransactionUseFailure::TimedOut),
                dispatch_source_abort: !commit_in_flight,
                kernel_effects: Some(plan_transaction_completion_effects(if commit_in_flight {
                    TransactionCompletionEvent::CommitRequestTimedOutAfterDispatch
                } else {
                    TransactionCompletionEvent::TimeoutBeforeCommitDispatch
                })),
            })
        }
        terminal @ (TransactionState::Committed
        | TransactionState::Aborted
        | TransactionState::TimedOut
        | TransactionState::SourceDown) => Ok(TransactionRuntimeTransitionPlan {
            final_state: terminal,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: transaction_terminal_failure(terminal),
            dispatch_source_abort: false,
            kernel_effects: None,
        }),
    }
}

/// Plans the transition for a transaction already bound to a source that went Down.
pub fn plan_transaction_bound_source_down<'a>(
    limits: &LcsLimits,
    state: TransactionState<'a>,
) -> LcsResult<TransactionRuntimeTransitionPlan<'a>> {
    match state {
        TransactionState::ActiveBound(binding) => {
            validate_transaction_binding(limits, binding)?;
            Ok(TransactionRuntimeTransitionPlan {
                final_state: TransactionState::SourceDown,
                binding: Some(binding),
                state_changed: true,
                wake_poll_waiters: true,
                fd_remains_present: true,
                future_operation_failure: Some(TransactionUseFailure::SourceDown),
                dispatch_source_abort: false,
                kernel_effects: Some(plan_transaction_completion_effects(
                    TransactionCompletionEvent::SourceDownCancellation,
                )),
            })
        }
        TransactionState::ActiveUnbound => Ok(TransactionRuntimeTransitionPlan {
            final_state: TransactionState::ActiveUnbound,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: None,
            dispatch_source_abort: false,
            kernel_effects: None,
        }),
        terminal @ (TransactionState::Committed
        | TransactionState::Aborted
        | TransactionState::TimedOut
        | TransactionState::SourceDown) => Ok(TransactionRuntimeTransitionPlan {
            final_state: terminal,
            binding: None,
            state_changed: false,
            wake_poll_waiters: false,
            fd_remains_present: true,
            future_operation_failure: transaction_terminal_failure(terminal),
            dispatch_source_abort: false,
            kernel_effects: None,
        }),
    }
}

/// Plans mutation of the per-source count of currently bound transactions.
pub fn plan_transaction_bound_counter_update(
    limits: &LcsLimits,
    current_bound_transactions_for_source: usize,
    update: TransactionBoundCounterUpdate,
) -> LcsResult<TransactionBoundCounterPlan> {
    match update {
        TransactionBoundCounterUpdate::NoChange => Ok(TransactionBoundCounterPlan {
            update,
            previous_count: current_bound_transactions_for_source,
            next_count: current_bound_transactions_for_source,
        }),
        TransactionBoundCounterUpdate::Increment => {
            if current_bound_transactions_for_source >= limits.max_bound_transactions_per_source {
                return Err(LcsError::InvalidTransactionRuntimeState);
            }
            Ok(TransactionBoundCounterPlan {
                update,
                previous_count: current_bound_transactions_for_source,
                next_count: current_bound_transactions_for_source + 1,
            })
        }
        TransactionBoundCounterUpdate::Decrement => {
            let next_count = current_bound_transactions_for_source
                .checked_sub(1)
                .ok_or(LcsError::InvalidTransactionRuntimeState)?;
            Ok(TransactionBoundCounterPlan {
                update,
                previous_count: current_bound_transactions_for_source,
                next_count,
            })
        }
    }
}

/// Selects the per-source bound-transaction counter update for a state transition.
pub fn plan_transaction_bound_counter_transition<'a>(
    limits: &LcsLimits,
    previous_state: TransactionState<'a>,
    next_state: TransactionState<'a>,
    current_bound_transactions_for_source: usize,
) -> LcsResult<TransactionBoundCounterTransitionPlan<'a>> {
    let (affected_binding, update) = match (previous_state, next_state) {
        (TransactionState::ActiveUnbound, TransactionState::ActiveUnbound) => {
            (None, TransactionBoundCounterUpdate::NoChange)
        }
        (TransactionState::ActiveUnbound, TransactionState::ActiveBound(next)) => {
            validate_transaction_binding(limits, next)?;
            (Some(next), TransactionBoundCounterUpdate::Increment)
        }
        (TransactionState::ActiveUnbound, next) if is_terminal_transaction_state(next) => {
            (None, TransactionBoundCounterUpdate::NoChange)
        }
        (TransactionState::ActiveBound(previous), TransactionState::ActiveBound(next)) => {
            if !same_transaction_binding(limits, previous, next)? {
                return Err(LcsError::InvalidTransactionRuntimeState);
            }
            (Some(previous), TransactionBoundCounterUpdate::NoChange)
        }
        (TransactionState::ActiveBound(previous), next) if is_terminal_transaction_state(next) => {
            validate_transaction_binding(limits, previous)?;
            (Some(previous), TransactionBoundCounterUpdate::Decrement)
        }
        (previous, next)
            if is_terminal_transaction_state(previous)
                && is_terminal_transaction_state(next)
                && previous == next =>
        {
            (None, TransactionBoundCounterUpdate::NoChange)
        }
        _ => return Err(LcsError::InvalidTransactionRuntimeState),
    };

    Ok(TransactionBoundCounterTransitionPlan {
        affected_binding,
        counter: plan_transaction_bound_counter_update(
            limits,
            current_bound_transactions_for_source,
            update,
        )?,
    })
}

fn validate_transaction_binding(
    limits: &LcsLimits,
    binding: TransactionBinding<'_>,
) -> LcsResult<()> {
    validate_hive_name_bytes(binding.hive_name.as_bytes(), limits)?;
    if binding.hive_root_guid == NIL_GUID {
        return Err(LcsError::NilHiveRootGuid);
    }
    Ok(())
}

fn same_transaction_binding(
    limits: &LcsLimits,
    left: TransactionBinding<'_>,
    right: TransactionBinding<'_>,
) -> LcsResult<bool> {
    validate_transaction_binding(limits, left)?;
    validate_transaction_binding(limits, right)?;
    Ok(left.source_id == right.source_id
        && left.hive_root_guid == right.hive_root_guid
        && casefold_eq(left.hive_name, right.hive_name))
}

fn is_terminal_transaction_state(state: TransactionState<'_>) -> bool {
    matches!(
        state,
        TransactionState::Committed
            | TransactionState::Aborted
            | TransactionState::TimedOut
            | TransactionState::SourceDown
    )
}
