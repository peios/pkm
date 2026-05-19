use crate::config::LcsLimits;
use crate::constants::{
    REG_TXN_ABORTED, REG_TXN_ACTIVE_BOUND, REG_TXN_ACTIVE_UNBOUND, REG_TXN_COMMITTED,
    REG_TXN_SOURCE_DOWN, REG_TXN_TIMED_OUT,
};
use crate::error::{LcsError, LcsResult};
use crate::hives::SourceId;

/// Kernel-internal transaction identifier.
pub type TransactionId = u64;

/// Source/hive binding selected by the first mutating operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionBinding<'a> {
    pub source_id: SourceId,
    pub hive_name: &'a str,
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

/// Pre-dispatch failure class for operations using a transaction fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionUseFailure {
    Invalid,
    TimedOut,
    SourceDown,
}

/// Source-dispatch-ready commit precheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionCommitPlan<'a> {
    pub binding: TransactionBinding<'a>,
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
