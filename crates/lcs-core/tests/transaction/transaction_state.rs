use lcs_core::{
    LcsError, LcsLimits, REG_TXN_ABORTED, REG_TXN_ACTIVE_BOUND, REG_TXN_ACTIVE_UNBOUND,
    REG_TXN_COMMITTED, REG_TXN_SOURCE_DOWN, REG_TXN_TIMED_OUT, TransactionBinding,
    TransactionIdCounter, TransactionState, TransactionTerminalErrno, TransactionUseFailure,
    plan_begin_transaction, plan_transaction_commit, transaction_status,
    transaction_terminal_failure,
};

#[test]
fn transaction_id_counter_allocates_nonzero_monotonic_ids() {
    let mut counter = TransactionIdCounter::default();
    assert_eq!(counter.next_id(), 1);
    assert_eq!(counter.allocate(), Ok(1));
    assert_eq!(counter.allocate(), Ok(2));
    assert_eq!(counter.next_id(), 3);

    assert_eq!(
        TransactionIdCounter::from_next_id(0),
        Err(LcsError::InvalidTransactionId)
    );

    let mut exhausted = TransactionIdCounter::from_next_id(u64::MAX).expect("max is storable");
    assert_eq!(exhausted.allocate(), Err(LcsError::TransactionIdOverflow));
}

#[test]
fn begin_transaction_is_source_agnostic_and_starts_timeout() {
    let mut limits = LcsLimits::default();
    limits.transaction_timeout_ms = 12_345;
    let mut counter = TransactionIdCounter::from_next_id(7).expect("nonzero next id");

    let started =
        plan_begin_transaction(&limits, &mut counter).expect("begin should allocate transaction");
    assert_eq!(started.transaction_id, 7);
    assert_eq!(started.state, TransactionState::ActiveUnbound);
    assert_eq!(started.timeout_ms, 12_345);
    assert!(started.start_timeout_timer);
    assert_eq!(counter.next_id(), 8);
}

#[test]
fn transaction_status_maps_active_and_terminal_states() {
    let binding = TransactionBinding {
        source_id: 3,
        hive_name: "Machine",
        hive_root_guid: [0x11; 16],
    };
    let cases = [
        (
            TransactionState::ActiveUnbound,
            REG_TXN_ACTIVE_UNBOUND,
            TransactionTerminalErrno::None,
        ),
        (
            TransactionState::ActiveBound(binding),
            REG_TXN_ACTIVE_BOUND,
            TransactionTerminalErrno::None,
        ),
        (
            TransactionState::Committed,
            REG_TXN_COMMITTED,
            TransactionTerminalErrno::None,
        ),
        (
            TransactionState::Aborted,
            REG_TXN_ABORTED,
            TransactionTerminalErrno::Invalid,
        ),
        (
            TransactionState::TimedOut,
            REG_TXN_TIMED_OUT,
            TransactionTerminalErrno::TimedOut,
        ),
        (
            TransactionState::SourceDown,
            REG_TXN_SOURCE_DOWN,
            TransactionTerminalErrno::Io,
        ),
    ];

    for (state, state_code, terminal_errno) in cases {
        let status = transaction_status(state);
        assert_eq!(status.state_code, state_code);
        assert_eq!(status.terminal_errno, terminal_errno);
    }
}

#[test]
fn transaction_terminal_failure_classifies_future_operation_errors() {
    assert_eq!(
        transaction_terminal_failure(TransactionState::ActiveUnbound),
        None
    );
    assert_eq!(
        transaction_terminal_failure(TransactionState::Committed),
        Some(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        transaction_terminal_failure(TransactionState::Aborted),
        Some(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        transaction_terminal_failure(TransactionState::TimedOut),
        Some(TransactionUseFailure::TimedOut)
    );
    assert_eq!(
        transaction_terminal_failure(TransactionState::SourceDown),
        Some(TransactionUseFailure::SourceDown)
    );
}

#[test]
fn commit_precheck_requires_active_bound_transaction() {
    let binding = TransactionBinding {
        source_id: 9,
        hive_name: "Machine",
        hive_root_guid: [0x22; 16],
    };
    let commit =
        plan_transaction_commit(TransactionState::ActiveBound(binding)).expect("bound commit");
    assert_eq!(commit.binding, binding);

    assert_eq!(
        plan_transaction_commit(TransactionState::ActiveUnbound),
        Err(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        plan_transaction_commit(TransactionState::Committed),
        Err(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        plan_transaction_commit(TransactionState::Aborted),
        Err(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        plan_transaction_commit(TransactionState::TimedOut),
        Err(TransactionUseFailure::TimedOut)
    );
    assert_eq!(
        plan_transaction_commit(TransactionState::SourceDown),
        Err(TransactionUseFailure::SourceDown)
    );
}
