use lcs_core::{
    LcsError, LcsLimits, TransactionFdPublicationPlan, TransactionIdCounter, TransactionState,
    plan_begin_transaction_fd,
};

#[test]
fn begin_transaction_fd_plan_is_source_agnostic_and_publishes_active_unbound_fd() {
    let limits = LcsLimits::default();
    let mut counter = TransactionIdCounter::new();

    assert_eq!(
        plan_begin_transaction_fd(&limits, &mut counter),
        Ok(TransactionFdPublicationPlan {
            transaction_id: 1,
            initial_state: TransactionState::ActiveUnbound,
            timeout_ms: limits.transaction_timeout_ms,
            publish_anonymous_fd: true,
            start_timeout_timer: true,
            source_contact_required: false,
            close_without_commit_aborts: true,
        })
    );
    assert_eq!(counter.next_id(), 2);
}

#[test]
fn begin_transaction_fd_plan_allocates_monotonic_ids() {
    let limits = LcsLimits::default();
    let mut counter = TransactionIdCounter::from_next_id(41).expect("valid counter");

    let first = plan_begin_transaction_fd(&limits, &mut counter).expect("first id");
    let second = plan_begin_transaction_fd(&limits, &mut counter).expect("second id");

    assert_eq!(first.transaction_id, 41);
    assert_eq!(second.transaction_id, 42);
    assert_eq!(counter.next_id(), 43);
}

#[test]
fn begin_transaction_fd_plan_fails_closed_on_id_overflow() {
    let limits = LcsLimits::default();
    let mut counter = TransactionIdCounter::from_next_id(u64::MAX).expect("max counter");

    assert_eq!(
        plan_begin_transaction_fd(&limits, &mut counter),
        Err(LcsError::TransactionIdOverflow)
    );
    assert_eq!(counter.next_id(), u64::MAX);
}
