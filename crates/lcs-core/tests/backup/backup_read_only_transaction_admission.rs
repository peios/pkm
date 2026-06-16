use lcs_core::{
    BackupReadOnlySnapshotReleaseReason, LcsError, LcsLimits, RSI_TXN_READ_ONLY,
    ReadOnlySnapshotCounterUpdate, TransactionIdCounter, plan_backup_read_only_snapshot_admission,
    plan_backup_read_only_snapshot_release, plan_read_only_snapshot_counter_update,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn backup_read_only_snapshot_begin_reserves_slot_and_uses_read_only_mode() {
    let limits = limits();
    let mut counter = TransactionIdCounter::from_next_id(42).unwrap();

    let plan = plan_backup_read_only_snapshot_admission(&limits, &mut counter, 2).unwrap();

    assert_eq!(plan.transaction_id, 42);
    assert_eq!(counter.next_id(), 43);
    assert_eq!(plan.source_transaction_mode, RSI_TXN_READ_ONLY);
    assert!(plan.dispatch_begin_transaction);
    assert!(plan.release_with_abort_transaction);
    assert!(!plan.dispatch_commit_transaction);
    assert!(!plan.affects_bound_transaction_counter);
    assert_eq!(
        plan.counter.update,
        ReadOnlySnapshotCounterUpdate::Increment
    );
    assert_eq!(plan.counter.previous_count, 2);
    assert_eq!(plan.counter.next_count, 3);
}

#[test]
fn backup_read_only_snapshot_begin_at_cap_fails_before_id_allocation() {
    let limits = limits();
    let mut counter = TransactionIdCounter::from_next_id(100).unwrap();

    assert_eq!(
        plan_backup_read_only_snapshot_admission(
            &limits,
            &mut counter,
            limits.max_read_only_transactions_per_source,
        ),
        Err(LcsError::TooManyReadOnlyTransactions {
            count: limits.max_read_only_transactions_per_source,
            max: limits.max_read_only_transactions_per_source,
        })
    );
    assert_eq!(counter.next_id(), 100);
}

#[test]
fn backup_read_only_snapshot_release_decrements_and_aborts_when_source_transaction_exists() {
    let limits = limits();

    for reason in [
        BackupReadOnlySnapshotReleaseReason::BackupCompleted,
        BackupReadOnlySnapshotReleaseReason::BackupFailed,
    ] {
        let plan = plan_backup_read_only_snapshot_release(&limits, 4, reason).unwrap();

        assert_eq!(plan.reason, reason);
        assert!(plan.dispatch_abort_transaction);
        assert!(!plan.dispatch_commit_transaction);
        assert!(!plan.affects_bound_transaction_counter);
        assert_eq!(
            plan.counter.update,
            ReadOnlySnapshotCounterUpdate::Decrement
        );
        assert_eq!(plan.counter.previous_count, 4);
        assert_eq!(plan.counter.next_count, 3);
    }
}

#[test]
fn backup_read_only_snapshot_release_without_source_transaction_only_releases_reservation() {
    let limits = limits();

    for reason in [
        BackupReadOnlySnapshotReleaseReason::SourceBeginFailed,
        BackupReadOnlySnapshotReleaseReason::SourceConnectionTornDown,
    ] {
        let plan = plan_backup_read_only_snapshot_release(&limits, 1, reason).unwrap();

        assert_eq!(plan.reason, reason);
        assert!(!plan.dispatch_abort_transaction);
        assert!(!plan.dispatch_commit_transaction);
        assert!(!plan.affects_bound_transaction_counter);
        assert_eq!(plan.counter.previous_count, 1);
        assert_eq!(plan.counter.next_count, 0);
    }
}

#[test]
fn backup_read_only_snapshot_release_underflow_fails_closed() {
    let limits = limits();

    assert_eq!(
        plan_backup_read_only_snapshot_release(
            &limits,
            0,
            BackupReadOnlySnapshotReleaseReason::BackupCompleted,
        ),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}

#[test]
fn read_only_snapshot_counter_no_change_is_explicit_and_separate() {
    let limits = limits();

    let plan =
        plan_read_only_snapshot_counter_update(&limits, 7, ReadOnlySnapshotCounterUpdate::NoChange)
            .unwrap();

    assert_eq!(plan.update, ReadOnlySnapshotCounterUpdate::NoChange);
    assert_eq!(plan.previous_count, 7);
    assert_eq!(plan.next_count, 7);
}
