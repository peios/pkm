use lcs_core::{
    LcsLimits, RsiMappedErrno, TransactionBinding, TransactionState, TransactionUseFailure,
    plan_transaction_mutation_binding, plan_transaction_read, transaction_use_failure_errno,
};

const MACHINE_ROOT: [u8; 16] = [0x11; 16];
const USERS_ROOT: [u8; 16] = [0x22; 16];

fn binding(
    source_id: u32,
    hive_name: &'static str,
    hive_root_guid: [u8; 16],
) -> TransactionBinding<'static> {
    TransactionBinding {
        source_id,
        hive_name,
        hive_root_guid,
    }
}

#[test]
fn transaction_use_failure_errno_covers_all_specified_classes() {
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::Invalid),
        RsiMappedErrno::Einval
    );
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::TimedOut),
        RsiMappedErrno::Etimedout
    );
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::SourceDown),
        RsiMappedErrno::Eio
    );
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::CrossHive),
        RsiMappedErrno::Exdev
    );
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::Busy),
        RsiMappedErrno::Ebusy
    );
    assert_eq!(
        transaction_use_failure_errno(TransactionUseFailure::NotSupported),
        RsiMappedErrno::Enotsup
    );
}

#[test]
fn read_transaction_failures_map_to_caller_visible_errno() {
    let limits = LcsLimits::default();
    let original = binding(7, "Machine", MACHINE_ROOT);
    let other = binding(7, "Users", USERS_ROOT);

    for (state, target, errno) in [
        (
            TransactionState::ActiveBound(original),
            other,
            RsiMappedErrno::Exdev,
        ),
        (
            TransactionState::Committed,
            original,
            RsiMappedErrno::Einval,
        ),
        (TransactionState::Aborted, original, RsiMappedErrno::Einval),
        (
            TransactionState::TimedOut,
            original,
            RsiMappedErrno::Etimedout,
        ),
        (TransactionState::SourceDown, original, RsiMappedErrno::Eio),
    ] {
        let failure = plan_transaction_read(&limits, state, target)
            .expect_err("read should fail for this transaction state");
        assert_eq!(transaction_use_failure_errno(failure), errno);
    }
}

#[test]
fn mutating_transaction_bind_failures_map_to_caller_visible_errno() {
    let mut limits = LcsLimits::default();
    limits.max_bound_transactions_per_source = 1;
    let target = binding(7, "Machine", MACHINE_ROOT);

    let unsupported = plan_transaction_mutation_binding(
        &limits,
        TransactionState::ActiveUnbound,
        target,
        false,
        0,
    )
    .expect_err("unsupported source should fail first bind");
    assert_eq!(
        transaction_use_failure_errno(unsupported),
        RsiMappedErrno::Enotsup
    );

    let busy = plan_transaction_mutation_binding(
        &limits,
        TransactionState::ActiveUnbound,
        target,
        true,
        1,
    )
    .expect_err("bound transaction limit should fail first bind");
    assert_eq!(transaction_use_failure_errno(busy), RsiMappedErrno::Ebusy);

    let invalid = plan_transaction_mutation_binding(
        &limits,
        TransactionState::ActiveUnbound,
        binding(7, "CurrentUser", MACHINE_ROOT),
        true,
        0,
    )
    .expect_err("malformed binding should fail closed");
    assert_eq!(
        transaction_use_failure_errno(invalid),
        RsiMappedErrno::Einval
    );
}
