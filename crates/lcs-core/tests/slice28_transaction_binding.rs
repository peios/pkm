use lcs_core::{
    LcsLimits, TransactionBinding, TransactionMutationBindingPlan, TransactionReadPlan,
    TransactionState, TransactionUseFailure, plan_transaction_mutation_binding,
    plan_transaction_read,
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
fn first_mutating_operation_binds_active_unbound_transaction() {
    let limits = LcsLimits::default();
    let target = binding(7, "Machine", MACHINE_ROOT);

    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveUnbound,
            target,
            true,
            0,
        ),
        Ok(TransactionMutationBindingPlan::BindNew(target))
    );
}

#[test]
fn first_bind_rejects_unsupported_sources_and_bound_limit_without_binding() {
    let mut limits = LcsLimits::default();
    limits.max_bound_transactions_per_source = 2;
    let target = binding(7, "Machine", MACHINE_ROOT);

    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveUnbound,
            target,
            false,
            0,
        ),
        Err(TransactionUseFailure::NotSupported)
    );
    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveUnbound,
            target,
            true,
            2,
        ),
        Err(TransactionUseFailure::Busy)
    );
}

#[test]
fn bound_mutations_must_target_same_source_and_hive_identity() {
    let limits = LcsLimits::default();
    let original = binding(7, "Machine", MACHINE_ROOT);
    let same_folded = binding(7, "machine", MACHINE_ROOT);

    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveBound(original),
            same_folded,
            false,
            usize::MAX,
        ),
        Ok(TransactionMutationBindingPlan::UseExisting(original))
    );

    for target in [
        binding(8, "Machine", MACHINE_ROOT),
        binding(7, "Users", USERS_ROOT),
        binding(7, "Machine", USERS_ROOT),
    ] {
        assert_eq!(
            plan_transaction_mutation_binding(
                &limits,
                TransactionState::ActiveBound(original),
                target,
                true,
                0,
            ),
            Err(TransactionUseFailure::CrossHive)
        );
    }
}

#[test]
fn read_planning_does_not_bind_unbound_transactions() {
    let limits = LcsLimits::default();
    let target = binding(7, "Machine", MACHINE_ROOT);

    assert_eq!(
        plan_transaction_read(&limits, TransactionState::ActiveUnbound, target),
        Ok(TransactionReadPlan::NonTransactional)
    );
    assert_eq!(
        plan_transaction_read(&limits, TransactionState::ActiveBound(target), target),
        Ok(TransactionReadPlan::Transactional(target))
    );
}

#[test]
fn read_planning_rejects_cross_hive_and_terminal_transactions() {
    let limits = LcsLimits::default();
    let original = binding(7, "Machine", MACHINE_ROOT);
    let other = binding(7, "Users", USERS_ROOT);

    assert_eq!(
        plan_transaction_read(&limits, TransactionState::ActiveBound(original), other),
        Err(TransactionUseFailure::CrossHive)
    );
    assert_eq!(
        plan_transaction_read(&limits, TransactionState::Committed, original),
        Err(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        plan_transaction_read(&limits, TransactionState::TimedOut, original),
        Err(TransactionUseFailure::TimedOut)
    );
    assert_eq!(
        plan_transaction_read(&limits, TransactionState::SourceDown, original),
        Err(TransactionUseFailure::SourceDown)
    );
}

#[test]
fn binding_validation_fails_closed_on_malformed_targets() {
    let limits = LcsLimits::default();

    assert_eq!(
        plan_transaction_mutation_binding(
            &limits,
            TransactionState::ActiveUnbound,
            binding(7, "CurrentUser", MACHINE_ROOT),
            true,
            0,
        ),
        Err(TransactionUseFailure::Invalid)
    );
    assert_eq!(
        plan_transaction_read(
            &limits,
            TransactionState::ActiveUnbound,
            binding(7, "Machine", [0; 16]),
        ),
        Err(TransactionUseFailure::Invalid)
    );
}
