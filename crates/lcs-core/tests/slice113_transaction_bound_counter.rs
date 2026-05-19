use lcs_core::{
    LcsError, LcsLimits, TransactionBoundCounterPlan, TransactionBoundCounterUpdate,
    TransactionMutationBindingPlan, plan_transaction_bound_counter_update,
};

#[test]
fn accepted_first_bind_increments_per_source_bound_transaction_count() {
    let mut limits = LcsLimits::default();
    limits.max_bound_transactions_per_source = 4;

    assert_eq!(
        plan_transaction_bound_counter_update(&limits, 3, TransactionBoundCounterUpdate::Increment),
        Ok(TransactionBoundCounterPlan {
            update: TransactionBoundCounterUpdate::Increment,
            previous_count: 3,
            next_count: 4,
        })
    );
}

#[test]
fn first_bind_counter_update_fails_closed_if_precheck_was_bypassed() {
    let mut limits = LcsLimits::default();
    limits.max_bound_transactions_per_source = 4;

    assert_eq!(
        plan_transaction_bound_counter_update(&limits, 4, TransactionBoundCounterUpdate::Increment),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}

#[test]
fn active_bound_terminal_transition_decrements_per_source_count() {
    let limits = LcsLimits::default();

    assert_eq!(
        plan_transaction_bound_counter_update(&limits, 1, TransactionBoundCounterUpdate::Decrement),
        Ok(TransactionBoundCounterPlan {
            update: TransactionBoundCounterUpdate::Decrement,
            previous_count: 1,
            next_count: 0,
        })
    );
}

#[test]
fn decrement_fails_closed_when_count_is_already_zero() {
    let limits = LcsLimits::default();

    assert_eq!(
        plan_transaction_bound_counter_update(&limits, 0, TransactionBoundCounterUpdate::Decrement),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}

#[test]
fn no_change_preserves_count_for_unbound_reads_and_existing_bind_reuse() {
    let limits = LcsLimits::default();

    assert_eq!(
        plan_transaction_bound_counter_update(&limits, 7, TransactionBoundCounterUpdate::NoChange),
        Ok(TransactionBoundCounterPlan {
            update: TransactionBoundCounterUpdate::NoChange,
            previous_count: 7,
            next_count: 7,
        })
    );
}

#[test]
fn counter_update_pairs_with_existing_first_bind_plan_shape() {
    let binding_plan = TransactionMutationBindingPlan::BindNew(lcs_core::TransactionBinding {
        source_id: 9,
        hive_name: "Machine",
        hive_root_guid: [0x11; 16],
    });
    let counter_update = match binding_plan {
        TransactionMutationBindingPlan::BindNew(_) => TransactionBoundCounterUpdate::Increment,
        TransactionMutationBindingPlan::UseExisting(_) => TransactionBoundCounterUpdate::NoChange,
    };

    assert_eq!(
        plan_transaction_bound_counter_update(&LcsLimits::default(), 0, counter_update),
        Ok(TransactionBoundCounterPlan {
            update: TransactionBoundCounterUpdate::Increment,
            previous_count: 0,
            next_count: 1,
        })
    );
}
