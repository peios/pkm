use lcs_core::{
    LcsError, LcsLimits, TransactionBinding, TransactionBoundCounterPlan,
    TransactionBoundCounterTransitionPlan, TransactionBoundCounterUpdate, TransactionState,
    plan_transaction_bound_counter_transition,
};

const HIVE_ROOT: [u8; 16] = [0x66; 16];

fn binding() -> TransactionBinding<'static> {
    TransactionBinding {
        source_id: 12,
        hive_name: "Machine",
        hive_root_guid: HIVE_ROOT,
    }
}

#[test]
fn active_unbound_to_bound_transition_increments_source_counter() {
    let tx_binding = binding();

    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::ActiveUnbound,
            TransactionState::ActiveBound(tx_binding),
            0,
        ),
        Ok(TransactionBoundCounterTransitionPlan {
            affected_binding: Some(tx_binding),
            counter: TransactionBoundCounterPlan {
                update: TransactionBoundCounterUpdate::Increment,
                previous_count: 0,
                next_count: 1,
            },
        })
    );
}

#[test]
fn accepted_bind_transition_fails_closed_if_counter_cap_was_bypassed() {
    let mut limits = LcsLimits::default();
    limits.max_bound_transactions_per_source = 2;

    assert_eq!(
        plan_transaction_bound_counter_transition(
            &limits,
            TransactionState::ActiveUnbound,
            TransactionState::ActiveBound(binding()),
            2,
        ),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}

#[test]
fn bound_terminal_transitions_decrement_source_counter() {
    for terminal_state in [
        TransactionState::Committed,
        TransactionState::Aborted,
        TransactionState::TimedOut,
        TransactionState::SourceDown,
    ] {
        assert_eq!(
            plan_transaction_bound_counter_transition(
                &LcsLimits::default(),
                TransactionState::ActiveBound(binding()),
                terminal_state,
                3,
            ),
            Ok(TransactionBoundCounterTransitionPlan {
                affected_binding: Some(binding()),
                counter: TransactionBoundCounterPlan {
                    update: TransactionBoundCounterUpdate::Decrement,
                    previous_count: 3,
                    next_count: 2,
                },
            })
        );
    }
}

#[test]
fn retry_and_existing_bind_reuse_do_not_change_counter() {
    let tx_binding = binding();

    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::ActiveBound(tx_binding),
            TransactionState::ActiveBound(tx_binding),
            4,
        ),
        Ok(TransactionBoundCounterTransitionPlan {
            affected_binding: Some(tx_binding),
            counter: TransactionBoundCounterPlan {
                update: TransactionBoundCounterUpdate::NoChange,
                previous_count: 4,
                next_count: 4,
            },
        })
    );
}

#[test]
fn unbound_abort_and_terminal_noop_callbacks_do_not_change_counter() {
    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::ActiveUnbound,
            TransactionState::Aborted,
            5,
        ),
        Ok(TransactionBoundCounterTransitionPlan {
            affected_binding: None,
            counter: TransactionBoundCounterPlan {
                update: TransactionBoundCounterUpdate::NoChange,
                previous_count: 5,
                next_count: 5,
            },
        })
    );

    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::TimedOut,
            TransactionState::TimedOut,
            5,
        ),
        Ok(TransactionBoundCounterTransitionPlan {
            affected_binding: None,
            counter: TransactionBoundCounterPlan {
                update: TransactionBoundCounterUpdate::NoChange,
                previous_count: 5,
                next_count: 5,
            },
        })
    );
}

#[test]
fn impossible_rebind_resurrection_and_underflow_fail_closed() {
    let tx_binding = binding();
    let other_binding = TransactionBinding {
        source_id: 13,
        hive_name: "Machine",
        hive_root_guid: HIVE_ROOT,
    };

    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::ActiveBound(tx_binding),
            TransactionState::ActiveBound(other_binding),
            1,
        ),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::Committed,
            TransactionState::ActiveBound(tx_binding),
            1,
        ),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
    assert_eq!(
        plan_transaction_bound_counter_transition(
            &LcsLimits::default(),
            TransactionState::ActiveBound(tx_binding),
            TransactionState::Committed,
            0,
        ),
        Err(LcsError::InvalidTransactionRuntimeState)
    );
}
