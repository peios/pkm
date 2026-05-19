use lcs_core::{
    LcsError, LcsLimits, TransactionWatchBatchMember, TransactionWatchBatchPlan,
    TransactionWatchBurstPlan, plan_transaction_watch_batch,
};

#[test]
fn empty_transaction_batch_generates_no_events() {
    assert_eq!(
        plan_transaction_watch_batch(&LcsLimits::default(), &[]),
        Ok(TransactionWatchBatchPlan {
            operation_count: 0,
            total_event_count: 0,
            delivery: TransactionWatchBurstPlan::NoEvents,
            dispatch_without_interleaving: false,
        })
    );
}

#[test]
fn ordered_operation_batch_counts_events_for_individual_delivery() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 8;
    let members = [
        TransactionWatchBatchMember {
            operation_index: 10,
            event_count: 2,
        },
        TransactionWatchBatchMember {
            operation_index: 11,
            event_count: 0,
        },
        TransactionWatchBatchMember {
            operation_index: 12,
            event_count: 6,
        },
    ];

    assert_eq!(
        plan_transaction_watch_batch(&limits, &members),
        Ok(TransactionWatchBatchPlan {
            operation_count: 3,
            total_event_count: 8,
            delivery: TransactionWatchBurstPlan::EmitIndividualEvents { event_count: 8 },
            dispatch_without_interleaving: true,
        })
    );
}

#[test]
fn over_limit_batch_collapses_to_single_overflow_for_watcher() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 8;
    let members = [
        TransactionWatchBatchMember {
            operation_index: 1,
            event_count: 5,
        },
        TransactionWatchBatchMember {
            operation_index: 2,
            event_count: 4,
        },
    ];

    assert_eq!(
        plan_transaction_watch_batch(&limits, &members),
        Ok(TransactionWatchBatchPlan {
            operation_count: 2,
            total_event_count: 9,
            delivery: TransactionWatchBurstPlan::EmitOverflowOnly {
                attempted_event_count: 9,
                max_event_burst: 8,
            },
            dispatch_without_interleaving: true,
        })
    );
}

#[test]
fn duplicate_or_descending_operation_order_fails_closed() {
    let duplicate = [
        TransactionWatchBatchMember {
            operation_index: 3,
            event_count: 1,
        },
        TransactionWatchBatchMember {
            operation_index: 3,
            event_count: 1,
        },
    ];
    let descending = [
        TransactionWatchBatchMember {
            operation_index: 4,
            event_count: 1,
        },
        TransactionWatchBatchMember {
            operation_index: 2,
            event_count: 1,
        },
    ];

    assert_eq!(
        plan_transaction_watch_batch(&LcsLimits::default(), &duplicate),
        Err(LcsError::InvalidTransactionWatchBatchOrder { index: 1 })
    );
    assert_eq!(
        plan_transaction_watch_batch(&LcsLimits::default(), &descending),
        Err(LcsError::InvalidTransactionWatchBatchOrder { index: 1 })
    );
}

#[test]
fn event_count_overflow_fails_before_delivery_selection() {
    let members = [
        TransactionWatchBatchMember {
            operation_index: 1,
            event_count: usize::MAX,
        },
        TransactionWatchBatchMember {
            operation_index: 2,
            event_count: 1,
        },
    ];

    assert_eq!(
        plan_transaction_watch_batch(&LcsLimits::default(), &members),
        Err(LcsError::TransactionWatchBatchEventCountOverflow)
    );
}

#[test]
fn invalid_burst_limit_still_fails_closed_through_batch_planner() {
    let mut limits = LcsLimits::default();
    limits.max_transaction_watch_event_burst = 0;
    let members = [TransactionWatchBatchMember {
        operation_index: 1,
        event_count: 1,
    }];

    assert_eq!(
        plan_transaction_watch_batch(&limits, &members),
        Err(LcsError::InvalidTransactionWatchBurstLimit)
    );
}
