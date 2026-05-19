use lcs_core::{
    RSI_ABORT_TRANSACTION, RSI_BEGIN_TRANSACTION, RSI_COMMIT_TRANSACTION, RSI_CREATE_ENTRY,
    RSI_FLUSH, RSI_LOOKUP, RSI_SET_VALUE, RsiLateCleanupPlan, RsiLateMutatingKernelEffects,
    RsiLateResponseEffectPlan, RsiLateResponseTearDownReason, RsiLateSuccessEffectPlan,
    RsiLateSuccessMetadata, TransactionKernelEffectsPlan, plan_rsi_late_success_by_op_code,
};

fn metadata(txn_id: u64, effects: Option<RsiLateMutatingKernelEffects>) -> RsiLateSuccessMetadata {
    RsiLateSuccessMetadata {
        txn_id,
        mutation_effects: effects,
    }
}

fn effects(transaction: Option<TransactionKernelEffectsPlan>) -> RsiLateMutatingKernelEffects {
    RsiLateMutatingKernelEffects {
        update_hive_generation: true,
        dispatch_watch_events: true,
        refresh_layer_cache: false,
        track_orphans: false,
        transaction_commit_effects: transaction,
    }
}

fn missing_metadata_teardown() -> RsiLateSuccessEffectPlan {
    RsiLateSuccessEffectPlan::Effect(RsiLateResponseEffectPlan::MalformedProtocolTearDown {
        reason: RsiLateResponseTearDownReason::MissingOrInvalidKernelMetadata,
        tear_down_source: true,
        mark_source_down: true,
        release_in_flight_table: true,
    })
}

#[test]
fn late_read_only_success_is_discarded_by_opcode() {
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_LOOKUP, metadata(0, None)),
        RsiLateSuccessEffectPlan::Effect(
            RsiLateResponseEffectPlan::DiscardValidatedReadOnlyResponse {
                release_request_record: true,
            }
        )
    );
}

#[test]
fn late_ordinary_mutating_success_applies_supplied_effects() {
    let ordinary_effects = effects(None);

    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_SET_VALUE, metadata(0, Some(ordinary_effects))),
        RsiLateSuccessEffectPlan::Effect(RsiLateResponseEffectPlan::ApplyMutatingKernelEffects {
            effects: ordinary_effects,
            release_request_record: true,
        })
    );
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_CREATE_ENTRY, metadata(0, Some(ordinary_effects))),
        RsiLateSuccessEffectPlan::Effect(RsiLateResponseEffectPlan::ApplyMutatingKernelEffects {
            effects: ordinary_effects,
            release_request_record: true,
        })
    );
}

#[test]
fn late_mutating_success_without_metadata_fails_closed() {
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_SET_VALUE, metadata(0, None)),
        missing_metadata_teardown()
    );
}

#[test]
fn late_commit_success_requires_transaction_commit_effect_metadata() {
    assert_eq!(
        plan_rsi_late_success_by_op_code(
            RSI_COMMIT_TRANSACTION,
            metadata(
                9,
                Some(effects(Some(
                    TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
                ))),
            ),
        ),
        RsiLateSuccessEffectPlan::Effect(RsiLateResponseEffectPlan::ApplyMutatingKernelEffects {
            effects: effects(Some(
                TransactionKernelEffectsPlan::ApplyMutationLogAndEmitCommitEffects,
            )),
            release_request_record: true,
        })
    );
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_COMMIT_TRANSACTION, metadata(9, Some(effects(None)))),
        missing_metadata_teardown()
    );
}

#[test]
fn late_begin_success_queues_abort_cleanup_for_retained_transaction_id() {
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_BEGIN_TRANSACTION, metadata(44, None)),
        RsiLateSuccessEffectPlan::EnqueueCleanup {
            cleanup: RsiLateCleanupPlan {
                abort_transaction_id: 44,
                enqueue_abort_transaction: true,
            },
            release_request_record: true,
        }
    );
    assert_eq!(
        plan_rsi_late_success_by_op_code(RSI_BEGIN_TRANSACTION, metadata(0, None)),
        missing_metadata_teardown()
    );
}

#[test]
fn late_abort_and_flush_success_release_without_normal_effects() {
    for op_code in [RSI_ABORT_TRANSACTION, RSI_FLUSH] {
        assert_eq!(
            plan_rsi_late_success_by_op_code(op_code, metadata(44, None)),
            RsiLateSuccessEffectPlan::Effect(
                RsiLateResponseEffectPlan::ReleaseRecordNoNormalEffects {
                    source_errno: None,
                    release_request_record: true,
                },
            )
        );
    }
}

#[test]
fn unknown_success_opcode_fails_closed() {
    assert_eq!(
        plan_rsi_late_success_by_op_code(0xffff, metadata(44, None)),
        missing_metadata_teardown()
    );
}
