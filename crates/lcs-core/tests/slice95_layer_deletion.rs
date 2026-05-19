use lcs_core::{LayerDeletionPlan, LcsError, LcsLimits, plan_layer_deletion};

#[test]
fn layer_deletion_plans_global_purge_and_effect_recomputation() {
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "policy", 0),
        Ok(LayerDeletionPlan {
            layer_name: "policy",
            remove_from_layer_table: true,
            broadcast_delete_layer_to_all_sources: true,
            affected_bound_transaction_count: 0,
            abort_affected_bound_transactions: false,
            preserve_security_descriptors: true,
            recompute_effective_state: true,
            dispatch_watch_events_for_effective_changes: true,
        })
    );
}

#[test]
fn layer_deletion_aborts_affected_bound_transactions_before_broadcast() {
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "policy", 3)
            .unwrap()
            .abort_affected_bound_transactions,
        true
    );
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "policy", 3)
            .unwrap()
            .affected_bound_transaction_count,
        3
    );
}

#[test]
fn layer_deletion_rejects_base_layer() {
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "base", 0),
        Err(LcsError::BaseLayerDeletionNotAllowed)
    );
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "BASE", 0),
        Err(LcsError::BaseLayerDeletionNotAllowed)
    );
}

#[test]
fn layer_deletion_validates_layer_name_before_planning() {
    assert_eq!(
        plan_layer_deletion(&LcsLimits::default(), "bad/layer", 0),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}
