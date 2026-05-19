use lcs_core::{
    LayerDeletionPlan, LayerDeletionSourceCompletionPlan, LcsLimits, plan_layer_deletion,
    plan_layer_deletion_source_completion,
};

#[test]
fn layer_deletion_source_completion_marks_returned_orphans_for_unlink_lifecycle() {
    let deletion = plan_layer_deletion(&LcsLimits::default(), "policy", 2)
        .expect("non-base layer deletion should plan");

    assert_eq!(
        plan_layer_deletion_source_completion(&deletion, 3),
        LayerDeletionSourceCompletionPlan {
            layer_name: "policy",
            orphaned_guid_count: 3,
            mark_returned_guids_orphaned: true,
            retain_existing_key_fds: true,
            reject_new_namespace_ops_through_orphans: true,
            drop_orphans_on_last_fd_close: true,
            recompute_effective_state: true,
            dispatch_watch_events_for_effective_changes: true,
        }
    );
}

#[test]
fn layer_deletion_source_completion_handles_empty_orphan_set_without_drop_work() {
    let deletion = plan_layer_deletion(&LcsLimits::default(), "role", 0)
        .expect("non-base layer deletion should plan");

    assert_eq!(
        plan_layer_deletion_source_completion(&deletion, 0),
        LayerDeletionSourceCompletionPlan {
            layer_name: "role",
            orphaned_guid_count: 0,
            mark_returned_guids_orphaned: false,
            retain_existing_key_fds: false,
            reject_new_namespace_ops_through_orphans: false,
            drop_orphans_on_last_fd_close: false,
            recompute_effective_state: true,
            dispatch_watch_events_for_effective_changes: true,
        }
    );
}

#[test]
fn source_completion_inherits_effect_recompute_and_watch_intent_from_deletion_plan() {
    let deletion = LayerDeletionPlan {
        layer_name: "policy",
        remove_from_layer_table: true,
        broadcast_delete_layer_to_all_sources: true,
        affected_bound_transaction_count: 0,
        abort_affected_bound_transactions: false,
        preserve_security_descriptors: true,
        recompute_effective_state: false,
        dispatch_watch_events_for_effective_changes: false,
    };

    assert_eq!(
        plan_layer_deletion_source_completion(&deletion, 1),
        LayerDeletionSourceCompletionPlan {
            layer_name: "policy",
            orphaned_guid_count: 1,
            mark_returned_guids_orphaned: true,
            retain_existing_key_fds: true,
            reject_new_namespace_ops_through_orphans: true,
            drop_orphans_on_last_fd_close: true,
            recompute_effective_state: false,
            dispatch_watch_events_for_effective_changes: false,
        }
    );
}
