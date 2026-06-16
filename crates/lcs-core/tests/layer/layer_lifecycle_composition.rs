use crate::common::{limits, system_sid};
use lcs_core::{
    Guid, InternalWatchCallbackPlan, InternalWatchDirtyPath, LayerDeletionPlan,
    LayerDeletionSourceCompletionPlan, LayerPublicationInput, LayerPublicationPlan, LayerView, REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED, plan_internal_watch_callback,
    plan_layer_deletion, plan_layer_deletion_source_completion, plan_layer_publication,
};

const SE_SELF_RELATIVE: u16 = 0x8000;
const METADATA_GUID: Guid = [0x66; 16];



fn owner_only_sd() -> Vec<u8> {
    let owner = system_sid();
    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
    sd[4..8].copy_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd
}

#[test]
fn layer_creation_is_ordinary_subkey_create_then_complete_publication() {
    let sd = owner_only_sd();
    let callback = plan_internal_watch_callback(
        &limits(),
        InternalWatchDirtyPath::LayerSubkey {
            event_type: REG_WATCH_SUBKEY_CREATED,
            layer_name: "role-web",
        },
    )
    .unwrap();

    assert_eq!(
        callback,
        InternalWatchCallbackPlan::AddLayer {
            layer_name: "role-web",
            publish_only_complete_entry: true,
        }
    );
    assert_eq!(
        plan_layer_publication(
            &limits(),
            LayerPublicationInput {
                name: "role-web",
                precedence: 0,
                enabled: true,
                metadata_key_guid: METADATA_GUID,
                metadata_security_descriptor: &sd,
            },
        ),
        Ok(LayerPublicationPlan {
            view: LayerView {
                name: "role-web",
                precedence: 0,
                enabled: true,
            },
            metadata_key_guid: METADATA_GUID,
            metadata_security_descriptor: &sd,
            publish_atomically: true,
        })
    );
}

#[test]
fn layer_deletion_is_ordinary_subkey_delete_then_global_purge_completion() {
    let callback = plan_internal_watch_callback(
        &limits(),
        InternalWatchDirtyPath::LayerSubkey {
            event_type: REG_WATCH_SUBKEY_DELETED,
            layer_name: "role-web",
        },
    )
    .unwrap();
    let deletion = plan_layer_deletion(&limits(), "role-web", 2).unwrap();

    assert_eq!(
        callback,
        InternalWatchCallbackPlan::DeleteLayer {
            layer_name: "role-web",
        }
    );
    assert_eq!(
        deletion,
        LayerDeletionPlan {
            layer_name: "role-web",
            remove_from_layer_table: true,
            broadcast_delete_layer_to_all_sources: true,
            affected_bound_transaction_count: 2,
            abort_affected_bound_transactions: true,
            preserve_security_descriptors: true,
            recompute_effective_state: true,
            dispatch_watch_events_for_effective_changes: true,
        }
    );
    assert_eq!(
        plan_layer_deletion_source_completion(&deletion, 3),
        LayerDeletionSourceCompletionPlan {
            layer_name: "role-web",
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
