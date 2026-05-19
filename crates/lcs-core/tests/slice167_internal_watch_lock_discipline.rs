use lcs_core::{
    InternalLayerMetadataRefreshLockPlan, InternalLayerMetadataRefreshReason,
    InternalWatchCallbackPlan, InternalWatchDirtyPath, LcsLimits, REG_WATCH_SUBKEY_CREATED,
    plan_internal_layer_metadata_refresh_locking, plan_internal_watch_callback,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn layer_metadata_refresh_releases_locks_before_source_round_trip() {
    let callback = plan_internal_watch_callback(
        &limits(),
        InternalWatchDirtyPath::LayerMetadata {
            layer_name: "DomainPolicy",
        },
    )
    .unwrap();

    assert_eq!(
        plan_internal_layer_metadata_refresh_locking(callback),
        Some(InternalLayerMetadataRefreshLockPlan {
            layer_name: "DomainPolicy",
            reason: InternalLayerMetadataRefreshReason::MetadataChanged,
            release_watch_map_lock_before_source_round_trip: true,
            release_layer_publication_lock_before_source_round_trip: true,
            acquire_layer_publication_lock_only_for_atomic_publish: true,
            publish_only_complete_entry: true,
        })
    );
}

#[test]
fn layer_create_refresh_uses_same_complete_publication_lock_discipline() {
    let callback = plan_internal_watch_callback(
        &limits(),
        InternalWatchDirtyPath::LayerSubkey {
            event_type: REG_WATCH_SUBKEY_CREATED,
            layer_name: "RoleWeb",
        },
    )
    .unwrap();

    assert_eq!(
        plan_internal_layer_metadata_refresh_locking(callback),
        Some(InternalLayerMetadataRefreshLockPlan {
            layer_name: "RoleWeb",
            reason: InternalLayerMetadataRefreshReason::LayerCreated,
            release_watch_map_lock_before_source_round_trip: true,
            release_layer_publication_lock_before_source_round_trip: true,
            acquire_layer_publication_lock_only_for_atomic_publish: true,
            publish_only_complete_entry: true,
        })
    );
}

#[test]
fn non_layer_refresh_callbacks_have_no_layer_metadata_source_round_trip_plan() {
    assert_eq!(
        plan_internal_layer_metadata_refresh_locking(
            InternalWatchCallbackPlan::RefreshSelfConfiguration {
                dirty_value_name: "RequestTimeoutMs",
            },
        ),
        None
    );
    assert_eq!(
        plan_internal_layer_metadata_refresh_locking(InternalWatchCallbackPlan::DeleteLayer {
            layer_name: "RoleWeb",
        }),
        None
    );
    assert_eq!(
        plan_internal_layer_metadata_refresh_locking(
            InternalWatchCallbackPlan::ResolveAndRearmTargetedWatches,
        ),
        None
    );
}
