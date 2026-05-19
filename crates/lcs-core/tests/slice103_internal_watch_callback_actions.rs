use lcs_core::{
    InternalWatchCallbackPlan, InternalWatchDirtyPath, LcsError, LcsLimits, REG_WATCH_SD_CHANGED,
    REG_WATCH_SUBKEY_CREATED, REG_WATCH_SUBKEY_DELETED, REG_WATCH_VALUE_SET,
    plan_internal_watch_callback,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn internal_watch_callback_refreshes_self_configuration_for_dirty_config_values() {
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::SelfConfigurationValue {
                value_name: "RequestTimeoutMs",
            },
        ),
        Ok(InternalWatchCallbackPlan::RefreshSelfConfiguration {
            dirty_value_name: "RequestTimeoutMs",
        })
    );
}

#[test]
fn internal_watch_callback_refreshes_layer_metadata_without_partial_publication() {
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerMetadata {
                layer_name: "DomainPolicy",
            },
        ),
        Ok(InternalWatchCallbackPlan::RefreshLayerMetadata {
            dirty_layer_name: "DomainPolicy",
            publish_only_complete_entry: true,
        })
    );
}

#[test]
fn internal_watch_callback_maps_layer_lifecycle_subkey_events() {
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerSubkey {
                event_type: REG_WATCH_SUBKEY_CREATED,
                layer_name: "DomainPolicy",
            },
        ),
        Ok(InternalWatchCallbackPlan::AddLayer {
            layer_name: "DomainPolicy",
            publish_only_complete_entry: true,
        })
    );
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerSubkey {
                event_type: REG_WATCH_SUBKEY_DELETED,
                layer_name: "DomainPolicy",
            },
        ),
        Ok(InternalWatchCallbackPlan::DeleteLayer {
            layer_name: "DomainPolicy",
        })
    );
}

#[test]
fn internal_watch_callback_rearms_targeted_watches_after_registry_subtree_appears() {
    assert_eq!(
        plan_internal_watch_callback(&limits(), InternalWatchDirtyPath::RegistrySubtreeAvailable),
        Ok(InternalWatchCallbackPlan::ResolveAndRearmTargetedWatches)
    );
}

#[test]
fn internal_watch_callback_fails_closed_on_malformed_dirty_names_and_unexpected_events() {
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::SelfConfigurationValue {
                value_name: "bad\0value",
            },
        ),
        Err(LcsError::NullByte {
            field: "value_name",
        })
    );
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerMetadata {
                layer_name: "bad/layer",
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerSubkey {
                event_type: REG_WATCH_VALUE_SET,
                layer_name: "DomainPolicy",
            },
        ),
        Err(LcsError::UnexpectedInternalWatchEvent {
            event_type: REG_WATCH_VALUE_SET,
        })
    );
    assert_eq!(
        plan_internal_watch_callback(
            &limits(),
            InternalWatchDirtyPath::LayerSubkey {
                event_type: REG_WATCH_SD_CHANGED,
                layer_name: "DomainPolicy",
            },
        ),
        Err(LcsError::UnexpectedInternalWatchEvent {
            event_type: REG_WATCH_SD_CHANGED,
        })
    );
}
