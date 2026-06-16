use crate::common::{limits};
use lcs_core::{
    BASE_LAYER_NAME, BASE_LAYER_VIEW, LayerMetadataEntry, LayerView, LcsError,
    for_each_effective_layer, normalize_layer_target, plan_layer_deletion, validate_layer_views,
};


#[test]
fn base_layer_is_injected_without_persisted_metadata() {
    let limits = limits();
    let mut layers = Vec::<LayerView<'_>>::new();

    let count = for_each_effective_layer(&limits, &[], |layer| {
        layers.push(layer);
        Ok(())
    })
    .expect("base layer must exist without persisted metadata");

    assert_eq!(count, 1);
    assert_eq!(layers, [BASE_LAYER_VIEW]);
}

#[test]
fn contradictory_base_metadata_cannot_override_canonical_base_properties() {
    let limits = limits();
    let metadata = [LayerMetadataEntry {
        name: "BASE",
        precedence: Some(u32::MAX),
        enabled: Some(false),
    }];
    let mut layers = Vec::<LayerView<'_>>::new();

    let count = for_each_effective_layer(&limits, &metadata, |layer| {
        layers.push(layer);
        Ok(())
    })
    .expect("persisted base metadata is descriptive only");

    assert_eq!(count, 1);
    assert_eq!(layers, [BASE_LAYER_VIEW]);
}

#[test]
fn published_layer_snapshots_must_contain_exactly_canonical_base() {
    let limits = limits();

    assert_eq!(
        validate_layer_views(
            &limits,
            &[LayerView {
                name: "role-a",
                precedence: 0,
                enabled: true,
            }]
        ),
        Err(LcsError::MissingBaseLayer)
    );

    assert_eq!(
        validate_layer_views(
            &limits,
            &[LayerView {
                name: "base",
                precedence: 1,
                enabled: true,
            }]
        ),
        Err(LcsError::InvalidBaseLayerProperties {
            precedence: 1,
            enabled: true,
        })
    );

    assert_eq!(
        validate_layer_views(
            &limits,
            &[LayerView {
                name: "BASE",
                precedence: 0,
                enabled: false,
            }]
        ),
        Err(LcsError::InvalidBaseLayerProperties {
            precedence: 0,
            enabled: false,
        })
    );
}

#[test]
fn base_layer_cannot_be_deleted_and_missing_targets_default_to_base() {
    let limits = limits();

    assert_eq!(normalize_layer_target(None, &limits), Ok(BASE_LAYER_NAME));
    assert_eq!(
        plan_layer_deletion(&limits, "base", 0),
        Err(LcsError::BaseLayerDeletionNotAllowed)
    );
    assert_eq!(
        plan_layer_deletion(&limits, "BASE", 0),
        Err(LcsError::BaseLayerDeletionNotAllowed)
    );
}

#[test]
fn non_base_layer_metadata_defaults_remain_distinct_from_base_hardcoding() {
    let limits = limits();
    let metadata = [LayerMetadataEntry {
        name: "role-a",
        precedence: None,
        enabled: None,
    }];
    let mut layers = Vec::<LayerView<'_>>::new();

    let count = for_each_effective_layer(&limits, &metadata, |layer| {
        layers.push(layer);
        Ok(())
    })
    .expect("non-base layer defaults should apply after base injection");

    assert_eq!(count, 2);
    assert_eq!(layers[0], BASE_LAYER_VIEW);
    assert_eq!(
        layers[1],
        LayerView {
            name: "role-a",
            precedence: 0,
            enabled: true,
        }
    );
}
