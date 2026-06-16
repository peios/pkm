use lcs_core::{
    BASE_LAYER_NAME, BASE_LAYER_VIEW, Guid, LayerMetadataEntry, LayerResolutionContext, LayerView,
    LcsError, LcsLimits, PathEntry, PathResolution, PathTarget, for_each_effective_layer,
    normalize_layer_target, resolve_path_entry, validate_layer_views, validate_private_layer_set,
};

const GUID: Guid = [0x44; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn effective_layer_table_injects_base_and_defaults_non_base_metadata() {
    let limits = limits();
    let metadata = [
        LayerMetadataEntry {
            name: "BASE",
            precedence: Some(99),
            enabled: Some(false),
        },
        LayerMetadataEntry {
            name: "RoleA",
            precedence: None,
            enabled: None,
        },
        LayerMetadataEntry {
            name: "Policy",
            precedence: Some(10),
            enabled: Some(false),
        },
    ];
    let mut layers = Vec::<LayerView<'_>>::new();

    let count = for_each_effective_layer(&limits, &metadata, |layer| {
        layers.push(layer);
        Ok(())
    })
    .expect("layer metadata should normalize");

    assert_eq!(count, 3);
    assert_eq!(layers[0], BASE_LAYER_VIEW);
    assert_eq!(
        layers[1],
        LayerView {
            name: "RoleA",
            precedence: 0,
            enabled: true,
        }
    );
    assert_eq!(
        layers[2],
        LayerView {
            name: "Policy",
            precedence: 10,
            enabled: false,
        }
    );
}

#[test]
fn layer_table_validation_rejects_malformed_names_duplicate_identities_and_overflow() {
    let limits = limits();

    assert_eq!(
        for_each_effective_layer(
            &limits,
            &[LayerMetadataEntry {
                name: "bad/name",
                precedence: None,
                enabled: None,
            }],
            |_| Ok(())
        ),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );

    assert_eq!(
        for_each_effective_layer(
            &limits,
            &[
                LayerMetadataEntry {
                    name: "RoleA",
                    precedence: None,
                    enabled: None,
                },
                LayerMetadataEntry {
                    name: "rolea",
                    precedence: Some(1),
                    enabled: Some(true),
                },
            ],
            |_| Ok(())
        ),
        Err(LcsError::DuplicateLayerIdentity)
    );

    let mut tight_limits = limits;
    tight_limits.max_total_layers = 2;
    assert_eq!(
        for_each_effective_layer(
            &tight_limits,
            &[
                LayerMetadataEntry {
                    name: "RoleA",
                    precedence: None,
                    enabled: None,
                },
                LayerMetadataEntry {
                    name: "RoleB",
                    precedence: None,
                    enabled: None,
                },
            ],
            |_| Ok(())
        ),
        Err(LcsError::TooManyLayers { count: 3, max: 2 })
    );
}

#[test]
fn layer_target_defaults_to_base_and_validates_explicit_targets() {
    let limits = limits();

    assert_eq!(normalize_layer_target(None, &limits), Ok(BASE_LAYER_NAME));
    assert_eq!(
        normalize_layer_target(Some("role-service"), &limits),
        Ok("role-service")
    );
    assert_eq!(
        normalize_layer_target(Some("bad/name"), &limits),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
}

#[test]
fn layer_resolution_context_requires_valid_base_and_unique_layer_identities() {
    let limits = limits();
    let missing_base = [LayerView {
        name: "RoleA",
        precedence: 0,
        enabled: true,
    }];
    assert_eq!(
        validate_layer_views(&limits, &missing_base),
        Err(LcsError::MissingBaseLayer)
    );

    let invalid_base = [LayerView {
        name: "base",
        precedence: 1,
        enabled: false,
    }];
    assert_eq!(
        validate_layer_views(&limits, &invalid_base),
        Err(LcsError::InvalidBaseLayerProperties {
            precedence: 1,
            enabled: false,
        })
    );

    let duplicate = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "RoleA",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "rolea",
            precedence: 1,
            enabled: true,
        },
    ];
    assert_eq!(
        validate_layer_views(&limits, &duplicate),
        Err(LcsError::DuplicateLayerIdentity)
    );
}

#[test]
fn private_layer_set_validation_enforces_shape_bound_and_set_semantics() {
    let limits = limits();

    assert_eq!(validate_private_layer_set(&limits, &["private-a"]), Ok(()));
    assert_eq!(
        validate_private_layer_set(&limits, &["private/a"]),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name",
        })
    );
    assert_eq!(
        validate_private_layer_set(&limits, &["PrivateA", "privatea"]),
        Err(LcsError::DuplicatePrivateLayerIdentity)
    );

    let mut tight_limits = limits;
    tight_limits.max_private_layers_per_token = 1;
    assert_eq!(
        validate_private_layer_set(&tight_limits, &["private-a", "private-b"]),
        Err(LcsError::TooManyPrivateLayers { count: 2, max: 1 })
    );
}

#[test]
fn resolver_rejects_invalid_layer_context_before_source_entries_affect_state() {
    let limits = limits();
    let missing_base_layers = [LayerView {
        name: "policy",
        precedence: 10,
        enabled: true,
    }];
    let context = LayerResolutionContext {
        layers: &missing_base_layers,
        private_layers: &[],
        limits: &limits,
        next_sequence: 100,
    };

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "policy",
                sequence: 1,
                target: PathTarget::Guid(GUID),
            }],
        ),
        Err(LcsError::MissingBaseLayer)
    );

    let layers = [
        BASE_LAYER_VIEW,
        LayerView {
            name: "PrivateA",
            precedence: 5,
            enabled: false,
        },
    ];
    let duplicate_private = ["privatea", "PrivateA"];
    let context = LayerResolutionContext {
        layers: &layers,
        private_layers: &duplicate_private,
        limits: &limits,
        next_sequence: 100,
    };

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "PrivateA",
                sequence: 1,
                target: PathTarget::Guid(GUID),
            }],
        ),
        Err(LcsError::DuplicatePrivateLayerIdentity)
    );

    let private = ["privatea"];
    let context = LayerResolutionContext {
        layers: &layers,
        private_layers: &private,
        limits: &limits,
        next_sequence: 100,
    };

    assert_eq!(
        resolve_path_entry(
            &context,
            &[PathEntry {
                layer: "PrivateA",
                sequence: 1,
                target: PathTarget::Guid(GUID),
            }],
        ),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: GUID,
            layer: "PrivateA",
            precedence: 5,
            sequence: 1,
        }))
    );
}
