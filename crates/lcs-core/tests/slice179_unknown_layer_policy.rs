use lcs_core::{
    LayerResolutionContext, LayerTargetAdmissionErrno, LayerTargetAdmissionInput,
    LayerTargetAdmissionPlan, LayerView, LcsError, LcsLimits, PathEntry, PathResolution,
    PathTarget, REG_SZ, RegistryValueType, ValueEntry, ValueResolution,
    layer_target_admission_errno, plan_layer_target_admission, resolve_path_entry, resolve_value,
};

const LATENT_GUID: [u8; 16] = [0x22; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn context<'a>(layers: &'a [LayerView<'a>], limits: &'a LcsLimits) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

#[test]
fn well_formed_unknown_source_layer_is_latent_until_layer_metadata_exists() {
    let limits = limits();
    let base_only = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let source_value = [ValueEntry {
        layer: "Future",
        sequence: 1,
        value_type: REG_SZ,
        data: b"latent",
    }];
    let source_path = [PathEntry {
        layer: "Future",
        sequence: 1,
        target: PathTarget::Guid(LATENT_GUID),
    }];
    let absent = context(&base_only, &limits);

    assert_eq!(
        resolve_value(&absent, &source_value, &[]),
        Ok(ValueResolution::NotFound)
    );
    assert_eq!(
        resolve_path_entry(&absent, &source_path),
        Ok(PathResolution::NotFound)
    );

    let with_future = [
        base_only[0],
        LayerView {
            name: "future",
            precedence: 10,
            enabled: true,
        },
    ];
    let present = context(&with_future, &limits);

    assert_eq!(
        resolve_value(&present, &source_value, &[]),
        Ok(ValueResolution::Found(lcs_core::ResolvedValueEntry {
            value_type: RegistryValueType::Sz,
            data: b"latent",
            layer: "future",
            precedence: 10,
            sequence: 1,
        }))
    );
    assert_eq!(
        resolve_path_entry(&present, &source_path),
        Ok(PathResolution::Found(lcs_core::ResolvedPathEntry {
            guid: LATENT_GUID,
            layer: "future",
            precedence: 10,
            sequence: 1,
        }))
    );
}

#[test]
fn mutating_layer_target_admission_matches_published_layer_by_folded_identity() {
    let limits = limits();
    let layers = [
        LayerView {
            name: "base",
            precedence: 0,
            enabled: true,
        },
        LayerView {
            name: "policy",
            precedence: 10,
            enabled: true,
        },
    ];

    assert_eq!(
        plan_layer_target_admission(LayerTargetAdmissionInput {
            target_layer: "POLICY",
            layers: &layers,
            limits: &limits,
        }),
        Ok(LayerTargetAdmissionPlan {
            target_layer: "POLICY",
            matched_layer: layers[1],
        })
    );
}

#[test]
fn mutating_layer_target_absent_from_table_maps_to_enoent() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let err = plan_layer_target_admission(LayerTargetAdmissionInput {
        target_layer: "missing",
        layers: &layers,
        limits: &limits,
    })
    .unwrap_err();

    assert_eq!(err, LcsError::MissingLayerTarget);
    assert_eq!(
        layer_target_admission_errno(&err),
        Some(LayerTargetAdmissionErrno::Enoent)
    );
}

#[test]
fn malformed_mutating_layer_target_is_not_classified_as_missing() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let err = plan_layer_target_admission(LayerTargetAdmissionInput {
        target_layer: "bad/layer",
        layers: &layers,
        limits: &limits,
    })
    .unwrap_err();

    assert!(matches!(err, LcsError::NameContainsSeparator { .. }));
    assert_eq!(layer_target_admission_errno(&err), None);
}

#[test]
fn base_layer_target_is_admitted_normally() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];

    assert_eq!(
        plan_layer_target_admission(LayerTargetAdmissionInput {
            target_layer: "BASE",
            layers: &layers,
            limits: &limits,
        }),
        Ok(LayerTargetAdmissionPlan {
            target_layer: "BASE",
            matched_layer: layers[0],
        })
    );
}
