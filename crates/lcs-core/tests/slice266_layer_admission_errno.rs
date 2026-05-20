use lcs_core::{
    LayerCreationAdmissionInput, LayerTargetAdmissionInput, LayerView, LcsError, LcsLimits,
    LinuxErrno, layer_creation_admission_linux_errno, layer_target_admission_linux_errno,
    plan_layer_creation_admission, plan_layer_target_admission,
};

fn limits() -> LcsLimits {
    LcsLimits::default()
}

#[test]
fn layer_creation_cap_failure_projects_to_linux_enospc() {
    let mut limits = limits();
    limits.max_total_layers = 3;

    let admitted = plan_layer_creation_admission(
        &limits,
        LayerCreationAdmissionInput {
            current_total_layers: 2,
        },
    )
    .expect("below MaxTotalLayers should admit");
    assert_eq!(admitted.total_layers_after_create, 3);

    let err = plan_layer_creation_admission(
        &limits,
        LayerCreationAdmissionInput {
            current_total_layers: 3,
        },
    )
    .expect_err("at MaxTotalLayers should fail");
    assert_eq!(err, LcsError::TooManyLayers { count: 3, max: 3 });
    assert_eq!(
        layer_creation_admission_linux_errno(&err),
        Some(LinuxErrno::Enospc)
    );
}

#[test]
fn missing_layer_target_projects_to_linux_enoent() {
    let limits = limits();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];

    let admitted = plan_layer_target_admission(LayerTargetAdmissionInput {
        target_layer: "BASE",
        layers: &layers,
        limits: &limits,
    })
    .expect("folded base layer should admit");
    assert_eq!(admitted.matched_layer, layers[0]);

    let err = plan_layer_target_admission(LayerTargetAdmissionInput {
        target_layer: "missing",
        layers: &layers,
        limits: &limits,
    })
    .expect_err("absent caller-targeted layer should fail");
    assert_eq!(err, LcsError::MissingLayerTarget);
    assert_eq!(
        layer_target_admission_linux_errno(&err),
        Some(LinuxErrno::Enoent)
    );
}

#[test]
fn malformed_layer_target_is_not_reclassified_as_absent() {
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
    .expect_err("malformed target names should remain structural errors");

    assert!(matches!(err, LcsError::NameContainsSeparator { .. }));
    assert_eq!(layer_target_admission_linux_errno(&err), None);
    assert_eq!(
        layer_creation_admission_linux_errno(&LcsError::DuplicateLayerIdentity),
        None
    );
}
