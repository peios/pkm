use lcs_core::{
    LayerCreationAdmissionErrno, LayerCreationAdmissionInput, LayerCreationAdmissionPlan, LcsError,
    LcsLimits, layer_creation_admission_errno, plan_layer_creation_admission,
};

#[test]
fn layer_creation_admission_allows_new_layer_below_total_cap() {
    let mut limits = LcsLimits::default();
    limits.max_total_layers = 3;

    assert_eq!(
        plan_layer_creation_admission(
            &limits,
            LayerCreationAdmissionInput {
                current_total_layers: 2,
            },
        ),
        Ok(LayerCreationAdmissionPlan {
            total_layers_after_create: 3,
            strict_admission_control: true,
        })
    );
}

#[test]
fn layer_creation_admission_rejects_new_layer_at_or_above_total_cap() {
    let mut limits = LcsLimits::default();
    limits.max_total_layers = 3;

    for current_total_layers in [3, 4] {
        assert_eq!(
            plan_layer_creation_admission(
                &limits,
                LayerCreationAdmissionInput {
                    current_total_layers,
                },
            ),
            Err(LcsError::TooManyLayers {
                count: current_total_layers,
                max: 3,
            })
        );
    }
}

#[test]
fn layer_creation_cap_failure_maps_to_enospc_only_for_cap_error() {
    let error = LcsError::TooManyLayers { count: 3, max: 3 };

    assert_eq!(
        layer_creation_admission_errno(&error),
        Some(LayerCreationAdmissionErrno::Enospc)
    );
    assert_eq!(
        layer_creation_admission_errno(&LcsError::DuplicateLayerIdentity),
        None
    );
}
