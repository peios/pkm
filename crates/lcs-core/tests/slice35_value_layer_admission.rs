use lcs_core::{
    LcsError, LcsLimits, ValueLayerAdmissionInput, ValueLayerAdmissionPlan,
    plan_value_layer_admission,
};

#[test]
fn value_layer_admission_allows_new_layer_below_cap() {
    let mut limits = LcsLimits::default();
    limits.max_layers_per_value = 3;

    assert_eq!(
        plan_value_layer_admission(
            &limits,
            ValueLayerAdmissionInput {
                current_distinct_layers: 2,
                replacing_existing_layer_entry: false,
            },
        ),
        Ok(ValueLayerAdmissionPlan {
            distinct_layers_after_write: 3,
            best_effort_admission_control: true,
        })
    );
}

#[test]
fn value_layer_admission_rejects_new_layer_at_or_above_cap() {
    let mut limits = LcsLimits::default();
    limits.max_layers_per_value = 3;

    for count in [3, 4] {
        assert_eq!(
            plan_value_layer_admission(
                &limits,
                ValueLayerAdmissionInput {
                    current_distinct_layers: count,
                    replacing_existing_layer_entry: false,
                },
            ),
            Err(LcsError::TooManyLayersPerValue { count, max: 3 })
        );
    }
}

#[test]
fn value_layer_admission_does_not_apply_cap_to_same_layer_replacement() {
    let mut limits = LcsLimits::default();
    limits.max_layers_per_value = 3;

    assert_eq!(
        plan_value_layer_admission(
            &limits,
            ValueLayerAdmissionInput {
                current_distinct_layers: 99,
                replacing_existing_layer_entry: true,
            },
        ),
        Ok(ValueLayerAdmissionPlan {
            distinct_layers_after_write: 99,
            best_effort_admission_control: true,
        })
    );
}

#[test]
fn value_layer_admission_rejects_new_layer_when_configured_cap_is_zero() {
    let mut limits = LcsLimits::default();
    limits.max_layers_per_value = 0;

    assert_eq!(
        plan_value_layer_admission(
            &limits,
            ValueLayerAdmissionInput {
                current_distinct_layers: 0,
                replacing_existing_layer_entry: false,
            },
        ),
        Err(LcsError::TooManyLayersPerValue { count: 0, max: 0 })
    );
}
