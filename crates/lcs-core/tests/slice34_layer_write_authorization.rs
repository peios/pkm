use lcs_core::{
    GENERIC_READ, KEY_CREATE_SUB_KEY, KEY_SET_VALUE, KEY_WRITE, LayerWriteAuthorizationInput,
    LayerWriteAuthorizationPlan, LcsError, plan_layer_write_authorization,
};

fn input() -> LayerWriteAuthorizationInput {
    LayerWriteAuthorizationInput {
        target_fd_granted_access: KEY_WRITE,
        target_required_access: KEY_SET_VALUE,
        layer_metadata_granted_access: KEY_SET_VALUE,
        establishes_or_elevates_precedence_above_zero: false,
        caller_has_tcb: false,
    }
}

#[test]
fn layer_write_authorization_requires_target_and_layer_metadata_access() {
    assert_eq!(
        plan_layer_write_authorization(input()),
        Ok(LayerWriteAuthorizationPlan {
            target_required_access: KEY_SET_VALUE,
            layer_metadata_required_access: KEY_SET_VALUE,
            tcb_required_for_precedence: false,
        })
    );
}

#[test]
fn layer_write_authorization_denies_missing_target_fd_right() {
    let denied = LayerWriteAuthorizationInput {
        target_fd_granted_access: KEY_CREATE_SUB_KEY,
        ..input()
    };

    assert_eq!(
        plan_layer_write_authorization(denied),
        Err(LcsError::MissingTargetKeyFdAccess {
            required: KEY_SET_VALUE,
        })
    );
}

#[test]
fn layer_write_authorization_denies_missing_layer_metadata_right() {
    let denied = LayerWriteAuthorizationInput {
        layer_metadata_granted_access: 0,
        ..input()
    };

    assert_eq!(
        plan_layer_write_authorization(denied),
        Err(LcsError::MissingLayerMetadataSetValue)
    );
}

#[test]
fn high_precedence_layer_changes_require_tcb_after_access_checks_pass() {
    let missing_tcb = LayerWriteAuthorizationInput {
        establishes_or_elevates_precedence_above_zero: true,
        caller_has_tcb: false,
        ..input()
    };
    assert_eq!(
        plan_layer_write_authorization(missing_tcb),
        Err(LcsError::MissingLayerPrecedenceTcb)
    );

    let allowed = LayerWriteAuthorizationInput {
        caller_has_tcb: true,
        ..missing_tcb
    };
    assert_eq!(
        plan_layer_write_authorization(allowed),
        Ok(LayerWriteAuthorizationPlan {
            target_required_access: KEY_SET_VALUE,
            layer_metadata_required_access: KEY_SET_VALUE,
            tcb_required_for_precedence: true,
        })
    );
}

#[test]
fn layer_write_authorization_rejects_non_concrete_cached_masks() {
    let malformed = LayerWriteAuthorizationInput {
        target_fd_granted_access: KEY_WRITE | GENERIC_READ,
        ..input()
    };

    assert_eq!(
        plan_layer_write_authorization(malformed),
        Err(LcsError::UnknownAccessBits(GENERIC_READ))
    );
}
