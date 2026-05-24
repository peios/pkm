use lcs_core::{
    LayerResolutionContext, LayerView, LcsError, LcsLimits, LcsSourceValidationClass, REG_SZ,
    RsiMalformedSourceDataPlan, RsiMappedErrno, RsiSourceDataValidationFailure, ValueEntry,
    ValueResolution, plan_rsi_malformed_source_data, resolve_value,
};

fn context<'a>(layers: &'a [LayerView<'a>], limits: &'a LcsLimits) -> LayerResolutionContext<'a> {
    LayerResolutionContext {
        layers,
        private_layers: &[],
        limits,
        next_sequence: 100,
    }
}

#[test]
fn malformed_source_layer_name_rejects_before_resolution() {
    let limits = LcsLimits::default();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let entries = [ValueEntry {
        layer: "bad/layer",
        sequence: 1,
        value_type: REG_SZ,
        data: b"value",
    }];

    assert_eq!(
        resolve_value(&context(&layers, &limits), &entries, &[]),
        Err(LcsError::NameContainsSeparator {
            field: "layer_name"
        })
    );
}

#[test]
fn malformed_layer_name_maps_to_source_data_eio_audit_policy() {
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::MalformedLayerName),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::MalformedLayerName,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
}

#[test]
fn malformed_key_and_value_names_map_to_source_data_eio_audit_policy() {
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::MalformedKeyName),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::MalformedKeyName,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
    assert_eq!(
        plan_rsi_malformed_source_data(RsiSourceDataValidationFailure::MalformedValueName),
        RsiMalformedSourceDataPlan {
            failure: RsiSourceDataValidationFailure::MalformedValueName,
            caller_errno: RsiMappedErrno::Eio,
            emit_audit: true,
            keep_source_alive: true,
            retain_previous_layer_metadata_sd: false,
        }
    );
}

#[test]
fn remaining_source_validation_classes_map_to_source_data_eio_audit_policy() {
    for failure in [
        RsiSourceDataValidationFailure::MalformedResponsePayload,
        RsiSourceDataValidationFailure::MalformedKeyMetadata,
        RsiSourceDataValidationFailure::MalformedValuePayload,
        RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList,
    ] {
        assert_eq!(
            plan_rsi_malformed_source_data(failure),
            RsiMalformedSourceDataPlan {
                failure,
                caller_errno: RsiMappedErrno::Eio,
                emit_audit: true,
                keep_source_alive: true,
                retain_previous_layer_metadata_sd: false,
            }
        );
    }
}

#[test]
fn source_validation_audit_vocabulary_names_malformed_layer_names() {
    let class = LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedLayerName);

    assert_eq!(class, LcsSourceValidationClass::MalformedLayerName);
    assert_eq!(class.as_str(), "malformed_layer_name");
}

#[test]
fn source_validation_audit_vocabulary_names_malformed_key_and_value_names() {
    let key_class =
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedKeyName);
    let value_class =
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedValueName);

    assert_eq!(key_class, LcsSourceValidationClass::MalformedKeyName);
    assert_eq!(key_class.as_str(), "malformed_key_name");
    assert_eq!(value_class, LcsSourceValidationClass::MalformedValueName);
    assert_eq!(value_class.as_str(), "malformed_value_name");
}

#[test]
fn source_validation_audit_vocabulary_names_remaining_source_classes() {
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedResponsePayload)
            .as_str(),
        "malformed_response_payload"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedKeyMetadata)
            .as_str(),
        "malformed_key_metadata"
    );
    assert_eq!(
        LcsSourceValidationClass::from(RsiSourceDataValidationFailure::MalformedValuePayload)
            .as_str(),
        "malformed_value_payload"
    );
    assert_eq!(
        LcsSourceValidationClass::from(
            RsiSourceDataValidationFailure::MalformedDeleteLayerOrphanList,
        )
        .as_str(),
        "malformed_delete_layer_orphan_list"
    );
}

#[test]
fn well_formed_absent_source_layer_remains_latent_not_malformed() {
    let limits = LcsLimits::default();
    let layers = [LayerView {
        name: "base",
        precedence: 0,
        enabled: true,
    }];
    let entries = [ValueEntry {
        layer: "future",
        sequence: 1,
        value_type: REG_SZ,
        data: b"value",
    }];

    assert_eq!(
        resolve_value(&context(&layers, &limits), &entries, &[]),
        Ok(ValueResolution::NotFound)
    );
}
