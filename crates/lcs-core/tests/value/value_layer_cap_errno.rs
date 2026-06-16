use lcs_core::{
    LcsError, ValueLayerAdmissionErrno, value_layer_admission_errno, value_type_validation_errno,
};

#[test]
fn value_layer_cap_failure_maps_to_enospc() {
    let error = LcsError::TooManyLayersPerValue {
        count: 128,
        max: 128,
    };

    assert_eq!(
        value_layer_admission_errno(&error),
        Some(ValueLayerAdmissionErrno::Enospc)
    );
}

#[test]
fn value_layer_cap_errno_does_not_classify_unrelated_value_errors() {
    let error = LcsError::ValueDataTooLarge {
        len: 4097,
        max: 4096,
    };

    assert_eq!(value_layer_admission_errno(&error), None);
    assert_eq!(value_type_validation_errno(&error), None);
}
