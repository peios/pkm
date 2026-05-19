use lcs_core::{
    LAYER_METADATA_ENABLED_VALUE_NAME, LAYER_METADATA_OWNER_VALUE_NAME,
    LAYER_METADATA_PRECEDENCE_VALUE_NAME, LCS_LAYER_METADATA_ROOT_PATH, LayerMetadataValueEntry,
    LcsError, LcsLimits, ParsedLayerMetadataValue, REG_BINARY, REG_DWORD, REG_QWORD,
    parse_layer_metadata_value,
};

const LOCAL_SYSTEM_SID: &[u8] = &[
    1, 1, 0, 0, 0, 0, 0, 5, // SID header: S-1-5
    18, 0, 0, 0, // SECURITY_LOCAL_SYSTEM_RID
];

fn entry<'a>(name: &'a str, value_type: u32, data: &'a [u8]) -> LayerMetadataValueEntry<'a> {
    LayerMetadataValueEntry {
        name,
        value_type,
        data,
    }
}

#[test]
fn layer_metadata_constants_pin_normative_names() {
    assert_eq!(
        LCS_LAYER_METADATA_ROOT_PATH,
        "Machine\\System\\Registry\\Layers"
    );
    assert_eq!(LAYER_METADATA_PRECEDENCE_VALUE_NAME, "Precedence");
    assert_eq!(LAYER_METADATA_ENABLED_VALUE_NAME, "Enabled");
    assert_eq!(LAYER_METADATA_OWNER_VALUE_NAME, "Owner");
}

#[test]
fn precedence_parses_reg_dword_little_endian_case_insensitive() {
    let precedence = 0x0102_0304u32.to_le_bytes();
    let parsed = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("pReCeDeNcE", REG_DWORD, &precedence),
    )
    .unwrap();

    assert_eq!(
        parsed,
        Some(ParsedLayerMetadataValue::Precedence(0x0102_0304))
    );
}

#[test]
fn enabled_accepts_only_reg_dword_zero_or_one() {
    let zero = 0u32.to_le_bytes();
    let one = 1u32.to_le_bytes();
    let two = 2u32.to_le_bytes();
    let disabled =
        parse_layer_metadata_value(&LcsLimits::default(), entry("Enabled", REG_DWORD, &zero))
            .unwrap();
    let enabled =
        parse_layer_metadata_value(&LcsLimits::default(), entry("enabled", REG_DWORD, &one))
            .unwrap();
    let invalid =
        parse_layer_metadata_value(&LcsLimits::default(), entry("Enabled", REG_DWORD, &two))
            .unwrap_err();

    assert_eq!(disabled, Some(ParsedLayerMetadataValue::Enabled(false)));
    assert_eq!(enabled, Some(ParsedLayerMetadataValue::Enabled(true)));
    assert_eq!(invalid, LcsError::InvalidLayerMetadataEnabledValue(2));
}

#[test]
fn owner_parses_reg_binary_sid_without_interpreting_access_control() {
    let parsed = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("OWNER", REG_BINARY, LOCAL_SYSTEM_SID),
    )
    .unwrap();

    assert_eq!(
        parsed,
        Some(ParsedLayerMetadataValue::Owner(LOCAL_SYSTEM_SID))
    );
}

#[test]
fn unknown_valid_metadata_value_is_ignored() {
    let parsed = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("Future/Value", REG_QWORD, &[1, 2, 3, 4, 5, 6, 7, 8]),
    )
    .unwrap();

    assert_eq!(parsed, None);
}

#[test]
fn known_metadata_values_fail_closed_on_wrong_type_or_length() {
    let wrong_type = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("Precedence", REG_QWORD, &0u32.to_le_bytes()),
    )
    .unwrap_err();
    let wrong_length = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("Enabled", REG_DWORD, &[1, 0, 0]),
    )
    .unwrap_err();
    let malformed_owner = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("Owner", REG_BINARY, &[1, 0, 0, 0, 0, 0, 0]),
    )
    .unwrap_err();

    assert_eq!(
        wrong_type,
        LcsError::LayerMetadataValueTypeMismatch {
            value_name: "Precedence",
            expected: REG_DWORD,
            actual: REG_QWORD,
        }
    );
    assert_eq!(
        wrong_length,
        LcsError::LayerMetadataValueLengthMismatch {
            value_name: "Enabled",
            expected: 4,
            actual: 3,
        }
    );
    assert_eq!(malformed_owner, LcsError::MalformedLayerOwnerSid);
}

#[test]
fn invalid_value_name_fails_before_metadata_classification() {
    let error = parse_layer_metadata_value(
        &LcsLimits::default(),
        entry("Owner\0", REG_BINARY, LOCAL_SYSTEM_SID),
    )
    .unwrap_err();

    assert_eq!(
        error,
        LcsError::NullByte {
            field: "value_name"
        }
    );
}
