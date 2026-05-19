use lcs_core::{
    LcsError, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ,
    REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_RESOURCE_LIST,
    REG_RESOURCE_REQUIREMENTS_LIST, REG_SZ, REG_TOMBSTONE, RegistryValueType, ValidatedValueType,
    validate_value_write_type,
};

const NORMAL_TYPES: &[(u32, RegistryValueType)] = &[
    (REG_NONE, RegistryValueType::None),
    (REG_SZ, RegistryValueType::Sz),
    (REG_EXPAND_SZ, RegistryValueType::ExpandSz),
    (REG_BINARY, RegistryValueType::Binary),
    (REG_DWORD, RegistryValueType::Dword),
    (REG_DWORD_BIG_ENDIAN, RegistryValueType::DwordBigEndian),
    (REG_LINK, RegistryValueType::Link),
    (REG_MULTI_SZ, RegistryValueType::MultiSz),
    (REG_RESOURCE_LIST, RegistryValueType::ResourceList),
    (
        REG_FULL_RESOURCE_DESCRIPTOR,
        RegistryValueType::FullResourceDescriptor,
    ),
    (
        REG_RESOURCE_REQUIREMENTS_LIST,
        RegistryValueType::ResourceRequirementsList,
    ),
    (REG_QWORD, RegistryValueType::Qword),
];

#[test]
fn normal_value_type_set_matches_psd_005_codes() {
    for (code, expected) in NORMAL_TYPES {
        assert_eq!(RegistryValueType::from_code(*code), Some(*expected));
        assert_eq!(expected.code(), *code);
    }

    assert_eq!(RegistryValueType::from_code(REG_TOMBSTONE), None);
    assert_eq!(RegistryValueType::from_code(12), None);
}

#[test]
fn normal_value_types_validate_as_opaque_typed_blobs() {
    let opaque_payload = b"\xff\0not utf8, not typed shape";

    for (code, expected) in NORMAL_TYPES {
        assert_eq!(
            validate_value_write_type(*code, opaque_payload.len(), false),
            Ok(ValidatedValueType::Normal(*expected)),
            "type {code} should validate without interpreting payload bytes"
        );
    }
}

#[test]
fn resource_list_value_types_have_no_special_write_shape() {
    for code in [
        REG_RESOURCE_LIST,
        REG_FULL_RESOURCE_DESCRIPTOR,
        REG_RESOURCE_REQUIREMENTS_LIST,
    ] {
        assert_eq!(
            validate_value_write_type(code, 0, false),
            Ok(ValidatedValueType::Normal(
                RegistryValueType::from_code(code).unwrap()
            ))
        );
        assert_eq!(
            validate_value_write_type(code, 64, false),
            Ok(ValidatedValueType::Normal(
                RegistryValueType::from_code(code).unwrap()
            ))
        );
    }
}

#[test]
fn unknown_types_and_non_explicit_tombstones_fail_closed() {
    assert_eq!(
        validate_value_write_type(12, 0, false),
        Err(LcsError::UnknownValueType(12))
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 0, false),
        Err(LcsError::TombstoneNotExplicit)
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 1, true),
        Err(LcsError::TombstoneDataMustBeEmpty { len: 1 })
    );
    assert_eq!(
        validate_value_write_type(REG_TOMBSTONE, 0, true),
        Ok(ValidatedValueType::Tombstone)
    );
}
