use lcs_core::{
    LcsError, LcsLimits, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_EXPAND_SZ,
    REG_FULL_RESOURCE_DESCRIPTOR, REG_LINK, REG_MULTI_SZ, REG_NONE, REG_QWORD, REG_RESOURCE_LIST,
    REG_RESOURCE_REQUIREMENTS_LIST, REG_SZ, RegistryValueType, SequenceCounter, ValidatedValueType,
    ValueWriteInput, ValueWriteRequest, plan_value_write, validate_value_write_request,
};

const KEY_GUID: lcs_core::Guid = [0x62; 16];

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

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn write_request(value_type: u32, data: &[u8]) -> ValueWriteRequest<'_> {
    ValueWriteRequest {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "base",
        sequence: 7,
        value_type,
        data,
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn normal_value_writes_preserve_opaque_payload_bytes_for_every_public_type() {
    let limits = limits();
    let opaque_payload = b"\xff\0not utf8, not a dword, not a registry path";

    for (code, expected_type) in NORMAL_TYPES {
        let validated =
            validate_value_write_request(&limits, &write_request(*code, opaque_payload))
                .unwrap_or_else(|err| panic!("type {code} should accept opaque bytes: {err:?}"));

        assert_eq!(
            validated.value_type,
            ValidatedValueType::Normal(*expected_type)
        );
        assert_eq!(validated.data, opaque_payload);
    }
}

#[test]
fn reg_link_write_payload_is_not_interpreted_at_write_boundary() {
    let limits = limits();
    let malformed_link_target = b"\xff\0not\\a\\valid\\target";

    let validated =
        validate_value_write_request(&limits, &write_request(REG_LINK, malformed_link_target))
            .expect("REG_LINK payload interpretation is limited to symlink resolution");

    assert_eq!(
        validated.value_type,
        ValidatedValueType::Normal(RegistryValueType::Link)
    );
    assert_eq!(validated.data, malformed_link_target);
}

#[test]
fn max_value_size_is_inclusive_and_applies_before_sequence_allocation() {
    let mut limits = limits();
    limits.max_value_size = 4;

    let exact = validate_value_write_request(&limits, &write_request(REG_BINARY, b"1234"))
        .expect("payload exactly at MaxValueSize should validate");
    assert_eq!(exact.data, b"1234");

    let mut counter = SequenceCounter::new(900);
    let too_large = ValueWriteInput {
        key_guid: KEY_GUID,
        name: "Setting",
        layer: "base",
        value_type: REG_BINARY,
        data: b"12345",
        explicit_tombstone_operation: false,
        expected_sequence: None,
    };

    assert_eq!(
        plan_value_write(&limits, &mut counter, &too_large),
        Err(LcsError::ValueDataTooLarge { len: 5, max: 4 })
    );
    assert_eq!(counter.next_sequence(), 900);
}
