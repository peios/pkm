use crate::common::{limits};
use lcs_core::{
    Guid, REG_LINK, REG_SZ, RegistryValueType, SymlinkDefaultValue,
    SymlinkDefaultValueResolution, SymlinkResolutionErrno, ValidatedValueType, ValueWriteRequest,
    classify_symlink_default_value_resolution, validate_value_write_request,
};

const KEY_GUID: Guid = [0x41; 16];


fn default_value_write(value_type: u32, data: &'static [u8]) -> ValueWriteRequest<'static> {
    ValueWriteRequest {
        key_guid: KEY_GUID,
        name: "",
        layer: "base",
        sequence: 11,
        value_type,
        data,
        explicit_tombstone_operation: false,
        expected_sequence: None,
    }
}

#[test]
fn symlink_resolution_maps_non_reg_link_default_to_einval() {
    let outcome = classify_symlink_default_value_resolution(
        &limits(),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Sz,
            data: b"Machine\\Target",
        }),
    );

    assert_eq!(
        outcome,
        SymlinkDefaultValueResolution::Failed(SymlinkResolutionErrno::Einval)
    );
}

#[test]
fn symlink_resolution_maps_missing_default_to_einval() {
    assert_eq!(
        classify_symlink_default_value_resolution(&limits(), None),
        SymlinkDefaultValueResolution::Failed(SymlinkResolutionErrno::Einval)
    );
}

#[test]
fn symlink_resolution_accepts_effective_reg_link_targets() {
    let outcome = classify_symlink_default_value_resolution(
        &limits(),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data: b"Machine\\Target",
        }),
    );

    let SymlinkDefaultValueResolution::Target(target) = outcome else {
        panic!("REG_LINK default should resolve to a target path");
    };
    assert_eq!(target.raw, "Machine\\Target");
    assert_eq!(target.first_component, "Machine");
    assert_eq!(target.final_component, "Target");
}

#[test]
fn default_value_writes_do_not_validate_symlink_target_type() {
    let reg_sz = validate_value_write_request(&limits(), &default_value_write(REG_SZ, b"not-link"))
        .expect("default REG_SZ writes remain valid value writes");
    assert_eq!(reg_sz.name, "");
    assert_eq!(
        reg_sz.value_type,
        ValidatedValueType::Normal(RegistryValueType::Sz)
    );

    let reg_link = validate_value_write_request(
        &limits(),
        &default_value_write(REG_LINK, b"Machine\\Target"),
    )
    .expect("default REG_LINK writes remain ordinary value writes");
    assert_eq!(
        reg_link.value_type,
        ValidatedValueType::Normal(RegistryValueType::Link)
    );
}
