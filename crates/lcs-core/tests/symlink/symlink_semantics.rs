use crate::common::{limits};
use lcs_core::{
    LcsError, PathKind, RegistryValueType, SymlinkDefaultValue,
    validate_symlink_default_value, validate_symlink_follow_depth, validate_symlink_target_bytes,
};


#[test]
fn symlink_default_value_requires_effective_reg_link() {
    let limits = limits();

    assert_eq!(
        validate_symlink_default_value(&limits, None),
        Err(LcsError::SymlinkDefaultValueMissing)
    );
    assert_eq!(
        validate_symlink_default_value(
            &limits,
            Some(SymlinkDefaultValue {
                value_type: RegistryValueType::Sz,
                data: b"Machine\\Software",
            }),
        ),
        Err(LcsError::SymlinkDefaultNotRegLink(
            RegistryValueType::Sz.code()
        ))
    );
}

#[test]
fn symlink_default_value_accepts_length_delimited_absolute_registry_path() {
    let limits = limits();
    let target = validate_symlink_default_value(
        &limits,
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data: b"Machine/Software/App",
        }),
    )
    .expect("REG_LINK target should validate");

    assert_eq!(target.raw, "Machine/Software/App");
    assert_eq!(target.kind, PathKind::SymlinkTarget);
    assert_eq!(target.component_count, 3);
    assert_eq!(target.first_component, "Machine");
    assert_eq!(target.final_component, "App");
    assert!(target.used_forward_separator);
}

#[test]
fn symlink_target_validation_rejects_invalid_encoding_and_structure() {
    let limits = limits();

    assert_eq!(
        validate_symlink_target_bytes(&limits, b""),
        Err(LcsError::EmptyPath)
    );
    assert_eq!(
        validate_symlink_target_bytes(&limits, b"Machine\\\\Software"),
        Err(LcsError::EmptyPathComponent)
    );
    assert_eq!(
        validate_symlink_target_bytes(&limits, b"Machine\\Software\\"),
        Err(LcsError::TrailingPathSeparator)
    );
    assert_eq!(
        validate_symlink_target_bytes(&limits, b"Machine\\Soft\0ware"),
        Err(LcsError::NullByte { field: "path" })
    );
    assert_eq!(
        validate_symlink_target_bytes(&limits, &[0xff]),
        Err(LcsError::InvalidUtf8 { field: "path" })
    );
}

#[test]
fn symlink_target_validation_applies_path_limits() {
    let mut component_limits = limits();
    component_limits.max_path_component_length = 3;
    assert_eq!(
        validate_symlink_target_bytes(&component_limits, b"Mach"),
        Err(LcsError::NameTooLong {
            field: "path_component",
            len: 4,
            max: 3,
        })
    );

    let mut total_limits = limits();
    total_limits.max_total_path_length = 7;
    assert_eq!(
        validate_symlink_target_bytes(&total_limits, b"Machine\\X"),
        Err(LcsError::PathTooLong { len: 9, max: 7 })
    );
}

#[test]
fn symlink_follow_depth_advances_until_configured_limit() {
    let mut limits = limits();
    limits.symlink_depth_limit = 2;

    assert_eq!(validate_symlink_follow_depth(0, &limits), Ok(1));
    assert_eq!(validate_symlink_follow_depth(1, &limits), Ok(2));
    assert_eq!(
        validate_symlink_follow_depth(2, &limits),
        Err(LcsError::SymlinkDepthExceeded { depth: 3, max: 2 })
    );
}
