use lcs_core::{
    LcsLimits, LinuxErrno, RegistryValueType, SymlinkDefaultValue, SymlinkDefaultValueResolution,
    SymlinkFollowDepthResolution, classify_symlink_default_value_resolution,
    classify_symlink_follow_depth, symlink_default_value_resolution_errno,
    symlink_follow_depth_resolution_errno,
};

#[test]
fn valid_symlink_default_value_resolution_has_no_errno() {
    let outcome = classify_symlink_default_value_resolution(
        &LcsLimits::default(),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data: b"Machine\\Target",
        }),
    );

    assert!(matches!(outcome, SymlinkDefaultValueResolution::Target(_)));
    assert_eq!(symlink_default_value_resolution_errno(&outcome), None);
}

#[test]
fn missing_non_link_and_malformed_symlink_targets_project_to_einval() {
    let limits = LcsLimits::default();
    let cases = [
        None,
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Sz,
            data: b"Machine\\Target",
        }),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data: b"Machine\\\\Target",
        }),
    ];

    for default_value in cases {
        let outcome = classify_symlink_default_value_resolution(&limits, default_value);
        assert_eq!(
            symlink_default_value_resolution_errno(&outcome),
            Some(LinuxErrno::Einval)
        );
    }
}

#[test]
fn symlink_follow_depth_outcomes_project_to_linux_errno() {
    let mut limits = LcsLimits::default();
    limits.symlink_depth_limit = 2;

    assert_eq!(
        classify_symlink_follow_depth(1, &limits),
        SymlinkFollowDepthResolution::Advanced(2)
    );
    assert_eq!(
        symlink_follow_depth_resolution_errno(classify_symlink_follow_depth(1, &limits)),
        None
    );
    assert_eq!(
        symlink_follow_depth_resolution_errno(classify_symlink_follow_depth(2, &limits)),
        Some(LinuxErrno::Eloop)
    );
}
