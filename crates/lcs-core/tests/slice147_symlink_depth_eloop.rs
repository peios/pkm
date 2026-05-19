use lcs_core::{
    LcsLimits, SymlinkFollowDepthResolution, SymlinkResolutionErrno, classify_symlink_follow_depth,
    validate_symlink_follow_depth,
};

#[test]
fn symlink_depth_limit_default_is_configurable_input() {
    let limits = LcsLimits::default();

    assert_eq!(limits.symlink_depth_limit, 16);
    assert_eq!(
        classify_symlink_follow_depth(0, &limits),
        SymlinkFollowDepthResolution::Advanced(1)
    );
}

#[test]
fn symlink_follow_depth_advances_until_configured_limit() {
    let mut limits = LcsLimits::default();
    limits.symlink_depth_limit = 2;

    assert_eq!(
        classify_symlink_follow_depth(0, &limits),
        SymlinkFollowDepthResolution::Advanced(1)
    );
    assert_eq!(
        classify_symlink_follow_depth(1, &limits),
        SymlinkFollowDepthResolution::Advanced(2)
    );
}

#[test]
fn exceeding_symlink_follow_depth_maps_to_eloop() {
    let mut limits = LcsLimits::default();
    limits.symlink_depth_limit = 2;

    assert_eq!(
        classify_symlink_follow_depth(2, &limits),
        SymlinkFollowDepthResolution::Failed(SymlinkResolutionErrno::Eloop)
    );
    assert_eq!(
        validate_symlink_follow_depth(2, &limits),
        Err(lcs_core::LcsError::SymlinkDepthExceeded { depth: 3, max: 2 })
    );
}
