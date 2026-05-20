use lcs_core::{
    LcsError, LinuxErrno, source_lifecycle_error_linux_errno, source_registration_error_linux_errno,
};

#[test]
fn source_registration_errors_project_directly_to_linux_errno() {
    let cases = [
        (LcsError::MissingTcbPrivilege, LinuxErrno::Eperm),
        (LcsError::HiveIdentityCollision, LinuxErrno::Eexist),
        (
            LcsError::TooManyRegisteredSources { count: 33, max: 32 },
            LinuxErrno::Enospc,
        ),
        (
            LcsError::TooManyHives { count: 65, max: 64 },
            LinuxErrno::Enospc,
        ),
        (LcsError::SequenceOverflow, LinuxErrno::Eoverflow),
        (LcsError::StaleSourceHiveIdentity, LinuxErrno::Estale),
        (LcsError::ReservedHiveName, LinuxErrno::Einval),
        (LcsError::PartialSourceResume, LinuxErrno::Einval),
    ];

    for (error, errno) in cases {
        assert_eq!(source_registration_error_linux_errno(error), Some(errno));
    }
}

#[test]
fn source_lifecycle_errors_project_directly_to_linux_errno() {
    let cases = [
        (LcsError::HiveSourceUnavailable, LinuxErrno::Eio),
        (LcsError::RestartedSourceKeyNotFound, LinuxErrno::Enoent),
    ];

    for (error, errno) in cases {
        assert_eq!(source_lifecycle_error_linux_errno(error), Some(errno));
    }
}

#[test]
fn source_errno_helpers_do_not_classify_unrelated_errors() {
    assert_eq!(
        source_registration_error_linux_errno(LcsError::HiveSourceUnavailable),
        None
    );
    assert_eq!(
        source_lifecycle_error_linux_errno(LcsError::MissingTcbPrivilege),
        None
    );
}
