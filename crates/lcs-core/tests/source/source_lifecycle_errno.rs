use lcs_core::{LcsError, LinuxErrno, SourceLifecycleErrno, source_lifecycle_error_errno};

fn assert_errno(error: LcsError, expected: SourceLifecycleErrno, linux: LinuxErrno) {
    assert_eq!(source_lifecycle_error_errno(error), Some(expected));
    assert_eq!(LinuxErrno::from(expected), linux);
}

#[test]
fn source_down_round_trip_failure_projects_to_eio() {
    assert_errno(
        LcsError::HiveSourceUnavailable,
        SourceLifecycleErrno::Eio,
        LinuxErrno::Eio,
    );
    assert_eq!(LinuxErrno::from(SourceLifecycleErrno::Eio).raw(), 5);
}

#[test]
fn disappeared_guid_after_resume_projects_to_enoent() {
    assert_errno(
        LcsError::RestartedSourceKeyNotFound,
        SourceLifecycleErrno::Enoent,
        LinuxErrno::Enoent,
    );
    assert_eq!(LinuxErrno::from(SourceLifecycleErrno::Enoent).raw(), 2);
}

#[test]
fn source_lifecycle_errno_helper_does_not_classify_unrelated_errors() {
    assert_eq!(
        source_lifecycle_error_errno(LcsError::MissingTcbPrivilege),
        None
    );
    assert_eq!(source_lifecycle_error_errno(LcsError::NilKeyGuid), None);
}
