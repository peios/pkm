use lcs_core::{LcsError, LinuxErrno, SourceRegistrationErrno, source_registration_error_errno};

fn assert_errno(error: LcsError, expected: SourceRegistrationErrno, linux: LinuxErrno) {
    assert_eq!(source_registration_error_errno(error), Some(expected));
    assert_eq!(LinuxErrno::from(expected), linux);
}

#[test]
fn source_registration_errno_projection_matches_psd_005_table() {
    assert_errno(
        LcsError::MissingTcbPrivilege,
        SourceRegistrationErrno::Eperm,
        LinuxErrno::Eperm,
    );
    assert_errno(
        LcsError::HiveIdentityCollision,
        SourceRegistrationErrno::Eexist,
        LinuxErrno::Eexist,
    );
    assert_errno(
        LcsError::TooManyRegisteredSources { count: 33, max: 32 },
        SourceRegistrationErrno::Enospc,
        LinuxErrno::Enospc,
    );
    assert_errno(
        LcsError::TooManyHives { count: 65, max: 64 },
        SourceRegistrationErrno::Enospc,
        LinuxErrno::Enospc,
    );
    assert_errno(
        LcsError::SequenceOverflow,
        SourceRegistrationErrno::Eoverflow,
        LinuxErrno::Eoverflow,
    );
    assert_errno(
        LcsError::StaleSourceHiveIdentity,
        SourceRegistrationErrno::Estale,
        LinuxErrno::Estale,
    );
}

#[test]
fn malformed_registration_arguments_project_to_einval() {
    let cases = [
        LcsError::InvalidUtf8 { field: "hive_name" },
        LcsError::NullByte { field: "hive_name" },
        LcsError::EmptyString { field: "hive_name" },
        LcsError::NameContainsSeparator { field: "hive_name" },
        LcsError::NameTooLong {
            field: "hive_name",
            len: 65,
            max: 64,
        },
        LcsError::ReservedHiveName,
        LcsError::ZeroHiveCount,
        LcsError::UnknownHiveFlags {
            flags: 0x05,
            unknown: 0x04,
        },
        LcsError::GlobalHiveHasScopeGuid,
        LcsError::NilHiveRootGuid,
        LcsError::DuplicateHiveRootGuid,
        LcsError::DuplicateHiveIdentity,
        LcsError::PartialSourceResume,
    ];

    for error in cases {
        assert_errno(error, SourceRegistrationErrno::Einval, LinuxErrno::Einval);
    }
}

#[test]
fn non_registration_errors_are_not_projected_as_registration_errno() {
    assert_eq!(
        source_registration_error_errno(LcsError::HiveSourceUnavailable),
        None
    );
}
