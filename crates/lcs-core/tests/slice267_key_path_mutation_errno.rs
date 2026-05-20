use lcs_core::{LcsError, LinuxErrno, key_path_mutation_linux_errno};

#[test]
fn key_path_mutation_failures_project_to_linux_errnos() {
    assert_eq!(
        key_path_mutation_linux_errno(&LcsError::HiveRootKeyOperation),
        Some(LinuxErrno::Einval)
    );
    assert_eq!(
        key_path_mutation_linux_errno(&LcsError::OrphanedKeyNamespaceOperation),
        Some(LinuxErrno::Enoent)
    );
    assert_eq!(
        key_path_mutation_linux_errno(&LcsError::KeyHasVisibleChildren { count: 3 }),
        Some(LinuxErrno::Enotempty)
    );
}

#[test]
fn unrelated_errors_are_not_key_path_mutation_errno() {
    assert_eq!(
        key_path_mutation_linux_errno(&LcsError::SequenceOverflow),
        None
    );
    assert_eq!(
        key_path_mutation_linux_errno(&LcsError::InvalidFdAncestry),
        None
    );
}
