use lcs_core::{
    KeyFdOperation, LcsError, LinuxErrno, key_fd_orphan_operation_linux_errno,
    plan_key_fd_orphan_operation,
};

#[test]
fn orphaned_key_fd_rejected_operations_project_to_linux_enoent() {
    let namespace_error =
        plan_key_fd_orphan_operation(true, KeyFdOperation::CreateChildKey).unwrap_err();
    assert_eq!(
        key_fd_orphan_operation_linux_errno(&namespace_error),
        Some(LinuxErrno::Enoent)
    );

    let backup_error = plan_key_fd_orphan_operation(true, KeyFdOperation::Backup).unwrap_err();
    assert_eq!(
        key_fd_orphan_operation_linux_errno(&backup_error),
        Some(LinuxErrno::Enoent)
    );
}

#[test]
fn reachable_and_guid_local_orphaned_operations_have_no_orphan_errno() {
    assert!(
        plan_key_fd_orphan_operation(false, KeyFdOperation::CreateChildKey).is_ok(),
        "reachable namespace operations do not trip the orphan gate"
    );
    assert!(
        plan_key_fd_orphan_operation(true, KeyFdOperation::SetValue).is_ok(),
        "GUID-local orphaned operations remain admitted"
    );

    assert_eq!(
        key_fd_orphan_operation_linux_errno(&LcsError::SequenceOverflow),
        None
    );
    assert_eq!(
        key_fd_orphan_operation_linux_errno(&LcsError::InvalidFdAncestry),
        None
    );
}
