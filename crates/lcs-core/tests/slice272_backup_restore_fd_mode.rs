use lcs_core::{
    BackupRestoreFdModeErrno, BackupRestoreFdModePlan, BackupRestoreFdOperation, LinuxErrno,
    backup_restore_fd_mode_linux_errno, plan_backup_restore_fd_mode,
};

#[test]
fn backup_requires_writable_external_fd_before_starting() {
    let allowed = plan_backup_restore_fd_mode(BackupRestoreFdOperation::BackupOutput, false, true);
    assert_eq!(
        allowed,
        BackupRestoreFdModePlan::Allowed {
            operation: BackupRestoreFdOperation::BackupOutput,
            requires_readable: false,
            requires_writable: true,
        }
    );
    assert_eq!(backup_restore_fd_mode_linux_errno(&allowed), None);

    let denied = plan_backup_restore_fd_mode(BackupRestoreFdOperation::BackupOutput, true, false);
    assert_eq!(
        denied,
        BackupRestoreFdModePlan::Denied {
            operation: BackupRestoreFdOperation::BackupOutput,
            requires_readable: false,
            requires_writable: true,
            errno: BackupRestoreFdModeErrno::Ebadf,
        }
    );
    assert_eq!(
        backup_restore_fd_mode_linux_errno(&denied),
        Some(LinuxErrno::Ebadf)
    );
}

#[test]
fn restore_requires_readable_external_fd_before_starting() {
    let allowed = plan_backup_restore_fd_mode(BackupRestoreFdOperation::RestoreInput, true, false);
    assert_eq!(
        allowed,
        BackupRestoreFdModePlan::Allowed {
            operation: BackupRestoreFdOperation::RestoreInput,
            requires_readable: true,
            requires_writable: false,
        }
    );
    assert_eq!(backup_restore_fd_mode_linux_errno(&allowed), None);

    let denied = plan_backup_restore_fd_mode(BackupRestoreFdOperation::RestoreInput, false, true);
    assert_eq!(
        denied,
        BackupRestoreFdModePlan::Denied {
            operation: BackupRestoreFdOperation::RestoreInput,
            requires_readable: true,
            requires_writable: false,
            errno: BackupRestoreFdModeErrno::Ebadf,
        }
    );
    assert_eq!(
        backup_restore_fd_mode_linux_errno(&denied),
        Some(LinuxErrno::Ebadf)
    );
}

#[test]
fn read_write_external_fds_satisfy_both_backup_and_restore_mode_gates() {
    let backup = plan_backup_restore_fd_mode(BackupRestoreFdOperation::BackupOutput, true, true);
    let restore = plan_backup_restore_fd_mode(BackupRestoreFdOperation::RestoreInput, true, true);

    assert!(matches!(backup, BackupRestoreFdModePlan::Allowed { .. }));
    assert!(matches!(restore, BackupRestoreFdModePlan::Allowed { .. }));
    assert_eq!(backup_restore_fd_mode_linux_errno(&backup), None);
    assert_eq!(backup_restore_fd_mode_linux_errno(&restore), None);
}
