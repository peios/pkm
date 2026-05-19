use lcs_core::{
    KeyFdOperation, KeyFdOperationScope, KeyFdOrphanOperationErrno, KeyFdOrphanOperationPlan,
    LcsError, key_fd_orphan_operation_errno, plan_key_fd_orphan_operation,
};

fn guid_local_operations() -> [KeyFdOperation; 10] {
    [
        KeyFdOperation::QueryValue,
        KeyFdOperation::SetValue,
        KeyFdOperation::DeleteValue,
        KeyFdOperation::SetBlanketTombstone,
        KeyFdOperation::RemoveBlanketTombstone,
        KeyFdOperation::QuerySecurityDescriptor,
        KeyFdOperation::SetSecurityDescriptor,
        KeyFdOperation::QueryMetadata,
        KeyFdOperation::FlushHive,
        KeyFdOperation::Close,
    ]
}

fn namespace_operations() -> [KeyFdOperation; 5] {
    [
        KeyFdOperation::CreateChildKey,
        KeyFdOperation::RelativeOpenKey,
        KeyFdOperation::RelativeCreateKey,
        KeyFdOperation::DeletePathEntry,
        KeyFdOperation::HideKey,
    ]
}

#[test]
fn orphaned_key_fds_keep_guid_local_operations() {
    for operation in guid_local_operations() {
        assert_eq!(
            plan_key_fd_orphan_operation(true, operation),
            Ok(KeyFdOrphanOperationPlan {
                operation,
                scope: KeyFdOperationScope::GuidLocal,
                orphaned: true,
            })
        );
    }
}

#[test]
fn orphaned_key_fds_reject_namespace_operations_as_enoent() {
    for operation in namespace_operations() {
        let error = plan_key_fd_orphan_operation(true, operation).unwrap_err();

        assert_eq!(error, LcsError::OrphanedKeyNamespaceOperation);
        assert_eq!(
            key_fd_orphan_operation_errno(&error),
            Some(KeyFdOrphanOperationErrno::Enoent)
        );
    }
}

#[test]
fn orphaned_key_fds_reject_backup_as_enoent() {
    let error = plan_key_fd_orphan_operation(true, KeyFdOperation::Backup).unwrap_err();

    assert_eq!(error, LcsError::OrphanedKeyBackupOperation);
    assert_eq!(
        key_fd_orphan_operation_errno(&error),
        Some(KeyFdOrphanOperationErrno::Enoent)
    );
}

#[test]
fn reachable_key_fds_do_not_trip_the_orphan_gate() {
    for (operation, scope) in guid_local_operations()
        .into_iter()
        .map(|operation| (operation, KeyFdOperationScope::GuidLocal))
        .chain(
            namespace_operations()
                .into_iter()
                .map(|operation| (operation, KeyFdOperationScope::Namespace)),
        )
        .chain([(KeyFdOperation::Backup, KeyFdOperationScope::Backup)])
    {
        assert_eq!(
            plan_key_fd_orphan_operation(false, operation),
            Ok(KeyFdOrphanOperationPlan {
                operation,
                scope,
                orphaned: false,
            })
        );
    }
}
