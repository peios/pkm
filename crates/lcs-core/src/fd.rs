use crate::access::{registry_fd_has_right, validate_registry_granted_access};
use crate::config::LcsLimits;
use crate::errno::LinuxErrno;
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_hive_name_bytes, validate_key_component_bytes};
use crate::resolution::Guid;
use crate::source::{NIL_GUID, SourceSlotStatus};
use crate::watch::KeyWatchState;

/// Semantic snapshot stored by an open registry key fd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdOpenView<'a> {
    pub key_guid: Guid,
    pub granted_access: u32,
    pub resolved_path: &'a [&'a str],
    pub ancestor_guids: &'a [Guid],
    pub watch_state: KeyWatchState,
}

/// Capability transferred when a key fd is passed to another process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdDelegationPlan {
    pub delegated_granted_access: u32,
}

/// Operation category for orphaned-key fd admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFdOperationScope {
    GuidLocal,
    Namespace,
    Backup,
}

/// Key-fd operation admitted or rejected by the orphaned-key gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFdOperation {
    QueryValue,
    SetValue,
    DeleteValue,
    SetBlanketTombstone,
    RemoveBlanketTombstone,
    QuerySecurityDescriptor,
    SetSecurityDescriptor,
    QueryMetadata,
    FlushHive,
    Close,
    CreateChildKey,
    RelativeOpenKey,
    RelativeCreateKey,
    DeletePathEntry,
    HideKey,
    Backup,
}

impl KeyFdOperation {
    pub fn scope(self) -> KeyFdOperationScope {
        match self {
            Self::QueryValue
            | Self::SetValue
            | Self::DeleteValue
            | Self::SetBlanketTombstone
            | Self::RemoveBlanketTombstone
            | Self::QuerySecurityDescriptor
            | Self::SetSecurityDescriptor
            | Self::QueryMetadata
            | Self::FlushHive
            | Self::Close => KeyFdOperationScope::GuidLocal,
            Self::CreateChildKey
            | Self::RelativeOpenKey
            | Self::RelativeCreateKey
            | Self::DeletePathEntry
            | Self::HideKey => KeyFdOperationScope::Namespace,
            Self::Backup => KeyFdOperationScope::Backup,
        }
    }
}

/// Caller-visible errno class for orphaned-key fd admission failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFdOrphanOperationErrno {
    Enoent,
}

/// Successful orphaned-key fd admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdOrphanOperationPlan {
    pub operation: KeyFdOperation,
    pub scope: KeyFdOperationScope,
    pub orphaned: bool,
}

/// Planned cleanup when a key fd is closed by normal Linux fd teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdClosePlan {
    pub release_key_reference: bool,
    pub remove_watch: bool,
    pub discard_pending_watch_events: bool,
}

/// Planned cleanup when the last fd to an orphaned key closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanedKeyLastFdClosePlan {
    pub send_rsi_drop_key: bool,
    pub dispatch_drop_before_releasing_kernel_state: bool,
    pub release_kernel_key_state: bool,
    pub queue_deferred_drop: bool,
    pub close_reports_cleanup_failure: bool,
    pub source_startup_cleanup_responsible: bool,
}

/// Validates the immutable semantic fields captured on a key fd at open time.
pub fn validate_key_fd_open_view(limits: &LcsLimits, fd: &KeyFdOpenView<'_>) -> LcsResult<()> {
    if fd.key_guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    validate_registry_granted_access(fd.granted_access)?;
    validate_fd_ancestry(limits, fd.resolved_path, fd.ancestor_guids, fd.key_guid)
}

/// Checks an ioctl-required mask against a key fd's immutable granted mask.
pub fn key_fd_granted_access_allows(fd_granted_access: u32, required: u32) -> LcsResult<bool> {
    validate_registry_granted_access(fd_granted_access)?;
    validate_registry_granted_access(required)?;
    Ok(registry_fd_has_right(fd_granted_access, required))
}

/// Plans explicit fd-capability delegation over SCM_RIGHTS.
pub fn plan_key_fd_delegation(
    limits: &LcsLimits,
    fd: &KeyFdOpenView<'_>,
) -> LcsResult<KeyFdDelegationPlan> {
    validate_key_fd_open_view(limits, fd)?;
    Ok(KeyFdDelegationPlan {
        delegated_granted_access: fd.granted_access,
    })
}

/// Applies the orphaned-key operation split to an existing key fd.
pub fn plan_key_fd_orphan_operation(
    orphaned: bool,
    operation: KeyFdOperation,
) -> LcsResult<KeyFdOrphanOperationPlan> {
    let scope = operation.scope();
    if orphaned {
        match scope {
            KeyFdOperationScope::GuidLocal => {}
            KeyFdOperationScope::Namespace => {
                return Err(LcsError::OrphanedKeyNamespaceOperation);
            }
            KeyFdOperationScope::Backup => {
                return Err(LcsError::OrphanedKeyBackupOperation);
            }
        }
    }

    Ok(KeyFdOrphanOperationPlan {
        operation,
        scope,
        orphaned,
    })
}

/// Maps orphaned-key fd admission failures to their PSD-005 errno class.
pub fn key_fd_orphan_operation_errno(error: &LcsError) -> Option<KeyFdOrphanOperationErrno> {
    match error {
        LcsError::OrphanedKeyNamespaceOperation | LcsError::OrphanedKeyBackupOperation => {
            Some(KeyFdOrphanOperationErrno::Enoent)
        }
        _ => None,
    }
}

/// Projects orphaned-key fd admission failures to Linux errno.
pub fn key_fd_orphan_operation_linux_errno(error: &LcsError) -> Option<LinuxErrno> {
    key_fd_orphan_operation_errno(error).map(LinuxErrno::from)
}

/// Plans source cleanup for the last fd close on an already-orphaned key.
pub fn plan_orphaned_key_last_fd_close(
    key_guid: Guid,
    source_status: SourceSlotStatus,
) -> LcsResult<OrphanedKeyLastFdClosePlan> {
    if key_guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }

    Ok(match source_status {
        SourceSlotStatus::Active => OrphanedKeyLastFdClosePlan {
            send_rsi_drop_key: true,
            dispatch_drop_before_releasing_kernel_state: true,
            release_kernel_key_state: true,
            queue_deferred_drop: false,
            close_reports_cleanup_failure: false,
            source_startup_cleanup_responsible: false,
        },
        SourceSlotStatus::Down => OrphanedKeyLastFdClosePlan {
            send_rsi_drop_key: false,
            dispatch_drop_before_releasing_kernel_state: false,
            release_kernel_key_state: true,
            queue_deferred_drop: false,
            close_reports_cleanup_failure: false,
            source_startup_cleanup_responsible: true,
        },
    })
}

/// Plans key-fd release side effects for close(), close-on-exec, or process exit.
pub fn plan_key_fd_close(limits: &LcsLimits, fd: &KeyFdOpenView<'_>) -> LcsResult<KeyFdClosePlan> {
    validate_key_fd_open_view(limits, fd)?;
    Ok(KeyFdClosePlan {
        release_key_reference: true,
        remove_watch: fd.watch_state.armed,
        discard_pending_watch_events: fd.watch_state.armed,
    })
}

fn validate_fd_ancestry(
    limits: &LcsLimits,
    resolved_path: &[&str],
    ancestor_guids: &[Guid],
    key_guid: Guid,
) -> LcsResult<()> {
    if resolved_path.is_empty()
        || ancestor_guids.len() != resolved_path.len()
        || ancestor_guids[ancestor_guids.len() - 1] != key_guid
    {
        return Err(LcsError::InvalidFdAncestry);
    }

    validate_hive_name_bytes(resolved_path[0].as_bytes(), limits)?;
    for component in &resolved_path[1..] {
        validate_key_component_bytes(component.as_bytes(), limits)?;
    }

    Ok(())
}
