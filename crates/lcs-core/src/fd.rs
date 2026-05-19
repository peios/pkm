use crate::access::{registry_fd_has_right, validate_registry_granted_access};
use crate::config::LcsLimits;
use crate::error::{LcsError, LcsResult};
use crate::path::{validate_hive_name_bytes, validate_key_component_bytes};
use crate::resolution::Guid;
use crate::source::NIL_GUID;
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

/// Planned cleanup when a key fd is closed by normal Linux fd teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyFdClosePlan {
    pub release_key_reference: bool,
    pub remove_watch: bool,
    pub discard_pending_watch_events: bool,
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
