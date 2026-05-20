use crate::casefold::casefold_eq;
use crate::config::LcsLimits;
use crate::errno::LinuxErrno;
use crate::error::{LcsError, LcsResult};
use crate::path::{
    PathKind, is_reserved_current_user_name, validate_hive_name_bytes,
    validate_key_component_bytes, validate_registry_path_str,
};
use crate::resolution::Guid;
use core::fmt::{self, Write};

const USERS_HIVE_NAME: &str = "Users";
pub const MAX_TEXTUAL_SID_COMPONENT_LEN: usize =
    2 + 3 + 1 + 14 + ((kacs_core::Sid::MAX_SUB_AUTHORITIES as usize) * 11);

/// Opaque source identifier used by pure routing helpers.
pub type SourceId = u32;

/// Source connectivity state for one published hive route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveStatus {
    Active,
    Unavailable,
}

/// Visibility namespace for one hive route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveScope {
    Global,
    Private(Guid),
}

/// One published hive route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HiveView<'a> {
    pub name: &'a str,
    pub root_guid: Guid,
    pub source_id: SourceId,
    pub status: HiveStatus,
    pub scope: HiveScope,
}

/// A hive selected by routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutedHive<'a> {
    pub name: &'a str,
    pub root_guid: Guid,
    pub source_id: SourceId,
    pub scope: HiveScope,
}

/// Result of routing the first component of an absolute registry path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveRoute<'a> {
    Active(RoutedHive<'a>),
    Unavailable(RoutedHive<'a>),
    NotRegistered,
}

/// Caller-facing errno category selected after hive routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveRouteErrno {
    Enoent,
    Eio,
}

/// Kernel-facing routing outcome before integer errno translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveRouteOutcome<'a> {
    Dispatch(RoutedHive<'a>),
    Failure(HiveRouteErrno),
}

/// Controls whether `CurrentUser` is treated as an initial caller alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentUserRewrite<'a> {
    InitialCallerPath { user_sid_component: &'a str },
    Literal,
}

/// Fixed-capacity textual SID component used for `CurrentUser` rewriting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentUserSidComponent {
    bytes: [u8; MAX_TEXTUAL_SID_COMPONENT_LEN],
    len: usize,
}

impl CurrentUserSidComponent {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_TEXTUAL_SID_COMPONENT_LEN],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len])
            .expect("SID formatter only writes UTF-8 ASCII")
    }
}

impl Write for CurrentUserSidComponent {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Converts a binary token user SID into the textual path component used by
/// `CurrentUser` rewriting.
pub fn current_user_sid_component_from_binary_sid(
    limits: &LcsLimits,
    sid_bytes: &[u8],
) -> LcsResult<CurrentUserSidComponent> {
    let sid = kacs_core::Sid::parse(sid_bytes).map_err(|_| LcsError::MalformedTokenSid {
        field: "current_user_sid",
    })?;
    let mut component = CurrentUserSidComponent::new();
    write!(&mut component, "{sid}").map_err(|_| LcsError::NameTooLong {
        field: "current_user_sid",
        len: MAX_TEXTUAL_SID_COMPONENT_LEN + 1,
        max: MAX_TEXTUAL_SID_COMPONENT_LEN,
    })?;
    validate_key_component_bytes(component.as_str().as_bytes(), limits)?;
    Ok(component)
}

/// Validates a published hive table snapshot.
pub fn validate_hive_table(limits: &LcsLimits, hives: &[HiveView<'_>]) -> LcsResult<()> {
    for (index, hive) in hives.iter().enumerate() {
        validate_registered_hive_name(hive.name, limits)?;
        if hive_seen_before(limits, hives, index, hive)? {
            return Err(LcsError::DuplicateHiveIdentity);
        }
    }
    Ok(())
}

/// Validates ordered private-hive scope GUIDs carried by credentials.
pub fn validate_scope_guid_set(limits: &LcsLimits, scopes: &[Guid]) -> LcsResult<()> {
    if scopes.len() > limits.max_scope_guids_per_token {
        return Err(LcsError::TooManyScopeGuids {
            count: scopes.len(),
            max: limits.max_scope_guids_per_token,
        });
    }

    for (index, scope) in scopes.iter().enumerate() {
        if scopes[..index].iter().any(|previous| previous == scope) {
            return Err(LcsError::DuplicateScopeGuid);
        }
    }
    Ok(())
}

/// Routes an absolute path's first component through private then global hives.
pub fn route_hive<'a>(
    limits: &LcsLimits,
    hives: &'a [HiveView<'a>],
    hive_name: &'a str,
    scope_guids: &[Guid],
) -> LcsResult<HiveRoute<'a>> {
    validate_hive_table(limits, hives)?;
    validate_scope_guid_set(limits, scope_guids)?;
    let hive_name = validate_key_component_bytes(hive_name.as_bytes(), limits)?;

    for scope in scope_guids {
        if let Some(hive) = find_private_hive(hives, hive_name, *scope) {
            return Ok(route_from_hive(hive));
        }
    }

    if let Some(hive) = find_global_hive(hives, hive_name) {
        return Ok(route_from_hive(hive));
    }

    Ok(HiveRoute::NotRegistered)
}

/// Maps a pure hive route to the syscall-visible routing outcome.
pub fn classify_hive_route(route: HiveRoute<'_>) -> HiveRouteOutcome<'_> {
    match route {
        HiveRoute::Active(hive) => HiveRouteOutcome::Dispatch(hive),
        HiveRoute::Unavailable(_) => HiveRouteOutcome::Failure(HiveRouteErrno::Eio),
        HiveRoute::NotRegistered => HiveRouteOutcome::Failure(HiveRouteErrno::Enoent),
    }
}

/// Projects a hive-route outcome to the caller-visible Linux errno.
pub fn hive_route_outcome_errno(outcome: HiveRouteOutcome<'_>) -> Option<LinuxErrno> {
    match outcome {
        HiveRouteOutcome::Dispatch(_) => None,
        HiveRouteOutcome::Failure(errno) => Some(LinuxErrno::from(errno)),
    }
}

/// Routes a validated routable path by its first emitted path component.
pub fn route_routable_path_hive<'a>(
    limits: &LcsLimits,
    hives: &'a [HiveView<'a>],
    path: &'a str,
    rewrite: CurrentUserRewrite<'a>,
    scope_guids: &[Guid],
) -> LcsResult<HiveRouteOutcome<'a>> {
    let mut first_component = None;
    for_each_routable_path_component(limits, path, rewrite, |component| {
        if first_component.is_none() {
            first_component = Some(component);
        }
        Ok(())
    })?;
    let first_component =
        first_component.expect("validated non-empty path emits at least one component");
    Ok(classify_hive_route(route_hive(
        limits,
        hives,
        first_component,
        scope_guids,
    )?))
}

/// Emits normalized absolute path components, applying `CurrentUser` only for
/// initial caller paths.
pub fn for_each_routable_path_component<'a, F>(
    limits: &LcsLimits,
    path: &'a str,
    rewrite: CurrentUserRewrite<'a>,
    mut emit: F,
) -> LcsResult<usize>
where
    F: FnMut(&'a str) -> LcsResult<()>,
{
    let summary = validate_registry_path_str(path, PathKind::Absolute, limits)?;
    let first = summary.first_component;

    if is_reserved_current_user_name(first) {
        if let CurrentUserRewrite::InitialCallerPath { user_sid_component } = rewrite {
            let user_sid_component =
                validate_key_component_bytes(user_sid_component.as_bytes(), limits)?;
            validate_rewritten_current_user_len(path, first, user_sid_component, limits)?;

            let mut emitted = 0usize;
            emit(USERS_HIVE_NAME)?;
            emitted += 1;
            emit(user_sid_component)?;
            emitted += 1;
            for_each_path_component_after_first(path, |component| {
                emit(component)?;
                emitted += 1;
                Ok(())
            })?;
            return Ok(emitted);
        }
    }

    let mut emitted = 0usize;
    for_each_path_component(path, |component| {
        emit(component)?;
        emitted += 1;
        Ok(())
    })?;
    Ok(emitted)
}

fn validate_registered_hive_name<'a>(name: &'a str, limits: &LcsLimits) -> LcsResult<&'a str> {
    validate_hive_name_bytes(name.as_bytes(), limits)
}

fn hive_seen_before(
    limits: &LcsLimits,
    hives: &[HiveView<'_>],
    index: usize,
    current: &HiveView<'_>,
) -> LcsResult<bool> {
    let current_name = validate_registered_hive_name(current.name, limits)?;
    for previous in &hives[..index] {
        let previous_name = validate_registered_hive_name(previous.name, limits)?;
        if !casefold_eq(previous_name, current_name) {
            continue;
        }

        match (previous.scope, current.scope) {
            (HiveScope::Global, HiveScope::Global) => return Ok(true),
            (HiveScope::Private(previous_scope), HiveScope::Private(current_scope))
                if previous_scope == current_scope =>
            {
                return Ok(true);
            }
            _ => {}
        }
    }
    Ok(false)
}

fn find_private_hive<'a>(
    hives: &'a [HiveView<'a>],
    hive_name: &str,
    scope: Guid,
) -> Option<&'a HiveView<'a>> {
    hives.iter().find(|hive| {
        matches!(hive.scope, HiveScope::Private(candidate) if candidate == scope)
            && casefold_eq(hive.name, hive_name)
    })
}

fn find_global_hive<'a>(hives: &'a [HiveView<'a>], hive_name: &str) -> Option<&'a HiveView<'a>> {
    hives
        .iter()
        .find(|hive| hive.scope == HiveScope::Global && casefold_eq(hive.name, hive_name))
}

fn route_from_hive<'a>(hive: &'a HiveView<'a>) -> HiveRoute<'a> {
    let routed = RoutedHive {
        name: hive.name,
        root_guid: hive.root_guid,
        source_id: hive.source_id,
        scope: hive.scope,
    };
    match hive.status {
        HiveStatus::Active => HiveRoute::Active(routed),
        HiveStatus::Unavailable => HiveRoute::Unavailable(routed),
    }
}

fn validate_rewritten_current_user_len(
    path: &str,
    first_component: &str,
    user_sid_component: &str,
    limits: &LcsLimits,
) -> LcsResult<()> {
    let remainder_len = path.len() - first_component.len();
    let rewritten_len = USERS_HIVE_NAME.len() + 1 + user_sid_component.len() + remainder_len;
    if rewritten_len > limits.max_total_path_length {
        return Err(LcsError::PathTooLong {
            len: rewritten_len,
            max: limits.max_total_path_length,
        });
    }
    Ok(())
}

fn for_each_path_component<'a, F>(path: &'a str, mut emit: F) -> LcsResult<()>
where
    F: FnMut(&'a str) -> LcsResult<()>,
{
    let mut start = 0usize;
    for (index, byte) in path.as_bytes().iter().copied().enumerate() {
        if byte == b'\\' || byte == b'/' {
            emit(&path[start..index])?;
            start = index + 1;
        }
    }
    emit(&path[start..])
}

fn for_each_path_component_after_first<'a, F>(path: &'a str, mut emit: F) -> LcsResult<()>
where
    F: FnMut(&'a str) -> LcsResult<()>,
{
    let mut start = 0usize;
    let mut skipped_first = false;
    for (index, byte) in path.as_bytes().iter().copied().enumerate() {
        if byte != b'\\' && byte != b'/' {
            continue;
        }
        if skipped_first {
            emit(&path[start..index])?;
        } else {
            skipped_first = true;
        }
        start = index + 1;
    }
    if skipped_first {
        emit(&path[start..])?;
    }
    Ok(())
}
