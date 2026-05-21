use crate::access::{
    parse_registry_source_security_descriptor, registry_kacs_generic_mapping,
    validate_registry_desired_access, validate_registry_granted_access,
};
use crate::constants::REG_OPEN_LINK;
use crate::errno::LinuxErrno;
use crate::error::{LcsError, LcsResult};
use crate::resolution::Guid;
use crate::source::NIL_GUID;

const REG_OPEN_KEY_KNOWN_FLAGS: u32 = REG_OPEN_LINK;

/// The object whose SD must be evaluated for a key-open operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryOpenAccessTarget {
    /// The resolved final key is not a symlink, so evaluate that key.
    FinalKey,
    /// Ordinary symlink open: follow the link and evaluate the target key.
    SymlinkTarget,
    /// `REG_OPEN_LINK`: evaluate the symlink key itself.
    SymlinkKey,
}

/// Inputs for final key-vs-symlink target binding after path resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryKeyOpenResolutionInput {
    pub final_key_guid: Guid,
    pub final_component_is_symlink: bool,
    pub symlink_target_guid: Option<Guid>,
    pub flags: u32,
}

/// Pure plan for the object checked and published by `reg_open_key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryKeyOpenResolutionPlan {
    pub access_target: RegistryOpenAccessTarget,
    pub access_check_key_guid: Guid,
    pub published_fd_key_guid: Guid,
    pub follows_symlink: bool,
}

/// Caller-visible errno for pre-resolution open access validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryOpenPreResolutionErrno {
    Einval,
}

/// Pre-resolution decision for `reg_open_key` desired access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryOpenPreResolutionAccessPlan {
    Continue {
        requested_access: u32,
        mapped_desired_access: u32,
        maximum_allowed: bool,
        path_resolution_allowed: bool,
    },
    Reject {
        errno: RegistryOpenPreResolutionErrno,
        path_resolution_allowed: bool,
    },
}

/// Scalar AccessCheck decision for a key-open operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryOpenAccessDecision {
    /// All requested rights were granted and fd publication may proceed after
    /// any required audit payload is constructed and KMES enqueue is attempted.
    Allowed,
    /// AccessCheck denied at least one requested concrete right. No fd may be
    /// published.
    Denied,
}

/// Inputs for the pure key-open AccessCheck planner after path resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryKeyOpenAccessInput<'a> {
    pub key_sd: &'a [u8],
    pub token: &'a kacs_core::AccessCheckToken<'a>,
    pub desired_access: u32,
    pub pip: kacs_core::PipContext,
    pub conditional_context: kacs_core::ConditionalContext<'a>,
    pub object_audit_context: Option<&'a [u8]>,
    pub privilege_intent: u32,
    pub caap_policies: &'a [kacs_core::CaapPolicyEntry<'a>],
}

/// Result of key-open AccessCheck planning before KMES emission or fd publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryKeyOpenAccessPlan {
    pub decision: RegistryOpenAccessDecision,
    pub requested_access: u32,
    pub mapped_desired_access: u32,
    pub maximum_allowed: bool,
    pub access_check_granted: u32,
    pub fd_granted_access: Option<u32>,
    pub key_open_sacl_audit_required: bool,
    pub audit_payload_failure_blocks_completion: bool,
    pub privilege_use_audit_required: bool,
    pub updated_privileges: kacs_core::TokenPrivileges,
}

/// Validates `reg_open_key` flags before path resolution.
pub fn validate_registry_open_flags(flags: u32) -> LcsResult<()> {
    let unknown = flags & !REG_OPEN_KEY_KNOWN_FLAGS;
    if unknown != 0 {
        return Err(LcsError::UnknownOpenFlags { flags, unknown });
    }

    Ok(())
}

/// Validates `reg_open_key` flags and selects which SD path resolution must
/// feed into AccessCheck.
pub fn select_registry_open_access_target(
    final_component_is_symlink: bool,
    flags: u32,
) -> LcsResult<RegistryOpenAccessTarget> {
    validate_registry_open_flags(flags)?;

    if final_component_is_symlink {
        if (flags & REG_OPEN_LINK) != 0 {
            Ok(RegistryOpenAccessTarget::SymlinkKey)
        } else {
            Ok(RegistryOpenAccessTarget::SymlinkTarget)
        }
    } else {
        Ok(RegistryOpenAccessTarget::FinalKey)
    }
}

/// Validates caller desired access before any path resolution is attempted.
pub fn plan_registry_open_pre_resolution_access(
    desired_access: u32,
) -> RegistryOpenPreResolutionAccessPlan {
    match validate_registry_desired_access(desired_access) {
        Ok(normalized) => RegistryOpenPreResolutionAccessPlan::Continue {
            requested_access: normalized.requested,
            mapped_desired_access: normalized.mapped,
            maximum_allowed: normalized.maximum_allowed,
            path_resolution_allowed: true,
        },
        Err(_) => RegistryOpenPreResolutionAccessPlan::Reject {
            errno: RegistryOpenPreResolutionErrno::Einval,
            path_resolution_allowed: false,
        },
    }
}

/// Projects pre-resolution `reg_open_key` desired-access failures to Linux errno.
pub fn registry_open_pre_resolution_linux_errno(
    plan: &RegistryOpenPreResolutionAccessPlan,
) -> Option<LinuxErrno> {
    match plan {
        RegistryOpenPreResolutionAccessPlan::Continue { .. } => None,
        RegistryOpenPreResolutionAccessPlan::Reject { errno, .. } => Some(LinuxErrno::from(*errno)),
    }
}

/// Plans whether a final symlink is followed and which key GUID future fd
/// publication must bind to.
pub fn plan_registry_key_open_resolution(
    input: RegistryKeyOpenResolutionInput,
) -> LcsResult<RegistryKeyOpenResolutionPlan> {
    validate_open_key_guid(input.final_key_guid)?;
    let access_target =
        select_registry_open_access_target(input.final_component_is_symlink, input.flags)?;

    match access_target {
        RegistryOpenAccessTarget::FinalKey | RegistryOpenAccessTarget::SymlinkKey => {
            Ok(RegistryKeyOpenResolutionPlan {
                access_target,
                access_check_key_guid: input.final_key_guid,
                published_fd_key_guid: input.final_key_guid,
                follows_symlink: false,
            })
        }
        RegistryOpenAccessTarget::SymlinkTarget => {
            let target_guid = input
                .symlink_target_guid
                .ok_or(LcsError::SymlinkDefaultValueMissing)?;
            validate_open_key_guid(target_guid)?;
            Ok(RegistryKeyOpenResolutionPlan {
                access_target,
                access_check_key_guid: target_guid,
                published_fd_key_guid: target_guid,
                follows_symlink: true,
            })
        }
    }
}

/// Plans key-open authorization using the KACS scalar AccessCheck core.
pub fn plan_registry_key_open_access(
    input: RegistryKeyOpenAccessInput<'_>,
) -> LcsResult<RegistryKeyOpenAccessPlan> {
    let normalized = validate_registry_desired_access(input.desired_access)?;
    let sd = parse_registry_source_security_descriptor(input.key_sd, "registry_open.key_sd")?;
    let mapping = registry_kacs_generic_mapping();

    let state = match kacs_core::access_check_core(
        Some(&sd),
        input.token,
        input.pip,
        input.desired_access,
        &mapping,
        kacs_core::AccessCheckMode::Scalar,
        None,
        &input.conditional_context,
        input.object_audit_context,
        input.privilege_intent,
        input.caap_policies,
    ) {
        Ok(state) => state,
        Err(kacs_core::KacsError::AccessDenied) => {
            return Ok(RegistryKeyOpenAccessPlan {
                decision: RegistryOpenAccessDecision::Denied,
                requested_access: normalized.requested,
                mapped_desired_access: normalized.mapped,
                maximum_allowed: normalized.maximum_allowed,
                access_check_granted: 0,
                fd_granted_access: None,
                key_open_sacl_audit_required: false,
                audit_payload_failure_blocks_completion: false,
                privilege_use_audit_required: false,
                updated_privileges: input.token.privileges,
            });
        }
        Err(_) => return Err(LcsError::AccessCheckEvaluationFailed),
    };

    let access_check_granted = state
        .object_granted_list
        .as_ref()
        .and_then(|list| list.first().copied())
        .unwrap_or(state.granted);
    validate_registry_granted_access(access_check_granted)
        .map_err(|_| LcsError::AccessCheckEvaluationFailed)?;

    let allowed = state.mapped_desired == 0
        || (access_check_granted & state.mapped_desired) == state.mapped_desired;
    let fd_granted_access = if allowed {
        let fd_granted = if normalized.maximum_allowed {
            access_check_granted
        } else {
            normalized.mapped
        };
        validate_registry_granted_access(fd_granted)
            .map_err(|_| LcsError::AccessCheckEvaluationFailed)?;
        Some(fd_granted)
    } else {
        None
    };
    let key_open_sacl_audit_required = state.audit_events.iter().any(|event| !event.policy_forced);

    Ok(RegistryKeyOpenAccessPlan {
        decision: if allowed {
            RegistryOpenAccessDecision::Allowed
        } else {
            RegistryOpenAccessDecision::Denied
        },
        requested_access: normalized.requested,
        mapped_desired_access: state.mapped_desired,
        maximum_allowed: normalized.maximum_allowed,
        access_check_granted,
        fd_granted_access,
        key_open_sacl_audit_required,
        audit_payload_failure_blocks_completion: key_open_sacl_audit_required,
        privilege_use_audit_required: !state.privilege_use_events.is_empty(),
        updated_privileges: state.updated_privileges,
    })
}

fn validate_open_key_guid(guid: Guid) -> LcsResult<()> {
    if guid == NIL_GUID {
        return Err(LcsError::NilKeyGuid);
    }
    Ok(())
}
