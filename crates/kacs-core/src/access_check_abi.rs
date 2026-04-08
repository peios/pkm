use crate::access_check::{access_check_core, AccessCheckMode, PrivilegeUseEvent};
use crate::access_mask::GenericMapping;
use crate::audit::AuditEvent;
use crate::caap::CaapPolicyEntry;
use crate::claims::{parse_claim_attribute_array, ClaimAttribute};
use crate::condition::ConditionalContext;
use crate::dacl::AccessStatus;
use crate::error::{KacsError, KacsResult};
use crate::object_tree::{ObjectTypeList, ObjectTypeNode};
use crate::pkm_alloc::{slice_to_vec, Vec};
use crate::pip::PipContext;
use crate::privilege::TokenPrivileges;
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::{AccessCheckToken, SidAndAttributes};

pub const KACS_ACCESS_CHECK_ARGS_SIZE: usize = 136;
pub const KACS_ACCESS_CHECK_ARGS_V1_SIZE: u32 = 40;
pub const KACS_OBJECT_TYPE_ENTRY_SIZE: usize = 20;
pub const KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN: u32 = 4096;
pub const KACS_ABI_EACCES: i32 = -13;

pub trait AccessCheckAbiMemory {
    fn read_bytes(&self, ptr: u64, len: usize) -> Option<Vec<u8>>;
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct AccessCheckAbiRequest {
    pub token_fd: i32,
    pub desired_access: u32,
    pub mapping: GenericMapping,
    pub privilege_intent: u32,
    pub pip: PipContext,
    pub sd_bytes: Vec<u8>,
    pub self_sid_bytes: Option<Vec<u8>>,
    pub object_tree: Option<ObjectTypeList>,
    pub local_claims: Vec<ClaimAttribute>,
    pub audit_context: Option<Vec<u8>>,
    pub granted_out_ptr: Option<u64>,
    pub continuous_audit_out_ptr: Option<u64>,
    pub staging_mismatch_out_ptr: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCheckAbiResolved<'a> {
    pub token: &'a AccessCheckToken<'a>,
    pub default_pip: PipContext,
    pub device_groups: &'a [SidAndAttributes<'a>],
    pub user_claims: &'a [ClaimAttribute],
    pub device_claims: &'a [ClaimAttribute],
    pub policies: &'a [CaapPolicyEntry<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessCheckAbiReturn {
    Granted(u32),
    AccessDenied,
    Success,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct U32Writeback {
    pub ptr: u64,
    pub value: u32,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct OwnedAuditEvent {
    pub ace_bytes: Option<Vec<u8>>,
    pub requested: u32,
    pub granted: u32,
    pub success: bool,
    pub policy_forced: bool,
    pub privilege: Option<u64>,
    pub object_audit_context: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KacsNodeResultAbi {
    pub granted: u32,
    pub status: i32,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct AccessCheckAbiExecution {
    pub disposition: AccessCheckAbiReturn,
    pub granted_out: Option<U32Writeback>,
    pub continuous_audit_out: Option<U32Writeback>,
    pub staging_mismatch_out: Option<U32Writeback>,
    pub node_results: Option<Vec<KacsNodeResultAbi>>,
    pub audit_events: Vec<OwnedAuditEvent>,
    pub privilege_use_events: Vec<PrivilegeUseEvent>,
    pub updated_privileges: TokenPrivileges,
}

pub fn parse_access_check_abi_request<M: AccessCheckAbiMemory>(
    args_bytes: &[u8],
    memory: &M,
) -> KacsResult<AccessCheckAbiRequest> {
    if args_bytes.len() < 4 {
        return Err(KacsError::Truncated("kacs_access_check_args"));
    }

    let caller_size = read_u32(args_bytes, 0, "kacs_access_check_args")?;
    if caller_size < KACS_ACCESS_CHECK_ARGS_V1_SIZE {
        return Err(KacsError::InvalidAbiStructSize {
            provided: caller_size,
            minimum: KACS_ACCESS_CHECK_ARGS_V1_SIZE,
        });
    }

    let copied_len = usize::try_from(caller_size)
        .map_err(|_| KacsError::InvalidAbiInput("kacs_access_check_args size overflow"))?
        .min(KACS_ACCESS_CHECK_ARGS_SIZE);
    if args_bytes.len() < copied_len {
        return Err(KacsError::Truncated("kacs_access_check_args"));
    }

    let mut raw = [0u8; KACS_ACCESS_CHECK_ARGS_SIZE];
    raw[..copied_len].copy_from_slice(&args_bytes[..copied_len]);

    require_zero_u32(&raw, 68, "_pad0")?;
    require_zero_u32(&raw, 84, "_pad1")?;
    require_zero_u32(&raw, 116, "_pad2")?;

    let token_fd = read_i32_fixed(&raw, 4);
    let sd_ptr = read_u64_fixed(&raw, 8);
    let sd_len = read_u32_fixed(&raw, 16);
    let desired_access = read_u32_fixed(&raw, 20);
    let mapping = GenericMapping {
        read: read_u32_fixed(&raw, 24),
        write: read_u32_fixed(&raw, 28),
        execute: read_u32_fixed(&raw, 32),
        all: read_u32_fixed(&raw, 36),
    };
    let self_sid_ptr = read_u64_fixed(&raw, 40);
    let self_sid_len = read_u32_fixed(&raw, 48);
    let privilege_intent = read_u32_fixed(&raw, 52);
    let object_tree_ptr = read_u64_fixed(&raw, 56);
    let object_tree_count = read_u32_fixed(&raw, 64);
    let local_claims_ptr = read_u64_fixed(&raw, 72);
    let local_claims_len = read_u32_fixed(&raw, 80);
    let granted_out_ptr = nonzero_ptr(read_u64_fixed(&raw, 88));
    let pip = PipContext {
        pip_type: read_u32_fixed(&raw, 96),
        pip_trust: read_u32_fixed(&raw, 100),
    };
    let audit_context_ptr = read_u64_fixed(&raw, 104);
    let audit_context_len = read_u32_fixed(&raw, 112);
    let continuous_audit_out_ptr = nonzero_ptr(read_u64_fixed(&raw, 120));
    let staging_mismatch_out_ptr = nonzero_ptr(read_u64_fixed(&raw, 128));

    let sd_len_usize =
        usize::try_from(sd_len).map_err(|_| KacsError::InvalidAbiInput("sd_len overflow"))?;
    if sd_ptr == 0 || sd_len_usize == 0 {
        return Err(KacsError::InvalidAbiInput("sd_ptr and sd_len are required"));
    }
    let sd_bytes = read_memory(memory, "sd", sd_ptr, sd_len_usize)?;

    let self_sid_bytes = read_optional_memory(memory, "self_sid", self_sid_ptr, self_sid_len)?;
    if let Some(bytes) = self_sid_bytes.as_deref() {
        let _ = Sid::parse(bytes)?;
    }

    let object_tree = parse_object_tree(memory, object_tree_ptr, object_tree_count)?;
    let local_claims = parse_local_claims(memory, local_claims_ptr, local_claims_len)?;
    let audit_context = parse_audit_context(memory, audit_context_ptr, audit_context_len)?;

    Ok(AccessCheckAbiRequest {
        token_fd,
        desired_access,
        mapping,
        privilege_intent,
        pip,
        sd_bytes,
        self_sid_bytes,
        object_tree,
        local_claims,
        audit_context,
        granted_out_ptr,
        continuous_audit_out_ptr,
        staging_mismatch_out_ptr,
    })
}

pub fn execute_access_check_abi<'a>(
    request: &'a AccessCheckAbiRequest,
    resolved: &'a AccessCheckAbiResolved<'a>,
) -> KacsResult<AccessCheckAbiExecution> {
    let sd = SecurityDescriptor::parse(&request.sd_bytes)?;
    let self_sid = request
        .self_sid_bytes
        .as_deref()
        .map(Sid::parse)
        .transpose()?;
    let conditional_context = ConditionalContext {
        self_sid,
        principal_self_matches: None,
        caller_is_owner: false,
        identity: None,
        identity_membership_is_presence_based: false,
        device_groups: resolved.device_groups,
        user_claims: resolved.user_claims,
        device_claims: resolved.device_claims,
        resource_claims: &[],
        local_claims: &request.local_claims,
    };
    let state = access_check_core(
        Some(&sd),
        resolved.token,
        effective_pip(request.pip, resolved.default_pip),
        request.desired_access,
        &request.mapping,
        AccessCheckMode::Scalar,
        request.object_tree.as_ref(),
        &conditional_context,
        request.audit_context.as_deref(),
        request.privilege_intent,
        resolved.policies,
    )?;

    let granted = state
        .object_granted_list
        .as_ref()
        .and_then(|list| list.first().copied())
        .unwrap_or(state.granted);
    let allowed =
        state.mapped_desired == 0 || (granted & state.mapped_desired) == state.mapped_desired;

    Ok(AccessCheckAbiExecution {
        disposition: if allowed {
            AccessCheckAbiReturn::Granted(granted)
        } else {
            AccessCheckAbiReturn::AccessDenied
        },
        granted_out: request.granted_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: granted,
        }),
        continuous_audit_out: request.continuous_audit_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: state.continuous_audit_mask,
        }),
        staging_mismatch_out: request.staging_mismatch_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: u32::from(state.staging_mismatch),
        }),
        node_results: None,
        audit_events: own_audit_events(&state.audit_events)?,
        privilege_use_events: state.privilege_use_events,
        updated_privileges: state.updated_privileges,
    })
}

pub fn execute_access_check_list_abi<'a>(
    request: &'a AccessCheckAbiRequest,
    results_count: u32,
    resolved: &'a AccessCheckAbiResolved<'a>,
) -> KacsResult<AccessCheckAbiExecution> {
    let object_tree = request
        .object_tree
        .as_ref()
        .ok_or(KacsError::InvalidAbiInput(
            "kacs_access_check_list requires object tree",
        ))?;
    if results_count != object_tree.len() as u32 {
        return Err(KacsError::AccessCheckListResultsCountMismatch {
            expected: object_tree.len() as u32,
            actual: results_count,
        });
    }

    let sd = SecurityDescriptor::parse(&request.sd_bytes)?;
    let self_sid = request
        .self_sid_bytes
        .as_deref()
        .map(Sid::parse)
        .transpose()?;
    let conditional_context = ConditionalContext {
        self_sid,
        principal_self_matches: None,
        caller_is_owner: false,
        identity: None,
        identity_membership_is_presence_based: false,
        device_groups: resolved.device_groups,
        user_claims: resolved.user_claims,
        device_claims: resolved.device_claims,
        resource_claims: &[],
        local_claims: &request.local_claims,
    };
    let state = access_check_core(
        Some(&sd),
        resolved.token,
        effective_pip(request.pip, resolved.default_pip),
        request.desired_access,
        &request.mapping,
        AccessCheckMode::ResultList,
        Some(object_tree),
        &conditional_context,
        request.audit_context.as_deref(),
        request.privilege_intent,
        resolved.policies,
    )?;

    let granted_list = state
        .object_granted_list
        .ok_or(KacsError::InvariantViolation(
            "result-list ABI execution requires object grants",
        ))?;
    let root_granted = granted_list.first().copied().unwrap_or(0);
    let mut node_results = Vec::with_capacity(granted_list.len())?;
    for granted in granted_list.iter() {
        node_results.push(KacsNodeResultAbi {
            granted: *granted,
            status: if state.mapped_desired == 0
                || (*granted & state.mapped_desired) == state.mapped_desired
            {
                access_status_code(AccessStatus::Ok)
            } else {
                access_status_code(AccessStatus::AccessDenied)
            },
        })?;
    }

    Ok(AccessCheckAbiExecution {
        disposition: AccessCheckAbiReturn::Success,
        granted_out: request.granted_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: root_granted,
        }),
        continuous_audit_out: request.continuous_audit_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: state.continuous_audit_mask,
        }),
        staging_mismatch_out: request.staging_mismatch_out_ptr.map(|ptr| U32Writeback {
            ptr,
            value: u32::from(state.staging_mismatch),
        }),
        node_results: Some(node_results),
        audit_events: own_audit_events(&state.audit_events)?,
        privilege_use_events: state.privilege_use_events,
        updated_privileges: state.updated_privileges,
    })
}

fn parse_object_tree<M: AccessCheckAbiMemory>(
    memory: &M,
    ptr: u64,
    count: u32,
) -> KacsResult<Option<ObjectTypeList>> {
    if ptr == 0 && count == 0 {
        return Ok(None);
    }
    if ptr == 0 || count == 0 {
        return Err(KacsError::InvalidAbiInput(
            "object_tree_ptr and object_tree_count must both be present",
        ));
    }

    let count_usize = usize::try_from(count)
        .map_err(|_| KacsError::InvalidAbiInput("object_tree_count overflow"))?;
    let total_len = count_usize
        .checked_mul(KACS_OBJECT_TYPE_ENTRY_SIZE)
        .ok_or(KacsError::InvalidAbiInput("object_tree_count overflow"))?;
    let bytes = read_memory(memory, "object_tree", ptr, total_len)?;
    let mut nodes = Vec::with_capacity(count_usize)?;
    for entry in bytes.chunks_exact(KACS_OBJECT_TYPE_ENTRY_SIZE) {
        let level = u16::from_le_bytes([entry[0], entry[1]]);
        let reserved = u16::from_le_bytes([entry[2], entry[3]]);
        if reserved != 0 {
            return Err(KacsError::NonZeroAbiReservedField(
                "kacs_object_type_entry._reserved",
            ));
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&entry[4..20]);
        nodes.push(ObjectTypeNode { level, guid })?;
    }

    Ok(Some(ObjectTypeList::new(&nodes)?))
}

fn parse_local_claims<M: AccessCheckAbiMemory>(
    memory: &M,
    ptr: u64,
    len: u32,
) -> KacsResult<Vec<ClaimAttribute>> {
    let Some(bytes) = read_optional_memory(memory, "local_claims", ptr, len)? else {
        return Ok(Vec::new());
    };
    parse_claim_attribute_array(&bytes)
}

fn parse_audit_context<M: AccessCheckAbiMemory>(
    memory: &M,
    ptr: u64,
    len: u32,
) -> KacsResult<Option<Vec<u8>>> {
    if len > KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN {
        return Err(KacsError::InvalidAbiInput("audit_context_len exceeds 4096"));
    }
    read_optional_memory(memory, "audit_context", ptr, len)
}

fn read_optional_memory<M: AccessCheckAbiMemory>(
    memory: &M,
    field: &'static str,
    ptr: u64,
    len: u32,
) -> KacsResult<Option<Vec<u8>>> {
    if ptr == 0 && len == 0 {
        return Ok(None);
    }
    if ptr == 0 || len == 0 {
        return Err(KacsError::InvalidAbiInput(match field {
            "self_sid" => "self_sid_ptr and self_sid_len must both be present",
            "local_claims" => "local_claims_ptr and local_claims_len must both be present",
            "audit_context" => "audit_context_ptr and audit_context_len must both be present",
            _ => "pointer and length must both be present",
        }));
    }

    let len_usize =
        usize::try_from(len).map_err(|_| KacsError::InvalidAbiInput("length overflow"))?;
    Ok(Some(read_memory(memory, field, ptr, len_usize)?))
}

fn read_memory<M: AccessCheckAbiMemory>(
    memory: &M,
    field: &'static str,
    ptr: u64,
    len: usize,
) -> KacsResult<Vec<u8>> {
    memory
        .read_bytes(ptr, len)
        .ok_or(KacsError::UserMemoryFault { field, ptr, len })
}

fn effective_pip(requested: PipContext, fallback: PipContext) -> PipContext {
    PipContext {
        pip_type: if requested.pip_type == 0 {
            fallback.pip_type
        } else {
            requested.pip_type
        },
        pip_trust: if requested.pip_trust == 0 {
            fallback.pip_trust
        } else {
            requested.pip_trust
        },
    }
}

fn own_audit_events(events: &[AuditEvent<'_>]) -> KacsResult<Vec<OwnedAuditEvent>> {
    let mut owned = Vec::with_capacity(events.len())?;
    for event in events {
        owned.push(OwnedAuditEvent {
            ace_bytes: event
                .ace_bytes
                .map(slice_to_vec)
                .transpose()?,
            requested: event.requested,
            granted: event.granted,
            success: event.success,
            policy_forced: event.policy_forced,
            privilege: event.privilege,
            object_audit_context: event
                .object_audit_context
                .as_ref()
                .map(|bytes| slice_to_vec(bytes.as_slice()))
                .transpose()?,
        })?;
    }
    Ok(owned)
}

fn access_status_code(status: AccessStatus) -> i32 {
    match status {
        AccessStatus::Ok => 0,
        AccessStatus::AccessDenied => KACS_ABI_EACCES,
    }
}

fn require_zero_u32(
    bytes: &[u8; KACS_ACCESS_CHECK_ARGS_SIZE],
    offset: usize,
    field: &'static str,
) -> KacsResult<()> {
    if read_u32_fixed(bytes, offset) != 0 {
        return Err(KacsError::NonZeroAbiReservedField(field));
    }
    Ok(())
}

fn nonzero_ptr(ptr: u64) -> Option<u64> {
    (ptr != 0).then_some(ptr)
}

fn read_u32(bytes: &[u8], offset: usize, truncated_name: &'static str) -> KacsResult<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(KacsError::Truncated(truncated_name))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u32_fixed(bytes: &[u8; KACS_ACCESS_CHECK_ARGS_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32_fixed(bytes: &[u8; KACS_ACCESS_CHECK_ARGS_SIZE], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_fixed(bytes: &[u8; KACS_ACCESS_CHECK_ARGS_SIZE], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
