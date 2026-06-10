use crate::access_check::{
    access_check_core, AccessCheckMode, CaapDiagnosticEvent, PrivilegeUseEvent,
};
use crate::access_mask::GenericMapping;
use crate::audit::AuditEvent;
use crate::caap::CaapPolicyEntry;
use crate::claims::{parse_claim_attribute_array, ClaimAttribute};
use crate::condition::ConditionalContext;
use crate::dacl::AccessStatus;
use crate::error::{KacsError, KacsResult};
use crate::object_tree::{ObjectTypeList, ObjectTypeNode};
use crate::pip::PipContext;
use crate::pkm_alloc::{slice_to_vec, Vec};
use crate::privilege::TokenPrivileges;
use crate::security_descriptor::{SecurityDescriptor, MAX_SECURITY_DESCRIPTOR_BYTES};
use crate::sid::Sid;
use crate::token::{AccessCheckToken, SidAndAttributes};

/// Full size of the current fixed-width `kacs_access_check_args` buffer copied
/// by the ABI parser.
pub const KACS_ACCESS_CHECK_ARGS_SIZE: usize = 136;
/// Minimum accepted caller-provided size for v0.20 AccessCheck args.
pub const KACS_ACCESS_CHECK_ARGS_V1_SIZE: u32 = 40;
/// Size of one flat object-type entry in the ABI array.
pub const KACS_OBJECT_TYPE_ENTRY_SIZE: usize = 20;
/// Maximum accepted object-audit context length in bytes.
pub const KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN: u32 = 4096;
/// Maximum accepted `@Local` claims blob length in bytes.
pub const KACS_ACCESS_CHECK_MAX_LOCAL_CLAIMS_LEN: u32 = 65536;
/// Maximum accepted object-type tree entry count. Bounds both the ABI buffer
/// allocation and the O(n^2) duplicate-GUID scan in `ObjectTypeList::new`.
pub const KACS_ACCESS_CHECK_MAX_OBJECT_TYPE_COUNT: u32 = 1024;
/// Negative errno value used for AccessCheck denial at the ABI boundary.
pub const KACS_ABI_EACCES: i32 = -13;

/// Abstracts raw pointer-backed reads for the pure ABI parser.
pub trait AccessCheckAbiMemory {
    /// Reads `len` bytes from a caller-controlled pointer, returning `None` on
    /// fault.
    fn read_bytes(&self, ptr: u64, len: usize) -> Option<Vec<u8>>;
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Owned representation of one parsed `kacs_access_check_args` buffer.
pub struct AccessCheckAbiRequest {
    /// Token file descriptor supplied by the caller.
    pub token_fd: i32,
    /// Raw desired-access mask from the caller.
    pub desired_access: u32,
    /// Generic mapping supplied by the caller.
    pub mapping: GenericMapping,
    /// Privilege-intent flags used while seeding privileges.
    pub privilege_intent: u32,
    /// PIP axes supplied at the ABI boundary. Per axis, a non-zero value
    /// overrides the PSB-derived default for this query; 0 uses the calling
    /// process's PSB pip (PSD-004 §10.7 "PIP source").
    pub pip: PipContext,
    /// Raw self-relative security descriptor bytes.
    pub sd_bytes: Vec<u8>,
    /// Optional raw `PRINCIPAL_SELF` substitution SID bytes.
    pub self_sid_bytes: Option<Vec<u8>>,
    /// Optional parsed object-type list for result-list mode.
    pub object_tree: Option<ObjectTypeList>,
    /// Parsed `@Local` claims supplied by the caller.
    pub local_claims: Vec<ClaimAttribute>,
    /// Optional object-audit context blob.
    pub audit_context: Option<Vec<u8>>,
    /// Optional scalar granted writeback pointer.
    pub granted_out_ptr: Option<u64>,
    /// Optional continuous-audit writeback pointer.
    pub continuous_audit_out_ptr: Option<u64>,
    /// Optional staging-mismatch writeback pointer.
    pub staging_mismatch_out_ptr: Option<u64>,
}

/// Runtime context supplied by kernel glue after token and policy resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCheckAbiResolved<'a> {
    /// Fully resolved subject token.
    pub token: &'a AccessCheckToken<'a>,
    /// Default PSB-derived PIP axes when the request leaves them zeroed.
    pub default_pip: PipContext,
    /// Device groups visible to conditional expressions.
    pub device_groups: &'a [SidAndAttributes<'a>],
    /// User claims visible to conditional expressions.
    pub user_claims: &'a [ClaimAttribute],
    /// Device claims visible to conditional expressions.
    pub device_claims: &'a [ClaimAttribute],
    /// CAAP policies visible to this AccessCheck request.
    pub policies: &'a [CaapPolicyEntry<'a>],
}

/// Final syscall-style disposition returned by ABI execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessCheckAbiReturn {
    /// Scalar mode granted the returned mask.
    Granted(u32),
    /// Access was denied and the caller should observe `-EACCES`.
    AccessDenied,
    /// List mode succeeded and the caller must inspect the result buffer.
    Success,
}

/// One scalar `u32` writeback scheduled by the ABI executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct U32Writeback {
    /// Destination pointer in caller memory.
    pub ptr: u64,
    /// Value to be written there.
    pub value: u32,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Owned audit event form returned by the pure ABI executor.
pub struct OwnedAuditEvent {
    /// Optional original ACE bytes for the matched audit/alarm ACE.
    pub ace_bytes: Option<Vec<u8>>,
    /// Requested bits considered by the event.
    pub requested: u32,
    /// Granted bits associated with the event.
    pub granted: u32,
    /// Whether the event describes a success or failure.
    pub success: bool,
    /// Whether the event came from forced object-access audit policy.
    pub policy_forced: bool,
    /// Optional privilege bit for privilege-use events.
    pub privilege: Option<u64>,
    /// Optional object-audit context copied into the event.
    pub object_audit_context: Option<Vec<u8>>,
}

/// ABI form of one result-list node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KacsNodeResultAbi {
    /// Granted bits for this node.
    pub granted: u32,
    /// Node status encoded as an integer for C-side writeback.
    pub status: i32,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Fully shaped ABI execution output ready for kernel copy-out.
pub struct AccessCheckAbiExecution {
    /// Final scalar or list disposition.
    pub disposition: AccessCheckAbiReturn,
    /// Optional granted writeback.
    pub granted_out: Option<U32Writeback>,
    /// Optional continuous-audit writeback.
    pub continuous_audit_out: Option<U32Writeback>,
    /// Optional staging-mismatch writeback.
    pub staging_mismatch_out: Option<U32Writeback>,
    /// Optional result-list node outputs.
    pub node_results: Option<Vec<KacsNodeResultAbi>>,
    /// Audit events emitted by the request.
    pub audit_events: Vec<OwnedAuditEvent>,
    /// Privilege-use events emitted by the request.
    pub privilege_use_events: Vec<PrivilegeUseEvent>,
    /// CAAP diagnostic events emitted by the request.
    pub caap_diagnostic_events: Vec<CaapDiagnosticEvent>,
    /// Updated privilege state after successful privilege-use marking.
    pub updated_privileges: TokenPrivileges,
}

/// Parses a raw `kacs_access_check_args` buffer and all pointer-referenced
/// inputs into an owned pure-core request.
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
    if sd_len_usize > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(KacsError::InvalidAbiInput(
            "sd_len exceeds maximum security descriptor size",
        ));
    }
    let sd_bytes = read_memory(memory, "sd", sd_ptr, sd_len_usize)?;

    if self_sid_len as usize > Sid::MAX_SIZE {
        return Err(KacsError::InvalidAbiInput(
            "self_sid_len exceeds maximum SID size",
        ));
    }
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

/// Executes scalar AccessCheck for a previously parsed ABI request.
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
        device_membership_uses_virtual_groups: false,
        membership_allowed: true,
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
        caap_diagnostic_events: state.caap_diagnostic_events,
        updated_privileges: state.updated_privileges,
    })
}

/// Executes result-list AccessCheck for a previously parsed ABI request.
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
        device_membership_uses_virtual_groups: false,
        membership_allowed: true,
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
        caap_diagnostic_events: state.caap_diagnostic_events,
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
    if count > KACS_ACCESS_CHECK_MAX_OBJECT_TYPE_COUNT {
        return Err(KacsError::InvalidAbiInput(
            "object_tree_count exceeds maximum",
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
    if len > KACS_ACCESS_CHECK_MAX_LOCAL_CLAIMS_LEN {
        return Err(KacsError::InvalidAbiInput(
            "local_claims_len exceeds maximum",
        ));
    }
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

/// Resolves the PIP context for the query: the caller's args pip overrides the
/// PSB-derived fallback per axis, with 0 meaning "use the calling process's PSB
/// value" (PSD-004 §10.7 "PIP source"). This lets a broker evaluate access under
/// a client's trust context, paralleling the per-call `token_fd`.
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

pub(crate) fn own_audit_events(events: &[AuditEvent<'_>]) -> KacsResult<Vec<OwnedAuditEvent>> {
    let mut owned = Vec::with_capacity(events.len())?;
    for event in events {
        owned.push(OwnedAuditEvent {
            ace_bytes: event.ace_bytes.map(slice_to_vec).transpose()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SD_PTR: u64 = 0x1000;
    const TREE_PTR: u64 = 0x2000;
    const AUDIT_PTR: u64 = 0x3000;
    const SD_BYTES: [u8; 1] = [0x42];

    struct TestMemory {
        entries: BTreeMap<u64, std::vec::Vec<u8>>,
    }

    impl TestMemory {
        fn new() -> Self {
            let mut entries = BTreeMap::new();
            entries.insert(SD_PTR, SD_BYTES.to_vec());
            Self { entries }
        }

        fn with(mut self, ptr: u64, bytes: &[u8]) -> Self {
            self.entries.insert(ptr, bytes.to_vec());
            self
        }
    }

    impl AccessCheckAbiMemory for TestMemory {
        fn read_bytes(&self, ptr: u64, len: usize) -> Option<Vec<u8>> {
            let bytes = self.entries.get(&ptr)?;
            if bytes.len() < len {
                return None;
            }
            let mut out = Vec::new();
            out.extend_from_slice(&bytes[..len]).ok()?;
            Some(out)
        }
    }

    fn base_args(caller_size: u32) -> std::vec::Vec<u8> {
        let mut args = std::vec![0u8; KACS_ACCESS_CHECK_ARGS_SIZE];
        write_u32(&mut args, 0, caller_size);
        write_i32(&mut args, 4, -1);
        write_u64(&mut args, 8, SD_PTR);
        write_u32(&mut args, 16, SD_BYTES.len() as u32);
        write_u32(&mut args, 20, 0x20089);
        args
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parser_accepts_v1_minimum_and_zero_fills_appended_fields() {
        let mut args = base_args(KACS_ACCESS_CHECK_ARGS_V1_SIZE);
        args.truncate(KACS_ACCESS_CHECK_ARGS_V1_SIZE as usize);

        let request = parse_access_check_abi_request(&args, &TestMemory::new()).unwrap();

        assert_eq!(request.token_fd, -1);
        assert_eq!(request.sd_bytes.as_slice(), &SD_BYTES);
        assert_eq!(request.self_sid_bytes, None);
        assert_eq!(request.object_tree, None);
        assert!(request.local_claims.is_empty());
        assert_eq!(request.audit_context, None);
        assert_eq!(request.granted_out_ptr, None);
        assert_eq!(request.continuous_audit_out_ptr, None);
        assert_eq!(request.staging_mismatch_out_ptr, None);
        assert_eq!(request.pip, PipContext::default());
    }

    #[test]
    fn parser_rejects_undersized_and_truncated_args() {
        let mut undersized = base_args(KACS_ACCESS_CHECK_ARGS_V1_SIZE - 1);
        undersized.truncate((KACS_ACCESS_CHECK_ARGS_V1_SIZE - 1) as usize);
        assert_eq!(
            parse_access_check_abi_request(&undersized, &TestMemory::new()).unwrap_err(),
            KacsError::InvalidAbiStructSize {
                provided: KACS_ACCESS_CHECK_ARGS_V1_SIZE - 1,
                minimum: KACS_ACCESS_CHECK_ARGS_V1_SIZE
            }
        );

        let mut truncated = base_args(KACS_ACCESS_CHECK_ARGS_SIZE as u32);
        truncated.truncate(KACS_ACCESS_CHECK_ARGS_SIZE - 1);
        assert_eq!(
            parse_access_check_abi_request(&truncated, &TestMemory::new()).unwrap_err(),
            KacsError::Truncated("kacs_access_check_args")
        );
    }

    #[test]
    fn parser_ignores_nonzero_bytes_after_current_struct_size() {
        let mut args = base_args(160);
        args.resize(160, 0xff);

        let request = parse_access_check_abi_request(&args, &TestMemory::new()).unwrap();

        assert_eq!(request.sd_bytes.as_slice(), &SD_BYTES);
    }

    #[test]
    fn parser_rejects_nonzero_reserved_padding_fields() {
        for (offset, field) in [(68, "_pad0"), (84, "_pad1"), (116, "_pad2")] {
            let mut args = base_args(KACS_ACCESS_CHECK_ARGS_SIZE as u32);
            write_u32(&mut args, offset, 1);

            assert_eq!(
                parse_access_check_abi_request(&args, &TestMemory::new()).unwrap_err(),
                KacsError::NonZeroAbiReservedField(field)
            );
        }
    }

    #[test]
    fn parser_rejects_optional_pointer_length_mismatches() {
        for (ptr_offset, len_offset, ptr_value, len_value, expected) in [
            (
                40,
                48,
                0x4000,
                0,
                "self_sid_ptr and self_sid_len must both be present",
            ),
            (
                40,
                48,
                0,
                8,
                "self_sid_ptr and self_sid_len must both be present",
            ),
            (
                56,
                64,
                0x4000,
                0,
                "object_tree_ptr and object_tree_count must both be present",
            ),
            (
                56,
                64,
                0,
                1,
                "object_tree_ptr and object_tree_count must both be present",
            ),
            (
                72,
                80,
                0x4000,
                0,
                "local_claims_ptr and local_claims_len must both be present",
            ),
            (
                72,
                80,
                0,
                4,
                "local_claims_ptr and local_claims_len must both be present",
            ),
            (
                104,
                112,
                0x4000,
                0,
                "audit_context_ptr and audit_context_len must both be present",
            ),
            (
                104,
                112,
                0,
                4,
                "audit_context_ptr and audit_context_len must both be present",
            ),
        ] {
            let mut args = base_args(KACS_ACCESS_CHECK_ARGS_SIZE as u32);
            write_u64(&mut args, ptr_offset, ptr_value);
            write_u32(&mut args, len_offset, len_value);

            assert_eq!(
                parse_access_check_abi_request(&args, &TestMemory::new()).unwrap_err(),
                KacsError::InvalidAbiInput(expected)
            );
        }
    }

    #[test]
    fn parser_rejects_object_tree_reserved_field() {
        let mut args = base_args(KACS_ACCESS_CHECK_ARGS_SIZE as u32);
        write_u64(&mut args, 56, TREE_PTR);
        write_u32(&mut args, 64, 1);

        let mut entry = [0u8; KACS_OBJECT_TYPE_ENTRY_SIZE];
        entry[2..4].copy_from_slice(&1u16.to_le_bytes());
        let memory = TestMemory::new().with(TREE_PTR, &entry);

        assert_eq!(
            parse_access_check_abi_request(&args, &memory).unwrap_err(),
            KacsError::NonZeroAbiReservedField("kacs_object_type_entry._reserved")
        );
    }

    #[test]
    fn parser_rejects_oversized_audit_context() {
        let mut args = base_args(KACS_ACCESS_CHECK_ARGS_SIZE as u32);
        write_u64(&mut args, 104, AUDIT_PTR);
        write_u32(&mut args, 112, KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN + 1);

        assert_eq!(
            parse_access_check_abi_request(&args, &TestMemory::new()).unwrap_err(),
            KacsError::InvalidAbiInput("audit_context_len exceeds 4096")
        );
    }
}
