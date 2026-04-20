// SPDX-License-Identifier: GPL-2.0-only

// These C-ABI items are exported for C and KUnit callers rather than for Rust
// re-export through the crate root.
#![allow(unreachable_pub)]

use crate::access_check_abi::{
    execute_access_check_abi, execute_access_check_list_abi, parse_access_check_abi_request,
    AccessCheckAbiExecution, AccessCheckAbiMemory, AccessCheckAbiResolved, AccessCheckAbiReturn,
    KacsNodeResultAbi, OwnedAuditEvent, KACS_ABI_EACCES, KACS_ACCESS_CHECK_ARGS_SIZE,
};
use crate::error::KacsError;
use crate::mic::{IntegrityLevel, TOKEN_MANDATORY_POLICY_NO_WRITE_UP};
use crate::pkm_alloc::Vec;
use crate::pip::PipContext;
use crate::privilege::TokenPrivileges;
use crate::sid::Sid;
use crate::token::{
    AccessCheckToken, ConfinementTokenContext, ImpersonationLevel, RestrictedTokenContext,
    TokenType, TokenView, AUDIT_POLICY_OBJECT_ACCESS_FAILURE, AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
};
use core::ffi::{c_long, c_void};

const EFAULT: c_long = -14;
const EINVAL: c_long = -22;
const ENOMEM: c_long = -12;

const KUNIT_CONTEXT_TAG: u8 = 0;
const KUNIT_USER_SID_BYTES: &[u8] = &[
    1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 160, 15, 0, 0,
];
const KUNIT_GROUPS: &[crate::token::SidAndAttributes<'static>] = &[];
const KUNIT_DEVICE_GROUPS: &[crate::token::SidAndAttributes<'static>] = &[];
const KUNIT_USER_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const KUNIT_DEVICE_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const KUNIT_POLICIES: &[crate::caap::CaapPolicyEntry<'static>] = &[];

#[repr(C)]
/// Opaque handle for a resolved AccessCheck context owned by kernel glue.
pub struct PkmKacsResolvedCtx {
    _private: [u8; 0],
}

#[repr(C)]
/// Usercopy callbacks used by the Rust ingress helper.
pub struct PkmKacsUsercopyOps {
    /// Opaque callback context.
    pub ctx: *mut c_void,
    /// Reads `len` bytes from `user_ptr` into `dst`.
    pub read_bytes:
        Option<unsafe extern "C" fn(ctx: *mut c_void, user_ptr: u64, dst: *mut c_void, len: usize) -> bool>,
    /// Writes `len` bytes from `src` to `user_ptr`.
    pub write_bytes:
        Option<unsafe extern "C" fn(ctx: *mut c_void, user_ptr: u64, src: *const c_void, len: usize) -> bool>,
}

#[repr(C)]
/// Read-only audit-event view passed back to C sinks.
pub struct PkmKacsAuditEventView {
    /// Pointer to raw ACE bytes, or null when absent.
    pub ace_bytes_ptr: *const u8,
    /// Length of `ace_bytes_ptr`.
    pub ace_bytes_len: usize,
    /// Requested bits considered by the event.
    pub requested: u32,
    /// Granted bits associated with the event.
    pub granted: u32,
    /// Whether the event describes success.
    pub success: bool,
    /// Whether the event came from forced object-access audit policy.
    pub policy_forced: bool,
    /// Whether `privilege` is populated.
    pub has_privilege: bool,
    /// Optional privilege bit carried by the event.
    pub privilege: u64,
    /// Pointer to object-audit context bytes, or null when absent.
    pub object_audit_context_ptr: *const u8,
    /// Length of `object_audit_context_ptr`.
    pub object_audit_context_len: usize,
}

#[repr(C)]
/// Read-only privilege-use event view passed back to C sinks.
pub struct PkmKacsPrivilegeUseEventView {
    /// Privilege bit responsible for the event.
    pub privilege: u64,
    /// Requested bits attributed to that privilege.
    pub requested: u32,
    /// Bits granted by the privilege before later narrowing.
    pub granted: u32,
    /// Bits that survived into the final result.
    pub surviving_bits: u32,
    /// Whether the privilege use counted as success.
    pub success: bool,
    /// Pointer to object-audit context bytes, or null when absent.
    pub object_audit_context_ptr: *const u8,
    /// Length of `object_audit_context_ptr`.
    pub object_audit_context_len: usize,
}

#[repr(C)]
/// Event sink callbacks used by the Rust ingress helper.
pub struct PkmKacsEventSinkOps {
    /// Opaque callback context.
    pub ctx: *mut c_void,
    /// Callback for each audit event.
    pub on_audit_event:
        Option<unsafe extern "C" fn(ctx: *mut c_void, event: *const PkmKacsAuditEventView)>,
    /// Callback for each privilege-use event.
    pub on_privilege_use_event:
        Option<unsafe extern "C" fn(ctx: *mut c_void, event: *const PkmKacsPrivilegeUseEventView)>,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// C-facing view of token privilege state after ingress execution.
pub struct PkmKacsPrivilegeStateView {
    /// Present privilege bits.
    pub present: u64,
    /// Enabled privilege bits.
    pub enabled: u64,
    /// Enabled-by-default privilege bits.
    pub enabled_by_default: u64,
    /// Used privilege bits.
    pub used: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// Summary written back by the ingress helper after one request.
pub struct PkmKacsIngressSummary {
    /// Updated privilege state after execution.
    pub updated_privileges: PkmKacsPrivilegeStateView,
    /// Number of audit events emitted.
    pub audit_event_count: u32,
    /// Number of privilege-use events emitted.
    pub privilege_use_event_count: u32,
}

struct CallbackMemory<'a> {
    ops: &'a PkmKacsUsercopyOps,
}

impl AccessCheckAbiMemory for CallbackMemory<'_> {
    fn read_bytes(&self, ptr: u64, len: usize) -> Option<Vec<u8>> {
        read_bytes_from_ops(self.ops, ptr, len).ok()
    }
}

#[no_mangle]
/// Returns the built-in KUnit-only resolved context handle used by the current
/// kernel ingress scaffold.
pub extern "C" fn kacs_rust_kunit_access_check_context() -> *const PkmKacsResolvedCtx {
    (&KUNIT_CONTEXT_TAG as *const u8).cast()
}

#[no_mangle]
/// Executes scalar AccessCheck through the kernel ingress helper.
pub extern "C" fn kacs_rust_access_check_ingress_scalar(
    ops: *const PkmKacsUsercopyOps,
    args_ptr: u64,
    resolved_ctx: *const PkmKacsResolvedCtx,
    event_sinks: *const PkmKacsEventSinkOps,
    summary_out: *mut PkmKacsIngressSummary,
) -> c_long {
    match with_resolved_context(resolved_ctx.cast(), |resolved| {
        let ops = validate_usercopy_ops(ops)?;
        zero_summary(summary_out);
        let args_bytes = read_args_prefix(ops, args_ptr)?;
        let request = parse_access_check_abi_request(&args_bytes, &CallbackMemory { ops })
            .map_err(map_kacs_error)?;
        let execution = execute_access_check_abi(&request, &resolved).map_err(map_kacs_error)?;
        finalize_execution(ops, event_sinks, summary_out, execution, None)
    }) {
        Ok(ret) => ret,
        Err(errno) => errno,
    }
}

#[no_mangle]
/// Executes result-list AccessCheck through the kernel ingress helper.
pub extern "C" fn kacs_rust_access_check_ingress_list(
    ops: *const PkmKacsUsercopyOps,
    args_ptr: u64,
    results_ptr: u64,
    results_count: u32,
    resolved_ctx: *const PkmKacsResolvedCtx,
    event_sinks: *const PkmKacsEventSinkOps,
    summary_out: *mut PkmKacsIngressSummary,
) -> c_long {
    match with_resolved_context(resolved_ctx.cast(), |resolved| {
        let ops = validate_usercopy_ops(ops)?;
        zero_summary(summary_out);
        let args_bytes = read_args_prefix(ops, args_ptr)?;
        let request = parse_access_check_abi_request(&args_bytes, &CallbackMemory { ops })
            .map_err(map_kacs_error)?;
        let execution = execute_access_check_list_abi(&request, results_count, &resolved)
            .map_err(map_kacs_error)?;
        finalize_execution(ops, event_sinks, summary_out, execution, Some((results_ptr, results_count)))
    }) {
        Ok(ret) => ret,
        Err(errno) => errno,
    }
}

fn with_resolved_context<T>(
    resolved_ctx: *const c_void,
    f: impl FnOnce(AccessCheckAbiResolved<'_>) -> Result<T, c_long>,
) -> Result<T, c_long> {
    if resolved_ctx.is_null() || resolved_ctx != (&KUNIT_CONTEXT_TAG as *const u8).cast() {
        return Err(EINVAL);
    }

    let user = Sid::parse(KUNIT_USER_SID_BYTES).map_err(map_kacs_error)?;
    let token = AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups: KUNIT_GROUPS,
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        audit_policy: AUDIT_POLICY_OBJECT_ACCESS_SUCCESS | AUDIT_POLICY_OBJECT_ACCESS_FAILURE,
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        restricted: RestrictedTokenContext::default(),
        confinement: ConfinementTokenContext::default(),
    };
    let resolved = AccessCheckAbiResolved {
        token: &token,
        default_pip: PipContext {
            pip_type: 0,
            pip_trust: 0,
        },
        device_groups: KUNIT_DEVICE_GROUPS,
        user_claims: KUNIT_USER_CLAIMS,
        device_claims: KUNIT_DEVICE_CLAIMS,
        policies: KUNIT_POLICIES,
    };
    f(resolved)
}

fn validate_usercopy_ops<'a>(ops: *const PkmKacsUsercopyOps) -> Result<&'a PkmKacsUsercopyOps, c_long> {
    let ops = unsafe { ops.as_ref() }.ok_or(EINVAL)?;
    if ops.read_bytes.is_none() || ops.write_bytes.is_none() {
        return Err(EINVAL);
    }
    Ok(ops)
}

fn read_args_prefix(ops: &PkmKacsUsercopyOps, args_ptr: u64) -> Result<Vec<u8>, c_long> {
    let mut size_bytes = [0u8; 4];
    read_exact_into(ops, args_ptr, &mut size_bytes)?;
    let caller_size = u32::from_le_bytes(size_bytes);
    let copied_len = usize::try_from(caller_size)
        .map_err(|_| EINVAL)?
        .min(KACS_ACCESS_CHECK_ARGS_SIZE);
    read_bytes_from_ops(ops, args_ptr, copied_len).map_err(map_kacs_error)
}

fn read_exact_into(ops: &PkmKacsUsercopyOps, user_ptr: u64, dst: &mut [u8]) -> Result<(), c_long> {
    let Some(read_bytes) = ops.read_bytes else {
        return Err(EINVAL);
    };
    let ok = unsafe { read_bytes(ops.ctx, user_ptr, dst.as_mut_ptr().cast(), dst.len()) };
    if ok {
        Ok(())
    } else {
        Err(EFAULT)
    }
}

fn read_bytes_from_ops(ops: &PkmKacsUsercopyOps, user_ptr: u64, len: usize) -> Result<Vec<u8>, KacsError> {
    let Some(read_bytes) = ops.read_bytes else {
        return Err(KacsError::InvalidAbiInput("missing usercopy read callback"));
    };
    let mut buffer = Vec::with_capacity(len)?;
    for _ in 0..len {
        buffer.push(0)?;
    }
    let ok = unsafe { read_bytes(ops.ctx, user_ptr, buffer.as_mut_ptr().cast(), len) };
    if ok {
        Ok(buffer)
    } else {
        Err(KacsError::UserMemoryFault {
            field: "usercopy",
            ptr: user_ptr,
            len,
        })
    }
}

fn write_bytes_to_ops(ops: &PkmKacsUsercopyOps, user_ptr: u64, src: &[u8]) -> Result<(), c_long> {
    let Some(write_bytes) = ops.write_bytes else {
        return Err(EINVAL);
    };
    let ok = unsafe { write_bytes(ops.ctx, user_ptr, src.as_ptr().cast(), src.len()) };
    if ok {
        Ok(())
    } else {
        Err(EFAULT)
    }
}

fn finalize_execution(
    ops: &PkmKacsUsercopyOps,
    event_sinks: *const PkmKacsEventSinkOps,
    summary_out: *mut PkmKacsIngressSummary,
    execution: AccessCheckAbiExecution,
    list_output: Option<(u64, u32)>,
) -> Result<c_long, c_long> {
    if let Some(writeback) = execution.granted_out {
        write_u32(ops, writeback.ptr, writeback.value)?;
    }
    if let Some(writeback) = execution.continuous_audit_out {
        write_u32(ops, writeback.ptr, writeback.value)?;
    }
    if let Some(writeback) = execution.staging_mismatch_out {
        write_u32(ops, writeback.ptr, writeback.value)?;
    }

    if let Some((results_ptr, results_count)) = list_output {
        let node_results = execution.node_results.as_ref().ok_or(EINVAL)?;
        if results_ptr == 0 {
            return Err(EFAULT);
        }
        if usize::try_from(results_count).map_err(|_| EINVAL)? != node_results.len() {
            return Err(EINVAL);
        }
        write_node_results(ops, results_ptr, node_results.as_slice())?;
    }

    emit_events(event_sinks, &execution.audit_events, &execution.privilege_use_events);
    write_summary(summary_out, &execution);

    Ok(match execution.disposition {
        AccessCheckAbiReturn::Granted(granted) => granted as c_long,
        AccessCheckAbiReturn::AccessDenied => KACS_ABI_EACCES as c_long,
        AccessCheckAbiReturn::Success => 0,
    })
}

fn write_u32(ops: &PkmKacsUsercopyOps, ptr: u64, value: u32) -> Result<(), c_long> {
    write_bytes_to_ops(ops, ptr, &value.to_le_bytes())
}

fn write_node_results(
    ops: &PkmKacsUsercopyOps,
    results_ptr: u64,
    results: &[KacsNodeResultAbi],
) -> Result<(), c_long> {
    let total_len = results.len().checked_mul(8).ok_or(EINVAL)?;
    let mut bytes = Vec::with_capacity(total_len).map_err(|_| ENOMEM)?;
    for result in results {
        bytes.extend_from_slice(&result.granted.to_le_bytes())
            .map_err(|_| ENOMEM)?;
        bytes.extend_from_slice(&result.status.to_le_bytes())
            .map_err(|_| ENOMEM)?;
    }
    write_bytes_to_ops(ops, results_ptr, bytes.as_slice())
}

fn emit_events(
    event_sinks: *const PkmKacsEventSinkOps,
    audit_events: &[OwnedAuditEvent],
    privilege_use_events: &[crate::PrivilegeUseEvent],
) {
    let Some(sinks) = (unsafe { event_sinks.as_ref() }) else {
        return;
    };

    if let Some(on_audit_event) = sinks.on_audit_event {
        for event in audit_events {
            let (ace_bytes_ptr, ace_bytes_len) = match event.ace_bytes.as_ref() {
                Some(bytes) => (bytes.as_slice().as_ptr(), bytes.len()),
                None => (core::ptr::null(), 0),
            };
            let (context_ptr, context_len) = match event.object_audit_context.as_ref() {
                Some(bytes) => (bytes.as_slice().as_ptr(), bytes.len()),
                None => (core::ptr::null(), 0),
            };
            let view = PkmKacsAuditEventView {
                ace_bytes_ptr,
                ace_bytes_len,
                requested: event.requested,
                granted: event.granted,
                success: event.success,
                policy_forced: event.policy_forced,
                has_privilege: event.privilege.is_some(),
                privilege: event.privilege.unwrap_or(0),
                object_audit_context_ptr: context_ptr,
                object_audit_context_len: context_len,
            };
            unsafe { on_audit_event(sinks.ctx, &view) };
        }
    }

    if let Some(on_privilege_use_event) = sinks.on_privilege_use_event {
        for event in privilege_use_events {
            let (context_ptr, context_len) = match event.object_audit_context.as_ref() {
                Some(bytes) => (bytes.as_slice().as_ptr(), bytes.len()),
                None => (core::ptr::null(), 0),
            };
            let view = PkmKacsPrivilegeUseEventView {
                privilege: event.privilege,
                requested: event.requested,
                granted: event.granted,
                surviving_bits: event.surviving_bits,
                success: event.success,
                object_audit_context_ptr: context_ptr,
                object_audit_context_len: context_len,
            };
            unsafe { on_privilege_use_event(sinks.ctx, &view) };
        }
    }
}

fn write_summary(summary_out: *mut PkmKacsIngressSummary, execution: &AccessCheckAbiExecution) {
    let Some(summary) = (unsafe { summary_out.as_mut() }) else {
        return;
    };

    summary.updated_privileges = PkmKacsPrivilegeStateView {
        present: execution.updated_privileges.present,
        enabled: execution.updated_privileges.enabled,
        enabled_by_default: execution.updated_privileges.enabled_by_default,
        used: execution.updated_privileges.used,
    };
    summary.audit_event_count = execution.audit_events.len() as u32;
    summary.privilege_use_event_count = execution.privilege_use_events.len() as u32;
}

fn zero_summary(summary_out: *mut PkmKacsIngressSummary) {
    if let Some(summary) = unsafe { summary_out.as_mut() } {
        *summary = PkmKacsIngressSummary::default();
    }
}

fn map_kacs_error(error: KacsError) -> c_long {
    match error {
        KacsError::UserMemoryFault { .. } => EFAULT,
        KacsError::AllocationFailure => ENOMEM,
        _ => EINVAL,
    }
}
