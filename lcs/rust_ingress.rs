// SPDX-License-Identifier: GPL-2.0-only

use core::ffi::{c_int, c_long, c_void};
use core::{slice, str};

use crate::kacs_core::PkmVec;
use crate::lcs_core::{
    classify_hive_route, current_user_sid_component_from_binary_sid,
    for_each_rsi_lookup_source_path_entry,
    parse_rsi_lookup_success_response_payload, plan_rsi_source_read,
    plan_registry_ioctl_fixed_fd_access_gate, plan_registry_key_open_access,
    plan_registry_open_pre_resolution_access, plan_registry_security_info_fd_access_gate,
    plan_source_registration_sequence_update, parse_rsi_request_header,
    registry_ioctl_access_requirement, registry_ioctl_fd_access_gate_errno,
    registry_open_pre_resolution_linux_errno, resolve_named_path_entry, route_hive,
    route_routable_path_hive, RSI_LOOKUP, rsi_queued_request_from_frame, rsi_status_code_errno,
    source_registration_error_linux_errno, source_registration_hive_scope, source_slot_hive_status,
    validate_key_component_bytes, validate_key_fd_open_view, validate_registry_open_flags,
    validate_resolved_relative_path_depth,
    validate_rsi_lookup_metadata_completeness,
    validate_rsi_lookup_metadata_security_descriptors, validate_rsi_lookup_path_response_names,
    validate_rsi_lookup_path_response_sequences, validate_source_registration,
    validate_source_slots, validate_syscall_path_c_string, write_rsi_lookup_request_frame,
    CurrentUserRewrite, HiveRouteOutcome, HiveView, KeyFdOpenView, KeyWatchState,
    LayerResolutionContext, LayerView, LcsError, LcsLimits, LinuxErrno, NamedPathEntry,
    NamedPathResolution, PathKind, RegisteredHiveIdentity, RegistryIoctlAccessRequirement,
    RegistryKeyOpenAccessInput, RegistryOpenAccessDecision, RegistryOpenPreResolutionAccessPlan,
    RsiReadPlan, RsiRetainedRequest, SourceRegistrationDecision, SourceRegistrationHive,
    SourceRegistrationRequest, SourceSlotStatus, SourceSlotView,
};

const PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE: u32 = 0;
const PKM_LCS_SOURCE_SLOT_STATUS_DOWN: u32 = 1;

const PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW: u32 = 0;
const PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN: u32 = 1;

const PKM_LCS_RSI_READ_ACTION_COPY: u32 = 0;
const PKM_LCS_RSI_READ_ACTION_WAIT: u32 = 1;
const PKM_LCS_RSI_READ_ACTION_EAGAIN: u32 = 2;
const PKM_LCS_RSI_READ_ACTION_EMSGSIZE: u32 = 3;
const PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE: u32 = 4;

#[repr(C)]
pub struct PkmLcsSourceRegistrationHiveCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub root_guid: [u8; 16],
    pub flags: u32,
    pub scope_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsSourceSlotViewCopy {
    pub source_id: u32,
    pub status: u32,
    pub hive_count: u32,
    pub _pad: u32,
    pub hives: *const PkmLcsSourceRegistrationHiveCopy,
}

#[repr(C)]
pub struct PkmLcsSourceRegistrationPlanCopy {
    pub hive_count: u32,
    pub source_next_sequence: u64,
    pub effective_next_sequence: u64,
    pub decision: u32,
    pub source_id: u32,
}

#[repr(C)]
pub struct PkmLcsHiveRouteResultCopy {
    pub source_id: u32,
    pub root_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsOpenPreflightPlanCopy {
    pub requested_access: u32,
    pub mapped_desired_access: u32,
    pub maximum_allowed: u8,
    pub path_resolution_allowed: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct PkmLcsKeyOpenAccessPlanCopy {
    pub requested_access: u32,
    pub mapped_desired_access: u32,
    pub access_check_granted: u32,
    pub fd_granted_access: u32,
    pub allowed: u8,
    pub maximum_allowed: u8,
    pub key_open_sacl_audit_required: u8,
    pub audit_failure_blocks_completion: u8,
    pub privilege_use_audit_required: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsKeyFdStringViewCopy {
    pub bytes: *const u8,
    pub len: u32,
}

#[repr(C)]
pub struct PkmLcsPathValidationResultCopy {
    pub component_count: u32,
    pub used_forward_separator: bool,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiBuiltRequestCopy {
    pub len: usize,
    pub request_id: u64,
    pub txn_id: u64,
    pub op_code: u16,
    pub _pad: [u8; 6],
}

#[repr(C)]
pub struct PkmLcsRsiReadPlanCopy {
    pub action: u32,
    pub _pad: u32,
    pub request_len: usize,
    pub required_len: usize,
}

#[repr(C)]
pub struct PkmLcsRsiLookupResponseSummaryCopy {
    pub path_entry_count: u32,
    pub metadata_count: u32,
    pub child_absent: bool,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiLayerViewCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub precedence: u32,
    pub enabled: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct PkmLcsRsiPrivateLayerViewCopy {
    pub name: *const u8,
    pub name_len: u32,
}

#[repr(C)]
pub struct PkmLcsRsiLookupChildResultCopy {
    pub source_path_entry_count: u32,
    pub sd_offset: u32,
    pub sd_len: u32,
    pub selected_precedence: u32,
    pub selected_sequence: u64,
    pub last_write_time: u64,
    pub found: u8,
    pub volatile_key: u8,
    pub symlink: u8,
    pub _pad: [u8; 5],
    pub key_guid: [u8; 16],
}

fn source_registration_error_return(err: crate::lcs_core::LcsError) -> c_int {
    source_registration_error_linux_errno(err)
        .unwrap_or(LinuxErrno::Einval)
        .negated_return() as c_int
}

fn absolute_route_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => LinuxErrno::Enametoolong,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn key_fd_open_view_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => {
            LinuxErrno::Enametoolong
        }
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn key_open_access_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::MalformedSecurityDescriptor { .. } => LinuxErrno::Eio,
        LcsError::AccessCheckEvaluationFailed => LinuxErrno::Eio,
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn rsi_request_frame_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::RsiFrameBufferTooSmall { .. } => LinuxErrno::Emsgsize,
        LcsError::NameTooLong { .. } | LcsError::PathTooLong { .. } => {
            LinuxErrno::Enametoolong
        }
        _ => LinuxErrno::Einval,
    }
    .negated_return() as c_int
}

fn rsi_lookup_response_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::RsiRequestIdMismatch { .. }
        | LcsError::RsiResponseOpcodeMismatch { .. }
        | LcsError::RsiMessageLengthMismatch { .. }
        | LcsError::RsiResponsePayloadParserMismatch { .. } => {
            LinuxErrno::Einval.negated_return() as c_int
        }
        LcsError::RsiResponseStatusNotOk(status) => match rsi_status_code_errno(status) {
            Ok(Some(errno)) => errno.negated_return() as c_int,
            Ok(None) => 0,
            Err(_) => LinuxErrno::Eio.negated_return() as c_int,
        },
        _ => LinuxErrno::Eio.negated_return() as c_int,
    }
}

fn rsi_lookup_materialization_error_return(err: LcsError) -> c_int {
    match err {
        LcsError::MissingBaseLayer
        | LcsError::InvalidBaseLayerProperties { .. }
        | LcsError::DuplicateLayerIdentity
        | LcsError::TooManyLayers { .. }
        | LcsError::TooManyPrivateLayers { .. }
        | LcsError::DuplicatePrivateLayerIdentity => LinuxErrno::Einval.negated_return() as c_int,
        _ => rsi_lookup_response_error_return(err),
    }
}

fn ioctl_access_gate_return(
    plan: crate::lcs_core::RegistryIoctlFdAccessGatePlan,
) -> c_int {
    match registry_ioctl_fd_access_gate_errno(&plan) {
        Some(errno) => errno.negated_return() as c_int,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_open_preflight(
    desired_access: u32,
    flags: u32,
    plan_out: *mut PkmLcsOpenPreflightPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsOpenPreflightPlanCopy {
            requested_access: 0,
            mapped_desired_access: 0,
            maximum_allowed: 0,
            path_resolution_allowed: 0,
            _pad: [0; 2],
        };
    }

    if validate_registry_open_flags(flags).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let plan = plan_registry_open_pre_resolution_access(desired_access);
    match plan {
        RegistryOpenPreResolutionAccessPlan::Continue {
            requested_access,
            mapped_desired_access,
            maximum_allowed,
            path_resolution_allowed,
        } => {
            unsafe {
                (*plan_out).requested_access = requested_access;
                (*plan_out).mapped_desired_access = mapped_desired_access;
                (*plan_out).maximum_allowed = maximum_allowed as u8;
                (*plan_out).path_resolution_allowed = path_resolution_allowed as u8;
            }
            0
        }
        RegistryOpenPreResolutionAccessPlan::Reject { .. } => {
            registry_open_pre_resolution_linux_errno(&plan)
                .unwrap_or(LinuxErrno::Einval)
                .negated_return() as c_int
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_open_access_plan(
    subject_token: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired_access: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    plan_out: *mut PkmLcsKeyOpenAccessPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsKeyOpenAccessPlanCopy {
            requested_access: 0,
            mapped_desired_access: 0,
            access_check_granted: 0,
            fd_granted_access: 0,
            allowed: 0,
            maximum_allowed: 0,
            key_open_sacl_audit_required: 0,
            audit_failure_blocks_completion: 0,
            privilege_use_audit_required: 0,
            _pad: [0; 3],
        };
    }

    if subject_token.is_null() {
        return LinuxErrno::Eacces.negated_return() as c_int;
    }
    if sd_ptr.is_null() || sd_len == 0 || desired_access == 0 || caap_cache.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let sd_bytes = unsafe { slice::from_raw_parts(sd_ptr, sd_len) };
    let pip = crate::kacs_core::PipContext {
        pip_type,
        pip_trust,
    };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        crate::token_runtime::with_access_check_resolved_from_token(
            subject_token,
            pip,
            policies,
            |resolved| {
                let conditional_context = crate::kacs_core::ConditionalContext {
                    device_groups: resolved.device_groups,
                    user_claims: resolved.user_claims,
                    device_claims: resolved.device_claims,
                    ..crate::kacs_core::ConditionalContext::default()
                };
                let plan = plan_registry_key_open_access(RegistryKeyOpenAccessInput {
                    key_sd: sd_bytes,
                    token: resolved.token,
                    desired_access,
                    pip,
                    conditional_context,
                    object_audit_context: None,
                    privilege_intent: 0,
                    caap_policies: resolved.policies,
                })
                .map_err(|err| key_open_access_error_return(err) as c_long)?;

                if !crate::token_runtime::mark_token_privileges_used(
                    subject_token,
                    plan.updated_privileges.used,
                ) {
                    return Err(LinuxErrno::Eacces.negated_return() as c_long);
                }

                unsafe {
                    (*plan_out).requested_access = plan.requested_access;
                    (*plan_out).mapped_desired_access = plan.mapped_desired_access;
                    (*plan_out).access_check_granted = plan.access_check_granted;
                    (*plan_out).fd_granted_access = plan.fd_granted_access.unwrap_or(0);
                    (*plan_out).allowed =
                        u8::from(plan.decision == RegistryOpenAccessDecision::Allowed);
                    (*plan_out).maximum_allowed = u8::from(plan.maximum_allowed);
                    (*plan_out).key_open_sacl_audit_required =
                        u8::from(plan.key_open_sacl_audit_required);
                    (*plan_out).audit_failure_blocks_completion =
                        u8::from(plan.audit_failure_blocks_completion);
                    (*plan_out).privilege_use_audit_required =
                        u8::from(plan.privilege_use_audit_required);
                }

                if plan.decision == RegistryOpenAccessDecision::Allowed {
                    Ok(0)
                } else {
                    Ok(LinuxErrno::Eacces.negated_return() as c_long)
                }
            },
        )
    }) {
        Ok(ret) => ret as c_int,
        Err(errno) => errno as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_key_fd_open_view(
    key_guid: *const u8,
    granted_access: u32,
    path_components: *const PkmLcsKeyFdStringViewCopy,
    path_component_count: usize,
    ancestor_guids: *const [u8; 16],
    ancestor_count: usize,
) -> c_int {
    if key_guid.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if path_component_count != 0 && path_components.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if ancestor_count != 0 && ancestor_guids.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let key_guid_bytes = unsafe { slice::from_raw_parts(key_guid, 16) };
    let mut key_guid_copy = [0u8; 16];
    key_guid_copy.copy_from_slice(key_guid_bytes);

    let mut parsed_components = match PkmVec::with_capacity(path_component_count) {
        Ok(parsed_components) => parsed_components,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };

    for index in 0..path_component_count {
        let raw = unsafe { &*path_components.add(index) };
        if raw.bytes.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }

        let bytes = unsafe { slice::from_raw_parts(raw.bytes, raw.len as usize) };
        let component = match str::from_utf8(bytes) {
            Ok(component) => component,
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        };
        if parsed_components.push(component).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let ancestors = if ancestor_count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ancestor_guids, ancestor_count) }
    };
    let fd = KeyFdOpenView {
        key_guid: key_guid_copy,
        granted_access,
        resolved_path: parsed_components.as_slice(),
        ancestor_guids: ancestors,
        watch_state: KeyWatchState {
            armed: false,
            orphaned: false,
        },
    };

    match validate_key_fd_open_view(&LcsLimits::DEFAULT, &fd) {
        Ok(()) => 0,
        Err(err) => key_fd_open_view_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_syscall_relative_path(
    path: *const u8,
    path_len: u32,
    result_out: *mut PkmLcsPathValidationResultCopy,
) -> c_int {
    if path.is_null() || result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsPathValidationResultCopy {
            component_count: 0,
            used_forward_separator: false,
            _pad: [0; 3],
        };
    }

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    match validate_syscall_path_c_string(path_bytes, PathKind::Relative, &LcsLimits::DEFAULT) {
        Ok(summary) => {
            unsafe {
                (*result_out).component_count = summary.component_count as u32;
                (*result_out).used_forward_separator = summary.used_forward_separator;
            }
            0
        }
        Err(err) => absolute_route_error_return(err),
    }
}

#[no_mangle]
pub extern "C" fn lcs_rust_validate_relative_open_depth(
    parent_depth: u32,
    relative_component_count: u32,
) -> c_int {
    match validate_resolved_relative_path_depth(
        parent_depth as usize,
        relative_component_count as usize,
        &LcsLimits::DEFAULT,
    ) {
        Ok(_) => 0,
        Err(err) => absolute_route_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_write_rsi_lookup_request_frame(
    dst: *mut u8,
    dst_len: usize,
    request_id: u64,
    txn_id: u64,
    parent_guid: *const u8,
    child_name: *const u8,
    child_name_len: u32,
    built_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if built_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *built_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if dst.is_null() || parent_guid.is_null() || child_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let dst_bytes = unsafe { slice::from_raw_parts_mut(dst, dst_len) };
    let parent_guid_bytes = unsafe { slice::from_raw_parts(parent_guid, 16) };
    let mut parent_guid_copy = [0u8; 16];
    parent_guid_copy.copy_from_slice(parent_guid_bytes);

    let child_name_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    if let Err(err) = validate_key_component_bytes(child_name_bytes, &LcsLimits::DEFAULT) {
        return rsi_request_frame_error_return(err);
    }

    match write_rsi_lookup_request_frame(
        dst_bytes,
        request_id,
        txn_id,
        parent_guid_copy,
        child_name_bytes,
    ) {
        Ok(built) => {
            unsafe {
                *built_out = PkmLcsRsiBuiltRequestCopy {
                    len: built.len,
                    request_id: built.retained.request_id,
                    txn_id,
                    op_code: built.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_queued_request_frame(
    frame: *const u8,
    frame_len: usize,
    retained_out: *mut PkmLcsRsiBuiltRequestCopy,
) -> c_int {
    if retained_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *retained_out = PkmLcsRsiBuiltRequestCopy {
            len: 0,
            request_id: 0,
            txn_id: 0,
            op_code: 0,
            _pad: [0; 6],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    match rsi_queued_request_from_frame(frame_bytes) {
        Ok(request) => {
            let header = match parse_rsi_request_header(frame_bytes) {
                Ok(header) => header,
                Err(err) => return rsi_request_frame_error_return(err),
            };
            unsafe {
                *retained_out = PkmLcsRsiBuiltRequestCopy {
                    len: request.frame.len(),
                    request_id: request.retained.request_id,
                    txn_id: header.txn_id,
                    op_code: request.retained.op_code,
                    _pad: [0; 6],
                };
            }
            0
        }
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_rsi_lookup_response_frame(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    summary_out: *mut PkmLcsRsiLookupResponseSummaryCopy,
) -> c_int {
    if summary_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *summary_out = PkmLcsRsiLookupResponseSummaryCopy {
            path_entry_count: 0,
            metadata_count: 0,
            child_absent: false,
            _pad: [0; 3],
        };
    }

    if frame.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let payload = match parse_rsi_lookup_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_lookup_response_error_return(err),
    };

    if let Err(err) = validate_rsi_lookup_metadata_completeness(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_names(&payload, &LcsLimits::DEFAULT) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_metadata_security_descriptors(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_sequences(&payload, next_sequence) {
        return rsi_lookup_response_error_return(err);
    }

    unsafe {
        (*summary_out).path_entry_count = payload.entry_count;
        (*summary_out).metadata_count = payload.metadata_count;
        (*summary_out).child_absent = payload.entry_count == 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_materialize_rsi_lookup_child(
    frame: *const u8,
    frame_len: usize,
    request_id: u64,
    next_sequence: u64,
    child_name: *const u8,
    child_name_len: u32,
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
    result_out: *mut PkmLcsRsiLookupChildResultCopy,
) -> c_int {
    if result_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *result_out = PkmLcsRsiLookupChildResultCopy {
            source_path_entry_count: 0,
            sd_offset: 0,
            sd_len: 0,
            selected_precedence: 0,
            selected_sequence: 0,
            last_write_time: 0,
            found: 0,
            volatile_key: 0,
            symlink: 0,
            _pad: [0; 5],
            key_guid: [0; 16],
        };
    }

    if frame.is_null()
        || child_name.is_null()
        || (layer_count != 0 && layers.is_null())
        || (private_layer_count != 0 && private_layers.is_null())
    {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let frame_bytes = unsafe { slice::from_raw_parts(frame, frame_len) };
    let child_bytes = unsafe { slice::from_raw_parts(child_name, child_name_len as usize) };
    let child_component = match str::from_utf8(child_bytes) {
        Ok(child_component) => child_component,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    if validate_key_component_bytes(child_bytes, &LcsLimits::DEFAULT).is_err() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let layer_views = match parse_layer_views(layers, layer_count) {
        Ok(layer_views) => layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let private_layer_views = match parse_private_layer_views(private_layers, private_layer_count) {
        Ok(private_layer_views) => private_layer_views,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let payload = match parse_rsi_lookup_success_response_payload(
        frame_bytes,
        RsiRetainedRequest {
            request_id,
            op_code: RSI_LOOKUP,
        },
    ) {
        Ok(payload) => payload,
        Err(err) => return rsi_lookup_response_error_return(err),
    };

    if let Err(err) = validate_rsi_lookup_metadata_completeness(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_names(&payload, &LcsLimits::DEFAULT) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_metadata_security_descriptors(&payload) {
        return rsi_lookup_response_error_return(err);
    }
    if let Err(err) = validate_rsi_lookup_path_response_sequences(&payload, next_sequence) {
        return rsi_lookup_response_error_return(err);
    }

    let context = LayerResolutionContext {
        layers: layer_views.as_slice(),
        private_layers: private_layer_views.as_slice(),
        limits: &LcsLimits::DEFAULT,
        next_sequence,
    };
    let mut path_storage = match PkmVec::<NamedPathEntry<'_>>::with_capacity(
        payload.entry_count as usize,
    ) {
        Ok(path_storage) => path_storage,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    let mut path_storage_allocation_failed = false;
    if let Err(err) = for_each_rsi_lookup_source_path_entry(
        &payload,
        &LcsLimits::DEFAULT,
        child_component,
        |entry| {
            if path_storage.push(entry).is_err() {
                path_storage_allocation_failed = true;
                return Err(LcsError::RsiPayloadLengthOverflow);
            }
            Ok(())
        },
    ) {
        if path_storage_allocation_failed {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
        return rsi_lookup_response_error_return(err);
    }

    let resolved = match resolve_named_path_entry(
        &context,
        child_component,
        path_storage.as_slice(),
    ) {
        Ok(resolved) => resolved,
        Err(err) => return rsi_lookup_materialization_error_return(err),
    };

    unsafe {
        (*result_out).source_path_entry_count = path_storage.len() as u32;
    }

    let NamedPathResolution::Found(found) = resolved else {
        return 0;
    };

    let base = frame_bytes.as_ptr() as usize;
    let end = base.saturating_add(frame_len);
    let mut matched = false;
    let mut metadata_errno = LinuxErrno::Eio;

    if let Err(err) = payload.for_each_key_metadata(|metadata| {
        if metadata.guid != found.path.guid {
            return Ok(());
        }
        let sd_ptr = metadata.sd.data.as_ptr() as usize;
        let sd_len = metadata.sd.data.len();
        let Some(sd_end) = sd_ptr.checked_add(sd_len) else {
            metadata_errno = LinuxErrno::Eoverflow;
            return Err(LcsError::RsiPayloadLengthOverflow);
        };
        if sd_ptr < base || sd_end > end {
            return Err(LcsError::RsiPayloadLengthOverflow);
        }
        let sd_offset = sd_ptr - base;
        if sd_offset > u32::MAX as usize || sd_len > u32::MAX as usize {
            metadata_errno = LinuxErrno::Eoverflow;
            return Err(LcsError::RsiPayloadLengthOverflow);
        }

        unsafe {
            (*result_out).source_path_entry_count = path_storage.len() as u32;
            (*result_out).sd_offset = sd_offset as u32;
            (*result_out).sd_len = sd_len as u32;
            (*result_out).selected_precedence = found.path.precedence;
            (*result_out).selected_sequence = found.path.sequence;
            (*result_out).last_write_time = metadata.last_write_time;
            (*result_out).found = 1;
            (*result_out).volatile_key = metadata.volatile as u8;
            (*result_out).symlink = metadata.symlink as u8;
            (*result_out).key_guid = found.path.guid;
        }
        matched = true;
        Ok(())
    }) {
        return match metadata_errno {
            LinuxErrno::Eoverflow => metadata_errno.negated_return() as c_int,
            _ => rsi_lookup_response_error_return(err),
        };
    }

    if !matched {
        return LinuxErrno::Eio.negated_return() as c_int;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_plan_rsi_source_read(
    has_next_request: bool,
    next_request_len: usize,
    caller_buffer_len: usize,
    nonblocking: bool,
    fd_closing: bool,
    plan_out: *mut PkmLcsRsiReadPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    unsafe {
        *plan_out = PkmLcsRsiReadPlanCopy {
            action: PKM_LCS_RSI_READ_ACTION_WAIT,
            _pad: 0,
            request_len: 0,
            required_len: 0,
        };
    }

    let next_request = if has_next_request {
        Some(next_request_len)
    } else {
        None
    };

    match plan_rsi_source_read(next_request, caller_buffer_len, nonblocking, fd_closing) {
        Ok(RsiReadPlan::ReturnOneCompleteRequest { request_len, .. }) => unsafe {
            *plan_out = PkmLcsRsiReadPlanCopy {
                action: PKM_LCS_RSI_READ_ACTION_COPY,
                _pad: 0,
                request_len,
                required_len: request_len,
            };
            0
        },
        Ok(RsiReadPlan::WaitForRequestOrClose) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_WAIT;
            0
        },
        Ok(RsiReadPlan::ReturnEagain) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_EAGAIN;
            0
        },
        Ok(RsiReadPlan::ReturnEmsgsize { required_len, .. }) => unsafe {
            *plan_out = PkmLcsRsiReadPlanCopy {
                action: PKM_LCS_RSI_READ_ACTION_EMSGSIZE,
                _pad: 0,
                request_len: 0,
                required_len,
            };
            0
        },
        Ok(RsiReadPlan::WakeForClose) => unsafe {
            (*plan_out).action = PKM_LCS_RSI_READ_ACTION_WAKE_CLOSE;
            0
        },
        Err(err) => rsi_request_frame_error_return(err),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_fd_fixed_ioctl_access_gate(
    granted_access: u32,
    ioctl_number: u32,
) -> c_int {
    if ioctl_number > u8::MAX as u32 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let ioctl_number = ioctl_number as u8;

    match plan_registry_ioctl_fixed_fd_access_gate(granted_access, ioctl_number) {
        Ok(Some(plan)) => ioctl_access_gate_return(plan),
        Ok(None) | Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_key_fd_security_ioctl_access_gate(
    granted_access: u32,
    ioctl_number: u32,
    security_info: u32,
) -> c_int {
    if ioctl_number > u8::MAX as u32 {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    let ioctl_number = ioctl_number as u8;

    let operation = match registry_ioctl_access_requirement(ioctl_number) {
        Ok(RegistryIoctlAccessRequirement::KeySecurityInfo(operation)) => operation,
        Ok(_) | Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };

    match plan_registry_security_info_fd_access_gate(granted_access, operation, security_info) {
        Ok(plan) => ioctl_access_gate_return(plan),
        Err(_) => LinuxErrno::Einval.negated_return() as c_int,
    }
}

fn parse_registration_hives<'a>(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
) -> Result<PkmVec<SourceRegistrationHive<'a>>, LinuxErrno> {
    let mut parsed = PkmVec::with_capacity(hive_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..hive_count {
        let raw = unsafe { &*hives.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;

        parsed
            .push(SourceRegistrationHive {
                name,
                root_guid: raw.root_guid,
                flags: raw.flags,
                scope_guid: raw.scope_guid,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

fn parse_existing_hives<'a>(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
) -> Result<PkmVec<RegisteredHiveIdentity<'a>>, LinuxErrno> {
    let registration_hives = parse_registration_hives(hives, hive_count)?;
    let mut existing_hives =
        PkmVec::with_capacity(registration_hives.len()).map_err(|_| LinuxErrno::Enomem)?;

    for hive in registration_hives.as_slice() {
        let scope = source_registration_hive_scope(hive).map_err(|err| {
            source_registration_error_linux_errno(err).unwrap_or(LinuxErrno::Einval)
        })?;
        existing_hives
            .push(RegisteredHiveIdentity {
                name: hive.name,
                root_guid: hive.root_guid,
                scope,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(existing_hives)
}

fn source_slot_status_from_raw(status: u32) -> Result<SourceSlotStatus, LinuxErrno> {
    match status {
        PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE => Ok(SourceSlotStatus::Active),
        PKM_LCS_SOURCE_SLOT_STATUS_DOWN => Ok(SourceSlotStatus::Down),
        _ => Err(LinuxErrno::Einval),
    }
}

fn parse_scope_guids<'a>(
    scope_guids: *const [u8; 16],
    scope_count: usize,
) -> Result<&'a [[u8; 16]], LinuxErrno> {
    if scope_count == 0 {
        return Ok(&[]);
    }
    if scope_guids.is_null() {
        return Err(LinuxErrno::Einval);
    }
    Ok(unsafe { slice::from_raw_parts(scope_guids, scope_count) })
}

fn parse_current_user_rewrite<'a>(
    rewrite_current_user: bool,
    current_user_sid_component: *const u8,
    current_user_sid_component_len: u32,
) -> Result<CurrentUserRewrite<'a>, LinuxErrno> {
    if !rewrite_current_user {
        return Ok(CurrentUserRewrite::Literal);
    }
    if current_user_sid_component.is_null() || current_user_sid_component_len == 0 {
        return Err(LinuxErrno::Einval);
    }

    let sid_bytes = unsafe {
        slice::from_raw_parts(
            current_user_sid_component,
            current_user_sid_component_len as usize,
        )
    };
    let sid_component = str::from_utf8(sid_bytes).map_err(|_| LinuxErrno::Einval)?;
    Ok(CurrentUserRewrite::InitialCallerPath {
        user_sid_component: sid_component,
    })
}

fn parse_layer_views<'a>(
    layers: *const PkmLcsRsiLayerViewCopy,
    layer_count: usize,
) -> Result<PkmVec<LayerView<'a>>, LinuxErrno> {
    let mut parsed = PkmVec::with_capacity(layer_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..layer_count {
        let raw = unsafe { &*layers.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;
        let enabled = match raw.enabled {
            0 => false,
            1 => true,
            _ => return Err(LinuxErrno::Einval),
        };
        parsed
            .push(LayerView {
                name,
                precedence: raw.precedence,
                enabled,
            })
            .map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

fn parse_private_layer_views<'a>(
    private_layers: *const PkmLcsRsiPrivateLayerViewCopy,
    private_layer_count: usize,
) -> Result<PkmVec<&'a str>, LinuxErrno> {
    let mut parsed =
        PkmVec::with_capacity(private_layer_count).map_err(|_| LinuxErrno::Enomem)?;

    for index in 0..private_layer_count {
        let raw = unsafe { &*private_layers.add(index) };
        if raw.name.is_null() {
            return Err(LinuxErrno::Einval);
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = str::from_utf8(name_bytes).map_err(|_| LinuxErrno::Einval)?;
        parsed.push(name).map_err(|_| LinuxErrno::Enomem)?;
    }

    Ok(parsed)
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_source_registration_empty(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
    max_sequence: u64,
    caller_has_tcb: bool,
    plan_out: *mut PkmLcsSourceRegistrationPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if hive_count != 0 && hives.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let parsed = match parse_registration_hives(hives, hive_count) {
        Ok(parsed) => parsed,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let request = SourceRegistrationRequest {
        hives: parsed.as_slice(),
        max_sequence,
        caller_has_tcb,
    };
    let plan = match validate_source_registration(&LcsLimits::DEFAULT, &[], &request) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };

    unsafe {
        (*plan_out).hive_count = plan.hive_count as u32;
        (*plan_out).source_next_sequence = plan.source_next_sequence;
        (*plan_out).effective_next_sequence = plan.source_next_sequence;
        (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW;
        (*plan_out).source_id = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_validate_source_registration(
    hives: *const PkmLcsSourceRegistrationHiveCopy,
    hive_count: usize,
    max_sequence: u64,
    caller_has_tcb: bool,
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    current_next_sequence_valid: bool,
    current_next_sequence: u64,
    plan_out: *mut PkmLcsSourceRegistrationPlanCopy,
) -> c_int {
    if plan_out.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if hive_count != 0 && hives.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let parsed = match parse_registration_hives(hives, hive_count) {
        Ok(parsed) => parsed,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };

    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };

    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let request = SourceRegistrationRequest {
        hives: parsed.as_slice(),
        max_sequence,
        caller_has_tcb,
    };
    let plan = match validate_source_registration(
        &LcsLimits::DEFAULT,
        existing_slots.as_slice(),
        &request,
    ) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };
    let sequence_plan = match plan_source_registration_sequence_update(
        current_next_sequence_valid.then_some(current_next_sequence),
        max_sequence,
    ) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };

    unsafe {
        (*plan_out).hive_count = plan.hive_count as u32;
        (*plan_out).source_next_sequence = plan.source_next_sequence;
        (*plan_out).effective_next_sequence = sequence_plan.effective_next_sequence;
        match plan.decision {
            SourceRegistrationDecision::NewSlot => {
                (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW;
                (*plan_out).source_id = 0;
            }
            SourceRegistrationDecision::ResumeDownSlot(source_id) => {
                (*plan_out).decision = PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN;
                (*plan_out).source_id = source_id;
            }
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_hive_from_source_slots(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    hive_name: *const u8,
    hive_name_len: u32,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
) -> c_int {
    if result_out.is_null() || hive_name.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let name_bytes = unsafe { slice::from_raw_parts(hive_name, hive_name_len as usize) };
    let hive_name = match str::from_utf8(name_bytes) {
        Ok(name) => name,
        Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
    };
    let scope_guids = match parse_scope_guids(scope_guids, scope_count) {
        Ok(scopes) => scopes,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut total_hives = 0usize;
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        total_hives += parsed_hives.len();
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    if let Err(err) = validate_source_slots(&LcsLimits::DEFAULT, existing_slots.as_slice()) {
        return source_registration_error_return(err);
    }

    let mut hive_views = match PkmVec::with_capacity(total_hives) {
        Ok(hives) => hives,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for slot in existing_slots.as_slice() {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            if hive_views
                .push(HiveView {
                    name: hive.name,
                    root_guid: hive.root_guid,
                    source_id: slot.source_id,
                    status,
                    scope: hive.scope,
                })
                .is_err()
            {
                return LinuxErrno::Enomem.negated_return() as c_int;
            }
        }
    }

    let route = match route_hive(
        &LcsLimits::DEFAULT,
        hive_views.as_slice(),
        hive_name,
        scope_guids,
    ) {
        Ok(route) => route,
        Err(err) => return source_registration_error_return(err),
    };
    match classify_hive_route(route) {
        HiveRouteOutcome::Dispatch(hive) => unsafe {
            (*result_out).source_id = hive.source_id;
            (*result_out).root_guid = hive.root_guid;
            0
        },
        HiveRouteOutcome::Failure(errno) => LinuxErrno::from(errno).negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_absolute_path_from_source_slots(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    path: *const u8,
    path_len: u32,
    rewrite_current_user: bool,
    current_user_sid_component: *const u8,
    current_user_sid_component_len: u32,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
) -> c_int {
    if result_out.is_null() || path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if slot_count != 0 && slots.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }

    let path_bytes = unsafe { slice::from_raw_parts(path, path_len as usize) };
    let path =
        match validate_syscall_path_c_string(path_bytes, PathKind::Absolute, &LcsLimits::DEFAULT) {
            Ok(summary) => summary.raw,
            Err(err) => return absolute_route_error_return(err),
        };
    let rewrite = match parse_current_user_rewrite(
        rewrite_current_user,
        current_user_sid_component,
        current_user_sid_component_len,
    ) {
        Ok(rewrite) => rewrite,
        Err(errno) => return errno.negated_return() as c_int,
    };
    let scope_guids = match parse_scope_guids(scope_guids, scope_count) {
        Ok(scopes) => scopes,
        Err(errno) => return errno.negated_return() as c_int,
    };

    let mut slot_hive_storage =
        match PkmVec::<PkmVec<RegisteredHiveIdentity<'_>>>::with_capacity(slot_count) {
            Ok(storage) => storage,
            Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
        };
    let mut total_hives = 0usize;
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        if raw_slot.hive_count != 0 && raw_slot.hives.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let parsed_hives = match parse_existing_hives(raw_slot.hives, raw_slot.hive_count as usize)
        {
            Ok(hives) => hives,
            Err(errno) => return errno.negated_return() as c_int,
        };
        total_hives += parsed_hives.len();
        if slot_hive_storage.push(parsed_hives).is_err() {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    let mut existing_slots = match PkmVec::with_capacity(slot_count) {
        Ok(slots) => slots,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for index in 0..slot_count {
        let raw_slot = unsafe { &*slots.add(index) };
        let status = match source_slot_status_from_raw(raw_slot.status) {
            Ok(status) => status,
            Err(errno) => return errno.negated_return() as c_int,
        };
        if existing_slots
            .push(SourceSlotView {
                source_id: raw_slot.source_id,
                status,
                hives: slot_hive_storage[index].as_slice(),
            })
            .is_err()
        {
            return LinuxErrno::Enomem.negated_return() as c_int;
        }
    }

    if let Err(err) = validate_source_slots(&LcsLimits::DEFAULT, existing_slots.as_slice()) {
        return source_registration_error_return(err);
    }

    let mut hive_views = match PkmVec::with_capacity(total_hives) {
        Ok(hives) => hives,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };
    for slot in existing_slots.as_slice() {
        let status = source_slot_hive_status(slot.status);
        for hive in slot.hives {
            if hive_views
                .push(HiveView {
                    name: hive.name,
                    root_guid: hive.root_guid,
                    source_id: slot.source_id,
                    status,
                    scope: hive.scope,
                })
                .is_err()
            {
                return LinuxErrno::Enomem.negated_return() as c_int;
            }
        }
    }

    let route = match route_routable_path_hive(
        &LcsLimits::DEFAULT,
        hive_views.as_slice(),
        path,
        rewrite,
        scope_guids,
    ) {
        Ok(route) => route,
        Err(err) => return absolute_route_error_return(err),
    };
    match route {
        HiveRouteOutcome::Dispatch(hive) => unsafe {
            (*result_out).source_id = hive.source_id;
            (*result_out).root_guid = hive.root_guid;
            0
        },
        HiveRouteOutcome::Failure(errno) => LinuxErrno::from(errno).negated_return() as c_int,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lcs_rust_route_absolute_path_from_source_slots_with_token_sid(
    slots: *const PkmLcsSourceSlotViewCopy,
    slot_count: usize,
    path: *const u8,
    path_len: u32,
    rewrite_current_user: bool,
    current_user_sid: *const u8,
    current_user_sid_len: usize,
    scope_guids: *const [u8; 16],
    scope_count: usize,
    result_out: *mut PkmLcsHiveRouteResultCopy,
) -> c_int {
    if result_out.is_null() || path.is_null() {
        return LinuxErrno::Einval.negated_return() as c_int;
    }
    if !rewrite_current_user {
        return unsafe {
            lcs_rust_route_absolute_path_from_source_slots(
                slots,
                slot_count,
                path,
                path_len,
                false,
                core::ptr::null(),
                0,
                scope_guids,
                scope_count,
                result_out,
            )
        };
    }
    if current_user_sid.is_null() || current_user_sid_len == 0 {
        return LinuxErrno::Eacces.negated_return() as c_int;
    }

    let sid_bytes = unsafe { slice::from_raw_parts(current_user_sid, current_user_sid_len) };
    let sid_component =
        match current_user_sid_component_from_binary_sid(&LcsLimits::DEFAULT, sid_bytes) {
            Ok(component) => component,
            Err(err) => return absolute_route_error_return(err),
        };
    let sid_component = sid_component.as_str();
    unsafe {
        lcs_rust_route_absolute_path_from_source_slots(
            slots,
            slot_count,
            path,
            path_len,
            true,
            sid_component.as_ptr(),
            sid_component.len() as u32,
            scope_guids,
            scope_count,
            result_out,
        )
    }
}
