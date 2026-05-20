// SPDX-License-Identifier: GPL-2.0-only

use core::ffi::c_int;
use core::{slice, str};

use crate::kacs_core::PkmVec;
use crate::lcs_core::{
    classify_hive_route, current_user_sid_component_from_binary_sid,
    plan_registry_ioctl_fixed_fd_access_gate, plan_registry_open_pre_resolution_access,
    plan_registry_security_info_fd_access_gate, plan_source_registration_sequence_update,
    registry_ioctl_access_requirement, registry_ioctl_fd_access_gate_errno,
    registry_open_pre_resolution_linux_errno, route_hive, route_routable_path_hive,
    source_registration_error_linux_errno, source_registration_hive_scope,
    source_slot_hive_status, validate_key_fd_open_view, validate_registry_open_flags,
    validate_resolved_relative_path_depth, validate_source_registration, validate_source_slots,
    validate_syscall_path_c_string, CurrentUserRewrite, HiveRouteOutcome, HiveView,
    KeyFdOpenView, KeyWatchState, LcsError, LcsLimits, LinuxErrno, PathKind,
    RegisteredHiveIdentity, RegistryIoctlAccessRequirement, RegistryOpenPreResolutionAccessPlan,
    SourceRegistrationDecision, SourceRegistrationHive, SourceRegistrationRequest,
    SourceSlotStatus, SourceSlotView,
};

const PKM_LCS_SOURCE_SLOT_STATUS_ACTIVE: u32 = 0;
const PKM_LCS_SOURCE_SLOT_STATUS_DOWN: u32 = 1;

const PKM_LCS_SOURCE_REGISTRATION_DECISION_NEW: u32 = 0;
const PKM_LCS_SOURCE_REGISTRATION_DECISION_RESUME_DOWN: u32 = 1;

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
