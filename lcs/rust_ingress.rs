// SPDX-License-Identifier: GPL-2.0-only

use core::ffi::c_int;
use core::{slice, str};

use crate::kacs_core::PkmVec;
use crate::lcs_core::{
    classify_hive_route, plan_source_registration_sequence_update, route_hive,
    source_registration_error_linux_errno, source_registration_hive_scope, source_slot_hive_status,
    validate_source_registration, validate_source_slots, HiveRouteOutcome, HiveView, LcsLimits,
    LinuxErrno, RegisteredHiveIdentity, SourceRegistrationDecision, SourceRegistrationHive,
    SourceRegistrationRequest, SourceSlotStatus, SourceSlotView,
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

fn source_registration_error_return(err: crate::lcs_core::LcsError) -> c_int {
    source_registration_error_linux_errno(err)
        .unwrap_or(LinuxErrno::Einval)
        .negated_return() as c_int
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
