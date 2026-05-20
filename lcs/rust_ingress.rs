// SPDX-License-Identifier: GPL-2.0-only

use core::ffi::c_int;
use core::{slice, str};

use crate::kacs_core::PkmVec;
use crate::lcs_core::{
    source_registration_error_linux_errno, validate_source_registration, LcsLimits, LinuxErrno,
    SourceRegistrationHive, SourceRegistrationRequest,
};

#[repr(C)]
pub struct PkmLcsSourceRegistrationHiveCopy {
    pub name: *const u8,
    pub name_len: u32,
    pub root_guid: [u8; 16],
    pub flags: u32,
    pub scope_guid: [u8; 16],
}

#[repr(C)]
pub struct PkmLcsSourceRegistrationPlanCopy {
    pub hive_count: u32,
    pub source_next_sequence: u64,
}

fn source_registration_error_return(err: crate::lcs_core::LcsError) -> c_int {
    source_registration_error_linux_errno(err)
        .unwrap_or(LinuxErrno::Einval)
        .negated_return() as c_int
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

    let mut parsed = match PkmVec::with_capacity(hive_count) {
        Ok(parsed) => parsed,
        Err(_) => return LinuxErrno::Enomem.negated_return() as c_int,
    };

    for index in 0..hive_count {
        let raw = unsafe { &*hives.add(index) };
        if raw.name.is_null() {
            return LinuxErrno::Einval.negated_return() as c_int;
        }
        let name_bytes = unsafe { slice::from_raw_parts(raw.name, raw.name_len as usize) };
        let name = match str::from_utf8(name_bytes) {
            Ok(name) => name,
            Err(_) => return LinuxErrno::Einval.negated_return() as c_int,
        };

        if parsed
            .push(SourceRegistrationHive {
                name,
                root_guid: raw.root_guid,
                flags: raw.flags,
                scope_guid: raw.scope_guid,
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
    let plan = match validate_source_registration(&LcsLimits::DEFAULT, &[], &request) {
        Ok(plan) => plan,
        Err(err) => return source_registration_error_return(err),
    };

    unsafe {
        (*plan_out).hive_count = plan.hive_count as u32;
        (*plan_out).source_next_sequence = plan.source_next_sequence;
    }
    0
}
