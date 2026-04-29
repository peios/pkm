// SPDX-License-Identifier: GPL-2.0-only

//! Narrow KMES payload builders for AccessCheck-generated KACS audit events.

use crate::access_check_abi::{AccessCheckAbiResolved, OwnedAuditEvent};
use crate::pip::PipContext;
use crate::pkm_alloc::Vec;
use crate::privilege::{
    SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
use crate::token::SidAndAttributes;
use crate::PrivilegeUseEvent;
use core::ffi::c_long;
use core::ptr::null_mut;
use core::str;

const EIO: c_long = -5;
const ENOMEM: c_long = -12;
const ERANGE: c_long = -34;

const KMES_ORIGIN_KACS: u8 = 2;
const ACCESS_AUDIT_TYPE: &[u8] = b"access-audit";
const PRIVILEGE_USE_TYPE: &[u8] = b"privilege-use";

extern "C" {
    fn pkm_kmes_emit_kernel(
        origin_class: u8,
        event_type: *const core::ffi::c_void,
        event_type_len: usize,
        payload: *const core::ffi::c_void,
        payload_len: usize,
    );
    fn pkm_kmes_current_process_info(
        pid_out: *mut u64,
        name_out: *mut u8,
        name_out_len: usize,
        name_len_out: *mut usize,
        path_out: *mut u8,
        path_out_len: usize,
        path_len_out: *mut usize,
    ) -> i32;
}

struct MsgpackWriter {
    bytes: Vec<u8>,
}

impl MsgpackWriter {
    fn with_capacity(capacity: usize) -> Result<Self, c_long> {
        Ok(Self {
            bytes: Vec::with_capacity(capacity).map_err(|_| ENOMEM)?,
        })
    }

    fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    fn push_byte(&mut self, value: u8) -> Result<(), c_long> {
        self.bytes.push(value).map_err(|_| ENOMEM)
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), c_long> {
        self.bytes.extend_from_slice(bytes).map_err(|_| ENOMEM)
    }

    fn write_map_len(&mut self, len: usize) -> Result<(), c_long> {
        if len <= 15 {
            self.push_byte(0x80 | (len as u8))
        } else if u16::try_from(len).is_ok() {
            self.push_byte(0xde)?;
            self.extend(&(len as u16).to_be_bytes())
        } else if u32::try_from(len).is_ok() {
            self.push_byte(0xdf)?;
            self.extend(&(len as u32).to_be_bytes())
        } else {
            Err(ERANGE)
        }
    }

    fn write_array_len(&mut self, len: usize) -> Result<(), c_long> {
        if len <= 15 {
            self.push_byte(0x90 | (len as u8))
        } else if u16::try_from(len).is_ok() {
            self.push_byte(0xdc)?;
            self.extend(&(len as u16).to_be_bytes())
        } else if u32::try_from(len).is_ok() {
            self.push_byte(0xdd)?;
            self.extend(&(len as u32).to_be_bytes())
        } else {
            Err(ERANGE)
        }
    }

    fn write_str(&mut self, value: &[u8]) -> Result<(), c_long> {
        let len = value.len();

        if len <= 31 {
            self.push_byte(0xa0 | (len as u8))?;
        } else if u8::try_from(len).is_ok() {
            self.push_byte(0xd9)?;
            self.push_byte(len as u8)?;
        } else if u16::try_from(len).is_ok() {
            self.push_byte(0xda)?;
            self.extend(&(len as u16).to_be_bytes())?;
        } else if u32::try_from(len).is_ok() {
            self.push_byte(0xdb)?;
            self.extend(&(len as u32).to_be_bytes())?;
        } else {
            return Err(ERANGE);
        }

        self.extend(value)
    }

    fn write_bin(&mut self, value: &[u8]) -> Result<(), c_long> {
        let len = value.len();

        if u8::try_from(len).is_ok() {
            self.push_byte(0xc4)?;
            self.push_byte(len as u8)?;
        } else if u16::try_from(len).is_ok() {
            self.push_byte(0xc5)?;
            self.extend(&(len as u16).to_be_bytes())?;
        } else if u32::try_from(len).is_ok() {
            self.push_byte(0xc6)?;
            self.extend(&(len as u32).to_be_bytes())?;
        } else {
            return Err(ERANGE);
        }

        self.extend(value)
    }

    fn write_u64(&mut self, value: u64) -> Result<(), c_long> {
        if value <= 0x7f {
            self.push_byte(value as u8)
        } else if u8::try_from(value).is_ok() {
            self.push_byte(0xcc)?;
            self.push_byte(value as u8)
        } else if u16::try_from(value).is_ok() {
            self.push_byte(0xcd)?;
            self.extend(&(value as u16).to_be_bytes())
        } else if u32::try_from(value).is_ok() {
            self.push_byte(0xce)?;
            self.extend(&(value as u32).to_be_bytes())
        } else {
            self.push_byte(0xcf)?;
            self.extend(&value.to_be_bytes())
        }
    }

    fn write_bool(&mut self, value: bool) -> Result<(), c_long> {
        self.push_byte(if value { 0xc3 } else { 0xc2 })
    }

    fn write_nil(&mut self) -> Result<(), c_long> {
        self.push_byte(0xc0)
    }

    fn write_key(&mut self, key: &[u8]) -> Result<(), c_long> {
        self.write_str(key)
    }
}

struct ProcessInfo {
    pid: u64,
    name: Vec<u8>,
    executable_path: Vec<u8>,
}

fn allocate_zeroed(len: usize) -> Result<Vec<u8>, c_long> {
    let mut bytes = Vec::with_capacity(len).map_err(|_| ENOMEM)?;

    for _ in 0..len {
        bytes.push(0).map_err(|_| ENOMEM)?;
    }

    Ok(bytes)
}

fn load_process_info() -> Result<ProcessInfo, c_long> {
    let mut pid = 0u64;
    let mut name_len = 0usize;
    let mut path_len = 0usize;
    let mut name;
    let mut path;
    let ret;

    let query_ret = unsafe {
        pkm_kmes_current_process_info(
            &mut pid,
            null_mut(),
            0,
            &mut name_len,
            null_mut(),
            0,
            &mut path_len,
        )
    };
    if query_ret != 0 {
        return Err(query_ret as c_long);
    }

    name = allocate_zeroed(name_len)?;
    path = allocate_zeroed(path_len)?;
    ret = unsafe {
        pkm_kmes_current_process_info(
            &mut pid,
            name.as_mut_ptr(),
            name.len(),
            &mut name_len,
            path.as_mut_ptr(),
            path.len(),
            &mut path_len,
        )
    };
    if ret != 0 {
        return Err(ret as c_long);
    }

    let _ = str::from_utf8(name.as_slice()).map_err(|_| EIO)?;
    let _ = str::from_utf8(path.as_slice()).map_err(|_| EIO)?;

    Ok(ProcessInfo {
        pid,
        name,
        executable_path: path,
    })
}

fn privilege_name(privilege: u64) -> Result<&'static [u8], c_long> {
    match privilege {
        SE_SECURITY_PRIVILEGE => Ok(b"SeSecurityPrivilege"),
        SE_TAKE_OWNERSHIP_PRIVILEGE => Ok(b"SeTakeOwnershipPrivilege"),
        SE_BACKUP_PRIVILEGE => Ok(b"SeBackupPrivilege"),
        SE_RESTORE_PRIVILEGE => Ok(b"SeRestorePrivilege"),
        SE_RELABEL_PRIVILEGE => Ok(b"SeRelabelPrivilege"),
        _ => Err(EIO),
    }
}

fn encode_sid_array(
    writer: &mut MsgpackWriter,
    groups: &[SidAndAttributes<'_>],
) -> Result<(), c_long> {
    writer.write_array_len(groups.len())?;
    for group in groups {
        writer.write_bin(group.sid.as_bytes())?;
    }
    Ok(())
}

fn encode_subject_map(
    resolved: AccessCheckAbiResolved<'_>,
    effective_pip: PipContext,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(256)?;

    writer.write_map_len(5)?;
    writer.write_key(b"user_sid")?;
    writer.write_bin(resolved.token.subject.user.as_bytes())?;
    writer.write_key(b"group_sids")?;
    encode_sid_array(&mut writer, resolved.token.subject.groups)?;
    writer.write_key(b"integrity_level")?;
    writer.write_u64(resolved.token.integrity_level as u32 as u64)?;
    writer.write_key(b"pip_type")?;
    writer.write_u64(effective_pip.pip_type as u64)?;
    writer.write_key(b"pip_trust")?;
    writer.write_u64(effective_pip.pip_trust as u64)?;

    Ok(writer.into_vec())
}

fn encode_process_map(process: &ProcessInfo) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(96 + process.executable_path.len())?;

    writer.write_map_len(3)?;
    writer.write_key(b"pid")?;
    writer.write_u64(process.pid)?;
    writer.write_key(b"name")?;
    writer.write_str(process.name.as_slice())?;
    writer.write_key(b"executable_path")?;
    writer.write_str(process.executable_path.as_slice())?;

    Ok(writer.into_vec())
}

fn encode_object_context(
    writer: &mut MsgpackWriter,
    object_context: Option<&[u8]>,
) -> Result<(), c_long> {
    match object_context {
        Some(bytes) => writer.write_bin(bytes),
        None => writer.write_nil(),
    }
}

fn encode_access_trigger(event: &OwnedAuditEvent) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(48)?;

    writer.write_map_len(2)?;
    writer.write_key(b"kind")?;
    if event.policy_forced {
        writer.write_str(b"policy")?;
    } else {
        writer.write_str(b"sacl")?;
    }
    writer.write_key(b"ace")?;
    if event.policy_forced {
        writer.write_nil()?;
    } else if let Some(bytes) = event.ace_bytes.as_ref() {
        writer.write_bin(bytes.as_slice())?;
    } else {
        return Err(EIO);
    }

    Ok(writer.into_vec())
}

fn encode_access_audit_payload(
    event: &OwnedAuditEvent,
    subject_map: &[u8],
    process_map: &[u8],
) -> Result<Vec<u8>, c_long> {
    let trigger = encode_access_trigger(event)?;
    let mut writer = MsgpackWriter::with_capacity(256)?;

    writer.write_map_len(7)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"object_context")?;
    encode_object_context(&mut writer, event.object_audit_context.as_deref())?;
    writer.write_key(b"requested_access")?;
    writer.write_u64(event.requested as u64)?;
    writer.write_key(b"granted_access")?;
    writer.write_u64(event.granted as u64)?;
    writer.write_key(b"success")?;
    writer.write_bool(event.success)?;
    writer.write_key(b"trigger")?;
    writer.extend(trigger.as_slice())?;
    writer.write_key(b"process")?;
    writer.extend(process_map)?;

    Ok(writer.into_vec())
}

fn encode_privilege_use_payload(
    event: &PrivilegeUseEvent,
    subject_map: &[u8],
    process_map: &[u8],
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(256)?;

    writer.write_map_len(8)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"object_context")?;
    encode_object_context(&mut writer, event.object_audit_context.as_deref())?;
    writer.write_key(b"privilege")?;
    writer.write_str(privilege_name(event.privilege)?)?;
    writer.write_key(b"requested_access")?;
    writer.write_u64(event.requested as u64)?;
    writer.write_key(b"granted_access")?;
    writer.write_u64(event.granted as u64)?;
    writer.write_key(b"surviving_access")?;
    writer.write_u64(event.surviving_bits as u64)?;
    writer.write_key(b"success")?;
    writer.write_bool(event.success)?;
    writer.write_key(b"process")?;
    writer.extend(process_map)?;

    Ok(writer.into_vec())
}

pub(crate) fn emit_access_check_events_to_kmes(
    audit_events: &[OwnedAuditEvent],
    privilege_use_events: &[PrivilegeUseEvent],
    resolved: AccessCheckAbiResolved<'_>,
    effective_pip: PipContext,
) -> Result<(), c_long> {
    let process_info;
    let process_map;
    let subject_map;

    if audit_events.is_empty() && privilege_use_events.is_empty() {
        return Ok(());
    }

    process_info = load_process_info()?;
    process_map = encode_process_map(&process_info)?;
    subject_map = encode_subject_map(resolved, effective_pip)?;

    for event in audit_events {
        let payload =
            encode_access_audit_payload(event, subject_map.as_slice(), process_map.as_slice())?;

        unsafe {
            pkm_kmes_emit_kernel(
                KMES_ORIGIN_KACS,
                ACCESS_AUDIT_TYPE.as_ptr().cast(),
                ACCESS_AUDIT_TYPE.len(),
                payload.as_ptr().cast(),
                payload.len(),
            );
        }
    }

    for event in privilege_use_events {
        let payload =
            encode_privilege_use_payload(event, subject_map.as_slice(), process_map.as_slice())?;

        unsafe {
            pkm_kmes_emit_kernel(
                KMES_ORIGIN_KACS,
                PRIVILEGE_USE_TYPE.as_ptr().cast(),
                PRIVILEGE_USE_TYPE.len(),
                payload.as_ptr().cast(),
                payload.len(),
            );
        }
    }

    Ok(())
}
