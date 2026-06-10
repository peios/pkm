// SPDX-License-Identifier: GPL-2.0-only

//! Narrow KMES payload builders for AccessCheck-generated KACS audit events.

use crate::access_check_abi::{AccessCheckAbiResolved, OwnedAuditEvent};
use crate::pip::PipContext;
use crate::pkm_alloc::Vec;
use crate::privilege::{
    SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
use crate::token::{AccessCheckToken, SidAndAttributes};
use crate::{CaapDiagnosticEvent, CaapDiagnosticKind, CaapSaclPhase, PrivilegeUseEvent};
use core::ffi::c_long;
use core::ptr::null_mut;
use core::str;

const EIO: c_long = -5;
const ENOMEM: c_long = -12;
const ERANGE: c_long = -34;

const KMES_ORIGIN_KACS: u8 = 2;
const ACCESS_AUDIT_TYPE: &[u8] = b"access-audit";
const CONTINUOUS_AUDIT_TYPE: &[u8] = b"continuous-audit";
const PRIVILEGE_USE_TYPE: &[u8] = b"privilege-use";
const CAAP_POLICY_DIAGNOSTIC_TYPE: &[u8] = b"caap-policy-diagnostic";
const LOGON_SESSION_DESTROYED_TYPE: &[u8] = b"logon-session-destroyed";

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

    // Process comm/exe-path are arbitrary byte strings, and TASK_COMM_LEN
    // truncation can split a multibyte sequence, so they are not guaranteed
    // UTF-8. Sanitize to valid UTF-8 (U+FFFD for invalid sequences) instead of
    // rejecting with EIO: an audited access decision is fail-closed, so a
    // non-UTF-8 name must never be allowed to deny the operation.
    let name = sanitize_utf8_lossy(name)?;
    let path = sanitize_utf8_lossy(path)?;

    Ok(ProcessInfo {
        pid,
        name,
        executable_path: path,
    })
}

/// Returns `bytes` unchanged when already valid UTF-8 (the common path, no
/// copy); otherwise returns a copy with each invalid byte sequence replaced by
/// U+FFFD, mirroring `String::from_utf8_lossy`.
fn sanitize_utf8_lossy(bytes: Vec<u8>) -> Result<Vec<u8>, c_long> {
    if str::from_utf8(bytes.as_slice()).is_ok() {
        return Ok(bytes);
    }

    const REPLACEMENT: &[u8] = &[0xEF, 0xBF, 0xBD];
    let mut out = Vec::with_capacity(bytes.len()).map_err(|_| ENOMEM)?;
    let mut input = bytes.as_slice();
    loop {
        match str::from_utf8(input) {
            Ok(valid) => {
                out.extend_from_slice(valid.as_bytes()).map_err(|_| ENOMEM)?;
                break;
            }
            Err(err) => {
                let valid_up_to = err.valid_up_to();
                out.extend_from_slice(&input[..valid_up_to])
                    .map_err(|_| ENOMEM)?;
                out.extend_from_slice(REPLACEMENT).map_err(|_| ENOMEM)?;
                match err.error_len() {
                    Some(len) => input = &input[valid_up_to + len..],
                    None => break,
                }
            }
        }
    }
    Ok(out)
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

fn caap_diagnostic_kind_name(kind: CaapDiagnosticKind) -> &'static [u8] {
    match kind {
        CaapDiagnosticKind::SaclError => b"sacl-error",
        CaapDiagnosticKind::StagingMismatch => b"staging-mismatch",
    }
}

fn caap_sacl_phase_name(phase: CaapSaclPhase) -> &'static [u8] {
    match phase {
        CaapSaclPhase::Effective => b"effective-sacl",
        CaapSaclPhase::Staged => b"staged-sacl",
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

fn encode_subject_token_map(
    token: &AccessCheckToken<'_>,
    effective_pip: PipContext,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(256)?;

    writer.write_map_len(5)?;
    writer.write_key(b"user_sid")?;
    writer.write_bin(token.subject.user.as_bytes())?;
    writer.write_key(b"group_sids")?;
    encode_sid_array(&mut writer, token.subject.groups)?;
    writer.write_key(b"integrity_level")?;
    writer.write_u64(token.integrity_level as u32 as u64)?;
    writer.write_key(b"pip_type")?;
    writer.write_u64(effective_pip.pip_type as u64)?;
    writer.write_key(b"pip_trust")?;
    writer.write_u64(effective_pip.pip_trust as u64)?;

    Ok(writer.into_vec())
}

fn encode_subject_map(
    resolved: AccessCheckAbiResolved<'_>,
    effective_pip: PipContext,
) -> Result<Vec<u8>, c_long> {
    encode_subject_token_map(resolved.token, effective_pip)
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

fn encode_caap_policy_diagnostic_payload(
    event: &CaapDiagnosticEvent,
    subject_map: &[u8],
    process_map: &[u8],
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(320)?;

    let _ = str::from_utf8(event.reason.as_bytes()).map_err(|_| EIO)?;

    writer.write_map_len(12)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"object_context")?;
    encode_object_context(&mut writer, event.object_audit_context.as_deref())?;
    writer.write_key(b"kind")?;
    writer.write_str(caap_diagnostic_kind_name(event.kind))?;
    writer.write_key(b"phase")?;
    match event.phase {
        Some(phase) => writer.write_str(caap_sacl_phase_name(phase))?,
        None => writer.write_nil()?,
    }
    writer.write_key(b"policy_sid")?;
    match event.policy_sid.as_ref() {
        Some(policy_sid) => writer.write_bin(policy_sid.as_slice())?,
        None => writer.write_nil()?,
    }
    writer.write_key(b"rule_index")?;
    match event.rule_index {
        Some(rule_index) => writer.write_u64(rule_index as u64)?,
        None => writer.write_nil()?,
    }
    writer.write_key(b"reason")?;
    writer.write_str(event.reason.as_bytes())?;
    writer.write_key(b"requested_access")?;
    writer.write_u64(event.requested as u64)?;
    writer.write_key(b"effective_granted_access")?;
    writer.write_u64(event.effective_granted as u64)?;
    writer.write_key(b"staged_granted_access")?;
    writer.write_u64(event.staged_granted as u64)?;
    writer.write_key(b"object_results_differ")?;
    writer.write_bool(event.object_results_differ)?;
    writer.write_key(b"process")?;
    writer.extend(process_map)?;

    Ok(writer.into_vec())
}

fn encode_continuous_audit_payload(
    subject_map: &[u8],
    process_map: &[u8],
    operation: &[u8],
    requested_access: u32,
    matched_access: u32,
    granted_access: u32,
    success: bool,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(256 + operation.len())?;

    let _ = str::from_utf8(operation).map_err(|_| EIO)?;
    if requested_access == 0 || matched_access == 0 {
        return Err(EIO);
    }

    writer.write_map_len(8)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"object_context")?;
    encode_object_context(&mut writer, None)?;
    writer.write_key(b"operation")?;
    writer.write_str(operation)?;
    writer.write_key(b"requested_access")?;
    writer.write_u64(requested_access as u64)?;
    writer.write_key(b"matched_access")?;
    writer.write_u64(matched_access as u64)?;
    writer.write_key(b"granted_access")?;
    writer.write_u64(granted_access as u64)?;
    writer.write_key(b"success")?;
    writer.write_bool(success)?;
    writer.write_key(b"process")?;
    writer.extend(process_map)?;

    Ok(writer.into_vec())
}

fn encode_logon_session_destroyed_payload(
    session_id: u64,
    user_sid: &[u8],
    logon_type: u32,
    auth_package: &[u8],
    created_at: u64,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(96 + user_sid.len() + auth_package.len())?;

    let _ = str::from_utf8(auth_package).map_err(|_| EIO)?;

    writer.write_map_len(5)?;
    writer.write_key(b"session_id")?;
    writer.write_u64(session_id)?;
    writer.write_key(b"user_sid")?;
    writer.write_bin(user_sid)?;
    writer.write_key(b"logon_type")?;
    writer.write_u64(logon_type as u64)?;
    writer.write_key(b"auth_package")?;
    writer.write_str(auth_package)?;
    writer.write_key(b"created_at")?;
    writer.write_u64(created_at)?;

    Ok(writer.into_vec())
}

pub(crate) fn emit_access_check_events_to_kmes(
    audit_events: &[OwnedAuditEvent],
    privilege_use_events: &[PrivilegeUseEvent],
    caap_diagnostic_events: &[CaapDiagnosticEvent],
    resolved: AccessCheckAbiResolved<'_>,
    effective_pip: PipContext,
) -> Result<(), c_long> {
    let process_info;
    let process_map;
    let subject_map;

    if audit_events.is_empty()
        && privilege_use_events.is_empty()
        && caap_diagnostic_events.is_empty()
    {
        return Ok(());
    }

    process_info = load_process_info()?;
    process_map = encode_process_map(&process_info)?;
    subject_map = encode_subject_map(resolved, effective_pip)?;

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

    for event in caap_diagnostic_events {
        let payload = encode_caap_policy_diagnostic_payload(
            event,
            subject_map.as_slice(),
            process_map.as_slice(),
        )?;

        unsafe {
            pkm_kmes_emit_kernel(
                KMES_ORIGIN_KACS,
                CAAP_POLICY_DIAGNOSTIC_TYPE.as_ptr().cast(),
                CAAP_POLICY_DIAGNOSTIC_TYPE.len(),
                payload.as_ptr().cast(),
                payload.len(),
            );
        }
    }

    Ok(())
}

pub(crate) fn emit_continuous_audit_to_kmes(
    token: &AccessCheckToken<'_>,
    effective_pip: PipContext,
    operation: &[u8],
    requested_access: u32,
    matched_access: u32,
    granted_access: u32,
    success: bool,
) -> Result<(), c_long> {
    let process_info = load_process_info()?;
    let process_map = encode_process_map(&process_info)?;
    let subject_map = encode_subject_token_map(token, effective_pip)?;
    let payload = encode_continuous_audit_payload(
        subject_map.as_slice(),
        process_map.as_slice(),
        operation,
        requested_access,
        matched_access,
        granted_access,
        success,
    )?;

    unsafe {
        pkm_kmes_emit_kernel(
            KMES_ORIGIN_KACS,
            CONTINUOUS_AUDIT_TYPE.as_ptr().cast(),
            CONTINUOUS_AUDIT_TYPE.len(),
            payload.as_ptr().cast(),
            payload.len(),
        );
    }

    Ok(())
}

pub(crate) fn emit_logon_session_destroyed_to_kmes(
    session_id: u64,
    user_sid: &[u8],
    logon_type: u32,
    auth_package: &[u8],
    created_at: u64,
) -> Result<(), c_long> {
    let payload = encode_logon_session_destroyed_payload(
        session_id,
        user_sid,
        logon_type,
        auth_package,
        created_at,
    )?;

    unsafe {
        pkm_kmes_emit_kernel(
            KMES_ORIGIN_KACS,
            LOGON_SESSION_DESTROYED_TYPE.as_ptr().cast(),
            LOGON_SESSION_DESTROYED_TYPE.len(),
            payload.as_ptr().cast(),
            payload.len(),
        );
    }

    Ok(())
}
