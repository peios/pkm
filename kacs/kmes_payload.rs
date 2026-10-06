// SPDX-License-Identifier: GPL-2.0-only

//! Narrow KMES payload builders for the KACS audit events.
//!
//! Each payload is the shape its event's record in `pkm/evman/kacs.evman`
//! describes (PGSS §6.4–§6.6): one nested map per field-path segment, a value
//! the emitter does not have left out rather than written as nil, and map
//! lengths counting only the keys written.

use crate::access_check_abi::{
    parse_audit_context_map, AccessCheckAbiResolved, AuditContextView, OwnedAuditEvent,
};
use crate::pip::PipContext;
use crate::pkm_alloc::Vec;
use crate::privilege::{
    SE_BACKUP_PRIVILEGE, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
    SE_TAKE_OWNERSHIP_PRIVILEGE,
};
use crate::token::{AccessCheckToken, ImpersonationLevel, SidAndAttributes, TokenType};
use crate::{CaapDiagnosticEvent, CaapDiagnosticKind, CaapSaclPhase, PrivilegeUseEvent};
use core::ffi::c_long;
use core::ptr::null_mut;
use core::str;

const EIO: c_long = -5;
const ENOMEM: c_long = -12;
const ERANGE: c_long = -34;

const KMES_ORIGIN_KACS: u8 = 2;
const ACCESS_CHECKED_TYPE: &[u8] = b"kacs.audit.access.checked";
const HANDLE_USED_TYPE: &[u8] = b"kacs.audit.handle.used";
const PRIVILEGE_USED_TYPE: &[u8] = b"kacs.audit.privilege.used";
const CAAP_SACL_SKIPPED_TYPE: &[u8] = b"kacs.caap.sacl.skipped";
const CAAP_STAGING_DIVERGED_TYPE: &[u8] = b"kacs.caap.staging.diverged";
const SESSION_DESTROYED_TYPE: &[u8] = b"kacs.session.destroyed";
const IMPERSONATION_STARTED_TYPE: &[u8] = b"kacs.impersonation.started";
const IMPERSONATION_REVERTED_TYPE: &[u8] = b"kacs.impersonation.reverted";
const DESCRIPTOR_CHANGED_TYPE: &[u8] = b"kacs.audit.descriptor.changed";

const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

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

    fn write_key(&mut self, key: &[u8]) -> Result<(), c_long> {
        self.write_str(key)
    }
}

struct ProcessInfo {
    pid: u64,
    name: Vec<u8>,
    executable_path: Vec<u8>,
}

/// The parts of the subject token's identity that live on the kernel token
/// object rather than on the `AccessCheckToken` view the core decides with.
#[derive(Clone, Copy)]
pub(crate) struct AuditSubjectIds {
    /// The token's own LUID (`subject.token.id`).
    pub(crate) token_id: u64,
    /// The token's logon-session LUID (`subject.token.auth-id`), when the
    /// token still has a session.
    pub(crate) auth_id: Option<u64>,
    /// The Linux UID the token projects onto (`subject.token.uid`).
    pub(crate) uid: u32,
}

/// What an access check was about, as the record's `object.*` describes it.
pub(crate) enum AuditObject<'a> {
    /// The kind is unknown, so `object` is left out: an access-check ioctl
    /// whose caller supplied no audit context, or an object kind the
    /// catalogue has no `object.kind` value for.
    Unknown,
    /// The kind alone. Its identity fields are not reachable where the check
    /// runs, so `object.<kind>` is left out.
    Kind(&'static [u8]),
    /// A token, identified by LUID and durable GUID.
    Token { id: u64, guid: [u8; 16] },
    /// The audit context an access-check ioctl caller supplied, already
    /// validated as a PGSS §6.7 map. Copied as the caller's claim.
    Asserted(AuditContextView<'a>),
}

impl<'a> AuditObject<'a> {
    /// The object an access-check ioctl names in its audit context, if any.
    pub(crate) fn from_audit_context(context: Option<&'a [u8]>) -> Result<Self, c_long> {
        match context {
            None => Ok(Self::Unknown),
            Some(bytes) => parse_audit_context_map(bytes)
                .map(Self::Asserted)
                .map_err(|_| EIO),
        }
    }
}

/// Per-check inputs to the access-check records beyond the core's own
/// output: who the subject token is and what the check was about.
pub(crate) struct AuditTarget<'a> {
    pub(crate) subject_ids: Option<AuditSubjectIds>,
    pub(crate) object: AuditObject<'a>,
    /// Whether the record carries values userspace supplied — every record
    /// of the AccessCheck syscall, whose descriptor is the caller's — and so
    /// must say `fields.attestation.userspace` (PGSS §6.7).
    pub(crate) asserted: bool,
    /// Whether the records a SACL generated are withheld because the
    /// AccessCheck syscall's caller lacks SeAuditPrivilege. Records the
    /// checked token's audit policy forces are written regardless.
    pub(crate) sacl_audit_suppressed: bool,
    /// What the mandatory checks withheld, for `kacs.audit.access.checked`.
    pub(crate) denials: AccessDenials,
}

/// The requested bits the mandatory checks denied in one access check:
/// `access.denied-integrity` and `access.denied-trust`, each written only
/// when non-zero.
#[derive(Clone, Copy, Default)]
pub(crate) struct AccessDenials {
    pub(crate) integrity: u32,
    pub(crate) trust: u32,
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

/// `privilege.name` for one privilege bit. A bit with no name is an
/// internal fault, and the record is refused rather than written unnamed.
fn privilege_name(privilege: u64) -> Result<&'static [u8], c_long> {
    use crate::peios_uapi as uapi;

    match privilege {
        SE_SECURITY_PRIVILEGE => Ok(b"SeSecurityPrivilege"),
        SE_TAKE_OWNERSHIP_PRIVILEGE => Ok(b"SeTakeOwnershipPrivilege"),
        SE_BACKUP_PRIVILEGE => Ok(b"SeBackupPrivilege"),
        SE_RESTORE_PRIVILEGE => Ok(b"SeRestorePrivilege"),
        SE_RELABEL_PRIVILEGE => Ok(b"SeRelabelPrivilege"),
        uapi::KACS_SE_CREATE_TOKEN_PRIVILEGE => Ok(b"SeCreateTokenPrivilege"),
        uapi::KACS_SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE => Ok(b"SeAssignPrimaryTokenPrivilege"),
        uapi::KACS_SE_LOCK_MEMORY_PRIVILEGE => Ok(b"SeLockMemoryPrivilege"),
        uapi::KACS_SE_INCREASE_QUOTA_PRIVILEGE => Ok(b"SeIncreaseQuotaPrivilege"),
        uapi::KACS_SE_TCB_PRIVILEGE => Ok(b"SeTcbPrivilege"),
        uapi::KACS_SE_LOAD_DRIVER_PRIVILEGE => Ok(b"SeLoadDriverPrivilege"),
        uapi::KACS_SE_SYSTEM_PROFILE_PRIVILEGE => Ok(b"SeSystemProfilePrivilege"),
        uapi::KACS_SE_SYSTEMTIME_PRIVILEGE => Ok(b"SeSystemtimePrivilege"),
        uapi::KACS_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE => Ok(b"SeProfileSingleProcessPrivilege"),
        uapi::KACS_SE_INCREASE_BASE_PRIORITY_PRIVILEGE => Ok(b"SeIncreaseBasePriorityPrivilege"),
        uapi::KACS_SE_SHUTDOWN_PRIVILEGE => Ok(b"SeShutdownPrivilege"),
        uapi::KACS_SE_DEBUG_PRIVILEGE => Ok(b"SeDebugPrivilege"),
        uapi::KACS_SE_AUDIT_PRIVILEGE => Ok(b"SeAuditPrivilege"),
        uapi::KACS_SE_CHANGE_NOTIFY_PRIVILEGE => Ok(b"SeChangeNotifyPrivilege"),
        uapi::KACS_SE_REMOTE_SHUTDOWN_PRIVILEGE => Ok(b"SeRemoteShutdownPrivilege"),
        uapi::KACS_SE_MANAGE_VOLUME_PRIVILEGE => Ok(b"SeManageVolumePrivilege"),
        uapi::KACS_SE_IMPERSONATE_PRIVILEGE => Ok(b"SeImpersonatePrivilege"),
        uapi::KACS_SE_CREATE_SYMBOLIC_LINK_PRIVILEGE => Ok(b"SeCreateSymbolicLinkPrivilege"),
        _ => Err(EIO),
    }
}

/// `linux.cap`: the `CAP_*` name without its prefix, in kebab case.
fn linux_cap_name(cap: u32) -> Option<&'static [u8]> {
    const NAMES: [&[u8]; 41] = [
        b"chown",
        b"dac-override",
        b"dac-read-search",
        b"fowner",
        b"fsetid",
        b"kill",
        b"setgid",
        b"setuid",
        b"setpcap",
        b"linux-immutable",
        b"net-bind-service",
        b"net-broadcast",
        b"net-admin",
        b"net-raw",
        b"ipc-lock",
        b"ipc-owner",
        b"sys-module",
        b"sys-rawio",
        b"sys-chroot",
        b"sys-ptrace",
        b"sys-pacct",
        b"sys-admin",
        b"sys-boot",
        b"sys-nice",
        b"sys-resource",
        b"sys-time",
        b"sys-tty-config",
        b"mknod",
        b"lease",
        b"audit-write",
        b"audit-control",
        b"setfcap",
        b"mac-override",
        b"mac-admin",
        b"syslog",
        b"wake-alarm",
        b"block-suspend",
        b"audit-read",
        b"perfmon",
        b"bpf",
        b"checkpoint-restore",
    ];
    NAMES.get(usize::try_from(cap).ok()?).copied()
}

/// Where a privilege was spent outside an access check.
#[derive(Clone, Copy)]
pub(crate) enum PrivilegeGate {
    /// A Linux capability check KACS answered with a privilege.
    LinuxCap(u32),
    /// The volume-management gate the mount paths ask instead of
    /// `CAP_SYS_ADMIN`.
    VolumeMount,
}

/// `kacs.audit.privilege.used` for a privilege spent at a gate rather than
/// in an access check: `operation.name` `linux-cap` or `volume-mount`.
pub(crate) fn emit_gate_privilege_use_to_kmes(
    token: &AccessCheckToken<'_>,
    subject_ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
    gate: PrivilegeGate,
    privilege: u64,
) -> Result<(), c_long> {
    let name = privilege_name(privilege)?;
    let (operation, cap): (&[u8], Option<&[u8]>) = match gate {
        PrivilegeGate::LinuxCap(cap) => (b"linux-cap", Some(linux_cap_name(cap).ok_or(EIO)?)),
        PrivilegeGate::VolumeMount => (b"volume-mount", None),
    };
    let process_info = load_process_info()?;
    let emitter_map = encode_emitter_map(&process_info)?;
    let subject_map = encode_subject_map(token, subject_ids, effective_pip)?;
    let mut writer =
        MsgpackWriter::with_capacity(160 + subject_map.len() + emitter_map.len())?;

    writer.write_map_len(5 + usize::from(cap.is_some()))?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map.as_slice())?;
    writer.write_key(b"emitter")?;
    writer.extend(emitter_map.as_slice())?;
    writer.write_key(b"operation")?;
    writer.write_map_len(1)?;
    writer.write_key(b"name")?;
    writer.write_str(operation)?;
    writer.write_key(b"privilege")?;
    writer.write_map_len(1)?;
    writer.write_key(b"name")?;
    writer.write_str(name)?;
    if let Some(cap) = cap {
        writer.write_key(b"linux")?;
        writer.write_map_len(1)?;
        writer.write_key(b"cap")?;
        writer.write_str(cap)?;
    }
    writer.write_key(b"outcome")?;
    writer.write_map_len(1)?;
    writer.write_key(b"success")?;
    writer.write_bool(true)?;

    emit(PRIVILEGE_USED_TYPE, writer.into_vec().as_slice());
    Ok(())
}

fn caap_sacl_phase_name(phase: CaapSaclPhase) -> &'static [u8] {
    match phase {
        CaapSaclPhase::Effective => b"effective-sacl",
        CaapSaclPhase::Staged => b"staged-sacl",
    }
}

/// `object.session.logon-type`, named for its `KACS_LOGON_TYPE_*` value. The
/// kernel refuses to create a session of any other type, so an unknown one
/// is an internal fault and the record is skipped rather than mislabelled.
fn logon_type_name(logon_type: u32) -> Result<&'static [u8], c_long> {
    match logon_type {
        2 => Ok(b"interactive"),
        3 => Ok(b"network"),
        4 => Ok(b"batch"),
        5 => Ok(b"service"),
        8 => Ok(b"network-cleartext"),
        9 => Ok(b"new-credentials"),
        10 => Ok(b"remote-interactive"),
        _ => Err(EIO),
    }
}

/// `outcome.reason` on a failed `kacs.audit.handle.used`, from the
/// `KACS_FSR_*` code with its prefix stripped and case folded. `DECISION`
/// names the ordinary path rather than a reason, and `AUDIT_EMIT_FAIL` is the
/// failure of this record's own emission, so neither is a value.
fn handle_failure_reason(reason: u8) -> Option<&'static [u8]> {
    match reason {
        1 => Some(b"signed-exec"),
        2 => Some(b"grant-deny"),
        3 => Some(b"append-deny"),
        4 => Some(b"unmanaged-sysfs"),
        _ => None,
    }
}

fn impersonation_level_value(level: ImpersonationLevel) -> u64 {
    match level {
        ImpersonationLevel::Anonymous => 0,
        ImpersonationLevel::Identification => 1,
        ImpersonationLevel::Impersonation => 2,
        ImpersonationLevel::Delegation => 3,
    }
}

fn write_group_arrays(
    writer: &mut MsgpackWriter,
    groups: &[SidAndAttributes<'_>],
) -> Result<(), c_long> {
    writer.write_key(b"groups")?;
    writer.write_array_len(groups.len())?;
    for group in groups {
        writer.write_bin(group.sid.as_bytes())?;
    }
    // Parallel to `groups`: the attributes the check itself read, so a
    // consumer can tell an enabled group from a deny-only one.
    writer.write_key(b"group-attributes")?;
    writer.write_array_len(groups.len())?;
    for group in groups {
        writer.write_u64(u64::from(group.attributes))?;
    }
    Ok(())
}

/// The `subject` map: `subject.token.*` and `subject.pip.*`.
fn encode_subject_map(
    token: &AccessCheckToken<'_>,
    ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(256 + token.subject.groups.len() * 32)?;
    let id_fields = match ids {
        Some(ids) => 2 + usize::from(ids.auth_id.is_some()),
        None => 0,
    };

    writer.write_map_len(2)?;
    writer.write_key(b"token")?;
    writer.write_map_len(6 + id_fields)?;
    writer.write_key(b"sid")?;
    writer.write_bin(token.subject.user.as_bytes())?;
    write_group_arrays(&mut writer, token.subject.groups)?;
    writer.write_key(b"integrity")?;
    writer.write_u64(u64::from(token.integrity_level.0))?;
    if let Some(ids) = ids {
        writer.write_key(b"id")?;
        writer.write_u64(ids.token_id)?;
        if let Some(auth_id) = ids.auth_id {
            writer.write_key(b"auth-id")?;
            writer.write_u64(auth_id)?;
        }
    }
    writer.write_key(b"type")?;
    // A primary token reports impersonation level 0, as Anonymous does;
    // `type` is what tells the two apart.
    let impersonation = match token.token_type {
        TokenType::Primary => {
            writer.write_str(b"primary")?;
            0
        }
        TokenType::Impersonation => {
            writer.write_str(b"impersonation")?;
            impersonation_level_value(token.impersonation_level)
        }
    };
    writer.write_key(b"impersonation")?;
    writer.write_u64(impersonation)?;
    if let Some(ids) = ids {
        writer.write_key(b"uid")?;
        writer.write_u64(u64::from(ids.uid))?;
    }
    writer.write_key(b"pip")?;
    writer.write_map_len(2)?;
    writer.write_key(b"type")?;
    writer.write_u64(u64::from(effective_pip.pip_type))?;
    writer.write_key(b"trust")?;
    writer.write_u64(u64::from(effective_pip.pip_trust))?;

    Ok(writer.into_vec())
}

/// The `emitter` map: `emitter.process.*`. A kernel access check runs in
/// the caller's own context, so the process that acted wrote the record.
fn encode_emitter_map(process: &ProcessInfo) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(96 + process.executable_path.len())?;

    writer.write_map_len(1)?;
    writer.write_key(b"process")?;
    writer.write_map_len(3)?;
    writer.write_key(b"pid")?;
    writer.write_u64(process.pid)?;
    writer.write_key(b"name")?;
    writer.write_str(process.name.as_slice())?;
    writer.write_key(b"executable")?;
    writer.write_str(process.executable_path.as_slice())?;

    Ok(writer.into_vec())
}

/// The `object` map, or `None` when the kind is unknown and the whole map
/// is left out.
fn encode_object_map(object: &AuditObject<'_>) -> Result<Option<Vec<u8>>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(64)?;

    match object {
        AuditObject::Unknown => return Ok(None),
        AuditObject::Kind(kind) => {
            writer.write_map_len(1)?;
            writer.write_key(b"kind")?;
            writer.write_str(kind)?;
        }
        AuditObject::Token { id, guid } => {
            writer.write_map_len(2)?;
            writer.write_key(b"kind")?;
            writer.write_str(b"token")?;
            writer.write_key(b"token")?;
            writer.write_map_len(2)?;
            writer.write_key(b"id")?;
            writer.write_u64(*id)?;
            writer.write_key(b"guid")?;
            writer.write_bin(guid)?;
        }
        AuditObject::Asserted(context) => {
            writer.write_map_len(1 + usize::from(context.body.is_some()))?;
            writer.write_key(b"kind")?;
            writer.write_str(context.kind)?;
            if let Some(body) = context.body {
                // The body is the caller's map verbatim, so its fields land
                // as `object.<kind>.*` and nowhere else.
                writer.write_key(context.kind)?;
                writer.extend(body)?;
            }
        }
    }

    Ok(Some(writer.into_vec()))
}

/// The maps every access-check record shares, built once per check.
struct CheckMaps {
    subject: Vec<u8>,
    emitter: Vec<u8>,
    object: Option<Vec<u8>>,
    asserted: bool,
    denials: AccessDenials,
}

impl CheckMaps {
    /// Root keys common to every access-check record beyond its own.
    fn common_len(&self) -> usize {
        2 + usize::from(self.object.is_some()) + usize::from(self.asserted)
    }

    fn write_head(&self, writer: &mut MsgpackWriter) -> Result<(), c_long> {
        writer.write_key(b"subject")?;
        writer.extend(self.subject.as_slice())?;
        writer.write_key(b"emitter")?;
        writer.extend(self.emitter.as_slice())?;
        if let Some(object) = self.object.as_ref() {
            writer.write_key(b"object")?;
            writer.extend(object.as_slice())?;
        }
        Ok(())
    }

    fn write_tail(&self, writer: &mut MsgpackWriter) -> Result<(), c_long> {
        if self.asserted {
            writer.write_key(b"fields")?;
            writer.write_map_len(1)?;
            writer.write_key(b"attestation")?;
            writer.write_map_len(1)?;
            writer.write_key(b"userspace")?;
            writer.write_bool(true)?;
        }
        Ok(())
    }
}

fn encode_access_checked_payload(
    event: &OwnedAuditEvent,
    maps: &CheckMaps,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(512)?;

    if !event.policy_forced && event.ace_bytes.is_none() {
        return Err(EIO);
    }

    writer.write_map_len(maps.common_len() + 3)?;
    maps.write_head(&mut writer)?;
    writer.write_key(b"access")?;
    writer.write_map_len(
        2 + usize::from(maps.denials.integrity != 0) + usize::from(maps.denials.trust != 0),
    )?;
    writer.write_key(b"requested")?;
    writer.write_u64(u64::from(event.requested))?;
    writer.write_key(b"granted")?;
    writer.write_u64(u64::from(event.granted))?;
    if maps.denials.integrity != 0 {
        writer.write_key(b"denied-integrity")?;
        writer.write_u64(u64::from(maps.denials.integrity))?;
    }
    if maps.denials.trust != 0 {
        writer.write_key(b"denied-trust")?;
        writer.write_u64(u64::from(maps.denials.trust))?;
    }
    writer.write_key(b"outcome")?;
    writer.write_map_len(1)?;
    writer.write_key(b"success")?;
    writer.write_bool(event.success)?;
    writer.write_key(b"trigger")?;
    match event.ace_bytes.as_ref() {
        Some(ace) if !event.policy_forced => {
            writer.write_map_len(2)?;
            writer.write_key(b"kind")?;
            writer.write_str(b"sacl")?;
            writer.write_key(b"ace")?;
            writer.write_bin(ace.as_slice())?;
        }
        _ => {
            writer.write_map_len(1)?;
            writer.write_key(b"kind")?;
            writer.write_str(b"policy")?;
        }
    }
    maps.write_tail(&mut writer)?;

    Ok(writer.into_vec())
}

fn encode_privilege_used_payload(
    event: &PrivilegeUseEvent,
    maps: &CheckMaps,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(512)?;

    writer.write_map_len(maps.common_len() + 4)?;
    maps.write_head(&mut writer)?;
    writer.write_key(b"operation")?;
    writer.write_map_len(1)?;
    writer.write_key(b"name")?;
    writer.write_str(b"access-check")?;
    writer.write_key(b"privilege")?;
    writer.write_map_len(3)?;
    writer.write_key(b"name")?;
    writer.write_str(privilege_name(event.privilege)?)?;
    writer.write_key(b"contributed")?;
    writer.write_u64(u64::from(event.contributed))?;
    writer.write_key(b"surviving")?;
    writer.write_u64(u64::from(event.surviving_bits))?;
    writer.write_key(b"access")?;
    writer.write_map_len(2)?;
    writer.write_key(b"requested")?;
    writer.write_u64(u64::from(event.check_requested))?;
    writer.write_key(b"granted")?;
    writer.write_u64(u64::from(event.check_granted))?;
    writer.write_key(b"outcome")?;
    writer.write_map_len(1)?;
    writer.write_key(b"success")?;
    writer.write_bool(event.success)?;
    maps.write_tail(&mut writer)?;

    Ok(writer.into_vec())
}

fn write_staged_access(
    writer: &mut MsgpackWriter,
    event: &CaapDiagnosticEvent,
) -> Result<(), c_long> {
    writer.write_key(b"access")?;
    writer.write_map_len(3)?;
    writer.write_key(b"requested")?;
    writer.write_u64(u64::from(event.requested))?;
    writer.write_key(b"granted")?;
    writer.write_u64(u64::from(event.effective_granted))?;
    writer.write_key(b"granted-staged")?;
    writer.write_u64(u64::from(event.staged_granted))
}

/// `kacs.caap.sacl.skipped` or `kacs.caap.staging.diverged`, with the event
/// type it is written under.
fn encode_caap_payload(
    event: &CaapDiagnosticEvent,
    maps: &CheckMaps,
) -> Result<(&'static [u8], Vec<u8>), c_long> {
    let mut writer = MsgpackWriter::with_capacity(512)?;

    match event.kind {
        CaapDiagnosticKind::SaclError => {
            let phase = event.phase.ok_or(EIO)?;
            let policy_sid = event.policy_sid.as_ref().ok_or(EIO)?;
            let rule_index = event.rule_index.ok_or(EIO)?;
            let _ = str::from_utf8(event.reason.as_bytes()).map_err(|_| EIO)?;

            writer.write_map_len(maps.common_len() + 3)?;
            maps.write_head(&mut writer)?;
            writer.write_key(b"caap")?;
            writer.write_map_len(3)?;
            writer.write_key(b"policy")?;
            writer.write_map_len(1)?;
            writer.write_key(b"sid")?;
            writer.write_bin(policy_sid.as_slice())?;
            writer.write_key(b"rule")?;
            writer.write_map_len(1)?;
            writer.write_key(b"index")?;
            writer.write_u64(u64::from(rule_index))?;
            writer.write_key(b"phase")?;
            writer.write_str(caap_sacl_phase_name(phase))?;
            writer.write_key(b"outcome")?;
            writer.write_map_len(1)?;
            writer.write_key(b"reason")?;
            writer.write_str(event.reason.as_bytes())?;
            write_staged_access(&mut writer, event)?;
            maps.write_tail(&mut writer)?;
            Ok((CAAP_SACL_SKIPPED_TYPE, writer.into_vec()))
        }
        CaapDiagnosticKind::StagingMismatch => {
            writer.write_map_len(maps.common_len() + 1)?;
            maps.write_head(&mut writer)?;
            write_staged_access(&mut writer, event)?;
            maps.write_tail(&mut writer)?;
            Ok((CAAP_STAGING_DIVERGED_TYPE, writer.into_vec()))
        }
    }
}

/// One operation on an already-open file handle, as FACS reports it for
/// `kacs.audit.handle.used`.
pub(crate) struct HandleUse<'a> {
    /// `operation.name`, such as `file.permission`.
    pub(crate) operation: &'a [u8],
    /// The absolute path of the handle's file, when it could be resolved.
    pub(crate) path: Option<&'a [u8]>,
    pub(crate) requested_access: u32,
    pub(crate) matched_access: u32,
    pub(crate) granted_access: u32,
    /// The continuous-audit mask cached on the handle.
    pub(crate) audit_mask: u32,
    pub(crate) success: bool,
    /// The `KACS_FSR_*` code the enforcement point resolved with.
    pub(crate) reason: u8,
}

fn encode_handle_used_payload(
    subject_map: &[u8],
    emitter_map: &[u8],
    handle: &HandleUse<'_>,
) -> Result<Vec<u8>, c_long> {
    let path_len = handle.path.map_or(0, <[u8]>::len);
    let mut writer = MsgpackWriter::with_capacity(320 + handle.operation.len() + path_len)?;
    let reason = if handle.success {
        None
    } else {
        handle_failure_reason(handle.reason)
    };

    let _ = str::from_utf8(handle.operation).map_err(|_| EIO)?;
    if handle.requested_access == 0 || handle.matched_access == 0 {
        return Err(EIO);
    }

    writer.write_map_len(6)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"emitter")?;
    writer.extend(emitter_map)?;
    writer.write_key(b"object")?;
    // FACS is the only enforcement point that reports handle use, so the
    // object is always a file.
    writer.write_map_len(1 + usize::from(handle.path.is_some()))?;
    writer.write_key(b"kind")?;
    writer.write_str(b"file")?;
    if let Some(path) = handle.path {
        writer.write_key(b"file")?;
        writer.write_map_len(1)?;
        writer.write_key(b"path")?;
        writer.write_str(path)?;
    }
    writer.write_key(b"operation")?;
    writer.write_map_len(1)?;
    writer.write_key(b"name")?;
    writer.write_str(handle.operation)?;
    writer.write_key(b"access")?;
    writer.write_map_len(4)?;
    writer.write_key(b"requested")?;
    writer.write_u64(u64::from(handle.requested_access))?;
    writer.write_key(b"matched")?;
    writer.write_u64(u64::from(handle.matched_access))?;
    writer.write_key(b"granted")?;
    writer.write_u64(u64::from(handle.granted_access))?;
    writer.write_key(b"audit-mask")?;
    writer.write_u64(u64::from(handle.audit_mask))?;
    writer.write_key(b"outcome")?;
    writer.write_map_len(1 + usize::from(reason.is_some()))?;
    writer.write_key(b"success")?;
    writer.write_bool(handle.success)?;
    if let Some(reason) = reason {
        writer.write_key(b"reason")?;
        writer.write_str(reason)?;
    }

    Ok(writer.into_vec())
}

/// The `emitter` map with the thread as well as the process:
/// `emitter.process.*` and `emitter.thread.tid`, for a record about
/// something scoped to one thread, such as impersonation.
fn encode_emitter_thread_map(process: &ProcessInfo, tid: u64) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(112 + process.executable_path.len())?;

    writer.write_map_len(2)?;
    writer.write_key(b"process")?;
    writer.write_map_len(3)?;
    writer.write_key(b"pid")?;
    writer.write_u64(process.pid)?;
    writer.write_key(b"name")?;
    writer.write_str(process.name.as_slice())?;
    writer.write_key(b"executable")?;
    writer.write_str(process.executable_path.as_slice())?;
    writer.write_key(b"thread")?;
    writer.write_map_len(1)?;
    writer.write_key(b"tid")?;
    writer.write_u64(tid)?;

    Ok(writer.into_vec())
}

/// The `outcome` map of a record whose action can fail: `success`, and on
/// failure the negative `errno` and, where one is known, the `reason`.
fn write_outcome(
    writer: &mut MsgpackWriter,
    errno: i32,
    reason: Option<&[u8]>,
) -> Result<(), c_long> {
    let failed = errno != 0;
    let reason = if failed { reason } else { None };

    writer.write_key(b"outcome")?;
    writer.write_map_len(1 + usize::from(failed) + usize::from(reason.is_some()))?;
    writer.write_key(b"success")?;
    writer.write_bool(!failed)?;
    if failed {
        writer.write_key(b"errno")?;
        write_i64(writer, i64::from(errno))?;
    }
    if let Some(reason) = reason {
        writer.write_key(b"reason")?;
        writer.write_str(reason)?;
    }
    Ok(())
}

/// A msgpack signed integer, smallest encoding.
fn write_i64(writer: &mut MsgpackWriter, value: i64) -> Result<(), c_long> {
    if value >= 0 {
        return writer.write_u64(value as u64);
    }
    if value >= -32 {
        writer.push_byte(value as i8 as u8)
    } else if value >= i64::from(i8::MIN) {
        writer.push_byte(0xd0)?;
        writer.push_byte(value as i8 as u8)
    } else if value >= i64::from(i16::MIN) {
        writer.push_byte(0xd1)?;
        writer.extend(&(value as i16).to_be_bytes())
    } else if value >= i64::from(i32::MIN) {
        writer.push_byte(0xd2)?;
        writer.extend(&(value as i32).to_be_bytes())
    } else {
        writer.push_byte(0xd3)?;
        writer.extend(&value.to_be_bytes())
    }
}

/// The client token of an impersonation, as `kacs.impersonation.started`
/// describes it under `object.token`.
pub(crate) struct ImpersonationClient<'a> {
    /// The installed token's GUID on success, the client token's otherwise.
    pub(crate) guid: [u8; 16],
    /// The installed token's LUID on success, the client token's otherwise.
    pub(crate) id: u64,
    pub(crate) sid: &'a [u8],
    pub(crate) token_type: TokenType,
    pub(crate) integrity: u32,
    pub(crate) auth_id: Option<u64>,
    pub(crate) restricted: bool,
    /// The client token's own impersonation level: the level asked for.
    pub(crate) requested: ImpersonationLevel,
    /// The level the gate permitted, as its ABI value, when the gate ran.
    pub(crate) permitted: Option<u32>,
    /// Whether the gate needed SeImpersonatePrivilege and used it.
    pub(crate) used_impersonate: bool,
}

fn encode_impersonation_started_payload(
    subject_map: &[u8],
    emitter_map: &[u8],
    client: &ImpersonationClient<'_>,
    errno: i32,
    reason: Option<&[u8]>,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(384 + client.sid.len())?;
    let impersonation = match client.token_type {
        TokenType::Primary => 0,
        TokenType::Impersonation => impersonation_level_value(client.requested),
    };

    writer.write_map_len(4 + usize::from(client.used_impersonate))?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map)?;
    writer.write_key(b"emitter")?;
    writer.extend(emitter_map)?;
    writer.write_key(b"object")?;
    writer.write_map_len(2)?;
    writer.write_key(b"kind")?;
    writer.write_str(b"token")?;
    writer.write_key(b"token")?;
    writer.write_map_len(
        7 + usize::from(client.auth_id.is_some()) + usize::from(client.permitted.is_some()),
    )?;
    writer.write_key(b"guid")?;
    writer.write_bin(&client.guid)?;
    writer.write_key(b"id")?;
    writer.write_u64(client.id)?;
    writer.write_key(b"sid")?;
    writer.write_bin(client.sid)?;
    writer.write_key(b"type")?;
    writer.write_str(match client.token_type {
        TokenType::Primary => b"primary",
        TokenType::Impersonation => b"impersonation",
    })?;
    writer.write_key(b"integrity")?;
    writer.write_u64(u64::from(client.integrity))?;
    if let Some(auth_id) = client.auth_id {
        writer.write_key(b"auth-id")?;
        writer.write_u64(auth_id)?;
    }
    writer.write_key(b"restricted")?;
    writer.write_bool(client.restricted)?;
    writer.write_key(b"impersonation")?;
    writer.write_u64(impersonation)?;
    if let Some(permitted) = client.permitted {
        writer.write_key(b"impersonation-permitted")?;
        writer.write_u64(u64::from(permitted))?;
    }
    if client.used_impersonate {
        writer.write_key(b"privilege")?;
        writer.write_map_len(2)?;
        writer.write_key(b"name")?;
        writer.write_str(b"SeImpersonatePrivilege")?;
        writer.write_key(b"held")?;
        writer.write_bool(true)?;
    }
    write_outcome(&mut writer, errno, reason)?;

    Ok(writer.into_vec())
}

/// `kacs.impersonation.started`, for an impersonation attempt that reached
/// the kernel's gate. `token` is the server's token, the one that acted.
pub(crate) fn emit_impersonation_started_to_kmes(
    token: &AccessCheckToken<'_>,
    subject_ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
    tid: u64,
    client: &ImpersonationClient<'_>,
    errno: i32,
    reason: Option<&[u8]>,
) -> Result<(), c_long> {
    let process_info = load_process_info()?;
    let emitter_map = encode_emitter_thread_map(&process_info, tid)?;
    let subject_map = encode_subject_map(token, subject_ids, effective_pip)?;
    let payload = encode_impersonation_started_payload(
        subject_map.as_slice(),
        emitter_map.as_slice(),
        client,
        errno,
        reason,
    )?;

    emit(IMPERSONATION_STARTED_TYPE, payload.as_slice());
    Ok(())
}

/// What a descriptor change was made to, as `object.<kind>` names it.
pub(crate) enum DescriptorObject<'a> {
    /// A file, by absolute path when the handle's path could be resolved.
    File { path: Option<&'a [u8]> },
    /// A token, by LUID and durable GUID.
    Token { id: u64, guid: [u8; 16] },
    /// A process, by durable GUID.
    Process { guid: [u8; 16] },
    /// A System V IPC object: `sem`, `shm` or `msg`, and its identifier.
    Ipc { kind: &'static [u8], id: i64 },
}

/// One side of a descriptor change: its length, SHA-256 digest and owner.
pub(crate) struct DescriptorFacts<'a> {
    pub(crate) len: usize,
    pub(crate) digest: [u8; 32],
    pub(crate) owner: Option<&'a [u8]>,
}

/// `kacs.audit.descriptor.changed`'s inputs beyond subject and emitter.
pub(crate) struct DescriptorChange<'a> {
    pub(crate) object: DescriptorObject<'a>,
    /// `object.sd.components`: the `KACS_SECINFO_*` bits addressed.
    pub(crate) components: u32,
    /// The descriptor replaced, when it was a stored one.
    pub(crate) previous: Option<DescriptorFacts<'a>>,
    /// The descriptor written, when the change applied.
    pub(crate) current: Option<DescriptorFacts<'a>>,
    /// The rights the change needed.
    pub(crate) requested: u32,
    /// The handle's grant and alarm mask, for a change made through one.
    pub(crate) handle: Option<(u32, u32)>,
    pub(crate) errno: i32,
}

fn write_descriptor_object(
    writer: &mut MsgpackWriter,
    change: &DescriptorChange<'_>,
) -> Result<(), c_long> {
    let (kind, has_body): (&[u8], bool) = match &change.object {
        DescriptorObject::File { path } => (b"file", path.is_some()),
        DescriptorObject::Token { .. } => (b"token", true),
        DescriptorObject::Process { .. } => (b"process", true),
        DescriptorObject::Ipc { .. } => (b"ipc", true),
    };

    writer.write_key(b"object")?;
    writer.write_map_len(2 + usize::from(has_body))?;
    writer.write_key(b"kind")?;
    writer.write_str(kind)?;
    match &change.object {
        DescriptorObject::File { path: Some(path) } => {
            writer.write_key(b"file")?;
            writer.write_map_len(1)?;
            writer.write_key(b"path")?;
            writer.write_str(path)?;
        }
        DescriptorObject::File { path: None } => {}
        DescriptorObject::Token { id, guid } => {
            writer.write_key(b"token")?;
            writer.write_map_len(2)?;
            writer.write_key(b"id")?;
            writer.write_u64(*id)?;
            writer.write_key(b"guid")?;
            writer.write_bin(guid)?;
        }
        DescriptorObject::Process { guid } => {
            writer.write_key(b"process")?;
            writer.write_map_len(1)?;
            writer.write_key(b"guid")?;
            writer.write_bin(guid)?;
        }
        DescriptorObject::Ipc { kind, id } => {
            writer.write_key(b"ipc")?;
            writer.write_map_len(2)?;
            writer.write_key(b"type")?;
            writer.write_str(kind)?;
            writer.write_key(b"id")?;
            write_i64(writer, *id)?;
        }
    }

    let side_len = |facts: &Option<DescriptorFacts<'_>>| match facts {
        Some(facts) => 2 + usize::from(facts.owner.is_some()),
        None => 0,
    };
    writer.write_key(b"sd")?;
    writer.write_map_len(1 + side_len(&change.current) + side_len(&change.previous))?;
    writer.write_key(b"components")?;
    writer.write_u64(u64::from(change.components))?;
    if let Some(current) = &change.current {
        writer.write_key(b"length")?;
        writer.write_u64(current.len as u64)?;
        writer.write_key(b"digest")?;
        writer.write_bin(&current.digest)?;
        if let Some(owner) = current.owner {
            writer.write_key(b"owner")?;
            writer.write_bin(owner)?;
        }
    }
    if let Some(previous) = &change.previous {
        writer.write_key(b"length-previous")?;
        writer.write_u64(previous.len as u64)?;
        writer.write_key(b"digest-previous")?;
        writer.write_bin(&previous.digest)?;
        if let Some(owner) = previous.owner {
            writer.write_key(b"owner-previous")?;
            writer.write_bin(owner)?;
        }
    }
    Ok(())
}

/// `kacs.audit.descriptor.changed`: `token` is the caller's token, the one
/// that made (or tried to make) the change.
pub(crate) fn emit_descriptor_changed_to_kmes(
    token: &AccessCheckToken<'_>,
    subject_ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
    change: &DescriptorChange<'_>,
) -> Result<(), c_long> {
    // A file name is an arbitrary byte string: sanitise, as for handle use.
    let sanitized = match &change.object {
        DescriptorObject::File { path: Some(path) } => {
            let mut copy = Vec::with_capacity(path.len()).map_err(|_| ENOMEM)?;
            copy.extend_from_slice(path).map_err(|_| ENOMEM)?;
            Some(sanitize_utf8_lossy(copy)?)
        }
        _ => None,
    };
    let change = DescriptorChange {
        object: match (&change.object, sanitized.as_deref()) {
            (DescriptorObject::File { .. }, path) => DescriptorObject::File { path },
            (DescriptorObject::Token { id, guid }, _) => DescriptorObject::Token {
                id: *id,
                guid: *guid,
            },
            (DescriptorObject::Process { guid }, _) => DescriptorObject::Process { guid: *guid },
            (DescriptorObject::Ipc { kind, id }, _) => DescriptorObject::Ipc { kind, id: *id },
        },
        previous: change.previous.as_ref().map(|facts| DescriptorFacts {
            len: facts.len,
            digest: facts.digest,
            owner: facts.owner,
        }),
        current: change.current.as_ref().map(|facts| DescriptorFacts {
            len: facts.len,
            digest: facts.digest,
            owner: facts.owner,
        }),
        ..*change
    };
    let process_info = load_process_info()?;
    let emitter_map = encode_emitter_map(&process_info)?;
    let subject_map = encode_subject_map(token, subject_ids, effective_pip)?;
    let mut writer = MsgpackWriter::with_capacity(
        512 + subject_map.len() + emitter_map.len() + sanitized.as_ref().map_or(0, |p| p.len()),
    )?;

    writer.write_map_len(5)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map.as_slice())?;
    writer.write_key(b"emitter")?;
    writer.extend(emitter_map.as_slice())?;
    write_descriptor_object(&mut writer, &change)?;
    writer.write_key(b"access")?;
    match change.handle {
        Some((granted, audit_mask)) => {
            // Zero when only the SACL made the record exist, as on the
            // registry's own record.
            let matched = change.requested & audit_mask;
            writer.write_map_len(4)?;
            writer.write_key(b"requested")?;
            writer.write_u64(u64::from(change.requested))?;
            writer.write_key(b"granted")?;
            writer.write_u64(u64::from(granted))?;
            writer.write_key(b"audit-mask")?;
            writer.write_u64(u64::from(audit_mask))?;
            writer.write_key(b"matched")?;
            writer.write_u64(u64::from(matched))?;
        }
        None => {
            writer.write_map_len(1)?;
            writer.write_key(b"requested")?;
            writer.write_u64(u64::from(change.requested))?;
        }
    }
    write_outcome(&mut writer, change.errno, None)?;

    emit(DESCRIPTOR_CHANGED_TYPE, writer.into_vec().as_slice());
    Ok(())
}

/// `kacs.impersonation.reverted`. `token` is the thread's token after the
/// revert; `dropped_guid` and `dropped_sid` identify the token it gave up.
pub(crate) fn emit_impersonation_reverted_to_kmes(
    token: &AccessCheckToken<'_>,
    subject_ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
    tid: u64,
    dropped_guid: &[u8; 16],
    dropped_sid: &[u8],
    operation: &[u8],
    errno: i32,
) -> Result<(), c_long> {
    let process_info = load_process_info()?;
    let emitter_map = encode_emitter_thread_map(&process_info, tid)?;
    let subject_map = encode_subject_map(token, subject_ids, effective_pip)?;
    let mut writer = MsgpackWriter::with_capacity(
        256 + subject_map.len() + emitter_map.len() + dropped_sid.len(),
    )?;

    writer.write_map_len(5)?;
    writer.write_key(b"subject")?;
    writer.extend(subject_map.as_slice())?;
    writer.write_key(b"emitter")?;
    writer.extend(emitter_map.as_slice())?;
    writer.write_key(b"object")?;
    writer.write_map_len(2)?;
    writer.write_key(b"kind")?;
    writer.write_str(b"token")?;
    writer.write_key(b"token")?;
    writer.write_map_len(2)?;
    writer.write_key(b"guid")?;
    writer.write_bin(dropped_guid)?;
    writer.write_key(b"sid")?;
    writer.write_bin(dropped_sid)?;
    writer.write_key(b"operation")?;
    writer.write_map_len(1)?;
    writer.write_key(b"name")?;
    writer.write_str(operation)?;
    write_outcome(&mut writer, errno, None)?;

    emit(IMPERSONATION_REVERTED_TYPE, writer.into_vec().as_slice());
    Ok(())
}

pub(crate) fn encode_logon_session_destroyed_payload(
    session_id: u64,
    user_sid: &[u8],
    logon_type: u32,
    auth_package: &[u8],
    created_at: u64,
) -> Result<Vec<u8>, c_long> {
    let mut writer = MsgpackWriter::with_capacity(128 + user_sid.len() + auth_package.len())?;
    let logon_type = logon_type_name(logon_type)?;
    // Sessions record their creation in whole seconds of the realtime clock;
    // `uint.time` is nanoseconds.
    let logon_time = created_at
        .checked_mul(NANOSECONDS_PER_SECOND)
        .ok_or(ERANGE)?;

    let _ = str::from_utf8(auth_package).map_err(|_| EIO)?;

    writer.write_map_len(1)?;
    writer.write_key(b"object")?;
    writer.write_map_len(1)?;
    writer.write_key(b"session")?;
    writer.write_map_len(5)?;
    writer.write_key(b"id")?;
    writer.write_u64(session_id)?;
    writer.write_key(b"user")?;
    writer.write_map_len(1)?;
    writer.write_key(b"sid")?;
    writer.write_bin(user_sid)?;
    writer.write_key(b"logon-type")?;
    writer.write_str(logon_type)?;
    writer.write_key(b"auth-package")?;
    writer.write_str(auth_package)?;
    writer.write_key(b"logon-time")?;
    writer.write_u64(logon_time)?;

    Ok(writer.into_vec())
}

fn emit(event_type: &[u8], payload: &[u8]) {
    unsafe {
        pkm_kmes_emit_kernel(
            KMES_ORIGIN_KACS,
            event_type.as_ptr().cast(),
            event_type.len(),
            payload.as_ptr().cast(),
            payload.len(),
        );
    }
}

pub(crate) fn emit_access_check_events_to_kmes(
    audit_events: &[OwnedAuditEvent],
    privilege_use_events: &[PrivilegeUseEvent],
    caap_diagnostic_events: &[CaapDiagnosticEvent],
    resolved: AccessCheckAbiResolved<'_>,
    effective_pip: PipContext,
    target: &AuditTarget<'_>,
) -> Result<(), c_long> {
    if audit_events.is_empty()
        && privilege_use_events.is_empty()
        && caap_diagnostic_events.is_empty()
    {
        return Ok(());
    }

    let process_info = load_process_info()?;
    let maps = CheckMaps {
        subject: encode_subject_map(resolved.token, target.subject_ids.as_ref(), effective_pip)?,
        emitter: encode_emitter_map(&process_info)?,
        object: encode_object_map(&target.object)?,
        asserted: target.asserted,
        denials: target.denials,
    };

    for event in privilege_use_events {
        let payload = encode_privilege_used_payload(event, &maps)?;
        emit(PRIVILEGE_USED_TYPE, payload.as_slice());
    }

    for event in audit_events {
        if target.sacl_audit_suppressed && !event.policy_forced {
            continue;
        }
        let payload = encode_access_checked_payload(event, &maps)?;
        emit(ACCESS_CHECKED_TYPE, payload.as_slice());
    }

    for event in caap_diagnostic_events {
        let (event_type, payload) = encode_caap_payload(event, &maps)?;
        emit(event_type, payload.as_slice());
    }

    Ok(())
}

pub(crate) fn emit_handle_used_to_kmes(
    token: &AccessCheckToken<'_>,
    subject_ids: Option<&AuditSubjectIds>,
    effective_pip: PipContext,
    handle: &HandleUse<'_>,
) -> Result<(), c_long> {
    let process_info = load_process_info()?;
    let emitter_map = encode_emitter_map(&process_info)?;
    let subject_map = encode_subject_map(token, subject_ids, effective_pip)?;
    // A file name is an arbitrary byte string. As with the process name,
    // sanitise rather than refuse: a failed emission fails the operation.
    let path = match handle.path {
        Some(path) => {
            let mut copy = Vec::with_capacity(path.len()).map_err(|_| ENOMEM)?;
            copy.extend_from_slice(path).map_err(|_| ENOMEM)?;
            Some(sanitize_utf8_lossy(copy)?)
        }
        None => None,
    };
    let handle = HandleUse {
        path: path.as_deref(),
        ..*handle
    };
    let payload =
        encode_handle_used_payload(subject_map.as_slice(), emitter_map.as_slice(), &handle)?;

    emit(HANDLE_USED_TYPE, payload.as_slice());
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

    emit(SESSION_DESTROYED_TYPE, payload.as_slice());
    Ok(())
}
