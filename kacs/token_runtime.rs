// SPDX-License-Identifier: GPL-2.0-only

//! Boot-time PKM token/session runtime substrate.
//!
//! Slice 22 still keeps this module narrower than a full token-handle
//! implementation. It provides:
//! - the boot Session 0 / SYSTEM token object
//! - reference management for that live token pointer
//! - current-token conversion into the closed Slice 20 AccessCheck context
//! - bounded token-own-SD material for the first self-open token-fd slice
//! - fixed boot-token default-object fields for the query ioctl surface
//! - bounded interactive-session mutation for `KACS_IOC_ADJUST_SESSIONID`
//! - bounded default-field mutation for `KACS_IOC_ADJUST_DEFAULT`
//! - bounded group-enabled-state mutation for `KACS_IOC_ADJUST_GROUPS`
//! - bounded privilege mutation for `KACS_IOC_ADJUST_PRIVS`
//! - a small KUnit snapshot seam for bootstrap verification
//!
//! Broader mutable token state remains deferred to later token-handle slices.

#![allow(unreachable_pub)]

use crate::access_check::access_check;
use crate::access_check_abi::AccessCheckAbiResolved;
use crate::access_mask::{
    GenericMapping, PROCESS_GENERIC_MAPPING, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED,
    GENERIC_ALL, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use crate::acl::Acl;
use crate::condition::ConditionalContext;
use crate::error::KacsError;
use crate::mic::{
    IntegrityLevel, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN, TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
use crate::pip::PipContext;
use crate::privilege::TokenPrivileges;
use crate::security_descriptor::SecurityDescriptor;
use crate::sid::Sid;
use crate::token::{
    AccessCheckToken, ConfinementTokenContext, ImpersonationLevel, RestrictedTokenContext,
    SidAndAttributes, TokenType, TokenView, AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null, null_mut};
use core::sync::atomic::{
    fence, AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};

const SYSTEM_PRIVILEGES_ALL: u64 = 0xC000_000F_FFFF_FFFC;
const SE_TCB_PRIVILEGE: u64 = 1 << 7;
const LOGON_TYPE_SERVICE: u32 = 5;
const LOGON_TYPE_NETWORK: u32 = 3;
const TOKEN_TYPE_PRIMARY_ABI: u32 = 1;
const TOKEN_TYPE_IMPERSONATION_ABI: u32 = 2;
const IMPERSONATION_LEVEL_ANONYMOUS_ABI: u32 = 0;
const IMPERSONATION_LEVEL_IDENTIFICATION_ABI: u32 = 1;
const IMPERSONATION_LEVEL_IMPERSONATION_ABI: u32 = 2;
const IMPERSONATION_LEVEL_DELEGATION_ABI: u32 = 3;
const TOKEN_ELEVATION_DEFAULT_ABI: u32 = 1;
const MAX_DEFAULT_DACL_BYTES: usize = 65_536;
const TOKEN_INDEX_NO_CHANGE: u32 = u32::MAX;
const MAX_BOOT_GROUPS: usize = 5;
const MAX_PRIVILEGE_ADJUST_ENTRIES: usize = 64;
const SD_HEADER_LEN: usize = 20;
const ACL_HEADER_LEN: usize = 8;
const ACE_HEADER_LEN: usize = 8;
const ACL_REVISION: u8 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const ERANGE: i32 = 34;

const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_OWNER: u32 = 0x0000_0008;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
const SE_PRIVILEGE_REMOVED: u32 = 0x0000_0004;
const KACS_PRIV_RESET_ALL_DEFAULTS: u32 = 0x8000_0000;

const KACS_TOKEN_IMPERSONATE: u32 = 0x0004;
const KACS_TOKEN_QUERY: u32 = 0x0008;
const KACS_TOKEN_QUERY_SOURCE: u32 = 0x0010;
const KACS_TOKEN_ADJUST_PRIVS: u32 = 0x0020;
const KACS_TOKEN_ADJUST_GROUPS: u32 = 0x0040;
const KACS_TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
const KACS_TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
const KACS_TOKEN_DEFAULT_SELF_ACCESS: u32 = KACS_TOKEN_QUERY
    | KACS_TOKEN_QUERY_SOURCE
    | KACS_TOKEN_ADJUST_PRIVS
    | KACS_TOKEN_ADJUST_GROUPS
    | KACS_TOKEN_ADJUST_DEFAULT;
const SE_IMPERSONATE_PRIVILEGE: u64 = 1 << 29;

const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ANONYMOUS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
const LOCAL_SERVICE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const EVERYONE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const AUTHENTICATED_USERS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const LOCAL_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
const LOGON_SID_BYTES: &[u8] = &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const ANONYMOUS_LOGON_SID_BYTES: &[u8] = &[
    1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 230, 3, 0, 0,
];
const AUTH_PACKAGE_NEGOTIATE: &[u8] = b"Negotiate";
const TOKEN_SOURCE_PEI_OS_KRN: &[u8; 8] = b"PeiosKrn";
const BOOT_SYSTEM_TOKEN_ID: u64 = 0;
const BOOT_SYSTEM_MODIFIED_ID: u64 = 0;
const ANONYMOUS_LOGON_LUID: u64 = 998;
const BOOT_SYSTEM_OWNER_SID_INDEX: u32 = 0;
const BOOT_SYSTEM_PRIMARY_GROUP_INDEX: u32 = 1;
const BOOT_SYSTEM_GROUP_ATTRIBUTES: [u32; MAX_BOOT_GROUPS] = [
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID,
];
const KUNIT_ADJUSTABLE_GROUP_ATTRIBUTES: [u32; MAX_BOOT_GROUPS] = [
    SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER,
    0,
    SE_GROUP_USE_FOR_DENY_ONLY,
    SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID,
];
const KUNIT_ADJUSTABLE_PRIVILEGES_PRESENT: u64 = (1u64 << 2) | (1u64 << 5) | (1u64 << 9);
const KUNIT_ADJUSTABLE_PRIVILEGES_ENABLED: u64 = (1u64 << 2) | (1u64 << 9);
const KUNIT_ADJUSTABLE_PRIVILEGES_ENABLED_BY_DEFAULT: u64 = (1u64 << 2) | (1u64 << 9);
const SYSTEM_DEFAULT_DACL_BYTES: &[u8] = &[
    2, 0, 52, 0, 2, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 16, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0,
    24, 0, 0, 0, 0, 16, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
];
const ANONYMOUS_PROJECTED_ID: u32 = 65534;
const EMPTY_DEVICE_GROUPS: &[SidAndAttributes<'static>] = &[];
const EMPTY_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const EMPTY_POLICIES: &[crate::caap::CaapPolicyEntry<'static>] = &[];
static NEXT_DYNAMIC_TOKEN_ID: AtomicU64 = AtomicU64::new(1);
const ANONYMOUS_ONLY_GROUP_ATTRIBUTES: [u32; MAX_BOOT_GROUPS] = [
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    0,
    0,
    0,
    0,
];
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const SOCKET_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: READ_CONTROL,
    write: FILE_WRITE_DATA | WRITE_DAC,
    execute: READ_CONTROL,
    all: FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
};
const TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: KACS_TOKEN_QUERY | READ_CONTROL,
    write: KACS_TOKEN_ADJUST_PRIVS
        | KACS_TOKEN_ADJUST_GROUPS
        | KACS_TOKEN_ADJUST_DEFAULT
        | WRITE_DAC,
    execute: KACS_TOKEN_IMPERSONATE,
    all: KACS_TOKEN_ALL_ACCESS,
};

const TOKEN_CLASS_USER: u32 = 0x01;
const TOKEN_CLASS_GROUPS: u32 = 0x02;
const TOKEN_CLASS_PRIVILEGES: u32 = 0x03;
const TOKEN_CLASS_TYPE: u32 = 0x04;
const TOKEN_CLASS_INTEGRITY_LEVEL: u32 = 0x05;
const TOKEN_CLASS_OWNER: u32 = 0x06;
const TOKEN_CLASS_PRIMARY_GROUP: u32 = 0x07;
const TOKEN_CLASS_SESSION_ID: u32 = 0x08;
const TOKEN_CLASS_RESTRICTED_SIDS: u32 = 0x09;
const TOKEN_CLASS_SOURCE: u32 = 0x0A;
const TOKEN_CLASS_STATISTICS: u32 = 0x0B;
const TOKEN_CLASS_ORIGIN: u32 = 0x0C;
const TOKEN_CLASS_ELEVATION_TYPE: u32 = 0x0D;
const TOKEN_CLASS_DEVICE_GROUPS: u32 = 0x0E;
const TOKEN_CLASS_APPCONTAINER_SID: u32 = 0x0F;
const TOKEN_CLASS_CAPABILITIES: u32 = 0x10;
const TOKEN_CLASS_MANDATORY_POLICY: u32 = 0x11;
const TOKEN_CLASS_LOGON_TYPE: u32 = 0x12;
const TOKEN_CLASS_LOGON_SID: u32 = 0x13;
const TOKEN_CLASS_DEFAULT_DACL: u32 = 0x14;
const TOKEN_CLASS_IMPERSONATION_LEVEL: u32 = 0x15;

extern "C" {
    fn pkm_kacs_boot_system_token_ptr() -> *const c_void;
    fn pkm_kacs_zalloc(size: usize) -> *mut c_void;
    fn pkm_kacs_free(ptr: *mut c_void);
}

#[repr(C)]
#[derive(Clone, Copy)]
/// C-visible view of one boot token group entry for KUnit checks.
pub struct PkmKacsBootGroupView {
    /// Raw SID pointer.
    pub sid_ptr: *const u8,
    /// SID length in bytes.
    pub sid_len: usize,
    /// Group attributes.
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// C-visible group-adjustment entry ABI for the bounded Slice 35 runtime.
pub struct PkmKacsGroupAdjustEntry {
    /// Zero-based group array index, or `u32::MAX` as the reset sentinel.
    pub index: u32,
    /// 1 = enable, 0 = disable. The reset sentinel requires 0.
    pub enable: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// C-visible privilege-adjustment entry ABI for the bounded Slice 36 runtime.
pub struct PkmKacsPrivilegeAdjustEntry {
    /// Privilege bit position, or 0 when paired with the reset sentinel.
    pub luid: u32,
    /// Disable = 0, enable = `SE_PRIVILEGE_ENABLED`, remove =
    /// `SE_PRIVILEGE_REMOVED`, reset = `KACS_PRIV_RESET_ALL_DEFAULTS`.
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// C-visible snapshot of the boot Session 0 / SYSTEM token state exercised by
/// Slice 21.
pub struct PkmKacsBootSnapshot {
    /// Opaque live token pointer.
    pub token_ptr: *const c_void,
    /// Boot session identifier.
    pub session_id: u64,
    /// Token auth_id / logon session LUID.
    pub auth_id: u64,
    /// Token instance LUID.
    pub token_id: u64,
    /// Token modified-id LUID.
    pub modified_id: u64,
    /// Logon type for Session 0.
    pub logon_type: u32,
    /// Authentication package bytes.
    pub auth_pkg_ptr: *const u8,
    /// Length of `auth_pkg_ptr`.
    pub auth_pkg_len: usize,
    /// SYSTEM user SID bytes.
    pub user_sid_ptr: *const u8,
    /// Length of `user_sid_ptr`.
    pub user_sid_len: usize,
    /// Session logon SID bytes.
    pub logon_sid_ptr: *const u8,
    /// Length of `logon_sid_ptr`.
    pub logon_sid_len: usize,
    /// Pointer to the fixed group view array.
    pub groups_ptr: *const PkmKacsBootGroupView,
    /// Number of entries in `groups_ptr`.
    pub group_count: u32,
    /// Owner SID index, with 0 = user and N = groups[N - 1].
    pub owner_sid_index: u32,
    /// Primary group SID index, with 0 = user and N = groups[N - 1].
    pub primary_group_index: u32,
    /// Default DACL bytes.
    pub default_dacl_ptr: *const u8,
    /// Length of `default_dacl_ptr`.
    pub default_dacl_len: usize,
    /// Present privilege mask.
    pub privileges_present: u64,
    /// Enabled privilege mask.
    pub privileges_enabled: u64,
    /// Enabled-by-default privilege mask.
    pub privileges_enabled_by_default: u64,
    /// Monotonic used privilege mask.
    pub privileges_used: u64,
    /// Integrity level RID.
    pub integrity_level: u32,
    /// Token type ABI value.
    pub token_type: u32,
    /// Impersonation level ABI value.
    pub impersonation_level: u32,
    /// Mandatory policy mask.
    pub mandatory_policy: u32,
    /// Interactive session id.
    pub interactive_session_id: u32,
    /// Projected Linux uid.
    pub projected_uid: u32,
    /// Projected Linux gid.
    pub projected_gid: u32,
    /// Audit policy mask.
    pub audit_policy: u32,
}

#[derive(Clone, Copy)]
struct PkmKacsBootSession {
    session_id: u64,
    logon_type: u32,
    user_sid: Sid<'static>,
    auth_package: &'static [u8],
    logon_sid: Sid<'static>,
}

struct PkmKacsBootToken {
    refcount: AtomicUsize,
    mutation_lock: AtomicBool,
    session: PkmKacsBootSession,
    user_sid: Sid<'static>,
    logon_sid: Sid<'static>,
    group_count: usize,
    group_sids: [Sid<'static>; MAX_BOOT_GROUPS],
    group_default_attributes: [u32; MAX_BOOT_GROUPS],
    group_attributes: [AtomicU32; MAX_BOOT_GROUPS],
    group_views: UnsafeCell<[PkmKacsBootGroupView; MAX_BOOT_GROUPS]>,
    token_id: u64,
    created_at: u64,
    modified_id: AtomicU64,
    owner_sid_index: AtomicU32,
    primary_group_index: AtomicU32,
    default_dacl_ptr: AtomicPtr<u8>,
    default_dacl_len: AtomicUsize,
    privileges_present: AtomicU64,
    privileges_enabled: AtomicU64,
    privileges_enabled_by_default: AtomicU64,
    privileges_used: AtomicU64,
    integrity_level: IntegrityLevel,
    mandatory_policy: u32,
    token_type: TokenType,
    impersonation_level: ImpersonationLevel,
    restricted: bool,
    audit_policy: u32,
    interactive_session_id: AtomicU32,
    projected_uid: u32,
    projected_gid: u32,
    own_sd_ptr: AtomicPtr<u8>,
    own_sd_len: AtomicUsize,
}

struct TokenMutationGuard<'a> {
    token: &'a PkmKacsBootToken,
}

impl Drop for TokenMutationGuard<'_> {
    fn drop(&mut self) {
        self.token.mutation_lock.store(false, Ordering::Release);
    }
}

struct QueryWriter {
    out: *mut u8,
    out_len: usize,
    pos: usize,
}

impl QueryWriter {
    fn new(out: *mut u8, out_len: usize) -> Self {
        Self {
            out,
            out_len,
            pos: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.pos.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.out_len {
            return false;
        }
        if !bytes.is_empty() {
            if self.out.is_null() {
                return false;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.out.add(self.pos), bytes.len())
            };
        }
        self.pos = end;
        true
    }

    fn write_u32(&mut self, value: u32) -> bool {
        self.write_bytes(&value.to_le_bytes())
    }

    fn write_u64(&mut self, value: u64) -> bool {
        self.write_bytes(&value.to_le_bytes())
    }

    fn written(&self) -> usize {
        self.pos
    }
}

fn sid_query_len(sids: &[Sid<'_>]) -> Option<usize> {
    let mut len = 4usize;

    for sid in sids {
        let sid_len = sid.as_bytes().len();

        if sid_len > u32::MAX as usize {
            return None;
        }
        len = len.checked_add(4)?;
        len = len.checked_add(sid_len)?;
        len = len.checked_add(4)?;
    }

    Some(len)
}

fn token_type_abi(token_type: TokenType) -> u32 {
    match token_type {
        TokenType::Primary => TOKEN_TYPE_PRIMARY_ABI,
        TokenType::Impersonation => TOKEN_TYPE_IMPERSONATION_ABI,
    }
}

fn impersonation_level_abi(level: ImpersonationLevel) -> u32 {
    match level {
        ImpersonationLevel::Anonymous => IMPERSONATION_LEVEL_ANONYMOUS_ABI,
        ImpersonationLevel::Identification => IMPERSONATION_LEVEL_IDENTIFICATION_ABI,
        ImpersonationLevel::Impersonation => IMPERSONATION_LEVEL_IMPERSONATION_ABI,
        ImpersonationLevel::Delegation => IMPERSONATION_LEVEL_DELEGATION_ABI,
    }
}

fn impersonation_level_from_abi(value: u32) -> Result<ImpersonationLevel, i32> {
    match value {
        IMPERSONATION_LEVEL_ANONYMOUS_ABI => Ok(ImpersonationLevel::Anonymous),
        IMPERSONATION_LEVEL_IDENTIFICATION_ABI => Ok(ImpersonationLevel::Identification),
        IMPERSONATION_LEVEL_IMPERSONATION_ABI => Ok(ImpersonationLevel::Impersonation),
        IMPERSONATION_LEVEL_DELEGATION_ABI => Ok(ImpersonationLevel::Delegation),
        _ => Err(-EINVAL),
    }
}

fn token_type_from_abi(value: u32) -> Result<TokenType, i32> {
    match value {
        TOKEN_TYPE_PRIMARY_ABI => Ok(TokenType::Primary),
        TOKEN_TYPE_IMPERSONATION_ABI => Ok(TokenType::Impersonation),
        _ => Err(-EINVAL),
    }
}

fn allocate_dynamic_token_id() -> Result<u64, i32> {
    NEXT_DYNAMIC_TOKEN_ID
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| -ERANGE)
}

fn integrity_level_from_abi(value: u32) -> Result<IntegrityLevel, i32> {
    match value {
        0 => Ok(IntegrityLevel::Untrusted),
        4096 => Ok(IntegrityLevel::Low),
        8192 => Ok(IntegrityLevel::Medium),
        12288 => Ok(IntegrityLevel::High),
        16384 => Ok(IntegrityLevel::System),
        _ => Err(-EINVAL),
    }
}

fn sid_from_kunit_kind(kind: u32) -> Result<Sid<'static>, i32> {
    match kind {
        0 => Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL),
        1 => Sid::parse(LOCAL_SERVICE_SID_BYTES).map_err(|_| -EINVAL),
        _ => Err(-EINVAL),
    }
}

fn write_integrity_sid(writer: &mut QueryWriter, integrity_level: IntegrityLevel) -> bool {
    writer.write_bytes(&[1, 1, 0, 0, 0, 0, 0, 16]) && writer.write_u32(integrity_level as u32)
}

fn alloc_copy_bytes(bytes: &[u8]) -> Result<(*mut u8, usize), i32> {
    let len = bytes.len();

    if len > MAX_DEFAULT_DACL_BYTES {
        return Err(-EINVAL);
    }
    if len == 0 {
        return Ok((null_mut(), 0));
    }

    let ptr = unsafe { pkm_kacs_zalloc(len) } as *mut u8;
    if ptr.is_null() {
        return Err(-ENOMEM);
    }

    unsafe { copy_nonoverlapping(bytes.as_ptr(), ptr, len) };
    Ok((ptr, len))
}

fn free_allocated_bytes(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { pkm_kacs_free(ptr.cast()) };
    }
}

fn build_group_views(
    group_sids: &[Sid<'static>; MAX_BOOT_GROUPS],
    group_attributes: &[u32; MAX_BOOT_GROUPS],
) -> [PkmKacsBootGroupView; MAX_BOOT_GROUPS] {
    core::array::from_fn(|index| PkmKacsBootGroupView {
        sid_ptr: group_sids[index].as_bytes().as_ptr(),
        sid_len: group_sids[index].as_bytes().len(),
        attributes: group_attributes[index],
    })
}

fn write_le_u16(dst: &mut [u8], offset: usize, value: u16) {
    dst[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_le_u32(dst: &mut [u8], offset: usize, value: u32) {
    dst[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn ace_len_for_sid(sid: Sid<'_>) -> Result<usize, i32> {
    ACE_HEADER_LEN
        .checked_add(sid.as_bytes().len())
        .ok_or(-ERANGE)
}

fn write_allow_ace(dst: &mut [u8], offset: usize, mask: u32, sid: Sid<'_>) -> Result<usize, i32> {
    let ace_len = ace_len_for_sid(sid)?;
    let end = offset.checked_add(ace_len).ok_or(-ERANGE)?;
    let ace = dst.get_mut(offset..end).ok_or(-ERANGE)?;

    ace[0] = ACCESS_ALLOWED_ACE_TYPE;
    ace[1] = 0;
    write_le_u16(ace, 2, ace_len as u16);
    write_le_u32(ace, 4, mask);
    ace[ACE_HEADER_LEN..].copy_from_slice(sid.as_bytes());
    Ok(ace_len)
}

fn build_process_sd_bytes(
    owner_sid: Sid<'_>,
    group_sid: Sid<'_>,
    self_mask: Option<u32>,
    admin_mask: Option<u32>,
    system_mask: Option<u32>,
    everyone_mask: Option<u32>,
) -> Result<(*mut u8, usize), i32> {
    let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).map_err(|_| -EINVAL)?;
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let mut ace_count = 0usize;
    let mut dacl_len = ACL_HEADER_LEN;

    for (mask, sid) in [
        (self_mask, owner_sid),
        (admin_mask, administrators),
        (system_mask, system),
        (everyone_mask, everyone),
    ] {
        if mask.is_some() {
            ace_count = ace_count.checked_add(1).ok_or(-ERANGE)?;
            dacl_len = dacl_len.checked_add(ace_len_for_sid(sid)?).ok_or(-ERANGE)?;
        }
    }

    let owner_len = owner_sid.as_bytes().len();
    let group_len = group_sid.as_bytes().len();
    let group_offset = SD_HEADER_LEN.checked_add(owner_len).ok_or(-ERANGE)?;
    let dacl_offset = group_offset.checked_add(group_len).ok_or(-ERANGE)?;
    let total_len = dacl_offset.checked_add(dacl_len).ok_or(-ERANGE)?;
    let ptr = unsafe { pkm_kacs_zalloc(total_len) } as *mut u8;
    let mut cursor = ACL_HEADER_LEN;

    if ptr.is_null() {
        return Err(-ENOMEM);
    }

    let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, total_len) };
    bytes[0] = 1;
    bytes[1] = 0;
    write_le_u16(bytes, 2, crate::security_descriptor::SE_SELF_RELATIVE | crate::security_descriptor::SE_DACL_PRESENT);
    write_le_u32(bytes, 4, SD_HEADER_LEN as u32);
    write_le_u32(bytes, 8, group_offset as u32);
    write_le_u32(bytes, 12, 0);
    write_le_u32(bytes, 16, dacl_offset as u32);
    bytes[SD_HEADER_LEN..group_offset].copy_from_slice(owner_sid.as_bytes());
    bytes[group_offset..dacl_offset].copy_from_slice(group_sid.as_bytes());

    bytes[dacl_offset] = ACL_REVISION;
    bytes[dacl_offset + 1] = 0;
    write_le_u16(bytes, dacl_offset + 2, dacl_len as u16);
    write_le_u16(bytes, dacl_offset + 4, ace_count as u16);
    write_le_u16(bytes, dacl_offset + 6, 0);

    for (mask, sid) in [
        (self_mask, owner_sid),
        (admin_mask, administrators),
        (system_mask, system),
        (everyone_mask, everyone),
    ] {
        if let Some(mask) = mask {
            let written = write_allow_ace(&mut bytes[dacl_offset..], cursor, mask, sid)?;
            cursor = cursor.checked_add(written).ok_or(-ERANGE)?;
        }
    }

    Ok((ptr, total_len))
}

fn build_default_process_sd_bytes(token: &PkmKacsBootToken) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid,
        group_sid,
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        Some(PROCESS_QUERY_LIMITED),
    )
}

fn build_default_socket_sd_bytes(token: &PkmKacsBootToken) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid,
        group_sid,
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        None,
    )
}

fn build_token_sd_bytes(
    creator_sid: Sid<'_>,
    token_user_sid: Sid<'_>,
    self_mask: Option<u32>,
    creator_mask: Option<u32>,
    system_mask: Option<u32>,
) -> Result<(*mut u8, usize), i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;
    let mut ace_count = 0usize;
    let mut dacl_len = ACL_HEADER_LEN;

    for (mask, sid) in [
        (self_mask, token_user_sid),
        (creator_mask, creator_sid),
        (system_mask, system),
    ] {
        if mask.is_some() {
            ace_count = ace_count.checked_add(1).ok_or(-ERANGE)?;
            dacl_len = dacl_len.checked_add(ace_len_for_sid(sid)?).ok_or(-ERANGE)?;
        }
    }

    let owner_len = creator_sid.as_bytes().len();
    let group_len = creator_sid.as_bytes().len();
    let group_offset = SD_HEADER_LEN.checked_add(owner_len).ok_or(-ERANGE)?;
    let dacl_offset = group_offset.checked_add(group_len).ok_or(-ERANGE)?;
    let total_len = dacl_offset.checked_add(dacl_len).ok_or(-ERANGE)?;
    let ptr = unsafe { pkm_kacs_zalloc(total_len) } as *mut u8;
    let mut cursor = ACL_HEADER_LEN;

    if ptr.is_null() {
        return Err(-ENOMEM);
    }

    let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, total_len) };
    bytes[0] = 1;
    bytes[1] = 0;
    write_le_u16(
        bytes,
        2,
        crate::security_descriptor::SE_SELF_RELATIVE
            | crate::security_descriptor::SE_DACL_PRESENT,
    );
    write_le_u32(bytes, 4, SD_HEADER_LEN as u32);
    write_le_u32(bytes, 8, group_offset as u32);
    write_le_u32(bytes, 12, 0);
    write_le_u32(bytes, 16, dacl_offset as u32);
    bytes[SD_HEADER_LEN..group_offset].copy_from_slice(creator_sid.as_bytes());
    bytes[group_offset..dacl_offset].copy_from_slice(creator_sid.as_bytes());

    bytes[dacl_offset] = ACL_REVISION;
    bytes[dacl_offset + 1] = 0;
    write_le_u16(bytes, dacl_offset + 2, dacl_len as u16);
    write_le_u16(bytes, dacl_offset + 4, ace_count as u16);
    write_le_u16(bytes, dacl_offset + 6, 0);

    for (mask, sid) in [
        (self_mask, token_user_sid),
        (creator_mask, creator_sid),
        (system_mask, system),
    ] {
        if let Some(mask) = mask {
            let written = write_allow_ace(&mut bytes[dacl_offset..], cursor, mask, sid)?;
            cursor = cursor.checked_add(written).ok_or(-ERANGE)?;
        }
    }

    Ok((ptr, total_len))
}

fn build_query_limited_only_process_sd_bytes(
    token: &PkmKacsBootToken,
) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(token.user_sid, group_sid, None, None, None, Some(PROCESS_QUERY_LIMITED))
}

fn build_query_information_only_process_sd_bytes(
    token: &PkmKacsBootToken,
) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid,
        group_sid,
        None,
        None,
        None,
        Some(PROCESS_QUERY_INFORMATION),
    )
}

fn build_read_only_socket_sd_bytes(
    token: &PkmKacsBootToken,
) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid,
        group_sid,
        None,
        None,
        None,
        Some(READ_CONTROL),
    )
}

impl PkmKacsBootToken {
    fn create_system_like(
        user_sid: Sid<'static>,
        creator_sid: Sid<'static>,
        integrity_level: IntegrityLevel,
        token_type: TokenType,
        impersonation_level: ImpersonationLevel,
        restricted: bool,
        token_id: u64,
        modified_id: u64,
        privileges_present: u64,
        privileges_enabled: u64,
        privileges_enabled_by_default: u64,
        group_attributes: [u32; MAX_BOOT_GROUPS],
        include_user_group: bool,
        audit_policy: u32,
    ) -> Option<*const c_void> {
        let logon_sid = Sid::parse(LOGON_SID_BYTES).ok()?;
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;
        let (default_dacl_ptr, default_dacl_len) =
            alloc_copy_bytes(SYSTEM_DEFAULT_DACL_BYTES).ok()?;
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            creator_sid,
            user_sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
        ) {
            Ok(value) => value,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                return None;
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return None;
        }

        let group_sids = [
            administrators,
            if include_user_group {
                user_sid
            } else {
                everyone
            },
            authenticated_users,
            local,
            logon_sid,
        ];
        let group_default_attributes = group_attributes;
        let group_views = build_group_views(&group_sids, &group_default_attributes);
        let group_attributes = group_default_attributes.map(AtomicU32::new);

        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: PkmKacsBootSession {
                session_id: 0,
                logon_type: LOGON_TYPE_SERVICE,
                user_sid,
                auth_package: AUTH_PACKAGE_NEGOTIATE,
                logon_sid,
            },
            user_sid,
            logon_sid,
            group_count: MAX_BOOT_GROUPS,
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            token_id,
            created_at: 0,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(BOOT_SYSTEM_OWNER_SID_INDEX),
            primary_group_index: AtomicU32::new(BOOT_SYSTEM_PRIMARY_GROUP_INDEX),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(privileges_present),
            privileges_enabled: AtomicU64::new(privileges_enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges_enabled_by_default),
            privileges_used: AtomicU64::new(0),
            integrity_level,
            mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            token_type,
            impersonation_level,
            restricted,
            audit_policy,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: 0,
            projected_gid: 0,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        Some(token_ptr.cast())
    }

    fn create_system() -> Option<*const c_void> {
        Self::create_system_like(
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            BOOT_SYSTEM_TOKEN_ID,
            BOOT_SYSTEM_MODIFIED_ID,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            false,
            0,
        )
    }

    fn create_query_only_system() -> Option<*const c_void> {
        let user_sid = Sid::parse(SYSTEM_SID_BYTES).ok()?;
        let creator_sid = user_sid;
        let logon_sid = Sid::parse(LOGON_SID_BYTES).ok()?;
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;
        let (default_dacl_ptr, default_dacl_len) =
            alloc_copy_bytes(SYSTEM_DEFAULT_DACL_BYTES).ok()?;
        let (own_sd_ptr, own_sd_len) = build_token_sd_bytes(
            creator_sid,
            user_sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            None,
            None,
        )
        .ok()?;
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return None;
        }
        let group_sids = [administrators, everyone, authenticated_users, local, logon_sid];
        let group_default_attributes = BOOT_SYSTEM_GROUP_ATTRIBUTES;
        let group_views = build_group_views(&group_sids, &group_default_attributes);
        let group_attributes = group_default_attributes.map(AtomicU32::new);
        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: PkmKacsBootSession {
                session_id: 0,
                logon_type: LOGON_TYPE_SERVICE,
                user_sid,
                auth_package: AUTH_PACKAGE_NEGOTIATE,
                logon_sid,
            },
            user_sid,
            logon_sid,
            group_count: MAX_BOOT_GROUPS,
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            token_id: BOOT_SYSTEM_TOKEN_ID,
            created_at: 0,
            modified_id: AtomicU64::new(BOOT_SYSTEM_MODIFIED_ID),
            owner_sid_index: AtomicU32::new(BOOT_SYSTEM_OWNER_SID_INDEX),
            primary_group_index: AtomicU32::new(BOOT_SYSTEM_PRIMARY_GROUP_INDEX),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(SYSTEM_PRIVILEGES_ALL),
            privileges_enabled: AtomicU64::new(SYSTEM_PRIVILEGES_ALL),
            privileges_enabled_by_default: AtomicU64::new(SYSTEM_PRIVILEGES_ALL),
            privileges_used: AtomicU64::new(0),
            integrity_level: IntegrityLevel::System,
            mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            token_type: TokenType::Primary,
            impersonation_level: ImpersonationLevel::Anonymous,
            restricted: false,
            audit_policy: 0,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: 0,
            projected_gid: 0,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        Some(token_ptr.cast())
    }

    fn create_without_tcb() -> Option<*const c_void> {
        let privileges = SYSTEM_PRIVILEGES_ALL & !SE_TCB_PRIVILEGE;

        Self::create_system_like(
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            BOOT_SYSTEM_TOKEN_ID,
            BOOT_SYSTEM_MODIFIED_ID,
            privileges,
            privileges,
            privileges,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            false,
            0,
        )
    }

    fn create_adjustable_groups() -> Option<*const c_void> {
        Self::create_system_like(
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            BOOT_SYSTEM_TOKEN_ID,
            BOOT_SYSTEM_MODIFIED_ID,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            KUNIT_ADJUSTABLE_GROUP_ATTRIBUTES,
            true,
            0,
        )
    }

    fn create_adjustable_privileges() -> Option<*const c_void> {
        Self::create_system_like(
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            BOOT_SYSTEM_TOKEN_ID,
            BOOT_SYSTEM_MODIFIED_ID,
            KUNIT_ADJUSTABLE_PRIVILEGES_PRESENT,
            KUNIT_ADJUSTABLE_PRIVILEGES_ENABLED,
            KUNIT_ADJUSTABLE_PRIVILEGES_ENABLED_BY_DEFAULT,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            false,
            0,
        )
    }

    fn create_privilege_audit() -> Option<*const c_void> {
        Self::create_system_like(
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            BOOT_SYSTEM_TOKEN_ID,
            BOOT_SYSTEM_MODIFIED_ID,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            SYSTEM_PRIVILEGES_ALL,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            false,
            AUDIT_POLICY_PRIVILEGE_USE_SUCCESS | AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
        )
    }

    fn create_kunit_variant(
        user_sid: Sid<'static>,
        integrity_level: IntegrityLevel,
        token_type: TokenType,
        impersonation_level: ImpersonationLevel,
        restricted: bool,
        enabled_privileges: u64,
    ) -> Option<*const c_void> {
        let token_id = allocate_dynamic_token_id().ok()?;

        Self::create_system_like(
            user_sid,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            integrity_level,
            token_type,
            impersonation_level,
            restricted,
            token_id,
            token_id,
            enabled_privileges,
            enabled_privileges,
            enabled_privileges,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            false,
            0,
        )
    }

    fn create_anonymous() -> Option<*const c_void> {
        let anonymous = Sid::parse(ANONYMOUS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let logon_sid = Sid::parse(ANONYMOUS_LOGON_SID_BYTES).ok()?;
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(&[]).ok()?;
        let (own_sd_ptr, own_sd_len) = build_token_sd_bytes(
            anonymous,
            anonymous,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            None,
            None,
        )
        .ok()?;
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        let token_id = allocate_dynamic_token_id().ok()?;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return None;
        }

        let empty_sid = Sid::parse(SYSTEM_SID_BYTES).ok()?;
        let group_sids = [everyone, empty_sid, empty_sid, empty_sid, empty_sid];
        let group_default_attributes = ANONYMOUS_ONLY_GROUP_ATTRIBUTES;
        let group_views = build_group_views(&group_sids, &group_default_attributes);
        let group_attributes = group_default_attributes.map(AtomicU32::new);
        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: PkmKacsBootSession {
                session_id: ANONYMOUS_LOGON_LUID,
                logon_type: LOGON_TYPE_NETWORK,
                user_sid: anonymous,
                auth_package: AUTH_PACKAGE_NEGOTIATE,
                logon_sid,
            },
            user_sid: anonymous,
            logon_sid,
            group_count: 1,
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            token_id,
            created_at: 0,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(0),
            primary_group_index: AtomicU32::new(1),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(0),
            privileges_enabled: AtomicU64::new(0),
            privileges_enabled_by_default: AtomicU64::new(0),
            privileges_used: AtomicU64::new(0),
            integrity_level: IntegrityLevel::Untrusted,
            mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            token_type: TokenType::Impersonation,
            impersonation_level: ImpersonationLevel::Anonymous,
            restricted: false,
            audit_policy: 0,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: ANONYMOUS_PROJECTED_ID,
            projected_gid: ANONYMOUS_PROJECTED_ID,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        Some(token_ptr.cast())
    }

    unsafe fn from_ptr<'a>(ptr: *const c_void) -> Option<&'a Self> {
        unsafe { (ptr as *const Self).as_ref() }
    }

    fn clone_ref(ptr: *const c_void) -> *const c_void {
        let Some(token) = (unsafe { Self::from_ptr(ptr) }) else {
            return null();
        };
        token.refcount.fetch_add(1, Ordering::Relaxed);
        ptr
    }

    fn deep_copy(ptr: *const c_void) -> *const c_void {
        let Some(token) = (unsafe { Self::from_ptr(ptr) }) else {
            return null();
        };
        let _guard = token.lock_mutation();
        let privileges = token.privileges_snapshot_locked();
        let group_attributes = token.current_group_attributes();
        let (default_dacl_ptr, default_dacl_len) =
            match alloc_copy_bytes(token.default_dacl_bytes()) {
                Ok(copy) => copy,
                Err(_) => return null(),
            };
        let (own_sd_ptr, own_sd_len) = match alloc_copy_bytes(token.own_sd_bytes()) {
            Ok(copy) => copy,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                return null();
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return null();
        }
        let copy = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: token.session,
            user_sid: token.user_sid,
            logon_sid: token.logon_sid,
            group_count: token.group_count,
            group_sids: token.group_sids,
            group_default_attributes: token.group_default_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&token.group_sids, &group_attributes)),
            token_id: token.token_id,
            created_at: token.created_at,
            modified_id: AtomicU64::new(token.modified_id.load(Ordering::Relaxed)),
            owner_sid_index: AtomicU32::new(token.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(token.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(privileges.present),
            privileges_enabled: AtomicU64::new(privileges.enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges.enabled_by_default),
            privileges_used: AtomicU64::new(privileges.used),
            integrity_level: token.integrity_level,
            mandatory_policy: token.mandatory_policy,
            token_type: token.token_type,
            impersonation_level: token.impersonation_level,
            restricted: token.restricted,
            audit_policy: token.audit_policy,
            interactive_session_id: AtomicU32::new(
                token.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: token.projected_uid,
            projected_gid: token.projected_gid,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, copy) };
        token_ptr.cast()
    }

    fn duplicate(
        &self,
        creator: &PkmKacsBootToken,
        new_type: TokenType,
        requested_level: ImpersonationLevel,
    ) -> Result<*const c_void, i32> {
        let _guard = self.lock_mutation();
        let privileges = self.privileges_snapshot_locked();
        let group_attributes = self.current_group_attributes();
        let group_default_attributes = group_attributes;
        let token_id = allocate_dynamic_token_id()?;
        let modified_id = token_id;
        let impersonation_level = match new_type {
            TokenType::Primary => ImpersonationLevel::Anonymous,
            TokenType::Impersonation => {
                if self.token_type == TokenType::Impersonation
                    && impersonation_level_abi(requested_level)
                        > impersonation_level_abi(self.impersonation_level)
                {
                    return Err(-EINVAL);
                }
                requested_level
            }
        };
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            creator.user_sid,
            self.user_sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
        ) {
            Ok(value) => value,
            Err(err) => {
                free_allocated_bytes(default_dacl_ptr);
                return Err(err);
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return Err(-ENOMEM);
        }

        let duplicate = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: self.session,
            user_sid: self.user_sid,
            logon_sid: self.logon_sid,
            group_count: self.group_count,
            group_sids: self.group_sids,
            group_default_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&self.group_sids, &group_attributes)),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(
                self.primary_group_index.load(Ordering::Relaxed),
            ),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(privileges.present),
            privileges_enabled: AtomicU64::new(privileges.enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges.enabled_by_default),
            privileges_used: AtomicU64::new(privileges.used),
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            token_type: new_type,
            impersonation_level,
            restricted: self.restricted,
            audit_policy: self.audit_policy,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, duplicate) };
        Ok(token_ptr.cast())
    }

    fn clone_with_impersonation_level(
        &self,
        level: ImpersonationLevel,
    ) -> Result<*const c_void, i32> {
        if self.token_type != TokenType::Impersonation {
            return Err(-EINVAL);
        }
        if impersonation_level_abi(level) > impersonation_level_abi(self.impersonation_level) {
            return Err(-EINVAL);
        }
        if level == self.impersonation_level {
            return Ok(Self::clone_ref((self as *const Self).cast()));
        }

        let _guard = self.lock_mutation();
        let privileges = self.privileges_snapshot_locked();
        let group_attributes = self.current_group_attributes();
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let (own_sd_ptr, own_sd_len) = match alloc_copy_bytes(self.own_sd_bytes()) {
            Ok(value) => value,
            Err(err) => {
                free_allocated_bytes(default_dacl_ptr);
                return Err(err);
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            return Err(-ENOMEM);
        }

        let derived = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session: self.session,
            user_sid: self.user_sid,
            logon_sid: self.logon_sid,
            group_count: self.group_count,
            group_sids: self.group_sids,
            group_default_attributes: self.group_default_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&self.group_sids, &group_attributes)),
            token_id: self.token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(self.modified_id.load(Ordering::Relaxed)),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(
                self.primary_group_index.load(Ordering::Relaxed),
            ),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(privileges.present),
            privileges_enabled: AtomicU64::new(privileges.enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges.enabled_by_default),
            privileges_used: AtomicU64::new(privileges.used),
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            token_type: TokenType::Impersonation,
            impersonation_level: level,
            restricted: self.restricted,
            audit_policy: self.audit_policy,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, derived) };
        Ok(token_ptr.cast())
    }

    unsafe fn drop_ref(ptr: *const c_void) {
        let Some(token) = (unsafe { Self::from_ptr(ptr) }) else {
            return;
        };
        if token.refcount.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            let token_ptr = ptr as *mut Self;
            free_allocated_bytes(token.default_dacl_ptr.load(Ordering::Relaxed));
            free_allocated_bytes(token.own_sd_ptr.load(Ordering::Relaxed));
            unsafe { core::ptr::drop_in_place(token_ptr) };
            unsafe { pkm_kacs_free(token_ptr.cast()) };
        }
    }

    fn boot_snapshot(&self, out: &mut PkmKacsBootSnapshot) {
        let _guard = self.lock_mutation();
        let owner_sid_index = self.owner_sid_index.load(Ordering::Relaxed);
        let primary_group_index = self.primary_group_index.load(Ordering::Relaxed);
        let default_dacl = self.default_dacl_bytes();
        let privileges = self.privileges_snapshot_locked();
        let group_views = unsafe { &*self.group_views.get() };

        *out = PkmKacsBootSnapshot {
            token_ptr: (self as *const Self).cast(),
            session_id: self.session.session_id,
            auth_id: self.session.session_id,
            token_id: self.token_id,
            modified_id: self.modified_id.load(Ordering::Relaxed),
            logon_type: self.session.logon_type,
            auth_pkg_ptr: self.session.auth_package.as_ptr(),
            auth_pkg_len: self.session.auth_package.len(),
            user_sid_ptr: self.session.user_sid.as_bytes().as_ptr(),
            user_sid_len: self.session.user_sid.as_bytes().len(),
            logon_sid_ptr: self.session.logon_sid.as_bytes().as_ptr(),
            logon_sid_len: self.session.logon_sid.as_bytes().len(),
            groups_ptr: group_views.as_ptr(),
            group_count: self.group_count as u32,
            owner_sid_index,
            primary_group_index,
            default_dacl_ptr: default_dacl.as_ptr(),
            default_dacl_len: default_dacl.len(),
            privileges_present: privileges.present,
            privileges_enabled: privileges.enabled,
            privileges_enabled_by_default: privileges.enabled_by_default,
            privileges_used: self.privileges_used.load(Ordering::Acquire),
            integrity_level: self.integrity_level as u32,
            token_type: token_type_abi(self.token_type),
            impersonation_level: impersonation_level_abi(self.impersonation_level),
            mandatory_policy: self.mandatory_policy,
            interactive_session_id: self.interactive_session_id.load(Ordering::Relaxed),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            audit_policy: self.audit_policy,
        };
    }

    fn privileges_snapshot_locked(&self) -> TokenPrivileges {
        TokenPrivileges {
            present: self.privileges_present.load(Ordering::Relaxed),
            enabled: self.privileges_enabled.load(Ordering::Relaxed),
            enabled_by_default: self.privileges_enabled_by_default.load(Ordering::Relaxed),
            used: self.privileges_used.load(Ordering::Acquire),
        }
    }

    fn privileges_snapshot(&self) -> TokenPrivileges {
        let _guard = self.lock_mutation();
        self.privileges_snapshot_locked()
    }

    fn mark_privileges_used(&self, used_mask: u64) {
        self.privileges_used.fetch_or(used_mask, Ordering::AcqRel);
    }

    fn lock_mutation(&self) -> TokenMutationGuard<'_> {
        while self
            .mutation_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        TokenMutationGuard { token: self }
    }

    fn adjust_session_id(&self, session_id: u32) -> Result<(), i32> {
        let _guard = self.lock_mutation();
        let modified_id = self.modified_id.load(Ordering::Relaxed);
        let Some(next_modified_id) = modified_id.checked_add(1) else {
            return Err(-ERANGE);
        };

        self.interactive_session_id
            .store(session_id, Ordering::Relaxed);
        self.modified_id.store(next_modified_id, Ordering::Relaxed);
        Ok(())
    }

    fn adjust_privileges(&self, entries: &[PkmKacsPrivilegeAdjustEntry]) -> Result<u64, i32> {
        let mut seen = [false; MAX_PRIVILEGE_ADJUST_ENTRIES];
        let _guard = self.lock_mutation();
        let previous = self.privileges_snapshot_locked();
        let modified_id = self.modified_id.load(Ordering::Relaxed);
        let Some(next_modified_id) = modified_id.checked_add(1) else {
            return Err(-ERANGE);
        };
        let mut next_present = previous.present;
        let mut next_enabled = previous.enabled;
        let mut next_enabled_by_default = previous.enabled_by_default;

        if entries.is_empty() {
            return Err(-EINVAL);
        }
        if entries[0].attributes == KACS_PRIV_RESET_ALL_DEFAULTS {
            if entries.len() != 1 || entries[0].luid != 0 {
                return Err(-EINVAL);
            }
            next_enabled = next_enabled_by_default & next_present;
            self.privileges_present
                .store(next_present, Ordering::Relaxed);
            self.privileges_enabled
                .store(next_enabled, Ordering::Relaxed);
            self.privileges_enabled_by_default
                .store(next_enabled_by_default, Ordering::Relaxed);
            self.modified_id.store(next_modified_id, Ordering::Relaxed);
            return Ok(previous.enabled);
        }

        for entry in entries {
            let mask = match entry.luid {
                0..=63 => 1u64 << entry.luid,
                _ => return Err(-EINVAL),
            };

            if seen[entry.luid as usize] {
                return Err(-EINVAL);
            }
            seen[entry.luid as usize] = true;

            match entry.attributes {
                0 | SE_PRIVILEGE_REMOVED => {}
                SE_PRIVILEGE_ENABLED => {
                    if (previous.present & mask) == 0 {
                        return Err(-EINVAL);
                    }
                }
                _ => return Err(-EINVAL),
            }
        }

        for entry in entries {
            let mask = 1u64 << entry.luid;

            match entry.attributes {
                0 => {
                    next_enabled &= !mask;
                }
                SE_PRIVILEGE_ENABLED => {
                    next_enabled |= mask;
                }
                SE_PRIVILEGE_REMOVED => {
                    next_present &= !mask;
                    next_enabled &= !mask;
                    next_enabled_by_default &= !mask;
                }
                _ => return Err(-EINVAL),
            }
        }

        self.privileges_present
            .store(next_present, Ordering::Relaxed);
        self.privileges_enabled
            .store(next_enabled, Ordering::Relaxed);
        self.privileges_enabled_by_default
            .store(next_enabled_by_default, Ordering::Relaxed);
        self.modified_id.store(next_modified_id, Ordering::Relaxed);
        Ok(previous.enabled)
    }

    fn default_dacl_bytes(&self) -> &[u8] {
        let ptr = self.default_dacl_ptr.load(Ordering::Relaxed);
        let len = self.default_dacl_len.load(Ordering::Relaxed);

        if len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(ptr.cast_const(), len) }
    }

    fn own_sd_bytes(&self) -> &[u8] {
        let ptr = self.own_sd_ptr.load(Ordering::Relaxed);
        let len = self.own_sd_len.load(Ordering::Relaxed);

        if len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(ptr.cast_const(), len) }
    }

    fn current_group_attributes(&self) -> [u32; MAX_BOOT_GROUPS] {
        core::array::from_fn(|index| self.group_attributes[index].load(Ordering::Relaxed))
    }

    fn current_groups(&self) -> [SidAndAttributes<'static>; MAX_BOOT_GROUPS] {
        let group_attributes = self.current_group_attributes();

        core::array::from_fn(|index| SidAndAttributes {
            sid: self.group_sids[index],
            attributes: group_attributes[index],
        })
    }

    fn sync_group_views_locked(&self, group_attributes: &[u32; MAX_BOOT_GROUPS]) {
        let group_views = unsafe { &mut *self.group_views.get() };

        for index in 0..group_views.len() {
            group_views[index].attributes = group_attributes[index];
        }
    }

    fn current_group_enabled_mask_locked(&self) -> u64 {
        let mut mask = 0u64;

        for index in 0..self.group_count.min(64) {
            let attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if (attributes & SE_GROUP_ENABLED) == SE_GROUP_ENABLED {
                mask |= 1u64 << index;
            }
        }

        mask
    }

    fn group_sid_at(&self, index: u32) -> Option<Sid<'static>> {
        if (index as usize) >= self.group_count {
            return None;
        }

        self.group_sids.get(index as usize).copied()
    }

    fn validate_owner_index(&self, index: u32) -> bool {
        if index == 0 {
            return true;
        }

        if ((index - 1) as usize) >= self.group_count {
            return false;
        }

        self.group_attributes
            .get((index - 1) as usize)
            .map(|entry| (entry.load(Ordering::Relaxed) & SE_GROUP_OWNER) == SE_GROUP_OWNER)
            .unwrap_or(false)
    }

    fn validate_group_index(&self, index: u32) -> bool {
        if index == 0 {
            return true;
        }

        ((index - 1) as usize) < self.group_count
    }

    fn adjust_default(
        &self,
        owner_index: u32,
        group_index: u32,
        dacl: Option<&[u8]>,
    ) -> Result<(), i32> {
        let (replacement_ptr, replacement_len) = match dacl {
            Some(bytes) => {
                if bytes.len() > MAX_DEFAULT_DACL_BYTES {
                    return Err(-EINVAL);
                }
                if !bytes.is_empty() {
                    Acl::parse(bytes).map_err(|_| -EINVAL)?;
                }
                alloc_copy_bytes(bytes)?
            }
            None => (null_mut(), 0),
        };
        let old_default_dacl_ptr;

        if owner_index != TOKEN_INDEX_NO_CHANGE && !self.validate_owner_index(owner_index) {
            free_allocated_bytes(replacement_ptr);
            return Err(-EINVAL);
        }
        if group_index != TOKEN_INDEX_NO_CHANGE && !self.validate_group_index(group_index) {
            free_allocated_bytes(replacement_ptr);
            return Err(-EINVAL);
        }

        {
            let _guard = self.lock_mutation();
            let modified_id = self.modified_id.load(Ordering::Relaxed);
            let Some(next_modified_id) = modified_id.checked_add(1) else {
                free_allocated_bytes(replacement_ptr);
                return Err(-ERANGE);
            };

            if owner_index != TOKEN_INDEX_NO_CHANGE {
                self.owner_sid_index.store(owner_index, Ordering::Relaxed);
            }
            if group_index != TOKEN_INDEX_NO_CHANGE {
                self.primary_group_index
                    .store(group_index, Ordering::Relaxed);
            }

            old_default_dacl_ptr = if dacl.is_some() {
                self.default_dacl_len
                    .store(replacement_len, Ordering::Relaxed);
                self.default_dacl_ptr
                    .swap(replacement_ptr, Ordering::Relaxed)
            } else {
                null_mut()
            };
            self.modified_id.store(next_modified_id, Ordering::Relaxed);
        }

        free_allocated_bytes(old_default_dacl_ptr);
        Ok(())
    }

    fn sid_by_index(&self, index: u32) -> Option<Sid<'_>> {
        if index == 0 {
            return Some(self.user_sid);
        }

        self.group_sid_at(index - 1)
    }

    fn with_access_token<T>(&self, f: impl FnOnce(AccessCheckToken<'_>) -> T) -> T {
        let (groups, privileges) = {
            let _guard = self.lock_mutation();
            (self.current_groups(), self.privileges_snapshot_locked())
        };
        let access_token = AccessCheckToken {
            subject: TokenView {
                user: self.user_sid,
                user_deny_only: false,
                groups: &groups[..self.group_count],
            },
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            audit_policy: self.audit_policy,
            privileges,
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            restricted: RestrictedTokenContext::default(),
            confinement: ConfinementTokenContext::default(),
        };

        f(access_token)
    }

    fn group_query_required_len(&self) -> Result<usize, i32> {
        sid_query_len(&self.group_sids[..self.group_count]).ok_or(-EINVAL)
    }

    fn write_group_query(&self, writer: &mut QueryWriter) -> Result<(), i32> {
        let _guard = self.lock_mutation();

        if self.group_count > u32::MAX as usize {
            return Err(-EINVAL);
        }
        if !writer.write_u32(self.group_count as u32) {
            return Err(-ERANGE);
        }

        for index in 0..self.group_count {
            let sid = self.group_sids[index].as_bytes();
            let attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if sid.len() > u32::MAX as usize {
                return Err(-EINVAL);
            }
            if !writer.write_u32(sid.len() as u32) {
                return Err(-ERANGE);
            }
            if !writer.write_bytes(sid) {
                return Err(-ERANGE);
            }
            if !writer.write_u32(attributes) {
                return Err(-ERANGE);
            }
        }

        Ok(())
    }

    fn adjust_groups(&self, entries: &[PkmKacsGroupAdjustEntry]) -> Result<u64, i32> {
        let mut seen = [false; MAX_BOOT_GROUPS];
        let _guard = self.lock_mutation();
        let previous_state = self.current_group_enabled_mask_locked();
        let modified_id = self.modified_id.load(Ordering::Relaxed);
        let Some(next_modified_id) = modified_id.checked_add(1) else {
            return Err(-ERANGE);
        };

        if entries.is_empty() {
            return Err(-EINVAL);
        }
        if entries[0].index == u32::MAX {
            if entries.len() != 1 || entries[0].enable != 0 {
                return Err(-EINVAL);
            }
            for index in 0..self.group_count {
                self.group_attributes[index]
                    .store(self.group_default_attributes[index], Ordering::Relaxed);
            }
            self.sync_group_views_locked(&self.group_default_attributes);
            self.modified_id.store(next_modified_id, Ordering::Relaxed);
            return Ok(previous_state);
        }

        for entry in entries {
            let index = entry.index as usize;
            if index >= self.group_count {
                return Err(-EINVAL);
            }
            let Some(group_sid) = self.group_sids.get(index) else {
                return Err(-EINVAL);
            };
            let attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if entry.enable > 1 {
                return Err(-EINVAL);
            }
            if seen[index] {
                return Err(-EINVAL);
            }
            seen[index] = true;

            if entry.enable == 0 {
                if (attributes & SE_GROUP_MANDATORY) == SE_GROUP_MANDATORY
                    || (attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID
                    || group_sid.as_bytes() == self.user_sid.as_bytes()
                {
                    return Err(-EINVAL);
                }
            } else if (attributes & SE_GROUP_USE_FOR_DENY_ONLY) == SE_GROUP_USE_FOR_DENY_ONLY {
                return Err(-EINVAL);
            }
        }

        for entry in entries {
            let index = entry.index as usize;
            let mut attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if entry.enable == 0 {
                attributes &= !SE_GROUP_ENABLED;
            } else {
                attributes |= SE_GROUP_ENABLED;
            }
            self.group_attributes[index].store(attributes, Ordering::Relaxed);
        }

        let current_group_attributes = self.current_group_attributes();
        self.sync_group_views_locked(&current_group_attributes);
        self.modified_id.store(next_modified_id, Ordering::Relaxed);
        Ok(previous_state)
    }

    fn query_required_len(&self, token_class: u32) -> Result<usize, i32> {
        match token_class {
            TOKEN_CLASS_USER => Ok(self.user_sid.as_bytes().len()),
            TOKEN_CLASS_GROUPS => self.group_query_required_len(),
            TOKEN_CLASS_PRIVILEGES => Ok(32),
            TOKEN_CLASS_TYPE => Ok(4),
            TOKEN_CLASS_INTEGRITY_LEVEL => Ok(12),
            TOKEN_CLASS_OWNER => {
                let _guard = self.lock_mutation();

                self.sid_by_index(self.owner_sid_index.load(Ordering::Relaxed))
                    .map(|sid| sid.as_bytes().len())
                    .ok_or(-EINVAL)
            }
            TOKEN_CLASS_PRIMARY_GROUP => {
                let _guard = self.lock_mutation();

                self.sid_by_index(self.primary_group_index.load(Ordering::Relaxed))
                    .map(|sid| sid.as_bytes().len())
                    .ok_or(-EINVAL)
            }
            TOKEN_CLASS_STATISTICS => Ok(40),
            TOKEN_CLASS_DEFAULT_DACL => {
                let _guard = self.lock_mutation();
                Ok(self.default_dacl_bytes().len())
            }
            TOKEN_CLASS_SESSION_ID => Ok(4),
            TOKEN_CLASS_RESTRICTED_SIDS => Ok(4),
            TOKEN_CLASS_SOURCE => Ok(16),
            TOKEN_CLASS_ORIGIN => Ok(8),
            TOKEN_CLASS_ELEVATION_TYPE => Ok(4),
            TOKEN_CLASS_DEVICE_GROUPS => Ok(4),
            TOKEN_CLASS_APPCONTAINER_SID => Ok(0),
            TOKEN_CLASS_CAPABILITIES => Ok(4),
            TOKEN_CLASS_MANDATORY_POLICY => Ok(4),
            TOKEN_CLASS_LOGON_TYPE => Ok(4),
            TOKEN_CLASS_LOGON_SID => Ok(self.logon_sid.as_bytes().len()),
            TOKEN_CLASS_IMPERSONATION_LEVEL => Ok(4),
            0 => Err(-EINVAL),
            value if value > TOKEN_CLASS_IMPERSONATION_LEVEL => Err(-EINVAL),
            _ => Err(-EINVAL),
        }
    }

    fn write_query(&self, token_class: u32, writer: &mut QueryWriter) -> Result<(), i32> {
        match token_class {
            TOKEN_CLASS_USER => writer.write_bytes(self.user_sid.as_bytes()),
            TOKEN_CLASS_GROUPS => {
                self.write_group_query(writer)?;
                true
            }
            TOKEN_CLASS_PRIVILEGES => {
                let _guard = self.lock_mutation();
                let privileges = self.privileges_snapshot_locked();

                writer.write_u64(privileges.present)
                    && writer.write_u64(privileges.enabled)
                    && writer.write_u64(privileges.enabled_by_default)
                    && writer.write_u64(privileges.used)
            }
            TOKEN_CLASS_TYPE => writer.write_u32(token_type_abi(self.token_type)),
            TOKEN_CLASS_INTEGRITY_LEVEL => write_integrity_sid(writer, self.integrity_level),
            TOKEN_CLASS_OWNER => {
                let _guard = self.lock_mutation();

                self.sid_by_index(self.owner_sid_index.load(Ordering::Relaxed))
                    .map(|sid| writer.write_bytes(sid.as_bytes()))
                    .ok_or(-EINVAL)?
            }
            TOKEN_CLASS_PRIMARY_GROUP => {
                let _guard = self.lock_mutation();

                self.sid_by_index(self.primary_group_index.load(Ordering::Relaxed))
                    .map(|sid| writer.write_bytes(sid.as_bytes()))
                    .ok_or(-EINVAL)?
            }
            TOKEN_CLASS_SESSION_ID => {
                let _guard = self.lock_mutation();
                writer.write_u32(self.interactive_session_id.load(Ordering::Relaxed))
            }
            TOKEN_CLASS_RESTRICTED_SIDS => writer.write_u32(0),
            TOKEN_CLASS_SOURCE => {
                writer.write_bytes(TOKEN_SOURCE_PEI_OS_KRN) && writer.write_u64(0)
            }
            TOKEN_CLASS_STATISTICS => {
                let _guard = self.lock_mutation();
                writer.write_u64(self.token_id)
                    && writer.write_u64(self.session.session_id)
                    && writer.write_u64(self.modified_id.load(Ordering::Relaxed))
                    && writer.write_u32(token_type_abi(self.token_type))
                    && writer.write_u32(0)
                    && writer.write_u64(0)
            }
            TOKEN_CLASS_ORIGIN => writer.write_u64(0),
            TOKEN_CLASS_ELEVATION_TYPE => writer.write_u32(TOKEN_ELEVATION_DEFAULT_ABI),
            TOKEN_CLASS_DEVICE_GROUPS => writer.write_u32(0),
            TOKEN_CLASS_APPCONTAINER_SID => true,
            TOKEN_CLASS_CAPABILITIES => writer.write_u32(0),
            TOKEN_CLASS_MANDATORY_POLICY => writer.write_u32(self.mandatory_policy),
            TOKEN_CLASS_LOGON_TYPE => writer.write_u32(self.session.logon_type),
            TOKEN_CLASS_LOGON_SID => writer.write_bytes(self.logon_sid.as_bytes()),
            TOKEN_CLASS_DEFAULT_DACL => {
                let _guard = self.lock_mutation();
                writer.write_bytes(self.default_dacl_bytes())
            }
            TOKEN_CLASS_IMPERSONATION_LEVEL => {
                writer.write_u32(impersonation_level_abi(self.impersonation_level))
            }
            _ => {
                return Err(self
                    .query_required_len(token_class)
                    .err()
                    .unwrap_or(-EINVAL))
            }
        }
        .then_some(())
        .ok_or(-ERANGE)
    }

    fn own_sd(&self) -> Option<SecurityDescriptor<'_>> {
        SecurityDescriptor::parse(self.own_sd_bytes()).ok()
    }
}

pub(crate) fn with_access_check_resolved_from_token<T>(
    token_ptr: *const c_void,
    default_pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
    f: impl FnOnce(AccessCheckAbiResolved<'_>) -> Result<T, core::ffi::c_long>,
) -> Result<T, core::ffi::c_long> {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return Err(-22);
    };
    token.with_access_token(|access_token| {
        let resolved = AccessCheckAbiResolved {
            token: &access_token,
            default_pip,
            device_groups: EMPTY_DEVICE_GROUPS,
            user_claims: EMPTY_CLAIMS,
            device_claims: EMPTY_CLAIMS,
            policies,
        };
        f(resolved)
    })
}

pub(crate) fn mark_token_privileges_used(token_ptr: *const c_void, used_mask: u64) -> bool {
    if used_mask == 0 {
        return true;
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return false;
    };
    token.mark_privileges_used(used_mask);
    true
}

fn token_has_enabled_privilege(token_ptr: *const c_void, privilege: u64) -> bool {
    if privilege == 0 {
        return false;
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return false;
    };
    let privileges = token.privileges_snapshot();

    (privileges.present & privilege) == privilege && (privileges.enabled & privilege) == privilege
}

fn min_impersonation_level(
    lhs: ImpersonationLevel,
    rhs: ImpersonationLevel,
) -> ImpersonationLevel {
    if impersonation_level_abi(lhs) <= impersonation_level_abi(rhs) {
        lhs
    } else {
        rhs
    }
}

fn impersonation_gate_effective_level(
    server: &PkmKacsBootToken,
    client: &PkmKacsBootToken,
) -> Result<(ImpersonationLevel, bool), i32> {
    let requested = client.impersonation_level;
    let mut permitted = requested;
    let mut used_impersonate = false;
    let same_user = server.user_sid.as_bytes() == client.user_sid.as_bytes();
    let same_restriction = server.restricted == client.restricted;

    if requested == ImpersonationLevel::Anonymous {
        return Ok((ImpersonationLevel::Anonymous, false));
    }

    if same_user && server.restricted && !client.restricted {
        return Err(-EPERM);
    }

    if !(same_user && same_restriction) {
        let privileges = server.privileges_snapshot();
        let has_impersonate = (privileges.present & SE_IMPERSONATE_PRIVILEGE)
            == SE_IMPERSONATE_PRIVILEGE
            && (privileges.enabled & SE_IMPERSONATE_PRIVILEGE) == SE_IMPERSONATE_PRIVILEGE;

        if has_impersonate {
            used_impersonate = true;
        } else {
            permitted = min_impersonation_level(
                permitted,
                ImpersonationLevel::Identification,
            );
        }
    }

    if (client.integrity_level as u32) > (server.integrity_level as u32) {
        permitted = min_impersonation_level(permitted, ImpersonationLevel::Identification);
    }

    Ok((permitted, used_impersonate))
}

fn token_open_check_errno(
    subject_token: *const c_void,
    target_token: *const c_void,
    desired: u32,
) -> i32 {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return -EACCES;
    };
    let Some(target) = (unsafe { PkmKacsBootToken::from_ptr(target_token) }) else {
        return -EACCES;
    };
    let Some(target_sd) = target.own_sd() else {
        return -EACCES;
    };
    let normalized = match TOKEN_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return -22,
        Err(_) => return -EACCES,
    };
    let conditional_context = ConditionalContext::default();
    let pip = PipContext {
        pip_type: 0,
        pip_trust: 0,
    };

    subject.with_access_token(|subject_token| {
        match access_check(
            Some(&target_sd),
            &subject_token,
            pip,
            desired,
            &TOKEN_GENERIC_MAPPING,
            None,
            &conditional_context,
            None,
            0,
            EMPTY_POLICIES,
        ) {
            Ok(result) => {
                if result.allowed {
                    if normalized.maximum_allowed {
                        result.granted as i32
                    } else {
                        (result.granted & normalized.mapped) as i32
                    }
                } else {
                    -EACCES
                }
            }
            Err(KacsError::AllocationFailure) => -ENOMEM,
            Err(KacsError::ReservedAccessMaskBits(_)) => -22,
            Err(KacsError::AccessDenied)
            | Err(KacsError::InvalidAbiInput(_))
            | Err(KacsError::MaximumAllowedInAce(_))
            | Err(KacsError::InvariantViolation(_))
            | Err(KacsError::InvalidTokenInvariant(_))
            | Err(KacsError::MissingSecurityDescriptorOwner)
            | Err(KacsError::MissingSelfRelativeControl(_))
            | Err(KacsError::InvalidSecurityDescriptorRevision(_))
            | Err(KacsError::InconsistentSecurityDescriptorField { .. })
            | Err(KacsError::SecurityDescriptorOffsetOutOfBounds { .. })
            | Err(KacsError::SecurityDescriptorOffsetInsideHeader { .. })
            | Err(KacsError::SecurityDescriptorComponentsOverlap { .. })
            | Err(KacsError::InvalidAclSize(_))
            | Err(KacsError::AclSizeExceedsBuffer { .. })
            | Err(KacsError::AclAceCountMismatch { .. })
            | Err(KacsError::AclTrailingBytes { .. })
            | Err(KacsError::InvalidAceSize(_))
            | Err(KacsError::InvalidSidRevision(_))
            | Err(KacsError::InvalidSidSubAuthorityCount(_))
            | Err(KacsError::InvalidSidLength { .. })
            | Err(KacsError::UnsupportedAceInDacl { .. })
            | Err(KacsError::NullSecurityDescriptor)
            | Err(KacsError::Truncated(_)) => -EACCES,
            Err(_) => -EACCES,
        }
    })
}

fn process_sd_access_check_errno(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
) -> Result<u32, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(|_| -EINVAL)?;
    let normalized = match PROCESS_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };
    let conditional_context = ConditionalContext::default();
    let pip = PipContext {
        pip_type: 0,
        pip_trust: 0,
    };

    subject.with_access_token(|subject_token| {
        match access_check(
            Some(&target_sd),
            &subject_token,
            pip,
            desired,
            &PROCESS_GENERIC_MAPPING,
            None,
            &conditional_context,
            None,
            0,
            EMPTY_POLICIES,
        ) {
            Ok(result) if result.allowed => {
                if normalized.maximum_allowed {
                    Ok(result.granted)
                } else {
                    Ok(result.granted & normalized.mapped)
                }
            }
            Ok(_) => Err(-EACCES),
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EINVAL),
        }
    })
}

fn socket_sd_access_check_errno(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
) -> Result<u32, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(|_| -EINVAL)?;
    let normalized = match SOCKET_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };
    let conditional_context = ConditionalContext::default();
    let pip = PipContext {
        pip_type: 0,
        pip_trust: 0,
    };

    subject.with_access_token(|subject_token| {
        match access_check(
            Some(&target_sd),
            &subject_token,
            pip,
            desired,
            &SOCKET_GENERIC_MAPPING,
            None,
            &conditional_context,
            None,
            0,
            EMPTY_POLICIES,
        ) {
            Ok(result) if result.allowed => {
                if normalized.maximum_allowed {
                    Ok(result.granted)
                } else {
                    Ok(result.granted & normalized.mapped)
                }
            }
            Ok(_) => Err(-EACCES),
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EACCES),
        }
    })
}

#[no_mangle]
/// Creates the boot SYSTEM token object described by Appendix A step 3.
pub extern "C" fn kacs_rust_create_boot_system_token() -> *const c_void {
    PkmKacsBootToken::create_system().unwrap_or(null())
}

#[no_mangle]
/// Increments the reference count on a live PKM token object.
pub extern "C" fn kacs_rust_token_clone(token: *const c_void) -> *const c_void {
    if token.is_null() {
        return null();
    }
    PkmKacsBootToken::clone_ref(token)
}

#[no_mangle]
/// Deep-copies a live PKM token object for process-boundary propagation.
pub extern "C" fn kacs_rust_token_deep_copy(token: *const c_void) -> *const c_void {
    if token.is_null() {
        return null();
    }
    PkmKacsBootToken::deep_copy(token)
}

#[no_mangle]
/// Drops one reference to a live PKM token object.
pub extern "C" fn kacs_rust_token_drop(token: *const c_void) {
    if token.is_null() {
        return;
    }
    unsafe { PkmKacsBootToken::drop_ref(token) };
}

#[no_mangle]
/// Returns whether the supplied live token object is a primary token.
pub extern "C" fn kacs_rust_token_is_primary(token: *const c_void) -> bool {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .map(|value| value.token_type == TokenType::Primary)
        .unwrap_or(false)
}

#[no_mangle]
/// Returns whether two live tokens carry the same user SID bytes.
pub extern "C" fn kacs_rust_token_same_user_sid(lhs: *const c_void, rhs: *const c_void) -> bool {
    let Some(lhs) = (unsafe { PkmKacsBootToken::from_ptr(lhs) }) else {
        return false;
    };
    let Some(rhs) = (unsafe { PkmKacsBootToken::from_ptr(rhs) }) else {
        return false;
    };

    lhs.user_sid.as_bytes() == rhs.user_sid.as_bytes()
}

#[no_mangle]
/// Returns whether the token has all requested standalone privilege bits
/// present and enabled.
pub extern "C" fn kacs_rust_token_has_enabled_privilege(
    token: *const c_void,
    privilege: u64,
) -> bool {
    token_has_enabled_privilege(token, privilege)
}

#[no_mangle]
/// Marks standalone privilege bits used on a live token.
pub extern "C" fn kacs_rust_token_mark_privileges_used(
    token: *const c_void,
    used_mask: u64,
) -> bool {
    mark_token_privileges_used(token, used_mask)
}

#[no_mangle]
/// Runs the bounded token-own-SD AccessCheck needed for Slice 22 token opens.
pub extern "C" fn kacs_rust_token_open_check(
    subject_token: *const c_void,
    target_token: *const c_void,
    desired_access: u32,
    granted_out: *mut u32,
) -> i32 {
    let result = token_open_check_errno(subject_token, target_token, desired_access);
    if result < 0 {
        return result;
    }

    if let Some(granted_out) = unsafe { granted_out.as_mut() } {
        *granted_out = result as u32;
    }
    0
}

#[no_mangle]
/// Duplicates a live token according to the bounded Slice 43 DuplicateToken
/// rules.
pub extern "C" fn kacs_rust_token_duplicate(
    source_token: *const c_void,
    creator_token: *const c_void,
    token_type: u32,
    impersonation_level: u32,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(source_token) = (unsafe { PkmKacsBootToken::from_ptr(source_token) }) else {
        return -EACCES;
    };
    let Some(creator_token) = (unsafe { PkmKacsBootToken::from_ptr(creator_token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };
    let token_type = match token_type_from_abi(token_type) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let impersonation_level = match impersonation_level_from_abi(impersonation_level) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match source_token.duplicate(creator_token, token_type, impersonation_level) {
        Ok(token) => {
            *out_token = token;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Computes the effective impersonation level for a server/client token pair.
pub extern "C" fn kacs_rust_token_impersonation_gate(
    server_token: *const c_void,
    client_token: *const c_void,
    effective_level_out: *mut u32,
    used_impersonate_privilege_out: *mut u32,
) -> i32 {
    let Some(server_token) = (unsafe { PkmKacsBootToken::from_ptr(server_token) }) else {
        return -EACCES;
    };
    let Some(client_token) = (unsafe { PkmKacsBootToken::from_ptr(client_token) }) else {
        return -EACCES;
    };
    let Some(effective_level_out) = (unsafe { effective_level_out.as_mut() }) else {
        return -EINVAL;
    };
    let Some(used_impersonate_privilege_out) =
        (unsafe { used_impersonate_privilege_out.as_mut() })
    else {
        return -EINVAL;
    };

    if client_token.token_type != TokenType::Impersonation {
        return -EINVAL;
    }

    match impersonation_gate_effective_level(server_token, client_token) {
        Ok((level, used_impersonate)) => {
            *effective_level_out = impersonation_level_abi(level);
            *used_impersonate_privilege_out = u32::from(used_impersonate);
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Clones an impersonation token while forcing a specific effective
/// impersonation level no greater than the source level.
pub extern "C" fn kacs_rust_token_clone_with_impersonation_level(
    token: *const c_void,
    impersonation_level: u32,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };
    let impersonation_level = match impersonation_level_from_abi(impersonation_level) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match token.clone_with_impersonation_level(impersonation_level) {
        Ok(clone) => {
            *out_token = clone;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn kacs_rust_create_anonymous_impersonation_token(
    out_token: *mut *const c_void,
) -> i32 {
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };

    match PkmKacsBootToken::create_anonymous() {
        Some(token) => {
            *out_token = token;
            0
        }
        None => -ENOMEM,
    }
}

#[no_mangle]
pub extern "C" fn kacs_rust_create_peer_impersonation_token(
    token: *const c_void,
    impersonation_level: u32,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(source_token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };
    let impersonation_level = match impersonation_level_from_abi(impersonation_level) {
        Ok(value) => value,
        Err(err) => return err,
    };

    if impersonation_level == ImpersonationLevel::Anonymous {
        return kacs_rust_create_anonymous_impersonation_token(out_token);
    }

    match source_token.duplicate(
        source_token,
        TokenType::Impersonation,
        impersonation_level,
    ) {
        Ok(token) => {
            *out_token = token;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Builds the default process SD for a new non-thread child process.
pub extern "C" fn kacs_rust_create_default_process_sd(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_default_process_sd_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds the default abstract-socket SD stamped at bind time.
pub extern "C" fn kacs_rust_create_default_socket_sd(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_default_socket_sd_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a restrictive KUnit-only process SD with only Everyone
/// `PROCESS_QUERY_LIMITED`.
pub extern "C" fn kacs_rust_kunit_create_query_limited_process_sd(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_query_limited_only_process_sd_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a restrictive KUnit-only process SD with only Everyone
/// `PROCESS_QUERY_INFORMATION`.
pub extern "C" fn kacs_rust_kunit_create_query_information_process_sd(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_query_information_only_process_sd_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only abstract-socket SD that grants only `READ_CONTROL` to
/// Everyone, so `FILE_WRITE_DATA` checks fail closed.
pub extern "C" fn kacs_rust_kunit_create_read_only_socket_sd(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_read_only_socket_sd_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Runs AccessCheck against one process SD using the supplied caller token.
pub extern "C" fn kacs_rust_check_process_sd(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match process_sd_access_check_errno(subject_token_ptr, sd_bytes, desired) {
        Ok(granted) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = granted;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one abstract-socket SD using the supplied caller
/// token.
pub extern "C" fn kacs_rust_check_socket_sd(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match socket_sd_access_check_errno(subject_token_ptr, sd_bytes, desired) {
        Ok(granted) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = granted;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Serializes one supported `KACS_IOC_QUERY` token information class.
///
/// When `out` is null or `out_len` is zero, only `required_out` is populated.
pub extern "C" fn kacs_rust_token_query(
    token: *const c_void,
    token_class: u32,
    out: *mut u8,
    out_len: usize,
    required_out: *mut usize,
) -> i32 {
    let Some(required_out) = (unsafe { required_out.as_mut() }) else {
        return -EINVAL;
    };
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let required = match token.query_required_len(token_class) {
        Ok(required) => required,
        Err(err) => return err,
    };

    *required_out = required;
    if out.is_null() || out_len == 0 {
        return 0;
    }
    if out_len < required {
        return -ERANGE;
    }

    let mut writer = QueryWriter::new(out, out_len);
    if let Err(err) = token.write_query(token_class, &mut writer) {
        return err;
    }

    *required_out = writer.written();
    0
}

#[no_mangle]
/// Adjusts a live token's privilege masks and returns the prior enabled mask.
pub extern "C" fn kacs_rust_token_adjust_privs(
    token: *const c_void,
    entries: *const PkmKacsPrivilegeAdjustEntry,
    count: u32,
    previous_enabled_out: *mut u64,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(previous_enabled_out) = (unsafe { previous_enabled_out.as_mut() }) else {
        return -EINVAL;
    };
    if count as usize > MAX_PRIVILEGE_ADJUST_ENTRIES {
        return -EINVAL;
    }
    let entries = if count == 0 {
        &[][..]
    } else if entries.is_null() {
        return -EINVAL;
    } else {
        unsafe { core::slice::from_raw_parts(entries, count as usize) }
    };

    match token.adjust_privileges(entries) {
        Ok(previous_enabled) => {
            *previous_enabled_out = previous_enabled;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Adjusts a live token's interactive session id and bumps `modified_id`.
pub extern "C" fn kacs_rust_token_adjust_session_id(token: *const c_void, session_id: u32) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };

    match token.adjust_session_id(session_id) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[no_mangle]
/// Adjusts a live token's default owner, primary group, and/or default DACL.
pub extern "C" fn kacs_rust_token_adjust_default(
    token: *const c_void,
    owner_index: u32,
    group_index: u32,
    dacl: *const u8,
    dacl_len: usize,
    change_dacl: u32,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let dacl = if change_dacl == 0 {
        None
    } else if dacl_len == 0 {
        Some(&[][..])
    } else if dacl.is_null() {
        return -EINVAL;
    } else {
        Some(unsafe { core::slice::from_raw_parts(dacl, dacl_len) })
    };

    match token.adjust_default(owner_index, group_index, dacl) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[no_mangle]
/// Adjusts a live token's group enabled-state according to the Slice 35 ABI.
pub extern "C" fn kacs_rust_token_adjust_groups(
    token: *const c_void,
    entries: *const PkmKacsGroupAdjustEntry,
    count: u32,
    previous_state_out: *mut u64,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(previous_state_out) = (unsafe { previous_state_out.as_mut() }) else {
        return -EINVAL;
    };
    if count > 256 {
        return -EINVAL;
    }
    let entries = if count == 0 {
        &[][..]
    } else if entries.is_null() {
        return -EINVAL;
    } else {
        unsafe { core::slice::from_raw_parts(entries, count as usize) }
    };

    match token.adjust_groups(entries) {
        Ok(previous_state) => {
            *previous_state_out = previous_state;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Returns the token's projected uid, or 65534 when the pointer is invalid.
pub extern "C" fn kacs_rust_token_projected_uid(token: *const c_void) -> u32 {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .map(|value| value.projected_uid)
        .unwrap_or(65534)
}

#[no_mangle]
/// Returns the token's projected gid, or 65534 when the pointer is invalid.
pub extern "C" fn kacs_rust_token_projected_gid(token: *const c_void) -> u32 {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .map(|value| value.projected_gid)
        .unwrap_or(65534)
}

#[no_mangle]
/// Fills a KUnit-visible snapshot of any live Slice 21 token object.
pub extern "C" fn kacs_rust_kunit_token_snapshot(
    token_ptr: *const c_void,
    out: *mut PkmKacsBootSnapshot,
) -> bool {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return false;
    };

    let token = unsafe { PkmKacsBootToken::from_ptr(token_ptr) };
    let Some(token) = token else {
        return false;
    };

    token.boot_snapshot(out);
    true
}

#[no_mangle]
/// Fills a KUnit-visible snapshot of the boot SYSTEM token and Session 0.
pub extern "C" fn kacs_rust_kunit_boot_snapshot(out: *mut PkmKacsBootSnapshot) -> bool {
    kacs_rust_kunit_token_snapshot(unsafe { pkm_kacs_boot_system_token_ptr() }, out)
}

#[no_mangle]
/// Creates a KUnit-only SYSTEM-like token whose own SD grants only query and
/// non-escalating adjust rights to its user SID.
pub extern "C" fn kacs_rust_kunit_create_query_only_token() -> *const c_void {
    PkmKacsBootToken::create_query_only_system().unwrap_or(null())
}

#[no_mangle]
/// Creates a KUnit-only SYSTEM-like token with `SeTcbPrivilege` absent.
pub extern "C" fn kacs_rust_kunit_create_without_tcb_token() -> *const c_void {
    PkmKacsBootToken::create_without_tcb().unwrap_or(null())
}

#[no_mangle]
/// Creates a KUnit-only SYSTEM-like token with non-mandatory and deny-only
/// groups so `KACS_IOC_ADJUST_GROUPS` can exercise both success and denial
/// paths.
pub extern "C" fn kacs_rust_kunit_create_adjustable_groups_token() -> *const c_void {
    PkmKacsBootToken::create_adjustable_groups().unwrap_or(null())
}

#[no_mangle]
/// Creates a KUnit-only SYSTEM-like token with a small nontrivial privilege
/// state so `KACS_IOC_ADJUST_PRIVS` can exercise success and fail-closed
/// paths.
pub extern "C" fn kacs_rust_kunit_create_adjustable_privileges_token() -> *const c_void {
    PkmKacsBootToken::create_adjustable_privileges().unwrap_or(null())
}

#[no_mangle]
/// Creates a KUnit-only SYSTEM-like token whose audit policy emits
/// privilege-use events for both success and failure outcomes.
pub extern "C" fn kacs_rust_kunit_create_privilege_audit_token() -> *const c_void {
    PkmKacsBootToken::create_privilege_audit().unwrap_or(null())
}

#[no_mangle]
/// Creates a bounded KUnit-only token variant for Slice 43 impersonation
/// gate and thread-token tests.
pub extern "C" fn kacs_rust_kunit_create_impersonation_variant_token(
    user_kind: u32,
    token_type: u32,
    impersonation_level: u32,
    integrity_level: u32,
    restricted: u32,
    enabled_privileges: u64,
) -> *const c_void {
    let Some(user_sid) = sid_from_kunit_kind(user_kind).ok() else {
        return null();
    };
    let Some(token_type) = token_type_from_abi(token_type).ok() else {
        return null();
    };
    let Some(impersonation_level) = impersonation_level_from_abi(impersonation_level).ok() else {
        return null();
    };
    let Some(integrity_level) = integrity_level_from_abi(integrity_level).ok() else {
        return null();
    };

    PkmKacsBootToken::create_kunit_variant(
        user_sid,
        integrity_level,
        token_type,
        impersonation_level,
        restricted != 0,
        enabled_privileges,
    )
    .unwrap_or(null())
}
