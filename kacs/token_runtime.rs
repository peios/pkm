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

use crate::access_check::{access_check, access_check_core, AccessCheckMode};
use crate::access_check_abi::AccessCheckAbiResolved;
use crate::access_mask::{
    GenericMapping, ACCESS_SYSTEM_SECURITY, GENERIC_ALL, PROCESS_GENERIC_MAPPING,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use crate::ace::{AceKind, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE};
use crate::acl::Acl;
use crate::claims::{parse_claim_attribute_entry, CLAIM_TYPE_INT64};
use crate::condition::ConditionalContext;
use crate::error::KacsError;
use crate::mic::{
    IntegrityLevel, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN, TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
use crate::pip::PipContext;
use crate::pkm_alloc::Vec;
use crate::privilege::{
    TokenPrivileges, RESTORE_INTENT, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE,
};
use crate::security_descriptor::{
    SecurityDescriptor, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
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
const LOGON_TYPE_INTERACTIVE: u32 = 2;
const LOGON_TYPE_NETWORK: u32 = 3;
const LOGON_TYPE_BATCH: u32 = 4;
const LOGON_TYPE_SERVICE: u32 = 5;
const LOGON_TYPE_NETWORK_CLEARTEXT: u32 = 8;
const LOGON_TYPE_NEW_CREDENTIALS: u32 = 9;
const TOKEN_TYPE_PRIMARY_ABI: u32 = 1;
const TOKEN_TYPE_IMPERSONATION_ABI: u32 = 2;
const IMPERSONATION_LEVEL_ANONYMOUS_ABI: u32 = 0;
const IMPERSONATION_LEVEL_IDENTIFICATION_ABI: u32 = 1;
const IMPERSONATION_LEVEL_IMPERSONATION_ABI: u32 = 2;
const IMPERSONATION_LEVEL_DELEGATION_ABI: u32 = 3;
const TOKEN_ELEVATION_DEFAULT_ABI: u32 = 1;
const TOKEN_ELEVATION_FULL_ABI: u32 = 2;
const TOKEN_ELEVATION_LIMITED_ABI: u32 = 3;
const MAX_DEFAULT_DACL_BYTES: usize = 65_536;
const MAX_SESSION_SPEC_BYTES: usize = 4096;
const MIN_SESSION_SPEC_BYTES: usize = 15;
const TOKEN_INDEX_NO_CHANGE: u32 = u32::MAX;
const MAX_BOOT_GROUPS: usize = 5;
const MAX_PRIVILEGE_ADJUST_ENTRIES: usize = 64;
const SD_HEADER_LEN: usize = 20;
const ACL_HEADER_LEN: usize = 8;
const ACE_HEADER_LEN: usize = 8;
const ACL_REVISION: u8 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
const CLAIM_SECURITY_ATTRIBUTE_MANDATORY: u32 = 0x0000_0020;
const INHERIT_ONLY_ACE: u8 = 0x08;

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
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
const ANONYMOUS_LOGON_SID_BYTES: &[u8] =
    &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 230, 3, 0, 0];
const AUTH_PACKAGE_NEGOTIATE: &[u8] = b"Negotiate";
const TOKEN_SOURCE_PEI_OS_KRN: &[u8; 8] = b"PeiosKrn";
const BOOT_SYSTEM_TOKEN_ID: u64 = 0;
const BOOT_SYSTEM_MODIFIED_ID: u64 = 0;
const ANONYMOUS_LOGON_LUID: u64 = 998;
const KUNIT_LOCAL_SERVICE_SESSION_LUID: u64 = 999;
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
static NEXT_DYNAMIC_SESSION_ID: AtomicU64 = AtomicU64::new(KUNIT_LOCAL_SERVICE_SESSION_LUID + 1);
static SESSION_LIST_HEAD: AtomicPtr<PkmKacsSession> = AtomicPtr::new(null_mut());
static SESSION_TABLE_LOCK: AtomicBool = AtomicBool::new(false);
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
    /// Opaque shared session pointer.
    pub session_ptr: *const c_void,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PkmKacsSessionSnapshot {
    pub session_ptr: *const c_void,
    pub session_id: u64,
    pub created_at: u64,
    pub logon_type: u32,
    pub auth_pkg_ptr: *const u8,
    pub auth_pkg_len: usize,
    pub user_sid_ptr: *const u8,
    pub user_sid_len: usize,
    pub logon_sid_ptr: *const u8,
    pub logon_sid_len: usize,
}

struct PkmKacsSession {
    refcount: AtomicUsize,
    next: AtomicPtr<PkmKacsSession>,
    session_id: u64,
    created_at: u64,
    logon_type: u32,
    user_sid_ptr: *mut u8,
    user_sid_len: usize,
    user_sid: Sid<'static>,
    auth_package_ptr: *mut u8,
    auth_package_len: usize,
    logon_sid_ptr: *mut u8,
    logon_sid_len: usize,
    logon_sid: Sid<'static>,
    linked_elevated: *const c_void,
    linked_filtered: *const c_void,
}

struct OwnedSidAndAttributes {
    sid_bytes: Vec<u8>,
    attributes: u32,
}

struct PkmKacsBootToken {
    refcount: AtomicUsize,
    mutation_lock: AtomicBool,
    session: *const PkmKacsSession,
    user_sid: Sid<'static>,
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
    elevation_type: AtomicU32,
    restricted: bool,
    user_deny_only: bool,
    write_restricted: bool,
    restricted_sids: Vec<OwnedSidAndAttributes>,
    restricted_sid_views: Vec<SidAndAttributes<'static>>,
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

struct SessionTableGuard;

impl Drop for SessionTableGuard {
    fn drop(&mut self) {
        SESSION_TABLE_LOCK.store(false, Ordering::Release);
    }
}

impl PkmKacsSession {
    unsafe fn from_ptr(ptr: *const c_void) -> Option<&'static Self> {
        if ptr.is_null() {
            return None;
        }

        Some(unsafe { &*(ptr as *const Self) })
    }

    fn clone_ref_ptr(ptr: *const Self) -> Option<*const Self> {
        let session = unsafe { Self::from_ptr(ptr.cast()) }?;

        session.refcount.fetch_add(1, Ordering::Relaxed);
        Some(ptr)
    }

    unsafe fn drop_ref(ptr: *const Self) {
        let Some(session) = (unsafe { Self::from_ptr(ptr.cast()) }) else {
            return;
        };

        if session.refcount.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            let session_ptr = ptr as *mut Self;
            let linked_elevated = session.linked_elevated;
            let linked_filtered = session.linked_filtered;

            if !linked_elevated.is_null() {
                unsafe { PkmKacsBootToken::drop_ref(linked_elevated) };
            }
            if !linked_filtered.is_null() {
                unsafe { PkmKacsBootToken::drop_ref(linked_filtered) };
            }

            free_allocated_bytes(session.user_sid_ptr);
            free_allocated_bytes(session.auth_package_ptr);
            free_allocated_bytes(session.logon_sid_ptr);
            unsafe { core::ptr::drop_in_place(session_ptr) };
            unsafe { pkm_kacs_free(session_ptr.cast()) };
        }
    }

    fn auth_package_bytes(&self) -> &[u8] {
        if self.auth_package_ptr.is_null() || self.auth_package_len == 0 {
            return &[];
        }

        unsafe {
            core::slice::from_raw_parts(self.auth_package_ptr.cast_const(), self.auth_package_len)
        }
    }

    fn snapshot(&self, out: &mut PkmKacsSessionSnapshot) {
        *out = PkmKacsSessionSnapshot {
            session_ptr: (self as *const Self).cast(),
            session_id: self.session_id,
            created_at: self.created_at,
            logon_type: self.logon_type,
            auth_pkg_ptr: self.auth_package_bytes().as_ptr(),
            auth_pkg_len: self.auth_package_bytes().len(),
            user_sid_ptr: self.user_sid.as_bytes().as_ptr(),
            user_sid_len: self.user_sid.as_bytes().len(),
            logon_sid_ptr: self.logon_sid.as_bytes().as_ptr(),
            logon_sid_len: self.logon_sid.as_bytes().len(),
        };
    }
}

fn lock_session_table() -> SessionTableGuard {
    while SESSION_TABLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    SessionTableGuard
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

fn sid_and_attributes_query_len(entries: &[SidAndAttributes<'_>]) -> Option<usize> {
    let mut len = 4usize;

    for entry in entries {
        let sid_len = entry.sid.as_bytes().len();

        if sid_len > u32::MAX as usize {
            return None;
        }
        len = len.checked_add(4)?;
        len = len.checked_add(sid_len)?;
        len = len.checked_add(4)?;
    }

    Some(len)
}

fn copy_sid_bytes(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let mut copied = Vec::with_capacity(bytes.len()).map_err(|_| -ENOMEM)?;

    copied.extend_from_slice(bytes).map_err(|_| -ENOMEM)?;
    Ok(copied)
}

fn build_owned_sid_entries_from_views(
    entries: &[SidAndAttributes<'_>],
) -> Result<(Vec<OwnedSidAndAttributes>, Vec<SidAndAttributes<'static>>), i32> {
    let mut owned = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;
    let mut views = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        owned
            .push(OwnedSidAndAttributes {
                sid_bytes: copy_sid_bytes(entry.sid.as_bytes())?,
                attributes: entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;

        let owned_entry = &owned[owned.len() - 1];
        let sid_bytes: &'static [u8] = unsafe {
            core::slice::from_raw_parts(owned_entry.sid_bytes.as_ptr(), owned_entry.sid_bytes.len())
        };
        let sid = Sid::parse(sid_bytes).map_err(|_| -EINVAL)?;

        views
            .push(SidAndAttributes {
                sid,
                attributes: owned_entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok((owned, views))
}

fn restrict_sid_list_contains(entries: &[SidAndAttributes<'_>], sid: Sid<'_>) -> bool {
    entries
        .iter()
        .any(|entry| entry.sid.as_bytes() == sid.as_bytes())
}

fn intersect_restricted_sid_views(
    source: &[SidAndAttributes<'static>],
    provided: &[SidAndAttributes<'_>],
) -> Result<(Vec<OwnedSidAndAttributes>, Vec<SidAndAttributes<'static>>), i32> {
    let mut survivors = Vec::with_capacity(source.len()).map_err(|_| -ENOMEM)?;

    for entry in source {
        if restrict_sid_list_contains(provided, entry.sid) {
            survivors.push(*entry).map_err(|_| -ENOMEM)?;
        }
    }

    build_owned_sid_entries_from_views(survivors.as_slice())
}

fn parse_restrict_payload<'a>(
    data: &'a [u8],
    num_deny_indices: u32,
    num_restrict_sids: u32,
) -> Result<(Vec<u32>, Vec<SidAndAttributes<'a>>), i32> {
    let deny_count = usize::try_from(num_deny_indices).map_err(|_| -EINVAL)?;
    let sid_count = usize::try_from(num_restrict_sids).map_err(|_| -EINVAL)?;
    let deny_bytes = deny_count.checked_mul(4).ok_or(-ERANGE)?;
    let mut deny_indices = Vec::with_capacity(deny_count).map_err(|_| -ENOMEM)?;
    let mut restrict_sids = Vec::with_capacity(sid_count).map_err(|_| -ENOMEM)?;
    let mut offset = deny_bytes;

    if data.len() < deny_bytes {
        return Err(-EINVAL);
    }

    for index in 0..deny_count {
        let start = index.checked_mul(4).ok_or(-ERANGE)?;
        let end = start.checked_add(4).ok_or(-ERANGE)?;
        let word = data.get(start..end).ok_or(-EINVAL)?;

        deny_indices
            .push(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .map_err(|_| -ENOMEM)?;
    }

    for _ in 0..sid_count {
        let (sid, consumed) =
            Sid::parse_prefix(data.get(offset..).ok_or(-EINVAL)?).map_err(|_| -EINVAL)?;

        restrict_sids
            .push(SidAndAttributes {
                sid,
                attributes: SE_GROUP_ENABLED,
            })
            .map_err(|_| -ENOMEM)?;
        offset = offset.checked_add(consumed).ok_or(-ERANGE)?;
    }

    if offset != data.len() {
        return Err(-EINVAL);
    }

    Ok((deny_indices, restrict_sids))
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

fn allocate_dynamic_session_id() -> Result<u64, i32> {
    NEXT_DYNAMIC_SESSION_ID
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

fn read_le_u16(src: &[u8], offset: usize) -> Option<u16> {
    let bytes = src.get(offset..offset.checked_add(2)?)?;

    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(src: &[u8], offset: usize) -> Option<u32> {
    let bytes = src.get(offset..offset.checked_add(4)?)?;

    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn session_logon_type_valid(logon_type: u32) -> bool {
    matches!(
        logon_type,
        LOGON_TYPE_INTERACTIVE
            | LOGON_TYPE_NETWORK
            | LOGON_TYPE_BATCH
            | LOGON_TYPE_SERVICE
            | LOGON_TYPE_NETWORK_CLEARTEXT
            | LOGON_TYPE_NEW_CREDENTIALS
    )
}

fn build_logon_sid_bytes(session_id: u64) -> [u8; 20] {
    let high = (session_id >> 32) as u32;
    let low = session_id as u32;

    [
        1,
        3,
        0,
        0,
        0,
        0,
        0,
        5,
        5,
        0,
        0,
        0,
        high as u8,
        (high >> 8) as u8,
        (high >> 16) as u8,
        (high >> 24) as u8,
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
    ]
}

fn session_list_find_locked(session_id: u64) -> Option<*mut PkmKacsSession> {
    let mut cursor = SESSION_LIST_HEAD.load(Ordering::Acquire);

    while !cursor.is_null() {
        let session = unsafe { &*cursor };

        if session.session_id == session_id {
            return Some(cursor);
        }
        cursor = session.next.load(Ordering::Relaxed);
    }

    None
}

fn create_session_object(
    session_id: u64,
    created_at: u64,
    logon_type: u32,
    auth_package: &[u8],
    user_sid: Sid<'_>,
) -> Result<*const PkmKacsSession, i32> {
    let (user_sid_ptr, user_sid_len) = alloc_copy_bytes(user_sid.as_bytes())?;
    let (auth_package_ptr, auth_package_len) = match alloc_copy_bytes(auth_package) {
        Ok(value) => value,
        Err(err) => {
            free_allocated_bytes(user_sid_ptr);
            return Err(err);
        }
    };
    let logon_sid_bytes = build_logon_sid_bytes(session_id);
    let (logon_sid_ptr, logon_sid_len) = match alloc_copy_bytes(&logon_sid_bytes) {
        Ok(value) => value,
        Err(err) => {
            free_allocated_bytes(user_sid_ptr);
            free_allocated_bytes(auth_package_ptr);
            return Err(err);
        }
    };
    let session_ptr =
        unsafe { pkm_kacs_zalloc(core::mem::size_of::<PkmKacsSession>()) } as *mut PkmKacsSession;

    if session_ptr.is_null() {
        free_allocated_bytes(user_sid_ptr);
        free_allocated_bytes(auth_package_ptr);
        free_allocated_bytes(logon_sid_ptr);
        return Err(-ENOMEM);
    }

    let user_sid = match Sid::parse(unsafe {
        core::slice::from_raw_parts(user_sid_ptr.cast_const(), user_sid_len)
    }) {
        Ok(user_sid) => user_sid,
        Err(_) => {
            free_allocated_bytes(user_sid_ptr);
            free_allocated_bytes(auth_package_ptr);
            free_allocated_bytes(logon_sid_ptr);
            unsafe { pkm_kacs_free(session_ptr.cast()) };
            return Err(-EINVAL);
        }
    };
    let logon_sid = match Sid::parse(unsafe {
        core::slice::from_raw_parts(logon_sid_ptr.cast_const(), logon_sid_len)
    }) {
        Ok(logon_sid) => logon_sid,
        Err(_) => {
            free_allocated_bytes(user_sid_ptr);
            free_allocated_bytes(auth_package_ptr);
            free_allocated_bytes(logon_sid_ptr);
            unsafe { pkm_kacs_free(session_ptr.cast()) };
            return Err(-EINVAL);
        }
    };

    unsafe {
        core::ptr::write(
            session_ptr,
            PkmKacsSession {
                refcount: AtomicUsize::new(1),
                next: AtomicPtr::new(null_mut()),
                session_id,
                created_at,
                logon_type,
                user_sid_ptr,
                user_sid_len,
                user_sid,
                auth_package_ptr,
                auth_package_len,
                logon_sid_ptr,
                logon_sid_len,
                logon_sid,
                linked_elevated: null(),
                linked_filtered: null(),
            },
        )
    };

    Ok(session_ptr.cast())
}

fn get_or_create_published_session(
    session_id: u64,
    created_at: u64,
    logon_type: u32,
    auth_package: &[u8],
    user_sid: Sid<'_>,
) -> Result<*const PkmKacsSession, i32> {
    let _guard = lock_session_table();

    if let Some(session_ptr) = session_list_find_locked(session_id) {
        return PkmKacsSession::clone_ref_ptr(session_ptr.cast()).ok_or(-EINVAL);
    }

    let session_ptr =
        create_session_object(session_id, created_at, logon_type, auth_package, user_sid)?;
    let head = SESSION_LIST_HEAD.load(Ordering::Relaxed);

    unsafe { &*session_ptr }.next.store(head, Ordering::Relaxed);
    SESSION_LIST_HEAD.store(session_ptr.cast_mut(), Ordering::Release);
    PkmKacsSession::clone_ref_ptr(session_ptr).ok_or(-EINVAL)
}

fn create_published_dynamic_session(
    created_at: u64,
    logon_type: u32,
    auth_package: &[u8],
    user_sid: Sid<'_>,
) -> Result<u64, i32> {
    let session_id = allocate_dynamic_session_id()?;
    let _guard = lock_session_table();
    let session_ptr =
        create_session_object(session_id, created_at, logon_type, auth_package, user_sid)?;
    let head = SESSION_LIST_HEAD.load(Ordering::Relaxed);

    unsafe { &*session_ptr }.next.store(head, Ordering::Relaxed);
    SESSION_LIST_HEAD.store(session_ptr.cast_mut(), Ordering::Release);
    Ok(session_id)
}

fn parse_session_spec(spec: &[u8]) -> Result<(u32, &[u8], Sid<'_>), i32> {
    if spec.len() < MIN_SESSION_SPEC_BYTES || spec.len() > MAX_SESSION_SPEC_BYTES {
        return Err(-EINVAL);
    }

    let logon_type = spec[0] as u32;
    if !session_logon_type_valid(logon_type) {
        return Err(-EINVAL);
    }

    let auth_pkg_len = usize::from(read_le_u16(spec, 1).ok_or(-EINVAL)?);
    let auth_pkg_end = 3usize.checked_add(auth_pkg_len).ok_or(-ERANGE)?;
    let user_sid_len =
        usize::try_from(read_le_u32(spec, auth_pkg_end).ok_or(-EINVAL)?).map_err(|_| -EINVAL)?;
    let user_sid_offset = auth_pkg_end.checked_add(4).ok_or(-ERANGE)?;
    let user_sid_end = user_sid_offset.checked_add(user_sid_len).ok_or(-ERANGE)?;
    if user_sid_end != spec.len() {
        return Err(-EINVAL);
    }

    let auth_package = spec.get(3..auth_pkg_end).ok_or(-EINVAL)?;
    let user_sid_bytes = spec.get(user_sid_offset..user_sid_end).ok_or(-EINVAL)?;
    let user_sid = Sid::parse(user_sid_bytes).map_err(|_| -EINVAL)?;
    if user_sid.as_bytes().len() != user_sid_len {
        return Err(-EINVAL);
    }

    Ok((logon_type, auth_package, user_sid))
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
    write_le_u16(
        bytes,
        2,
        crate::security_descriptor::SE_SELF_RELATIVE | crate::security_descriptor::SE_DACL_PRESENT,
    );
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

fn validate_sd_security_info(security_info: u32) -> Result<(), i32> {
    let supported = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;

    if security_info == 0 || (security_info & !supported) != 0 {
        return Err(-EINVAL);
    }
    if (security_info & SACL_SECURITY_INFORMATION) != 0
        && (security_info & LABEL_SECURITY_INFORMATION) != 0
    {
        return Err(-EINVAL);
    }

    Ok(())
}

fn clone_optional_acl_bytes(acl: Option<Acl<'_>>) -> Result<Option<Vec<u8>>, i32> {
    let Some(acl) = acl else {
        return Ok(None);
    };
    let mut bytes = Vec::with_capacity(acl.bytes().len()).map_err(|_| -ENOMEM)?;
    bytes.extend_from_slice(acl.bytes()).map_err(|_| -ENOMEM)?;
    Ok(Some(bytes))
}

fn build_acl_bytes_from_aces(revision: u8, aces: &[&[u8]]) -> Result<Option<Vec<u8>>, i32> {
    if aces.is_empty() {
        return Ok(None);
    }

    let mut acl_len = ACL_HEADER_LEN;
    for ace in aces {
        acl_len = acl_len.checked_add(ace.len()).ok_or(-ERANGE)?;
    }
    if acl_len > usize::from(u16::MAX) || aces.len() > usize::from(u16::MAX) {
        return Err(-EINVAL);
    }

    let mut bytes = Vec::with_capacity(acl_len).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[0u8; ACL_HEADER_LEN])
        .map_err(|_| -ENOMEM)?;
    bytes[0] = revision;
    bytes[1] = 0;
    bytes[2..4].copy_from_slice(&(acl_len as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes[6..8].copy_from_slice(&0u16.to_le_bytes());

    for ace in aces {
        bytes.extend_from_slice(ace).map_err(|_| -ENOMEM)?;
    }

    Ok(Some(bytes))
}

fn build_sd_bytes_from_components(
    base_control: u16,
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Result<(*mut u8, usize), i32> {
    let mut control = (base_control | SE_SELF_RELATIVE) & !(SE_SACL_PRESENT | SE_DACL_PRESENT);
    let owner_len = owner.map_or(0, <[u8]>::len);
    let group_len = group.map_or(0, <[u8]>::len);
    let sacl_len = sacl.map_or(0, <[u8]>::len);
    let dacl_len = dacl.map_or(0, <[u8]>::len);
    let mut total_len = SD_HEADER_LEN;

    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    }
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }

    total_len = total_len.checked_add(owner_len).ok_or(-ERANGE)?;
    total_len = total_len.checked_add(group_len).ok_or(-ERANGE)?;
    total_len = total_len.checked_add(sacl_len).ok_or(-ERANGE)?;
    total_len = total_len.checked_add(dacl_len).ok_or(-ERANGE)?;

    let mut bytes = Vec::with_capacity(total_len).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[0u8; SD_HEADER_LEN])
        .map_err(|_| -ENOMEM)?;
    bytes[0] = 1;
    bytes[1] = 0;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    if let Some(owner) = owner {
        let owner_offset = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
        bytes.extend_from_slice(owner).map_err(|_| -ENOMEM)?;
    }

    if let Some(group) = group {
        let group_offset = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
        bytes.extend_from_slice(group).map_err(|_| -ENOMEM)?;
    }

    if let Some(sacl) = sacl {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl).map_err(|_| -ENOMEM)?;
    }

    if let Some(dacl) = dacl {
        let dacl_offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        bytes.extend_from_slice(dacl).map_err(|_| -ENOMEM)?;
    }

    alloc_copy_bytes(bytes.as_slice())
}

fn build_label_ace_bytes(integrity_level: IntegrityLevel) -> Result<Vec<u8>, i32> {
    let sid_len = 12usize;
    let ace_len = ACE_HEADER_LEN.checked_add(sid_len).ok_or(-ERANGE)?;
    let mut bytes = Vec::with_capacity(ace_len).map_err(|_| -ENOMEM)?;

    bytes
        .extend_from_slice(&[
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            (ace_len as u16).to_le_bytes()[0],
            (ace_len as u16).to_le_bytes()[1],
        ])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&TOKEN_MANDATORY_POLICY_NO_WRITE_UP.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&(integrity_level as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_utf16_cstr_bytes(value: &str) -> Result<Vec<u8>, i32> {
    let mut bytes = Vec::new();

    for unit in value.encode_utf16() {
        bytes
            .extend_from_slice(&unit.to_le_bytes())
            .map_err(|_| -ENOMEM)?;
    }
    bytes
        .extend_from_slice(&0u16.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_int64_claim_entry(name: &str, values: &[i64], flags: u32) -> Result<Vec<u8>, i32> {
    let value_count = values.len();
    let offsets_start = 16usize;
    let values_start = offsets_start
        .checked_add(value_count.checked_mul(4).ok_or(-ERANGE)?)
        .ok_or(-ERANGE)?;
    let name_bytes = build_utf16_cstr_bytes(name)?;
    let name_offset = values_start
        .checked_add(value_count.checked_mul(8).ok_or(-ERANGE)?)
        .ok_or(-ERANGE)?;
    let mut bytes = Vec::new();

    bytes
        .extend_from_slice(&(name_offset as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&CLAIM_TYPE_INT64.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&0u16.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&flags.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&(value_count as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;

    for index in 0..value_count {
        let offset = values_start
            .checked_add(index.checked_mul(8).ok_or(-ERANGE)?)
            .ok_or(-ERANGE)?;
        bytes
            .extend_from_slice(&(offset as u32).to_le_bytes())
            .map_err(|_| -ENOMEM)?;
    }
    for value in values {
        bytes
            .extend_from_slice(&value.to_le_bytes())
            .map_err(|_| -ENOMEM)?;
    }
    bytes
        .extend_from_slice(name_bytes.as_slice())
        .map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_mandatory_resource_attribute_ace_bytes() -> Result<Vec<u8>, i32> {
    let application_data =
        build_int64_claim_entry("Mandatory", &[1], CLAIM_SECURITY_ATTRIBUTE_MANDATORY)?;
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let ace_len = ACE_HEADER_LEN
        .checked_add(everyone.as_bytes().len())
        .and_then(|value| value.checked_add(application_data.len()))
        .ok_or(-ERANGE)?;
    let mut bytes = Vec::with_capacity(ace_len).map_err(|_| -ENOMEM)?;

    bytes
        .extend_from_slice(&[
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
            0,
            (ace_len as u16).to_le_bytes()[0],
            (ace_len as u16).to_le_bytes()[1],
        ])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&0u32.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(everyone.as_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(application_data.as_slice())
        .map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn extract_label_subset_sacl_bytes(sd: &SecurityDescriptor<'_>) -> Result<Option<Vec<u8>>, i32> {
    let Some(sacl) = sd.sacl() else {
        return Ok(None);
    };

    for ace in sacl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        if ace.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        return build_acl_bytes_from_aces(sacl.revision(), &[ace.bytes()]);
    }

    Ok(None)
}

fn parse_label_subset_ace_bytes(input_sd: &SecurityDescriptor<'_>) -> Result<Option<Vec<u8>>, i32> {
    let Some(sacl) = input_sd.sacl() else {
        return Ok(None);
    };

    let mut entries = sacl.entries();
    let Some(first) = entries.next() else {
        return Err(-EINVAL);
    };
    let first = first.map_err(|_| -EINVAL)?;
    if entries.next().is_some() {
        return Err(-EINVAL);
    }
    if first.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
        return Err(-EINVAL);
    }
    if (first.ace_flags() & INHERIT_ONLY_ACE) != 0 {
        return Err(-EINVAL);
    }

    let mut bytes = Vec::with_capacity(first.bytes().len()).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(first.bytes())
        .map_err(|_| -ENOMEM)?;
    Ok(Some(bytes))
}

fn collect_mandatory_resource_attribute_aces(acl: Option<Acl<'_>>) -> Result<Vec<Vec<u8>>, i32> {
    let mut mandatory_aces = Vec::new();
    let Some(acl) = acl else {
        return Ok(mandatory_aces);
    };

    for ace in acl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        if ace.ace_type() != SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE {
            continue;
        }
        let AceKind::ResourceAttribute {
            application_data, ..
        } = ace.kind()
        else {
            continue;
        };
        let attribute = parse_claim_attribute_entry(application_data).map_err(|_| -EINVAL)?;
        if (attribute.flags & CLAIM_SECURITY_ATTRIBUTE_MANDATORY) == 0 {
            continue;
        }

        let mut bytes = Vec::with_capacity(ace.bytes().len()).map_err(|_| -ENOMEM)?;
        bytes.extend_from_slice(ace.bytes()).map_err(|_| -ENOMEM)?;
        mandatory_aces.push(bytes).map_err(|_| -ENOMEM)?;
    }

    Ok(mandatory_aces)
}

fn subject_has_enabled_privilege(subject: &PkmKacsBootToken, privilege: u64) -> bool {
    let privileges = subject.privileges_snapshot();

    (privileges.present & privilege) == privilege && (privileges.enabled & privilege) == privilege
}

fn validate_mandatory_resource_attribute_preservation(
    subject: &PkmKacsBootToken,
    current_sacl: Option<Acl<'_>>,
    new_sacl: Option<Acl<'_>>,
) -> Result<(), i32> {
    let current = collect_mandatory_resource_attribute_aces(current_sacl)?;

    if current.is_empty() {
        return Ok(());
    }

    let new = collect_mandatory_resource_attribute_aces(new_sacl)?;
    'next_current: for existing in current.iter() {
        for candidate in new.iter() {
            if existing.as_slice() == candidate.as_slice() {
                continue 'next_current;
            }
        }

        if !subject_has_enabled_privilege(subject, SE_TCB_PRIVILEGE) {
            return Err(-EACCES);
        }

        subject.mark_privileges_used(SE_TCB_PRIVILEGE);
        break;
    }

    Ok(())
}

fn label_integrity_from_ace(ace_bytes: &[u8]) -> Result<IntegrityLevel, i32> {
    let ace = crate::ace::Ace::parse(ace_bytes).map_err(|_| -EINVAL)?;
    let AceKind::SingleSid { sid, .. } = ace.kind() else {
        return Err(-EINVAL);
    };
    if sid.identifier_authority() != [0, 0, 0, 0, 0, 16] || sid.sub_authority_count() != 1 {
        return Err(-EINVAL);
    }

    match sid.sub_authority(0) {
        Some(0) => Ok(IntegrityLevel::Untrusted),
        Some(4096) => Ok(IntegrityLevel::Low),
        Some(8192) => Ok(IntegrityLevel::Medium),
        Some(12288) => Ok(IntegrityLevel::High),
        Some(16384) => Ok(IntegrityLevel::System),
        _ => Err(-EINVAL),
    }
}

fn validate_owner_assignment(subject: &PkmKacsBootToken, owner_sid: Sid<'_>) -> Result<(), i32> {
    if owner_sid.as_bytes() == subject.user_sid.as_bytes() {
        return Ok(());
    }

    for index in 0..subject.group_count {
        let attributes = subject.group_attributes[index].load(Ordering::Relaxed);
        if (attributes & SE_GROUP_OWNER) != SE_GROUP_OWNER {
            continue;
        }
        if subject.group_sids[index].as_bytes() == owner_sid.as_bytes() {
            return Ok(());
        }
    }

    if subject_has_enabled_privilege(subject, SE_RESTORE_PRIVILEGE) {
        subject.mark_privileges_used(SE_RESTORE_PRIVILEGE);
        return Ok(());
    }

    Err(-EACCES)
}

fn validate_label_assignment(
    subject: &PkmKacsBootToken,
    label_ace_bytes: Option<&[u8]>,
) -> Result<(), i32> {
    let Some(label_ace_bytes) = label_ace_bytes else {
        return Ok(());
    };
    let label_integrity = label_integrity_from_ace(label_ace_bytes)?;

    if (label_integrity as u32) <= (subject.integrity_level as u32) {
        return Ok(());
    }
    if subject_has_enabled_privilege(subject, SE_RELABEL_PRIVILEGE) {
        subject.mark_privileges_used(SE_RELABEL_PRIVILEGE);
        return Ok(());
    }

    Err(-EACCES)
}

fn build_sd_subset_bytes(sd_bytes: &[u8], security_info: u32) -> Result<(*mut u8, usize), i32> {
    validate_sd_security_info(security_info)?;

    let sd = SecurityDescriptor::parse(sd_bytes).map_err(|_| -EINVAL)?;
    let label_sacl = if (security_info & LABEL_SECURITY_INFORMATION) != 0 {
        extract_label_subset_sacl_bytes(&sd)?
    } else {
        None
    };
    let full_sacl = if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        clone_optional_acl_bytes(sd.sacl())?
    } else {
        None
    };
    let dacl = if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        clone_optional_acl_bytes(sd.dacl())?
    } else {
        None
    };

    build_sd_bytes_from_components(
        sd.control(),
        if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
            sd.owner().map(|sid| sid.as_bytes())
        } else {
            None
        },
        if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
            sd.group().map(|sid| sid.as_bytes())
        } else {
            None
        },
        full_sacl.as_deref().or(label_sacl.as_deref()),
        dacl.as_deref(),
    )
}

fn merge_process_sd_bytes(
    subject: &PkmKacsBootToken,
    current_sd_bytes: &[u8],
    security_info: u32,
    input_sd_bytes: &[u8],
) -> Result<(*mut u8, usize), i32> {
    let current_sd = SecurityDescriptor::parse(current_sd_bytes).map_err(|_| -EINVAL)?;
    let input_sd = SecurityDescriptor::parse(input_sd_bytes).map_err(|_| -EINVAL)?;
    let mut sacl = clone_optional_acl_bytes(current_sd.sacl())?;
    let mut dacl = clone_optional_acl_bytes(current_sd.dacl())?;
    let owner = if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
        let owner = input_sd.owner().ok_or(-EINVAL)?;
        validate_owner_assignment(subject, owner)?;
        owner
    } else {
        current_sd.owner().ok_or(-EINVAL)?
    };
    let group = if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
        input_sd.group().ok_or(-EINVAL)?
    } else {
        current_sd.group().ok_or(-EINVAL)?
    };

    validate_sd_security_info(security_info)?;

    if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        dacl = clone_optional_acl_bytes(input_sd.dacl())?;
    }

    if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        validate_mandatory_resource_attribute_preservation(
            subject,
            current_sd.sacl(),
            input_sd.sacl(),
        )?;
        sacl = clone_optional_acl_bytes(input_sd.sacl())?;
    } else if (security_info & LABEL_SECURITY_INFORMATION) != 0 {
        let label_ace = parse_label_subset_ace_bytes(&input_sd)?;
        validate_label_assignment(subject, label_ace.as_deref())?;

        let current_revision = current_sd
            .sacl()
            .map(|acl| acl.revision())
            .unwrap_or(ACL_REVISION);
        let mut preserved_aces = Vec::new();

        if let Some(existing_sacl) = current_sd.sacl() {
            for ace in existing_sacl.entries() {
                let ace = ace.map_err(|_| -EINVAL)?;
                if ace.ace_type() == SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                    continue;
                }
                let mut bytes = Vec::with_capacity(ace.bytes().len()).map_err(|_| -ENOMEM)?;
                bytes.extend_from_slice(ace.bytes()).map_err(|_| -ENOMEM)?;
                preserved_aces.push(bytes).map_err(|_| -ENOMEM)?;
            }
        }

        let mut ace_refs = Vec::new();
        if let Some(label_ace) = label_ace.as_ref() {
            ace_refs.push(label_ace.as_slice()).map_err(|_| -ENOMEM)?;
        }
        for ace in preserved_aces.iter() {
            ace_refs.push(ace.as_slice()).map_err(|_| -ENOMEM)?;
        }

        sacl = build_acl_bytes_from_aces(current_revision, ace_refs.as_slice())?;
    }

    build_sd_bytes_from_components(
        current_sd.control(),
        Some(owner.as_bytes()),
        Some(group.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    )
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

fn build_process_sd_with_mandatory_resource_attribute_bytes(
    token: &PkmKacsBootToken,
) -> Result<(*mut u8, usize), i32> {
    let (default_ptr, default_len) = build_default_process_sd_bytes(token)?;
    let default_bytes = unsafe { core::slice::from_raw_parts(default_ptr, default_len) };
    let default_sd = SecurityDescriptor::parse(default_bytes).map_err(|_| -EINVAL)?;
    let resource_ace = build_mandatory_resource_attribute_ace_bytes()?;
    let sacl = build_acl_bytes_from_aces(ACL_REVISION, &[resource_ace.as_slice()])?;
    let dacl = clone_optional_acl_bytes(default_sd.dacl())?;
    let result = build_sd_bytes_from_components(
        default_sd.control(),
        default_sd.owner().map(|sid| sid.as_bytes()),
        default_sd.group().map(|sid| sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    );

    free_allocated_bytes(default_ptr);
    result
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
        crate::security_descriptor::SE_SELF_RELATIVE | crate::security_descriptor::SE_DACL_PRESENT,
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

    build_process_sd_bytes(
        token.user_sid,
        group_sid,
        None,
        None,
        None,
        Some(PROCESS_QUERY_LIMITED),
    )
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

fn build_read_only_socket_sd_bytes(token: &PkmKacsBootToken) -> Result<(*mut u8, usize), i32> {
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

fn boot_system_session_ref() -> Result<*const PkmKacsSession, i32> {
    get_or_create_published_session(
        0,
        0,
        LOGON_TYPE_SERVICE,
        AUTH_PACKAGE_NEGOTIATE,
        Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?,
    )
}

fn anonymous_session_ref() -> Result<*const PkmKacsSession, i32> {
    get_or_create_published_session(
        ANONYMOUS_LOGON_LUID,
        0,
        LOGON_TYPE_NETWORK,
        AUTH_PACKAGE_NEGOTIATE,
        Sid::parse(ANONYMOUS_SID_BYTES).map_err(|_| -EINVAL)?,
    )
}

fn kunit_local_service_session_ref() -> Result<*const PkmKacsSession, i32> {
    get_or_create_published_session(
        KUNIT_LOCAL_SERVICE_SESSION_LUID,
        0,
        LOGON_TYPE_SERVICE,
        AUTH_PACKAGE_NEGOTIATE,
        Sid::parse(LOCAL_SERVICE_SID_BYTES).map_err(|_| -EINVAL)?,
    )
}

impl PkmKacsBootToken {
    fn session_ref(&self) -> Option<&PkmKacsSession> {
        unsafe { PkmKacsSession::from_ptr(self.session.cast()) }
    }

    fn create_system_like(
        session: *const PkmKacsSession,
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
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;
        let session_ref = match unsafe { PkmKacsSession::from_ptr(session.cast()) } {
            Some(session_ref) => session_ref,
            None => return None,
        };
        let logon_sid = session_ref.logon_sid;
        let (default_dacl_ptr, default_dacl_len) = match alloc_copy_bytes(SYSTEM_DEFAULT_DACL_BYTES)
        {
            Ok(value) => value,
            Err(_) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
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
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
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
            session,
            user_sid,
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
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted,
            user_deny_only: false,
            write_restricted: false,
            restricted_sids: Vec::new(),
            restricted_sid_views: Vec::new(),
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
        let session = boot_system_session_ref().ok()?;

        Self::create_system_like(
            session,
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
        let session = boot_system_session_ref().ok()?;
        let session_ref = match unsafe { PkmKacsSession::from_ptr(session.cast()) } {
            Some(session_ref) => session_ref,
            None => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let logon_sid = session_ref.logon_sid;
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;
        let (default_dacl_ptr, default_dacl_len) = match alloc_copy_bytes(SYSTEM_DEFAULT_DACL_BYTES)
        {
            Ok(value) => value,
            Err(_) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            creator_sid,
            user_sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            None,
            None,
        ) {
            Ok(value) => value,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
            return None;
        }
        let group_sids = [
            administrators,
            everyone,
            authenticated_users,
            local,
            logon_sid,
        ];
        let group_default_attributes = BOOT_SYSTEM_GROUP_ATTRIBUTES;
        let group_views = build_group_views(&group_sids, &group_default_attributes);
        let group_attributes = group_default_attributes.map(AtomicU32::new);
        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid,
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
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted: false,
            user_deny_only: false,
            write_restricted: false,
            restricted_sids: Vec::new(),
            restricted_sid_views: Vec::new(),
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
        let session = boot_system_session_ref().ok()?;

        Self::create_system_like(
            session,
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
        let session = boot_system_session_ref().ok()?;

        Self::create_system_like(
            session,
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
        let session = boot_system_session_ref().ok()?;

        Self::create_system_like(
            session,
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
        let session = boot_system_session_ref().ok()?;

        Self::create_system_like(
            session,
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
        let session = if user_sid.as_bytes() == SYSTEM_SID_BYTES {
            boot_system_session_ref().ok()?
        } else if user_sid.as_bytes() == LOCAL_SERVICE_SID_BYTES {
            kunit_local_service_session_ref().ok()?
        } else {
            return None;
        };

        Self::create_system_like(
            session,
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
        let session = anonymous_session_ref().ok()?;
        let session_ref = match unsafe { PkmKacsSession::from_ptr(session.cast()) } {
            Some(session_ref) => session_ref,
            None => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let logon_sid = session_ref.logon_sid;
        let (default_dacl_ptr, default_dacl_len) = match alloc_copy_bytes(&[]) {
            Ok(value) => value,
            Err(_) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            anonymous,
            anonymous,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            None,
            None,
        ) {
            Ok(value) => value,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        let token_id = match allocate_dynamic_token_id() {
            Ok(token_id) => token_id,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
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
            session,
            user_sid: anonymous,
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
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted: false,
            user_deny_only: false,
            write_restricted: false,
            restricted_sids: Vec::new(),
            restricted_sid_views: Vec::new(),
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
        let (restricted_sids, restricted_sid_views) =
            match build_owned_sid_entries_from_views(token.restricted_sid_views()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let (default_dacl_ptr, default_dacl_len) =
            match alloc_copy_bytes(token.default_dacl_bytes()) {
                Ok(copy) => copy,
                Err(_) => return null(),
            };
        let session = match PkmKacsSession::clone_ref_ptr(token.session) {
            Some(session) => session,
            None => {
                free_allocated_bytes(default_dacl_ptr);
                return null();
            }
        };
        let (own_sd_ptr, own_sd_len) = match alloc_copy_bytes(token.own_sd_bytes()) {
            Ok(copy) => copy,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                return null();
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session) };
            return null();
        }
        let copy = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: token.user_sid,
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
            elevation_type: AtomicU32::new(token.elevation_type.load(Ordering::Relaxed)),
            restricted: token.restricted,
            user_deny_only: token.user_deny_only,
            write_restricted: token.write_restricted,
            restricted_sids,
            restricted_sid_views,
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
        let (restricted_sids, restricted_sid_views) =
            build_owned_sid_entries_from_views(self.restricted_sid_views())?;
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
        let session = PkmKacsSession::clone_ref_ptr(self.session).ok_or(-EINVAL)?;
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
                unsafe { PkmKacsSession::drop_ref(session) };
                return Err(err);
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session) };
            return Err(-ENOMEM);
        }

        let duplicate = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: self.user_sid,
            group_count: self.group_count,
            group_sids: self.group_sids,
            group_default_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&self.group_sids, &group_attributes)),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
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
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted: self.restricted,
            user_deny_only: self.user_deny_only,
            write_restricted: self.write_restricted,
            restricted_sids,
            restricted_sid_views,
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
        let (restricted_sids, restricted_sid_views) =
            build_owned_sid_entries_from_views(self.restricted_sid_views())?;
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let session = PkmKacsSession::clone_ref_ptr(self.session).ok_or(-EINVAL)?;
        let (own_sd_ptr, own_sd_len) = match alloc_copy_bytes(self.own_sd_bytes()) {
            Ok(value) => value,
            Err(err) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                return Err(err);
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session) };
            return Err(-ENOMEM);
        }

        let derived = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: self.user_sid,
            group_count: self.group_count,
            group_sids: self.group_sids,
            group_default_attributes: self.group_default_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&self.group_sids, &group_attributes)),
            token_id: self.token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(self.modified_id.load(Ordering::Relaxed)),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
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
            elevation_type: AtomicU32::new(self.elevation_type.load(Ordering::Relaxed)),
            restricted: self.restricted,
            user_deny_only: self.user_deny_only,
            write_restricted: self.write_restricted,
            restricted_sids,
            restricted_sid_views,
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
            unsafe { PkmKacsSession::drop_ref(token.session.cast()) };
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
        let Some(session) = self.session_ref() else {
            return;
        };

        *out = PkmKacsBootSnapshot {
            token_ptr: (self as *const Self).cast(),
            session_ptr: session as *const PkmKacsSession as *const c_void,
            session_id: session.session_id,
            auth_id: session.session_id,
            token_id: self.token_id,
            modified_id: self.modified_id.load(Ordering::Relaxed),
            logon_type: session.logon_type,
            auth_pkg_ptr: session.auth_package_bytes().as_ptr(),
            auth_pkg_len: session.auth_package_bytes().len(),
            user_sid_ptr: session.user_sid.as_bytes().as_ptr(),
            user_sid_len: session.user_sid.as_bytes().len(),
            logon_sid_ptr: session.logon_sid.as_bytes().as_ptr(),
            logon_sid_len: session.logon_sid.as_bytes().len(),
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

    fn elevation_type(&self) -> u32 {
        self.elevation_type.load(Ordering::Acquire)
    }

    fn set_elevation_type(&self, elevation_type: u32) {
        self.elevation_type.store(elevation_type, Ordering::Release);
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

    fn linked_query_copy(&self) -> Result<*const c_void, i32> {
        let copy = self.duplicate(
            self,
            TokenType::Impersonation,
            ImpersonationLevel::Identification,
        )?;
        let Some(copy_token) = (unsafe { Self::from_ptr(copy) }) else {
            unsafe { Self::drop_ref(copy) };
            return Err(-EACCES);
        };

        copy_token.set_elevation_type(self.elevation_type());
        Ok(copy)
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

    fn restricted_sid_views(&self) -> &[SidAndAttributes<'static>] {
        self.restricted_sid_views.as_slice()
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
                user_deny_only: self.user_deny_only,
                groups: &groups[..self.group_count],
            },
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            audit_policy: self.audit_policy,
            privileges,
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            restricted: RestrictedTokenContext {
                restricted_sids: self.restricted_sid_views(),
                restricted_device_groups: EMPTY_DEVICE_GROUPS,
                write_restricted: self.write_restricted,
                privilege_granted: 0,
            },
            confinement: ConfinementTokenContext::default(),
        };

        f(access_token)
    }

    fn group_query_required_len(&self) -> Result<usize, i32> {
        sid_query_len(&self.group_sids[..self.group_count]).ok_or(-EINVAL)
    }

    fn restricted_sid_query_required_len(&self) -> Result<usize, i32> {
        sid_and_attributes_query_len(self.restricted_sid_views()).ok_or(-EINVAL)
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

    fn write_restricted_sid_query(&self, writer: &mut QueryWriter) -> Result<(), i32> {
        let entries = self.restricted_sid_views();

        if entries.len() > u32::MAX as usize {
            return Err(-EINVAL);
        }
        if !writer.write_u32(entries.len() as u32) {
            return Err(-ERANGE);
        }

        for entry in entries {
            let sid = entry.sid.as_bytes();

            if sid.len() > u32::MAX as usize {
                return Err(-EINVAL);
            }
            if !writer.write_u32(sid.len() as u32) {
                return Err(-ERANGE);
            }
            if !writer.write_bytes(sid) {
                return Err(-ERANGE);
            }
            if !writer.write_u32(entry.attributes) {
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

    fn restrict(
        &self,
        creator: &PkmKacsBootToken,
        privs_to_delete: u64,
        write_restricted_requested: bool,
        deny_indices: &[u32],
        restrict_sids: &[SidAndAttributes<'_>],
    ) -> Result<*const c_void, i32> {
        let _guard = self.lock_mutation();
        let privileges = self.privileges_snapshot_locked();
        let mut group_attributes = self.current_group_attributes();
        let mut seen = [false; MAX_BOOT_GROUPS];
        let source_was_restricted = !self.restricted_sid_views().is_empty();
        let privileges_present = privileges.present & !privs_to_delete;
        let privileges_enabled = privileges.enabled & !privs_to_delete;
        let privileges_enabled_by_default = privileges.enabled_by_default & !privs_to_delete;
        let token_id = allocate_dynamic_token_id()?;
        let write_restricted = write_restricted_requested || self.write_restricted;
        let user_deny_only = write_restricted;
        let (restricted_sids, restricted_sid_views) = if !source_was_restricted {
            build_owned_sid_entries_from_views(restrict_sids)?
        } else {
            intersect_restricted_sid_views(self.restricted_sid_views(), restrict_sids)?
        };
        if source_was_restricted && restricted_sid_views.is_empty() {
            return Err(-EINVAL);
        }
        let restricted = !restricted_sid_views.is_empty();
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let session = PkmKacsSession::clone_ref_ptr(self.session).ok_or(-EINVAL)?;
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
                unsafe { PkmKacsSession::drop_ref(session) };
                return Err(err);
            }
        };
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;

        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session) };
            return Err(-ENOMEM);
        }

        for deny_index in deny_indices {
            let index = usize::try_from(*deny_index).map_err(|_| -EINVAL)?;

            if index >= self.group_count {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                unsafe { pkm_kacs_free(token_ptr.cast()) };
                return Err(-EINVAL);
            }
            if seen[index] {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                unsafe { pkm_kacs_free(token_ptr.cast()) };
                return Err(-EINVAL);
            }
            seen[index] = true;
            group_attributes[index] |= SE_GROUP_USE_FOR_DENY_ONLY;
        }

        let restricted_token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: self.user_sid,
            group_count: self.group_count,
            group_sids: self.group_sids,
            group_default_attributes: group_attributes,
            group_attributes: group_attributes.map(AtomicU32::new),
            group_views: UnsafeCell::new(build_group_views(&self.group_sids, &group_attributes)),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            privileges_present: AtomicU64::new(privileges_present),
            privileges_enabled: AtomicU64::new(privileges_enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges_enabled_by_default),
            privileges_used: AtomicU64::new(0),
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted,
            user_deny_only,
            write_restricted,
            restricted_sids,
            restricted_sid_views,
            audit_policy: self.audit_policy,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
        };

        unsafe { core::ptr::write(token_ptr, restricted_token) };
        Ok(token_ptr.cast())
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
            TOKEN_CLASS_RESTRICTED_SIDS => self.restricted_sid_query_required_len(),
            TOKEN_CLASS_SOURCE => Ok(16),
            TOKEN_CLASS_ORIGIN => Ok(8),
            TOKEN_CLASS_ELEVATION_TYPE => Ok(4),
            TOKEN_CLASS_DEVICE_GROUPS => Ok(4),
            TOKEN_CLASS_APPCONTAINER_SID => Ok(0),
            TOKEN_CLASS_CAPABILITIES => Ok(4),
            TOKEN_CLASS_MANDATORY_POLICY => Ok(4),
            TOKEN_CLASS_LOGON_TYPE => Ok(4),
            TOKEN_CLASS_LOGON_SID => self
                .session_ref()
                .map(|session| session.logon_sid.as_bytes().len())
                .ok_or(-EINVAL),
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
            TOKEN_CLASS_RESTRICTED_SIDS => {
                self.write_restricted_sid_query(writer)?;
                true
            }
            TOKEN_CLASS_SOURCE => {
                writer.write_bytes(TOKEN_SOURCE_PEI_OS_KRN) && writer.write_u64(0)
            }
            TOKEN_CLASS_STATISTICS => {
                let _guard = self.lock_mutation();
                let Some(session) = self.session_ref() else {
                    return Err(-EINVAL);
                };
                writer.write_u64(self.token_id)
                    && writer.write_u64(session.session_id)
                    && writer.write_u64(self.modified_id.load(Ordering::Relaxed))
                    && writer.write_u32(token_type_abi(self.token_type))
                    && writer.write_u32(0)
                    && writer.write_u64(0)
            }
            TOKEN_CLASS_ORIGIN => writer.write_u64(0),
            TOKEN_CLASS_ELEVATION_TYPE => writer.write_u32(self.elevation_type()),
            TOKEN_CLASS_DEVICE_GROUPS => writer.write_u32(0),
            TOKEN_CLASS_APPCONTAINER_SID => true,
            TOKEN_CLASS_CAPABILITIES => writer.write_u32(0),
            TOKEN_CLASS_MANDATORY_POLICY => writer.write_u32(self.mandatory_policy),
            TOKEN_CLASS_LOGON_TYPE => {
                let Some(session) = self.session_ref() else {
                    return Err(-EINVAL);
                };
                writer.write_u32(session.logon_type)
            }
            TOKEN_CLASS_LOGON_SID => {
                let Some(session) = self.session_ref() else {
                    return Err(-EINVAL);
                };
                writer.write_bytes(session.logon_sid.as_bytes())
            }
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

    fn replace_own_sd(
        &self,
        subject: &PkmKacsBootToken,
        security_info: u32,
        input_sd_bytes: &[u8],
    ) -> Result<(), i32> {
        let _guard = self.lock_mutation();
        let modified_id = self.modified_id.load(Ordering::Relaxed);
        let Some(next_modified_id) = modified_id.checked_add(1) else {
            return Err(-ERANGE);
        };
        let (new_sd_ptr, new_sd_len) =
            merge_process_sd_bytes(subject, self.own_sd_bytes(), security_info, input_sd_bytes)?;
        let old_sd_ptr = self.own_sd_ptr.load(Ordering::Relaxed);

        self.own_sd_ptr.store(new_sd_ptr, Ordering::Relaxed);
        self.own_sd_len.store(new_sd_len, Ordering::Relaxed);
        self.modified_id.store(next_modified_id, Ordering::Relaxed);
        free_allocated_bytes(old_sd_ptr);
        Ok(())
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

fn validate_link_role(token: &PkmKacsBootToken, expected: u32) -> Result<(), i32> {
    match token.elevation_type() {
        TOKEN_ELEVATION_DEFAULT_ABI => Ok(()),
        value if value == expected => Ok(()),
        TOKEN_ELEVATION_FULL_ABI | TOKEN_ELEVATION_LIMITED_ABI => Err(-EINVAL),
        _ => Err(-EINVAL),
    }
}

fn link_tokens_on_session(
    elevated_token: &PkmKacsBootToken,
    filtered_token: &PkmKacsBootToken,
    session_id: u64,
) -> Result<(), i32> {
    let elevated_ptr = (elevated_token as *const PkmKacsBootToken).cast::<c_void>();
    let filtered_ptr = (filtered_token as *const PkmKacsBootToken).cast::<c_void>();
    let elevated_ref;
    let filtered_ref;
    let old_elevated;
    let old_filtered;
    let _guard = lock_session_table();
    let Some(session_ptr) = session_list_find_locked(session_id) else {
        return Err(-EINVAL);
    };
    let session = unsafe { &mut *session_ptr };

    if elevated_ptr == filtered_ptr {
        return Err(-EINVAL);
    }
    if elevated_token.token_type != TokenType::Primary
        || filtered_token.token_type != TokenType::Primary
    {
        return Err(-EINVAL);
    }
    if session_ptr.cast_const() != elevated_token.session
        || session_ptr.cast_const() != filtered_token.session
    {
        return Err(-EINVAL);
    }
    if elevated_token.user_sid.as_bytes() != filtered_token.user_sid.as_bytes() {
        return Err(-EINVAL);
    }

    validate_link_role(elevated_token, TOKEN_ELEVATION_FULL_ABI)?;
    validate_link_role(filtered_token, TOKEN_ELEVATION_LIMITED_ABI)?;

    elevated_ref = PkmKacsBootToken::clone_ref(elevated_ptr);
    if elevated_ref.is_null() {
        return Err(-EACCES);
    }
    filtered_ref = PkmKacsBootToken::clone_ref(filtered_ptr);
    if filtered_ref.is_null() {
        unsafe { PkmKacsBootToken::drop_ref(elevated_ref) };
        return Err(-EACCES);
    }

    old_elevated = session.linked_elevated;
    old_filtered = session.linked_filtered;
    session.linked_elevated = elevated_ref;
    session.linked_filtered = filtered_ref;
    elevated_token.set_elevation_type(TOKEN_ELEVATION_FULL_ABI);
    filtered_token.set_elevation_type(TOKEN_ELEVATION_LIMITED_ABI);

    if !old_elevated.is_null() {
        unsafe { PkmKacsBootToken::drop_ref(old_elevated) };
    }
    if !old_filtered.is_null() {
        unsafe { PkmKacsBootToken::drop_ref(old_filtered) };
    }

    Ok(())
}

fn get_linked_token(
    token: &PkmKacsBootToken,
    return_actual: bool,
) -> Result<*const c_void, i32> {
    let token_ptr = (token as *const PkmKacsBootToken).cast::<c_void>();
    let partner_ptr;
    let _guard = lock_session_table();
    let Some(session) = token.session_ref() else {
        return Err(-EACCES);
    };

    match token.elevation_type() {
        TOKEN_ELEVATION_FULL_ABI => {
            if session.linked_elevated != token_ptr {
                return Err(-ENOENT);
            }
            partner_ptr = session.linked_filtered;
        }
        TOKEN_ELEVATION_LIMITED_ABI => {
            if session.linked_filtered != token_ptr {
                return Err(-ENOENT);
            }
            partner_ptr = session.linked_elevated;
        }
        TOKEN_ELEVATION_DEFAULT_ABI => return Err(-ENOENT),
        _ => return Err(-EINVAL),
    }

    if partner_ptr.is_null() {
        return Err(-ENOENT);
    }

    let Some(partner) = (unsafe { PkmKacsBootToken::from_ptr(partner_ptr) }) else {
        return Err(-ENOENT);
    };

    if return_actual {
        let partner_ref = PkmKacsBootToken::clone_ref(partner_ptr);
        if partner_ref.is_null() {
            return Err(-EACCES);
        }
        Ok(partner_ref)
    } else {
        partner.linked_query_copy()
    }
}

fn min_impersonation_level(lhs: ImpersonationLevel, rhs: ImpersonationLevel) -> ImpersonationLevel {
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
            permitted = min_impersonation_level(permitted, ImpersonationLevel::Identification);
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

fn token_sd_access_check_errno_with_intent(
    subject_token: *const c_void,
    target_token: *const c_void,
    desired: u32,
    privilege_intent: u32,
) -> Result<u32, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let Some(target) = (unsafe { PkmKacsBootToken::from_ptr(target_token) }) else {
        return Err(-EACCES);
    };
    let Some(target_sd) = target.own_sd() else {
        return Err(-EACCES);
    };
    let normalized = match TOKEN_GENERIC_MAPPING.normalize_desired_access(desired) {
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
        match access_check_core(
            Some(&target_sd),
            &subject_token,
            pip,
            desired,
            &TOKEN_GENERIC_MAPPING,
            AccessCheckMode::Scalar,
            None,
            &conditional_context,
            None,
            privilege_intent,
            EMPTY_POLICIES,
        ) {
            Ok(result) => {
                subject.mark_privileges_used(result.updated_privileges.used);
                let granted = result
                    .object_granted_list
                    .as_ref()
                    .and_then(|list| list.first().copied())
                    .unwrap_or(result.granted);
                let allowed = result.mapped_desired == 0
                    || (granted & result.mapped_desired) == result.mapped_desired;

                if !allowed {
                    return Err(-EACCES);
                }
                if normalized.maximum_allowed {
                    Ok(granted)
                } else {
                    Ok(granted & normalized.mapped)
                }
            }
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EACCES),
        }
    })
}

fn process_sd_access_check_errno_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
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
        match access_check_core(
            Some(&target_sd),
            &subject_token,
            pip,
            desired,
            &PROCESS_GENERIC_MAPPING,
            AccessCheckMode::Scalar,
            None,
            &conditional_context,
            None,
            privilege_intent,
            EMPTY_POLICIES,
        ) {
            Ok(result) => {
                subject.mark_privileges_used(result.updated_privileges.used);
                let granted = result
                    .object_granted_list
                    .as_ref()
                    .and_then(|list| list.first().copied())
                    .unwrap_or(result.granted);
                let allowed = result.mapped_desired == 0
                    || (granted & result.mapped_desired) == result.mapped_desired;

                if !allowed {
                    return Err(-EACCES);
                }
                if normalized.maximum_allowed {
                    Ok(granted)
                } else {
                    Ok(granted & normalized.mapped)
                }
            }
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EINVAL),
        }
    })
}

fn process_sd_access_check_errno(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
) -> Result<u32, i32> {
    process_sd_access_check_errno_with_intent(subject_token, sd_bytes, desired, 0)
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
/// Creates one published logon-session object from the exact `v0.20`
/// wire-format session specification.
pub extern "C" fn kacs_rust_create_session(
    spec: *const u8,
    spec_len: usize,
    created_at: u64,
    session_id_out: *mut u64,
) -> i32 {
    let Some(session_id_out) = (unsafe { session_id_out.as_mut() }) else {
        return -EINVAL;
    };
    if spec.is_null() {
        return -EINVAL;
    }

    let spec = unsafe { core::slice::from_raw_parts(spec, spec_len) };
    let (logon_type, auth_package, user_sid) = match parse_session_spec(spec) {
        Ok(parsed) => parsed,
        Err(err) => return err,
    };

    match create_published_dynamic_session(created_at, logon_type, auth_package, user_sid) {
        Ok(session_id) => {
            *session_id_out = session_id;
            0
        }
        Err(err) => err,
    }
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
pub extern "C" fn kacs_rust_token_link_tokens(
    elevated_token: *const c_void,
    filtered_token: *const c_void,
    session_id: u64,
) -> i32 {
    let Some(elevated_token) = (unsafe { PkmKacsBootToken::from_ptr(elevated_token) }) else {
        return -EACCES;
    };
    let Some(filtered_token) = (unsafe { PkmKacsBootToken::from_ptr(filtered_token) }) else {
        return -EACCES;
    };

    match link_tokens_on_session(elevated_token, filtered_token, session_id) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn kacs_rust_token_get_linked_actual(
    token: *const c_void,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };

    match get_linked_token(token, true) {
        Ok(linked) => {
            *out_token = linked;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn kacs_rust_token_get_linked_query_copy(
    token: *const c_void,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };

    match get_linked_token(token, false) {
        Ok(linked) => {
            *out_token = linked;
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
    let Some(used_impersonate_privilege_out) = (unsafe { used_impersonate_privilege_out.as_mut() })
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

    match source_token.duplicate(source_token, TokenType::Impersonation, impersonation_level) {
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
/// Builds a KUnit-only self-relative SD subset carrying one explicit
/// mandatory-label ACE in the descriptor SACL field.
pub extern "C" fn kacs_rust_kunit_create_label_sd_subset(
    integrity_level: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(integrity_level) = integrity_level_from_abi(integrity_level).ok() else {
        return null();
    };
    let Ok(label_ace) = build_label_ace_bytes(integrity_level) else {
        return null();
    };
    let Ok(sacl) = build_acl_bytes_from_aces(ACL_REVISION, &[label_ace.as_slice()]) else {
        return null();
    };
    let Ok((ptr, len)) =
        build_sd_bytes_from_components(SE_SELF_RELATIVE, None, None, sacl.as_deref(), None)
    else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only process SD carrying one mandatory resource-attribute
/// ACE in the SACL.
pub extern "C" fn kacs_rust_kunit_create_process_sd_with_mandatory_resource_attr(
    token_ptr: *const c_void,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_process_sd_with_mandatory_resource_attribute_bytes(token) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only token SD that grants only the bounded self query and
/// non-escalating adjust rights to the token user SID.
pub extern "C" fn kacs_rust_kunit_create_query_only_token_sd(len_out: *mut usize) -> *const u8 {
    let Some(token_ptr) = PkmKacsBootToken::create_query_only_system() else {
        return null();
    };
    let result = {
        let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
            unsafe { PkmKacsBootToken::drop_ref(token_ptr) };
            return null();
        };
        alloc_copy_bytes(token.own_sd_bytes())
    };

    unsafe { PkmKacsBootToken::drop_ref(token_ptr) };
    let Ok((ptr, len)) = result else {
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
/// Runs AccessCheck against one process SD using the supplied caller token and
/// privilege-intent flags.
pub extern "C" fn kacs_rust_check_process_sd_with_intent(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match process_sd_access_check_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
    ) {
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
/// Runs live AccessCheck against one token's own SD using the supplied caller
/// token and privilege-intent flags.
pub extern "C" fn kacs_rust_check_token_sd_with_intent(
    subject_token_ptr: *const c_void,
    target_token_ptr: *const c_void,
    desired: u32,
    privilege_intent: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 {
        return -EINVAL;
    }

    match token_sd_access_check_errno_with_intent(
        subject_token_ptr,
        target_token_ptr,
        desired,
        privilege_intent,
    ) {
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
/// Serializes a requested subset of a live process SD into one self-relative
/// descriptor buffer.
pub extern "C" fn kacs_rust_query_process_sd_subset(
    sd_ptr: *const u8,
    sd_len: usize,
    security_info: u32,
    out_sd_ptr: *mut *const u8,
    out_sd_len: *mut usize,
) -> i32 {
    let Some(out_sd_ptr) = (unsafe { out_sd_ptr.as_mut() }) else {
        return -EINVAL;
    };
    let Some(out_sd_len) = (unsafe { out_sd_len.as_mut() }) else {
        return -EINVAL;
    };

    *out_sd_ptr = null();
    *out_sd_len = 0;

    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match build_sd_subset_bytes(sd_bytes, security_info) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Serializes a requested subset of a live token SD into one self-relative
/// descriptor buffer.
pub extern "C" fn kacs_rust_query_token_sd_subset(
    token_ptr: *const c_void,
    security_info: u32,
    out_sd_ptr: *mut *const u8,
    out_sd_len: *mut usize,
) -> i32 {
    let Some(out_sd_ptr) = (unsafe { out_sd_ptr.as_mut() }) else {
        return -EINVAL;
    };
    let Some(out_sd_len) = (unsafe { out_sd_len.as_mut() }) else {
        return -EINVAL;
    };
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return -EACCES;
    };

    *out_sd_ptr = null();
    *out_sd_len = 0;

    match build_sd_subset_bytes(token.own_sd_bytes(), security_info) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Merges one caller-supplied subset descriptor into the current live process
/// SD using the bounded Slice 52 process-SD rules.
pub extern "C" fn kacs_rust_merge_process_sd(
    subject_token_ptr: *const c_void,
    current_sd_ptr: *const u8,
    current_sd_len: usize,
    security_info: u32,
    input_sd_ptr: *const u8,
    input_sd_len: usize,
    out_sd_ptr: *mut *const u8,
    out_sd_len: *mut usize,
) -> i32 {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token_ptr) }) else {
        return -EACCES;
    };
    let Some(out_sd_ptr) = (unsafe { out_sd_ptr.as_mut() }) else {
        return -EINVAL;
    };
    let Some(out_sd_len) = (unsafe { out_sd_len.as_mut() }) else {
        return -EINVAL;
    };

    *out_sd_ptr = null();
    *out_sd_len = 0;

    if current_sd_ptr.is_null()
        || current_sd_len == 0
        || input_sd_ptr.is_null()
        || input_sd_len == 0
    {
        return -EINVAL;
    }

    let current_sd_bytes = unsafe { core::slice::from_raw_parts(current_sd_ptr, current_sd_len) };
    let input_sd_bytes = unsafe { core::slice::from_raw_parts(input_sd_ptr, input_sd_len) };
    match merge_process_sd_bytes(subject, current_sd_bytes, security_info, input_sd_bytes) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Merges one caller-supplied subset descriptor into the current live token SD
/// using the generic set-security rules.
pub extern "C" fn kacs_rust_set_token_sd(
    subject_token_ptr: *const c_void,
    target_token_ptr: *const c_void,
    security_info: u32,
    input_sd_ptr: *const u8,
    input_sd_len: usize,
) -> i32 {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token_ptr) }) else {
        return -EACCES;
    };
    let Some(target) = (unsafe { PkmKacsBootToken::from_ptr(target_token_ptr) }) else {
        return -EACCES;
    };

    if input_sd_ptr.is_null() || input_sd_len == 0 {
        return -EINVAL;
    }

    let input_sd_bytes = unsafe { core::slice::from_raw_parts(input_sd_ptr, input_sd_len) };
    match target.replace_own_sd(subject, security_info, input_sd_bytes) {
        Ok(()) => 0,
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
pub extern "C" fn kacs_rust_token_restrict(
    source_token: *const c_void,
    creator_token: *const c_void,
    privs_to_delete: u64,
    flags: u32,
    payload: *const u8,
    payload_len: usize,
    num_deny_indices: u32,
    num_restrict_sids: u32,
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
    let payload = if payload_len == 0 {
        &[][..]
    } else if payload.is_null() {
        return -EINVAL;
    } else {
        unsafe { core::slice::from_raw_parts(payload, payload_len) }
    };

    if flags & !1u32 != 0 {
        return -EINVAL;
    }

    let (deny_indices, restrict_sids) =
        match parse_restrict_payload(payload, num_deny_indices, num_restrict_sids) {
            Ok(value) => value,
            Err(err) => return err,
        };

    match source_token.restrict(
        creator_token,
        privs_to_delete,
        (flags & 1u32) == 1u32,
        deny_indices.as_slice(),
        restrict_sids.as_slice(),
    ) {
        Ok(token) => {
            *out_token = token;
            0
        }
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
/// Fills one KUnit-visible snapshot of a published logon session by id.
pub extern "C" fn kacs_rust_kunit_session_snapshot(
    session_id: u64,
    out: *mut PkmKacsSessionSnapshot,
) -> i32 {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -EINVAL;
    };
    let _guard = lock_session_table();
    let Some(session_ptr) = session_list_find_locked(session_id) else {
        return -EACCES;
    };
    let session = unsafe { &*session_ptr };

    session.snapshot(out);
    0
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
