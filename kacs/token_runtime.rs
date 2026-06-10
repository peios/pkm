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

use crate::access_check::{access_check_core, AccessCheckMode};
use crate::access_check_abi::{own_audit_events, AccessCheckAbiResolved};
use crate::access_mask::{
    GenericMapping, ACCESS_SYSTEM_SECURITY, FILE_GENERIC_MAPPING, FILE_READ_DATA,
    FILE_WRITE_DATA, GENERIC_ALL, PROCESS_GENERIC_MAPPING, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use crate::audit::evaluate_sacl;
use crate::ace::{
    minimum_acl_revision_with_source_floor_for_opaque, AceKind, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACL_REVISION, ACL_REVISION_DS, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
};
use crate::acl::Acl;
use crate::claims::{
    parse_claim_attribute_array, parse_claim_attribute_entry, ClaimAttribute, ClaimValue,
    CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64, CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING,
    CLAIM_TYPE_UINT64,
};
use crate::condition::ConditionalContext;
use crate::error::KacsError;
use crate::inheritance::{inherit_registry_container_child_sd, RegistryContainerChildInheritance};
use crate::kmes_payload::{
    emit_access_check_events_to_kmes, emit_continuous_audit_to_kmes,
    emit_logon_session_destroyed_to_kmes,
};
use crate::mic::{
    IntegrityLevel, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
use crate::pip::PipContext;
use crate::pkm_alloc::{slice_to_vec, String, TryClone, Vec};
use crate::privilege::{
    TokenPrivileges, SE_RELABEL_PRIVILEGE, SE_RESTORE_PRIVILEGE, SE_SECURITY_PRIVILEGE,
};
use crate::sacl::extract_sacl_metadata;
use crate::security_descriptor::{
    SecurityDescriptor, SecurityDescriptorComponentLayout, SecurityDescriptorLayout,
    MAX_SECURITY_DESCRIPTOR_BYTES, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ,
    SE_DACL_DEFAULTED, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_DACL_TRUSTED,
    SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_RM_CONTROL_VALID, SE_SACL_AUTO_INHERITED,
    SE_SACL_AUTO_INHERIT_REQ, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
    SE_SELF_RELATIVE, SE_SERVER_SECURITY,
};
use crate::sid::Sid;
use crate::token::{
    AccessCheckToken, ConfinementTokenContext, ImpersonationLevel, RestrictedTokenContext,
    SidAndAttributes, TokenType, TokenView, AUDIT_POLICY_OBJECT_ACCESS_FAILURE,
    AUDIT_POLICY_OBJECT_ACCESS_SUCCESS, AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_long, c_ulong, c_void};
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
const TOKEN_SPEC_VERSION: u32 = 2;
const TOKEN_SPEC_HEADER_LEN: usize = 192;
const MAX_TOKEN_SPEC_BYTES: usize = 65_536;
const TOKEN_SOURCE_NAME_LEN: usize = 8;
const TOKEN_LCS_CREDENTIALS_VERSION: u32 = 1;
const TOKEN_LCS_CREDENTIALS_HEADER_LEN: usize = 16;
const KACS_LCS_SCOPE_GUID_BYTES: usize = 16;
const KACS_LCS_MAX_SCOPE_GUIDS_PER_TOKEN: usize = 256;
const KACS_LCS_MAX_PRIVATE_LAYERS_PER_TOKEN: usize = 256;
const KACS_LCS_MAX_PRIVATE_LAYER_NAME_BYTES: usize = 255;
const MAX_DEFAULT_DACL_BYTES: usize = 65_536;
const MAX_SESSION_SPEC_BYTES: usize = 4096;
const MIN_SESSION_SPEC_BYTES: usize = 15;
const MAX_BOOT_GROUPS: usize = 5;
const MAX_TOKEN_GROUPS: usize = 1024;
const GROUP_MASK_WORDS: usize = MAX_TOKEN_GROUPS / 64;
const TOKEN_INDEX_NO_CHANGE: u32 = u32::MAX;
const MAX_PRIVILEGE_ADJUST_ENTRIES: usize = 64;
const SD_HEADER_LEN: usize = 20;
const ACL_HEADER_LEN: usize = 8;
const ACE_HEADER_LEN: usize = 8;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const GROUP_SECURITY_INFORMATION: u32 = 0x0000_0002;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SACL_SECURITY_INFORMATION: u32 = 0x0000_0008;
const LABEL_SECURITY_INFORMATION: u32 = 0x0000_0010;
const CLAIM_SECURITY_ATTRIBUTE_MANDATORY: u32 = 0x0000_0020;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;
const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;

const EACCES: i32 = 13;
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const EBUSY: i32 = 16;
const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const ERANGE: i32 = 34;
const EOPNOTSUPP: i32 = 95;

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
    | KACS_TOKEN_ADJUST_PRIVS
    | KACS_TOKEN_ADJUST_GROUPS
    | KACS_TOKEN_ADJUST_DEFAULT;
const LCS_REGISTRY_KEY_ALL_ACCESS: u32 = 0x000F_003F;
const TOKEN_MANDATORY_POLICY_ALLOWED_MASK: u32 =
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
const TOKEN_AUDIT_POLICY_ALLOWED_MASK: u32 = AUDIT_POLICY_OBJECT_ACCESS_SUCCESS
    | AUDIT_POLICY_OBJECT_ACCESS_FAILURE
    | AUDIT_POLICY_PRIVILEGE_USE_SUCCESS
    | AUDIT_POLICY_PRIVILEGE_USE_FAILURE;
const SE_IMPERSONATE_PRIVILEGE: u64 = 1 << 29;
const SE_CREATE_TOKEN_PRIVILEGE: u64 = 1 << 2;

const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ANONYMOUS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
const LOCAL_SERVICE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const EVERYONE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const AUTHENTICATED_USERS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const LOCAL_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
const SERVICE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 6, 0, 0, 0];
const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const CREATOR_OWNER_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const CREATOR_GROUP_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0];
const LOGON_SID_BYTES: &[u8] = &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const ANONYMOUS_LOGON_SID_BYTES: &[u8] =
    &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 230, 3, 0, 0];
const AUTH_PACKAGE_NEGOTIATE: &[u8] = b"Negotiate";
const TOKEN_SOURCE_PEI_OS_KRN: &[u8; 8] = b"PeiosKrn";
const BOOT_SYSTEM_TOKEN_ID: u64 = 0;
const BOOT_SYSTEM_MODIFIED_ID: u64 = 0;
const ANONYMOUS_LOGON_LUID: u64 = 998;
const KUNIT_LOCAL_SERVICE_SESSION_LUID: u64 = 999;
const KUNIT_LOGON_TYPE_SESSION_LUID_BASE: u64 = 0x4b41_1000;
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
const KUNIT_LOCAL_SERVICE_GROUP_ATTRIBUTES: [u32; MAX_BOOT_GROUPS] = [
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
    SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
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
const LOGON_GROUP_ATTRIBUTES: u32 = SE_GROUP_MANDATORY
    | SE_GROUP_ENABLED_BY_DEFAULT
    | SE_GROUP_ENABLED
    | SE_GROUP_LOGON_ID;
const EMPTY_DEVICE_GROUPS: &[SidAndAttributes<'static>] = &[];
const EMPTY_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const EMPTY_POLICIES: &[crate::caap::CaapPolicyEntry<'static>] = &[];
static NEXT_DYNAMIC_TOKEN_ID: AtomicU64 = AtomicU64::new(KUNIT_LOCAL_SERVICE_SESSION_LUID + 1);
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
const TOKEN_CLASS_USER_CLAIMS: u32 = 0x16;
const TOKEN_CLASS_DEVICE_CLAIMS: u32 = 0x17;
const TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS: u32 = 0x18;
const KACS_UUID_BYTES: usize = 16;

extern "C" {
    fn pkm_kacs_boot_system_token_ptr() -> *const c_void;
    fn pkm_kacs_boot_anonymous_token_ptr() -> *const c_void;
    fn pkm_kacs_local_irq_save() -> c_ulong;
    fn pkm_kacs_local_irq_restore(flags: c_ulong);
    fn pkm_kacs_zalloc(size: usize) -> *mut c_void;
    fn pkm_kacs_free(ptr: *mut c_void);
    fn pkm_kacs_rcu_read_lock();
    fn pkm_kacs_rcu_read_unlock();
    fn pkm_kacs_free_after_rcu(ptr: *mut c_void);
    fn pkm_kacs_fill_uuid_v4(out: *mut u8);
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KacsRustCachedSdComponent {
    offset: u32,
    len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KacsRustCachedSdLayout {
    control: u16,
    rm_control: u8,
    owner_present: u8,
    group_present: u8,
    sacl_present: u8,
    dacl_present: u8,
    __reserved: u8,
    owner: KacsRustCachedSdComponent,
    group: KacsRustCachedSdComponent,
    sacl: KacsRustCachedSdComponent,
    dacl: KacsRustCachedSdComponent,
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
/// Bounded production token summary borrowed by LCS audit payload construction.
pub struct PkmKacsTokenAuditSummary {
    pub token_guid: [u8; KACS_UUID_BYTES],
    pub user_sid_ptr: *const u8,
    pub user_sid_len: usize,
    pub auth_id: u64,
    pub token_id: u64,
    pub token_type: u32,
    pub impersonation_level: u32,
    pub integrity_level: u32,
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
    /// Immutable token instance UUID.
    pub token_guid: [u8; KACS_UUID_BYTES],
    /// Token modified-id LUID.
    pub modified_id: u64,
    /// Token creation timestamp.
    pub created_at: u64,
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
    /// Token security descriptor bytes.
    pub own_sd_ptr: *const u8,
    /// Length of `own_sd_ptr`.
    pub own_sd_len: usize,
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
    /// Elevation type ABI value.
    pub elevation_type: u32,
    /// Whether the token has restricted SID semantics.
    pub restricted: u32,
    /// Whether the user SID participates as deny-only.
    pub user_deny_only: u32,
    /// Whether write-restricted AccessCheck evaluation is enabled.
    pub write_restricted: u32,
    /// Whether confinement checks treat the token as exempt.
    pub confinement_exempt: u32,
    /// Whether the token marks an isolation boundary.
    pub isolation_boundary: u32,
    /// Token source name bytes.
    pub source_name_ptr: *const u8,
    /// Length of `source_name_ptr`.
    pub source_name_len: usize,
    /// Token source LUID.
    pub source_id: u64,
    /// Expiration time, or zero for no expiry.
    pub expiration: u64,
    /// Origin LUID.
    pub origin: u64,
    /// Count of restricted SID entries.
    pub restricted_sid_count: u32,
    /// Whether a confinement SID is present.
    pub confinement_sid_present: u32,
    /// Count of confinement capability entries.
    pub confinement_capability_count: u32,
    /// Count of projected supplementary Linux GIDs.
    pub projected_supplementary_gid_count: u32,
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
    pub own_sd_ptr: *const u8,
    pub own_sd_len: usize,
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
    own_sd_ptr: *mut u8,
    own_sd_len: usize,
    live_tokens: AtomicUsize,
    destroying: AtomicBool,
    linked_elevated: *const c_void,
    linked_filtered: *const c_void,
}

struct OwnedSidAndAttributes {
    sid_bytes: Vec<u8>,
    sid: Sid<'static>,
    attributes: u32,
}

struct OwnedSid {
    sid_bytes: Vec<u8>,
    sid: Sid<'static>,
}

impl OwnedSid {
    fn as_bytes(&self) -> &[u8] {
        self.sid.as_bytes()
    }
}

struct PkmKacsBootToken {
    refcount: AtomicUsize,
    mutation_lock: AtomicBool,
    session: *const PkmKacsSession,
    user_sid: OwnedSid,
    groups: Vec<OwnedSidAndAttributes>,
    group_count: usize,
    group_sids: Vec<Sid<'static>>,
    group_default_attributes: Vec<u32>,
    group_attributes: Vec<AtomicU32>,
    group_views: UnsafeCell<Vec<PkmKacsBootGroupView>>,
    group_runtime_views: UnsafeCell<Vec<SidAndAttributes<'static>>>,
    token_guid: [u8; KACS_UUID_BYTES],
    token_id: u64,
    created_at: u64,
    modified_id: AtomicU64,
    owner_sid_index: AtomicU32,
    primary_group_index: AtomicU32,
    default_dacl_ptr: AtomicPtr<u8>,
    default_dacl_len: AtomicUsize,
    default_dacl_seq: AtomicU64,
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
    device_groups: Vec<OwnedSidAndAttributes>,
    device_group_views: Vec<SidAndAttributes<'static>>,
    restricted_device_groups: Vec<OwnedSidAndAttributes>,
    restricted_device_group_views: Vec<SidAndAttributes<'static>>,
    user_claims: Vec<ClaimAttribute>,
    device_claims: Vec<ClaimAttribute>,
    lcs_scope_guids: Vec<[u8; KACS_LCS_SCOPE_GUID_BYTES]>,
    lcs_private_layers: Vec<String>,
    confinement_sid: Option<OwnedSid>,
    confinement_capabilities: Vec<OwnedSidAndAttributes>,
    confinement_capability_views: Vec<SidAndAttributes<'static>>,
    confinement_exempt: bool,
    isolation_boundary: bool,
    audit_policy: u32,
    expiration: u64,
    source_name: [u8; TOKEN_SOURCE_NAME_LEN],
    source_id: u64,
    origin: u64,
    interactive_session_id: AtomicU32,
    projected_uid: u32,
    projected_gid: u32,
    projected_supplementary_gids: Vec<u32>,
    own_sd_ptr: AtomicPtr<u8>,
    own_sd_len: AtomicUsize,
    /// Seqlock guarding lockless snapshots of (own_sd_ptr, own_sd_len) against
    /// replace_own_sd. Mirrors default_dacl_seq; see own_sd_rcu_copy.
    own_sd_seq: AtomicU64,
}

struct TokenMutationGuard<'a> {
    token: &'a PkmKacsBootToken,
}

impl Drop for TokenMutationGuard<'_> {
    fn drop(&mut self) {
        self.token.mutation_lock.store(false, Ordering::Release);
    }
}

struct RcuReadGuard;

impl RcuReadGuard {
    fn new() -> Self {
        unsafe { pkm_kacs_rcu_read_lock() };
        Self
    }
}

impl Drop for RcuReadGuard {
    fn drop(&mut self) {
        unsafe { pkm_kacs_rcu_read_unlock() };
    }
}

fn new_uuid_v4() -> [u8; KACS_UUID_BYTES] {
    let mut uuid = [0u8; KACS_UUID_BYTES];

    unsafe { pkm_kacs_fill_uuid_v4(uuid.as_mut_ptr()) };
    uuid
}

struct DefaultDaclCopy {
    ptr: *mut u8,
    len: usize,
}

impl DefaultDaclCopy {
    fn empty() -> Self {
        Self {
            ptr: null_mut(),
            len: 0,
        }
    }

    fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(self.ptr.cast_const(), self.len) }
    }
}

impl Drop for DefaultDaclCopy {
    fn drop(&mut self) {
        free_allocated_bytes(self.ptr);
    }
}

struct SessionTableGuard {
    irq_flags: c_ulong,
}

impl Drop for SessionTableGuard {
    fn drop(&mut self) {
        SESSION_TABLE_LOCK.store(false, Ordering::Release);
        unsafe { pkm_kacs_local_irq_restore(self.irq_flags) };
    }
}

impl PkmKacsSession {
    fn session_list_remove_locked(target: *mut Self) -> bool {
        let mut prev: *mut Self = null_mut();
        let mut cursor = SESSION_LIST_HEAD.load(Ordering::Acquire);

        while !cursor.is_null() {
            let session = unsafe { &*cursor };

            if cursor == target {
                let next = session.next.load(Ordering::Relaxed);

                if prev.is_null() {
                    SESSION_LIST_HEAD.store(next, Ordering::Release);
                } else {
                    unsafe { &*prev }.next.store(next, Ordering::Relaxed);
                }
                session.next.store(null_mut(), Ordering::Relaxed);
                return true;
            }

            prev = cursor;
            cursor = session.next.load(Ordering::Relaxed);
        }

        false
    }

    fn prepare_destroy_locked(session_ptr: *mut Self) -> Option<(*const c_void, *const c_void)> {
        let session = unsafe { &mut *session_ptr };
        let linked_elevated;
        let linked_filtered;

        if session.destroying.swap(true, Ordering::AcqRel) {
            return None;
        }

        linked_elevated = session.linked_elevated;
        linked_filtered = if session.linked_filtered == linked_elevated {
            null()
        } else {
            session.linked_filtered
        };
        session.linked_elevated = null();
        session.linked_filtered = null();
        Self::session_list_remove_locked(session_ptr);
        Some((linked_elevated, linked_filtered))
    }

    fn finish_destroy(
        ptr: *const Self,
        linked_elevated: *const c_void,
        linked_filtered: *const c_void,
    ) {
        let Some(session) = (unsafe { Self::from_ptr(ptr.cast()) }) else {
            return;
        };

        let _ = emit_logon_session_destroyed_to_kmes(
            session.session_id,
            session.user_sid.as_bytes(),
            session.logon_type,
            session.auth_package_bytes(),
            session.created_at,
        );

        if !linked_elevated.is_null() {
            unsafe { PkmKacsBootToken::drop_ref(linked_elevated) };
        }
        if !linked_filtered.is_null() {
            unsafe { PkmKacsBootToken::drop_ref(linked_filtered) };
        }

        unsafe { Self::drop_ref(ptr) };
    }

    fn destroy_published_session(ptr: *const Self) {
        let prepared = {
            let _guard = lock_session_table();
            Self::prepare_destroy_locked(ptr as *mut Self)
        };

        if let Some((linked_elevated, linked_filtered)) = prepared {
            Self::finish_destroy(ptr, linked_elevated, linked_filtered);
        }
    }

    fn destroy_empty_published_session(session_id: u64) -> i32 {
        let prepared = {
            let _guard = lock_session_table();
            let Some(session_ptr) = session_list_find_locked(session_id) else {
                return -ENOENT;
            };
            let session = unsafe { &*session_ptr };

            if session.destroying.load(Ordering::Acquire)
                || session.refcount.load(Ordering::Acquire) != 1
                || session.live_tokens.load(Ordering::Acquire) != 0
                || !session.linked_elevated.is_null()
                || !session.linked_filtered.is_null()
            {
                return -EBUSY;
            }

            let Some((linked_elevated, linked_filtered)) =
                Self::prepare_destroy_locked(session_ptr)
            else {
                return -EBUSY;
            };

            (session_ptr.cast_const(), linked_elevated, linked_filtered)
        };

        let (session_ptr, linked_elevated, linked_filtered) = prepared;
        Self::finish_destroy(session_ptr, linked_elevated, linked_filtered);
        0
    }

    fn maybe_destroy_if_only_link_refs_remaining(ptr: *const Self) {
        let prepared = {
            let _guard = lock_session_table();
            let Some(session) = (unsafe { Self::from_ptr(ptr.cast()) }) else {
                return;
            };
            let Some(elevated) =
                (unsafe { PkmKacsBootToken::from_ptr(session.linked_elevated) })
            else {
                return;
            };
            let Some(filtered) =
                (unsafe { PkmKacsBootToken::from_ptr(session.linked_filtered) })
            else {
                return;
            };

            if session.destroying.load(Ordering::Acquire)
                || session.live_tokens.load(Ordering::Acquire) != 2
                || elevated.refcount.load(Ordering::Acquire) != 1
                || filtered.refcount.load(Ordering::Acquire) != 1
            {
                None
            } else {
                Self::prepare_destroy_locked(ptr as *mut Self)
            }
        };

        if let Some((linked_elevated, linked_filtered)) = prepared {
            Self::finish_destroy(ptr, linked_elevated, linked_filtered);
        }
    }

    fn register_live_token(ptr: *const Self) {
        let Some(session) = (unsafe { Self::from_ptr(ptr.cast()) }) else {
            return;
        };

        session.live_tokens.fetch_add(1, Ordering::Relaxed);
    }

    fn release_live_token(ptr: *const Self) -> usize {
        let Some(session) = (unsafe { Self::from_ptr(ptr.cast()) }) else {
            return 0;
        };

        loop {
            let current = session.live_tokens.load(Ordering::Acquire);

            if current == 0 {
                return 0;
            }
            if session
                .live_tokens
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return current - 1;
            }
        }
    }

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

        let previous = session.refcount.fetch_sub(1, Ordering::Release);

        if previous == 1 {
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
            free_allocated_bytes(session.own_sd_ptr);
            unsafe { core::ptr::drop_in_place(session_ptr) };
            unsafe { pkm_kacs_free(session_ptr.cast()) };
            return;
        }

        if previous == 2
            && session.live_tokens.load(Ordering::Acquire) == 0
            && !session.destroying.load(Ordering::Acquire)
        {
            Self::destroy_published_session(ptr);
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
            own_sd_ptr: self.own_sd_bytes().as_ptr(),
            own_sd_len: self.own_sd_bytes().len(),
        };
    }

    fn own_sd_bytes(&self) -> &[u8] {
        if self.own_sd_ptr.is_null() || self.own_sd_len == 0 {
            return &[];
        }

        unsafe {
            core::slice::from_raw_parts(self.own_sd_ptr.cast_const(), self.own_sd_len)
        }
    }
}

fn decimal_u64_len(mut value: u64) -> usize {
    let mut len = 1usize;

    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

fn session_listing_line_len(session: &PkmKacsSession) -> Option<usize> {
    let mut len = b"session_id=".len();

    len = len.checked_add(decimal_u64_len(session.session_id))?;
    len = len.checked_add(b" user_sid=".len())?;
    len = len.checked_add(session.user_sid.as_bytes().len().checked_mul(2)?)?;
    len = len.checked_add(b" logon_type=".len())?;
    len = len.checked_add(decimal_u64_len(u64::from(session.logon_type)))?;
    len = len.checked_add(b" auth_package=".len())?;
    len = len.checked_add(session.auth_package_bytes().len().checked_mul(2)?)?;
    len = len.checked_add(b" created_at=".len())?;
    len = len.checked_add(decimal_u64_len(session.created_at))?;
    len.checked_add(1)
}

fn sessions_listing_len_locked() -> Result<usize, i32> {
    let mut cursor = SESSION_LIST_HEAD.load(Ordering::Acquire);
    let mut len = 0usize;

    while !cursor.is_null() {
        let session = unsafe { &*cursor };

        len = len
            .checked_add(session_listing_line_len(session).ok_or(-ERANGE)?)
            .ok_or(-ERANGE)?;
        cursor = session.next.load(Ordering::Relaxed);
    }

    Ok(len)
}

fn write_decimal_u64(writer: &mut QueryWriter, mut value: u64) -> bool {
    let mut buf = [0u8; 20];
    let mut pos = buf.len();

    loop {
        pos -= 1;
        buf[pos] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    writer.write_bytes(&buf[pos..])
}

fn write_hex_bytes(writer: &mut QueryWriter, bytes: &[u8]) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for byte in bytes {
        let pair = [HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]];

        if !writer.write_bytes(&pair) {
            return false;
        }
    }

    true
}

fn write_session_listing_line(writer: &mut QueryWriter, session: &PkmKacsSession) -> bool {
    writer.write_bytes(b"session_id=")
        && write_decimal_u64(writer, session.session_id)
        && writer.write_bytes(b" user_sid=")
        && write_hex_bytes(writer, session.user_sid.as_bytes())
        && writer.write_bytes(b" logon_type=")
        && write_decimal_u64(writer, u64::from(session.logon_type))
        && writer.write_bytes(b" auth_package=")
        && write_hex_bytes(writer, session.auth_package_bytes())
        && writer.write_bytes(b" created_at=")
        && write_decimal_u64(writer, session.created_at)
        && writer.write_bytes(b"\n")
}

fn write_sessions_listing_locked(out: *mut u8, out_len: usize) -> Result<usize, i32> {
    let mut cursor = SESSION_LIST_HEAD.load(Ordering::Acquire);
    let mut writer = QueryWriter::new(out, out_len);

    while !cursor.is_null() {
        let session = unsafe { &*cursor };

        if !write_session_listing_line(&mut writer, session) {
            return Err(-ERANGE);
        }
        cursor = session.next.load(Ordering::Relaxed);
    }

    Ok(writer.written())
}

fn lock_session_table() -> SessionTableGuard {
    let irq_flags = unsafe { pkm_kacs_local_irq_save() };

    while SESSION_TABLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    SessionTableGuard { irq_flags }
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

    fn write_u16(&mut self, value: u16) -> bool {
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

fn claim_value_type_supported(value_type: u16) -> bool {
    matches!(
        value_type,
        CLAIM_TYPE_INT64
            | CLAIM_TYPE_UINT64
            | CLAIM_TYPE_STRING
            | CLAIM_TYPE_SID
            | CLAIM_TYPE_BOOLEAN
            | CLAIM_TYPE_OCTET
    )
}

fn utf16_cstr_len(value: &str) -> Option<usize> {
    let mut len = 2usize;

    for _ in value.encode_utf16() {
        len = len.checked_add(2)?;
    }

    Some(len)
}

fn claim_value_slot_len(value_type: u16) -> Result<usize, i32> {
    match value_type {
        CLAIM_TYPE_INT64 | CLAIM_TYPE_UINT64 | CLAIM_TYPE_BOOLEAN => Ok(8),
        CLAIM_TYPE_STRING | CLAIM_TYPE_SID | CLAIM_TYPE_OCTET => Ok(4),
        _ => Err(-EINVAL),
    }
}

fn claim_value_nested_len(value_type: u16, value: &ClaimValue) -> Result<usize, i32> {
    match (value_type, value) {
        (CLAIM_TYPE_INT64, ClaimValue::Int64(_))
        | (CLAIM_TYPE_UINT64, ClaimValue::UInt64(_))
        | (CLAIM_TYPE_BOOLEAN, ClaimValue::Boolean(_)) => Ok(0),
        (CLAIM_TYPE_STRING, ClaimValue::String(value)) => utf16_cstr_len(value.as_str()).ok_or(-EINVAL),
        (CLAIM_TYPE_SID, ClaimValue::Sid(value)) => Ok(value.len()),
        (CLAIM_TYPE_OCTET, ClaimValue::Octet(value)) => {
            4usize.checked_add(value.len()).ok_or(-EINVAL)
        }
        _ => Err(-EINVAL),
    }
}

fn claim_entry_query_len(claim: &ClaimAttribute) -> Result<usize, i32> {
    let value_type = claim.value_type;
    let value_count = claim.values.len();
    let offsets_len = value_count.checked_mul(4).ok_or(-EINVAL)?;
    let mut len = 16usize
        .checked_add(offsets_len)
        .and_then(|value| value.checked_add(utf16_cstr_len(claim.name.as_str())?))
        .ok_or(-EINVAL)?;

    if !claim_value_type_supported(value_type) {
        return Err(-EINVAL);
    }

    for value in claim.values.as_slice() {
        len = len
            .checked_add(claim_value_slot_len(value_type)?)
            .and_then(|value_len| value_len.checked_add(claim_value_nested_len(value_type, value).ok()?))
            .ok_or(-EINVAL)?;
    }

    if len > u32::MAX as usize {
        return Err(-EINVAL);
    }

    Ok(len)
}

fn claim_array_query_len(claims: &[ClaimAttribute]) -> Result<usize, i32> {
    let mut len = 0usize;

    for claim in claims {
        let entry_len = claim_entry_query_len(claim)?;
        len = len
            .checked_add(4)
            .and_then(|value| value.checked_add(entry_len))
            .ok_or(-EINVAL)?;
    }

    Ok(len)
}

fn write_utf16_cstr(writer: &mut QueryWriter, value: &str) -> bool {
    for unit in value.encode_utf16() {
        if !writer.write_u16(unit) {
            return false;
        }
    }

    writer.write_u16(0)
}

fn write_claim_array_query(
    claims: &[ClaimAttribute],
    writer: &mut QueryWriter,
) -> Result<(), i32> {
    for claim in claims {
        let entry_len = claim_entry_query_len(claim)?;

        if !writer.write_u32(entry_len as u32) {
            return Err(-ERANGE);
        }
        write_claim_entry(claim, writer)?;
    }

    Ok(())
}

fn write_claim_entry(claim: &ClaimAttribute, writer: &mut QueryWriter) -> Result<(), i32> {
    let value_type = claim.value_type;
    let value_count = claim.values.len();
    let offsets_len = value_count.checked_mul(4).ok_or(-EINVAL)?;
    let name_len = utf16_cstr_len(claim.name.as_str()).ok_or(-EINVAL)?;
    let name_offset = 16usize.checked_add(offsets_len).ok_or(-EINVAL)?;
    let value_slot_base = name_offset.checked_add(name_len).ok_or(-EINVAL)?;
    let mut slot_total_len = 0usize;

    if !claim_value_type_supported(value_type) {
        return Err(-EINVAL);
    }

    for value in claim.values.as_slice() {
        slot_total_len = slot_total_len
            .checked_add(claim_value_slot_len(value_type)?)
            .ok_or(-EINVAL)?;
        claim_value_nested_len(value_type, value)?;
    }

    if name_offset > u32::MAX as usize {
        return Err(-EINVAL);
    }
    if value_count > u32::MAX as usize {
        return Err(-EINVAL);
    }

    if !writer.write_u32(name_offset as u32)
        || !writer.write_u16(value_type)
        || !writer.write_u16(0)
        || !writer.write_u32(claim.flags)
        || !writer.write_u32(value_count as u32)
    {
        return Err(-ERANGE);
    }

    let mut slot_cursor = value_slot_base;
    for value in claim.values.as_slice() {
        if slot_cursor > u32::MAX as usize {
            return Err(-EINVAL);
        }
        if !writer.write_u32(slot_cursor as u32) {
            return Err(-ERANGE);
        }
        slot_cursor = slot_cursor
            .checked_add(claim_value_slot_len(value_type)?)
            .ok_or(-EINVAL)?;
    }

    if !write_utf16_cstr(writer, claim.name.as_str()) {
        return Err(-ERANGE);
    }

    let mut nested_cursor = value_slot_base
        .checked_add(slot_total_len)
        .ok_or(-EINVAL)?;
    for value in claim.values.as_slice() {
        match (value_type, value) {
            (CLAIM_TYPE_INT64, ClaimValue::Int64(value)) => {
                if !writer.write_bytes(&value.to_le_bytes()) {
                    return Err(-ERANGE);
                }
            }
            (CLAIM_TYPE_UINT64, ClaimValue::UInt64(value)) => {
                if !writer.write_u64(*value) {
                    return Err(-ERANGE);
                }
            }
            (CLAIM_TYPE_BOOLEAN, ClaimValue::Boolean(value)) => {
                if !writer.write_u64(*value) {
                    return Err(-ERANGE);
                }
            }
            (CLAIM_TYPE_STRING, ClaimValue::String(_))
            | (CLAIM_TYPE_SID, ClaimValue::Sid(_))
            | (CLAIM_TYPE_OCTET, ClaimValue::Octet(_)) => {
                if nested_cursor > u32::MAX as usize {
                    return Err(-EINVAL);
                }
                if !writer.write_u32(nested_cursor as u32) {
                    return Err(-ERANGE);
                }
                nested_cursor = nested_cursor
                    .checked_add(claim_value_nested_len(value_type, value)?)
                    .ok_or(-EINVAL)?;
            }
            _ => return Err(-EINVAL),
        }
    }

    for value in claim.values.as_slice() {
        match (value_type, value) {
            (CLAIM_TYPE_INT64, ClaimValue::Int64(_))
            | (CLAIM_TYPE_UINT64, ClaimValue::UInt64(_))
            | (CLAIM_TYPE_BOOLEAN, ClaimValue::Boolean(_)) => {}
            (CLAIM_TYPE_STRING, ClaimValue::String(value)) => {
                if !write_utf16_cstr(writer, value.as_str()) {
                    return Err(-ERANGE);
                }
            }
            (CLAIM_TYPE_SID, ClaimValue::Sid(value)) => {
                if !writer.write_bytes(value.as_slice()) {
                    return Err(-ERANGE);
                }
            }
            (CLAIM_TYPE_OCTET, ClaimValue::Octet(value)) => {
                if value.len() > u32::MAX as usize
                    || !writer.write_u32(value.len() as u32)
                    || !writer.write_bytes(value.as_slice())
                {
                    return Err(-ERANGE);
                }
            }
            _ => return Err(-EINVAL),
        }
    }

    Ok(())
}

fn u32_array_query_len(values: &[u32]) -> Result<usize, i32> {
    if values.len() > u32::MAX as usize {
        return Err(-EINVAL);
    }

    4usize
        .checked_add(values.len().checked_mul(4).ok_or(-EINVAL)?)
        .ok_or(-EINVAL)
}

fn write_u32_array_query(values: &[u32], writer: &mut QueryWriter) -> Result<(), i32> {
    if values.len() > u32::MAX as usize {
        return Err(-EINVAL);
    }
    if !writer.write_u32(values.len() as u32) {
        return Err(-ERANGE);
    }
    for value in values {
        if !writer.write_u32(*value) {
            return Err(-ERANGE);
        }
    }
    Ok(())
}

fn copy_sid_bytes(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let mut copied = Vec::with_capacity(bytes.len()).map_err(|_| -ENOMEM)?;

    copied.extend_from_slice(bytes).map_err(|_| -ENOMEM)?;
    Ok(copied)
}

fn build_owned_sid(bytes: &[u8]) -> Result<OwnedSid, i32> {
    let sid_bytes = copy_sid_bytes(bytes)?;
    let sid_slice: &'static [u8] =
        unsafe { core::slice::from_raw_parts(sid_bytes.as_ptr(), sid_bytes.len()) };
    let sid = Sid::parse(sid_slice).map_err(|_| -EINVAL)?;

    Ok(OwnedSid { sid_bytes, sid })
}

fn clone_owned_sid(value: &OwnedSid) -> Result<OwnedSid, i32> {
    build_owned_sid(value.as_bytes())
}

fn clone_optional_owned_sid(value: Option<&OwnedSid>) -> Result<Option<OwnedSid>, i32> {
    match value {
        Some(value) => Ok(Some(clone_owned_sid(value)?)),
        None => Ok(None),
    }
}

fn clone_owned_sid_entries(
    entries: &[OwnedSidAndAttributes],
) -> Result<Vec<OwnedSidAndAttributes>, i32> {
    let mut cloned = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        let sid_owned = build_owned_sid(entry.sid.as_bytes())?;
        cloned
            .push(OwnedSidAndAttributes {
                sid_bytes: sid_owned.sid_bytes,
                sid: sid_owned.sid,
                attributes: entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok(cloned)
}

fn build_sid_and_attributes_views(
    entries: &[OwnedSidAndAttributes],
) -> Result<Vec<SidAndAttributes<'static>>, i32> {
    let mut views = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        views
            .push(SidAndAttributes {
                sid: entry.sid,
                attributes: entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok(views)
}

fn sid_vec_from_owned_entries(entries: &[OwnedSidAndAttributes]) -> Result<Vec<Sid<'static>>, i32> {
    let mut sids = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        sids.push(entry.sid).map_err(|_| -ENOMEM)?;
    }

    Ok(sids)
}

fn build_owned_sid_entries_from_views(
    entries: &[SidAndAttributes<'_>],
) -> Result<(Vec<OwnedSidAndAttributes>, Vec<SidAndAttributes<'static>>), i32> {
    let mut owned = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;
    let mut views = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        let sid_bytes = copy_sid_bytes(entry.sid.as_bytes())?;
        let sid_slice: &'static [u8] =
            unsafe { core::slice::from_raw_parts(sid_bytes.as_ptr(), sid_bytes.len()) };
        let sid = Sid::parse(sid_slice).map_err(|_| -EINVAL)?;

        owned
            .push(OwnedSidAndAttributes {
                sid_bytes,
                sid,
                attributes: entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;

        let owned_entry = &owned[owned.len() - 1];
        views
            .push(SidAndAttributes {
                sid: owned_entry.sid,
                attributes: owned_entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok((owned, views))
}

fn parse_sid_and_attributes_array(
    bytes: &[u8],
    count: u32,
) -> Result<(Vec<OwnedSidAndAttributes>, Vec<SidAndAttributes<'static>>), i32> {
    let count = usize::try_from(count).map_err(|_| -EINVAL)?;
    // Bound count against the section size before reserving capacity: each entry
    // occupies at least 4 (sid_len) + Sid::MIN_SIZE + 4 (attributes) bytes, so a
    // header count far larger than the section cannot drive a huge with_capacity
    // reservation. A valid array always satisfies this bound.
    const MIN_ENTRY_BYTES: usize = 4 + Sid::MIN_SIZE + 4;
    if count > bytes.len() / MIN_ENTRY_BYTES {
        return Err(-EINVAL);
    }
    let mut owned = Vec::with_capacity(count).map_err(|_| -ENOMEM)?;
    let mut views = Vec::with_capacity(count).map_err(|_| -ENOMEM)?;
    let mut offset = 0usize;

    for _ in 0..count {
        let sid_len = usize::try_from(read_le_u32(bytes, offset).ok_or(-EINVAL)?)
            .map_err(|_| -EINVAL)?;
        let sid_offset = offset.checked_add(4).ok_or(-ERANGE)?;
        let sid_end = sid_offset.checked_add(sid_len).ok_or(-ERANGE)?;
        let attr_offset = sid_end;
        let attr_end = attr_offset.checked_add(4).ok_or(-ERANGE)?;
        let sid_bytes = bytes.get(sid_offset..sid_end).ok_or(-EINVAL)?;
        let attributes = read_le_u32(bytes, attr_offset).ok_or(-EINVAL)?;
        let sid_owned = build_owned_sid(sid_bytes)?;

        if sid_owned.sid.as_bytes().len() != sid_len {
            return Err(-EINVAL);
        }

        offset = attr_end;
        owned
            .push(OwnedSidAndAttributes {
                sid_bytes: sid_owned.sid_bytes,
                sid: sid_owned.sid,
                attributes,
            })
            .map_err(|_| -ENOMEM)?;

        let owned_entry = &owned[owned.len() - 1];
        views
            .push(SidAndAttributes {
                sid: owned_entry.sid,
                attributes: owned_entry.attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    if offset != bytes.len() {
        return Err(-EINVAL);
    }

    Ok((owned, views))
}

fn normalize_group_attributes_for_creation(attributes: u32) -> u32 {
    if (attributes & SE_GROUP_ENABLED_BY_DEFAULT) == SE_GROUP_ENABLED_BY_DEFAULT {
        attributes | SE_GROUP_ENABLED
    } else {
        attributes & !SE_GROUP_ENABLED
    }
}

fn normalize_group_entries_for_creation(entries: &mut [OwnedSidAndAttributes]) {
    for entry in entries {
        entry.attributes = normalize_group_attributes_for_creation(entry.attributes);
    }
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

    // Bound both counts against the payload size BEFORE reserving capacity, so a
    // huge num_deny_indices / num_restrict_sids cannot drive a multi-gigabyte
    // with_capacity reservation. Each deny index is 4 bytes; each restricted SID
    // is at least Sid::MIN_SIZE bytes.
    if data.len() < deny_bytes {
        return Err(-EINVAL);
    }
    if sid_count > (data.len() - deny_bytes) / Sid::MIN_SIZE {
        return Err(-EINVAL);
    }

    let mut deny_indices = Vec::with_capacity(deny_count).map_err(|_| -ENOMEM)?;
    let mut restrict_sids = Vec::with_capacity(sid_count).map_err(|_| -ENOMEM)?;
    let mut offset = deny_bytes;

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

fn alloc_bytes(len: usize) -> Result<*mut u8, i32> {
    if len > MAX_DEFAULT_DACL_BYTES {
        return Err(-EINVAL);
    }
    if len == 0 {
        return Ok(null_mut());
    }

    let ptr = unsafe { pkm_kacs_zalloc(len) } as *mut u8;
    if ptr.is_null() {
        return Err(-ENOMEM);
    }

    Ok(ptr)
}

fn alloc_copy_bytes(bytes: &[u8]) -> Result<(*mut u8, usize), i32> {
    let len = bytes.len();
    let ptr = alloc_bytes(len)?;

    if len == 0 {
        return Ok((ptr, 0));
    }

    unsafe { copy_nonoverlapping(bytes.as_ptr(), ptr, len) };
    Ok((ptr, len))
}

fn free_allocated_bytes(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { pkm_kacs_free(ptr.cast()) };
    }
}

fn free_allocated_bytes_after_rcu(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { pkm_kacs_free_after_rcu(ptr.cast()) };
    }
}

fn cached_component_from_core(
    component: Option<SecurityDescriptorComponentLayout>,
) -> (u8, KacsRustCachedSdComponent) {
    match component {
        Some(component) => (
            1,
            KacsRustCachedSdComponent {
                offset: component.offset.try_into().unwrap_or(u32::MAX),
                len: component.len.try_into().unwrap_or(u32::MAX),
            },
        ),
        None => (0, KacsRustCachedSdComponent { offset: 0, len: 0 }),
    }
}

fn cached_layout_from_core(layout: &SecurityDescriptorLayout) -> KacsRustCachedSdLayout {
    let (owner_present, owner) = cached_component_from_core(layout.owner);
    let (group_present, group) = cached_component_from_core(layout.group);
    let (sacl_present, sacl) = cached_component_from_core(layout.sacl);
    let (dacl_present, dacl) = cached_component_from_core(layout.dacl);

    KacsRustCachedSdLayout {
        control: layout.control,
        rm_control: layout.resource_manager_control,
        owner_present,
        group_present,
        sacl_present,
        dacl_present,
        __reserved: 0,
        owner,
        group,
        sacl,
        dacl,
    }
}

fn cached_component_to_core(
    present: u8,
    component: KacsRustCachedSdComponent,
) -> Result<Option<SecurityDescriptorComponentLayout>, i32> {
    match present {
        0 => Ok(None),
        1 => Ok(Some(SecurityDescriptorComponentLayout {
            offset: component.offset as usize,
            len: component.len as usize,
        })),
        _ => Err(-EINVAL),
    }
}

fn cached_layout_to_core(layout: &KacsRustCachedSdLayout) -> Result<SecurityDescriptorLayout, i32> {
    if layout.__reserved != 0 {
        return Err(-EINVAL);
    }

    Ok(SecurityDescriptorLayout {
        control: layout.control,
        resource_manager_control: layout.rm_control,
        owner: cached_component_to_core(layout.owner_present, layout.owner)?,
        group: cached_component_to_core(layout.group_present, layout.group)?,
        sacl: cached_component_to_core(layout.sacl_present, layout.sacl)?,
        dacl: cached_component_to_core(layout.dacl_present, layout.dacl)?,
    })
}

fn cached_file_sd_descriptor<'a>(
    sd_bytes: &'a [u8],
    layout: *const KacsRustCachedSdLayout,
) -> Result<SecurityDescriptor<'a>, i32> {
    let Some(layout) = (unsafe { layout.as_ref() }) else {
        return Err(-EINVAL);
    };
    let layout = cached_layout_to_core(layout)?;

    SecurityDescriptor::from_cached_layout(sd_bytes, &layout).map_err(sd_parse_errno)
}

fn read_le_u16(src: &[u8], offset: usize) -> Option<u16> {
    let bytes = src.get(offset..offset.checked_add(2)?)?;

    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(src: &[u8], offset: usize) -> Option<u32> {
    let bytes = src.get(offset..offset.checked_add(4)?)?;

    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_le_u64(src: &[u8], offset: usize) -> Option<u64> {
    let bytes = src.get(offset..offset.checked_add(8)?)?;

    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_bool_u8(src: &[u8], offset: usize) -> Result<bool, i32> {
    match *src.get(offset).ok_or(-EINVAL)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(-EINVAL),
    }
}

fn sorted_active_section_offsets(spec: &[u8], offsets: &[u32]) -> Result<Vec<usize>, i32> {
    let mut sorted = Vec::with_capacity(offsets.len()).map_err(|_| -ENOMEM)?;

    for raw_offset in offsets {
        if *raw_offset == 0 {
            continue;
        }

        let offset = usize::try_from(*raw_offset).map_err(|_| -EINVAL)?;
        if offset < TOKEN_SPEC_HEADER_LEN || offset >= spec.len() {
            return Err(-EINVAL);
        }

        let mut insert_at = sorted.len();
        for (index, existing) in sorted.iter().enumerate() {
            if *existing == offset {
                return Err(-EINVAL);
            }
            if *existing > offset {
                insert_at = index;
                break;
            }
        }

        sorted.push(0).map_err(|_| -ENOMEM)?;
        let mut cursor = sorted.len() - 1;
        while cursor > insert_at {
            sorted[cursor] = sorted[cursor - 1];
            cursor -= 1;
        }
        sorted[insert_at] = offset;
    }

    Ok(sorted)
}

fn section_limit(sorted_offsets: &[usize], offset: usize, total_len: usize) -> Result<usize, i32> {
    for (index, candidate) in sorted_offsets.iter().enumerate() {
        if *candidate == offset {
            return Ok(sorted_offsets
                .get(index + 1)
                .copied()
                .unwrap_or(total_len));
        }
    }

    Err(-EINVAL)
}

fn token_spec_fixed_section<'a>(
    spec: &'a [u8],
    sorted_offsets: &[usize],
    offset: u32,
    len: u32,
) -> Result<&'a [u8], i32> {
    if offset == 0 && len == 0 {
        return Ok(&[]);
    }
    if offset == 0 || len == 0 {
        return Err(-EINVAL);
    }

    let offset = usize::try_from(offset).map_err(|_| -EINVAL)?;
    let len = usize::try_from(len).map_err(|_| -EINVAL)?;
    let limit = section_limit(sorted_offsets, offset, spec.len())?;
    let end = offset.checked_add(len).ok_or(-ERANGE)?;
    if end > limit || end > spec.len() {
        return Err(-EINVAL);
    }

    spec.get(offset..end).ok_or(-EINVAL)
}

fn token_spec_count_section<'a>(
    spec: &'a [u8],
    sorted_offsets: &[usize],
    offset: u32,
    count: u32,
) -> Result<&'a [u8], i32> {
    if offset == 0 && count == 0 {
        return Ok(&[]);
    }
    if offset == 0 || count == 0 {
        return Err(-EINVAL);
    }

    let offset = usize::try_from(offset).map_err(|_| -EINVAL)?;
    let limit = section_limit(sorted_offsets, offset, spec.len())?;

    spec.get(offset..limit).ok_or(-EINVAL)
}

fn token_spec_unbounded_section<'a>(
    spec: &'a [u8],
    sorted_offsets: &[usize],
    offset: u32,
) -> Result<&'a [u8], i32> {
    if offset == 0 {
        return Err(-EINVAL);
    }

    let offset = usize::try_from(offset).map_err(|_| -EINVAL)?;
    let limit = section_limit(sorted_offsets, offset, spec.len())?;

    spec.get(offset..limit).ok_or(-EINVAL)
}

fn parse_projected_supplementary_gids(bytes: &[u8], count: u32) -> Result<Vec<u32>, i32> {
    let count = usize::try_from(count).map_err(|_| -EINVAL)?;
    let required_len = count.checked_mul(4).ok_or(-ERANGE)?;
    let mut gids = Vec::with_capacity(count).map_err(|_| -ENOMEM)?;

    if bytes.len() != required_len {
        return Err(-EINVAL);
    }

    for index in 0..count {
        let offset = index.checked_mul(4).ok_or(-ERANGE)?;
        gids.push(read_le_u32(bytes, offset).ok_or(-EINVAL)?)
            .map_err(|_| -ENOMEM)?;
    }

    Ok(gids)
}

fn string_from_utf8_bytes(bytes: &[u8]) -> Result<String, i32> {
    let value = core::str::from_utf8(bytes).map_err(|_| -EINVAL)?;
    let mut stored = String::new();

    for character in value.chars() {
        stored.push(character).map_err(|_| -ENOMEM)?;
    }

    Ok(stored)
}

fn parse_lcs_credential_extension(
    spec: &[u8],
    sorted_offsets: &[usize],
    offset: u32,
) -> Result<(Vec<[u8; KACS_LCS_SCOPE_GUID_BYTES]>, Vec<String>), i32> {
    let mut scope_guids = Vec::new();
    let mut private_layers = Vec::new();

    if offset == 0 {
        return Ok((scope_guids, private_layers));
    }

    let extension = token_spec_unbounded_section(spec, sorted_offsets, offset)?;
    if extension.len() < TOKEN_LCS_CREDENTIALS_HEADER_LEN {
        return Err(-EINVAL);
    }
    if read_le_u32(extension, 0).ok_or(-EINVAL)? != TOKEN_LCS_CREDENTIALS_VERSION {
        return Err(-EINVAL);
    }
    if read_le_u32(extension, 4).ok_or(-EINVAL)? != 0 {
        return Err(-EINVAL);
    }

    let scope_count =
        usize::try_from(read_le_u32(extension, 8).ok_or(-EINVAL)?).map_err(|_| -EINVAL)?;
    let private_layer_count =
        usize::try_from(read_le_u32(extension, 12).ok_or(-EINVAL)?).map_err(|_| -EINVAL)?;
    if scope_count > KACS_LCS_MAX_SCOPE_GUIDS_PER_TOKEN
        || private_layer_count > KACS_LCS_MAX_PRIVATE_LAYERS_PER_TOKEN
    {
        return Err(-EINVAL);
    }

    let scope_bytes = scope_count
        .checked_mul(KACS_LCS_SCOPE_GUID_BYTES)
        .ok_or(-ERANGE)?;
    let private_header_offset = TOKEN_LCS_CREDENTIALS_HEADER_LEN
        .checked_add(scope_bytes)
        .ok_or(-ERANGE)?;
    let private_header_bytes = private_layer_count.checked_mul(4).ok_or(-ERANGE)?;
    let private_payload_offset = private_header_offset
        .checked_add(private_header_bytes)
        .ok_or(-ERANGE)?;
    if private_payload_offset > extension.len() {
        return Err(-EINVAL);
    }

    scope_guids = Vec::with_capacity(scope_count).map_err(|_| -ENOMEM)?;
    for index in 0..scope_count {
        let start = TOKEN_LCS_CREDENTIALS_HEADER_LEN
            .checked_add(index.checked_mul(KACS_LCS_SCOPE_GUID_BYTES).ok_or(-ERANGE)?)
            .ok_or(-ERANGE)?;
        let end = start.checked_add(KACS_LCS_SCOPE_GUID_BYTES).ok_or(-ERANGE)?;
        let guid = <[u8; KACS_LCS_SCOPE_GUID_BYTES]>::try_from(
            extension.get(start..end).ok_or(-EINVAL)?,
        )
        .map_err(|_| -EINVAL)?;
        if guid.iter().all(|byte| *byte == 0) {
            return Err(-EINVAL);
        }
        if scope_guids.as_slice().iter().any(|existing| existing == &guid) {
            return Err(-EINVAL);
        }
        scope_guids.push(guid).map_err(|_| -ENOMEM)?;
    }

    private_layers = Vec::with_capacity(private_layer_count).map_err(|_| -ENOMEM)?;
    let mut payload_cursor = private_payload_offset;
    for index in 0..private_layer_count {
        let len_offset = private_header_offset
            .checked_add(index.checked_mul(4).ok_or(-ERANGE)?)
            .ok_or(-ERANGE)?;
        let name_len =
            usize::try_from(read_le_u32(extension, len_offset).ok_or(-EINVAL)?)
                .map_err(|_| -EINVAL)?;
        if name_len == 0 || name_len > KACS_LCS_MAX_PRIVATE_LAYER_NAME_BYTES {
            return Err(-EINVAL);
        }
        let end = payload_cursor.checked_add(name_len).ok_or(-ERANGE)?;
        let name_bytes = extension.get(payload_cursor..end).ok_or(-EINVAL)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| -EINVAL)?;
        if name.contains('\\') || name.contains('/') || name.as_bytes().contains(&0) {
            return Err(-EINVAL);
        }
        if private_layers
            .as_slice()
            .iter()
            .any(|existing| existing.as_str().eq_ignore_ascii_case(name))
        {
            return Err(-EINVAL);
        }
        let stored = string_from_utf8_bytes(name.as_bytes())?;
        private_layers.push(stored).map_err(|_| -ENOMEM)?;
        payload_cursor = end;
    }
    if payload_cursor != extension.len() {
        return Err(-EINVAL);
    }

    Ok((scope_guids, private_layers))
}

fn published_session_ref_by_id(session_id: u64) -> Result<*const PkmKacsSession, i32> {
    let _guard = lock_session_table();
    let Some(session_ptr) = session_list_find_locked(session_id) else {
        return Err(-EINVAL);
    };

    PkmKacsSession::clone_ref_ptr(session_ptr.cast()).ok_or(-EINVAL)
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
    group_sid: Sid<'_>,
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
    let (own_sd_ptr, own_sd_len) = match build_default_session_sd_bytes(user_sid, group_sid) {
        Ok(value) => value,
        Err(err) => {
            free_allocated_bytes(user_sid_ptr);
            free_allocated_bytes(auth_package_ptr);
            free_allocated_bytes(logon_sid_ptr);
            unsafe { pkm_kacs_free(session_ptr.cast()) };
            return Err(err);
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
                own_sd_ptr,
                own_sd_len,
                live_tokens: AtomicUsize::new(0),
                destroying: AtomicBool::new(false),
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
    group_sid: Sid<'_>,
) -> Result<*const PkmKacsSession, i32> {
    // Fast path: an existing session needs no allocation.
    {
        let _guard = lock_session_table();
        if let Some(session_ptr) = session_list_find_locked(session_id) {
            return PkmKacsSession::clone_ref_ptr(session_ptr.cast()).ok_or(-EINVAL);
        }
    }

    // KC-12: create_session_object allocates with GFP_KERNEL, which can
    // sleep/direct-reclaim. Build it OUTSIDE the IRQ-disabled session-table
    // spinlock, then re-check under the lock and either link it or — if another
    // thread published the same id meanwhile — discard our unpublished copy.
    let session_ptr = create_session_object(
        session_id,
        created_at,
        logon_type,
        auth_package,
        user_sid,
        group_sid,
    )?;

    let (result, discard) = {
        let _guard = lock_session_table();
        if let Some(existing) = session_list_find_locked(session_id) {
            (
                PkmKacsSession::clone_ref_ptr(existing.cast()).ok_or(-EINVAL),
                true,
            )
        } else {
            let head = SESSION_LIST_HEAD.load(Ordering::Relaxed);

            unsafe { &*session_ptr }.next.store(head, Ordering::Relaxed);
            SESSION_LIST_HEAD.store(session_ptr.cast_mut(), Ordering::Release);
            (
                PkmKacsSession::clone_ref_ptr(session_ptr).ok_or(-EINVAL),
                false,
            )
        }
    };

    if discard {
        // We lost the race: our session was never published (refcount 1,
        // unlinked), so drop_ref frees its buffers and struct directly.
        unsafe { PkmKacsSession::drop_ref(session_ptr) };
    }

    result
}

fn create_published_dynamic_session(
    created_at: u64,
    logon_type: u32,
    auth_package: &[u8],
    user_sid: Sid<'_>,
    group_sid: Sid<'_>,
) -> Result<u64, i32> {
    let session_id = allocate_dynamic_session_id()?;
    // KC-17/KC-12: create_session_object allocates with GFP_KERNEL, which can
    // sleep/direct-reclaim. Build it OUTSIDE the IRQ-disabled session-table
    // spinlock and take the lock only to link it in. The dynamic session id is
    // freshly allocated and unique, so no concurrent creator can race us.
    let session_ptr = create_session_object(
        session_id,
        created_at,
        logon_type,
        auth_package,
        user_sid,
        group_sid,
    )?;
    {
        let _guard = lock_session_table();
        let head = SESSION_LIST_HEAD.load(Ordering::Relaxed);

        unsafe { &*session_ptr }.next.store(head, Ordering::Relaxed);
        SESSION_LIST_HEAD.store(session_ptr.cast_mut(), Ordering::Release);
    }
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
    core::str::from_utf8(auth_package).map_err(|_| -EINVAL)?;
    let user_sid_bytes = spec.get(user_sid_offset..user_sid_end).ok_or(-EINVAL)?;
    let user_sid = Sid::parse(user_sid_bytes).map_err(|_| -EINVAL)?;
    if user_sid.as_bytes().len() != user_sid_len {
        return Err(-EINVAL);
    }

    Ok((logon_type, auth_package, user_sid))
}

fn build_group_views(
    group_sids: &[Sid<'static>],
    group_attributes: &[u32],
) -> Result<Vec<PkmKacsBootGroupView>, i32> {
    if group_sids.len() != group_attributes.len() {
        return Err(-EINVAL);
    }

    let mut views = Vec::with_capacity(group_sids.len()).map_err(|_| -ENOMEM)?;

    for (sid, attributes) in group_sids.iter().zip(group_attributes.iter()) {
        views
            .push(PkmKacsBootGroupView {
                sid_ptr: sid.as_bytes().as_ptr(),
                sid_len: sid.as_bytes().len(),
                attributes: *attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok(views)
}

fn build_group_runtime_views(
    group_sids: &[Sid<'static>],
    group_attributes: &[u32],
) -> Result<Vec<SidAndAttributes<'static>>, i32> {
    if group_sids.len() != group_attributes.len() {
        return Err(-EINVAL);
    }

    let mut views = Vec::with_capacity(group_sids.len()).map_err(|_| -ENOMEM)?;

    for (sid, attributes) in group_sids.iter().zip(group_attributes.iter()) {
        views
            .push(SidAndAttributes {
                sid: *sid,
                attributes: *attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok(views)
}

fn build_atomic_u32_vec(values: &[u32]) -> Result<Vec<AtomicU32>, i32> {
    let mut atoms = Vec::with_capacity(values.len()).map_err(|_| -ENOMEM)?;

    for value in values {
        atoms.push(AtomicU32::new(*value)).map_err(|_| -ENOMEM)?;
    }

    Ok(atoms)
}

fn try_clone_vec<T: TryClone>(values: &Vec<T>) -> Result<Vec<T>, i32> {
    values.try_clone().map_err(|_| -ENOMEM)
}

fn build_owned_group_entries(entries: &[(Sid<'_>, u32)]) -> Result<Vec<OwnedSidAndAttributes>, i32> {
    let mut owned = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for (sid, attributes) in entries {
        let sid_owned = build_owned_sid(sid.as_bytes())?;
        owned
            .push(OwnedSidAndAttributes {
                sid_bytes: sid_owned.sid_bytes,
                sid: sid_owned.sid,
                attributes: *attributes,
            })
            .map_err(|_| -ENOMEM)?;
    }

    Ok(owned)
}

fn attributes_vec_from_owned_entries(entries: &[OwnedSidAndAttributes]) -> Result<Vec<u32>, i32> {
    let mut attributes = Vec::with_capacity(entries.len()).map_err(|_| -ENOMEM)?;

    for entry in entries {
        attributes.push(entry.attributes).map_err(|_| -ENOMEM)?;
    }

    Ok(attributes)
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

fn write_basic_ace(
    dst: &mut [u8],
    offset: usize,
    ace_type: u8,
    mask: u32,
    sid: Sid<'_>,
) -> Result<usize, i32> {
    let ace_len = ace_len_for_sid(sid)?;
    let end = offset.checked_add(ace_len).ok_or(-ERANGE)?;
    let ace = dst.get_mut(offset..end).ok_or(-ERANGE)?;

    ace[0] = ace_type;
    ace[1] = 0;
    write_le_u16(ace, 2, ace_len as u16);
    write_le_u32(ace, 4, mask);
    ace[ACE_HEADER_LEN..].copy_from_slice(sid.as_bytes());
    Ok(ace_len)
}

fn write_allow_ace(dst: &mut [u8], offset: usize, mask: u32, sid: Sid<'_>) -> Result<usize, i32> {
    write_basic_ace(dst, offset, ACCESS_ALLOWED_ACE_TYPE, mask, sid)
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
    if total_len > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(-ERANGE);
    }
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
        SE_SELF_RELATIVE
            | SE_OWNER_DEFAULTED
            | SE_GROUP_DEFAULTED
            | SE_DACL_DEFAULTED
            | SE_DACL_PRESENT,
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

fn build_mount_fallback_file_sd_bytes() -> Result<(*mut u8, usize), i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;

    build_process_sd_bytes(
        system,
        system,
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        None,
        Some(crate::GENERIC_READ | crate::GENERIC_EXECUTE),
    )
}

fn build_securityfs_sessions_sd_bytes() -> Result<(*mut u8, usize), i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;

    build_process_sd_bytes(
        system,
        system,
        None,
        Some(FILE_READ_DATA),
        Some(FILE_READ_DATA),
        None,
    )
}

fn ace_inherits_to_child(ace_flags: u8, child_is_container: bool) -> bool {
    if child_is_container {
        (ace_flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != 0
    } else {
        (ace_flags & OBJECT_INHERIT_ACE) != 0
    }
}

fn inherited_ace_flags(parent_flags: u8, child_is_container: bool) -> u8 {
    let mut flags = (parent_flags | INHERITED_ACE) & !INHERIT_ONLY_ACE;

    if child_is_container
        && (parent_flags & OBJECT_INHERIT_ACE) != 0
        && (parent_flags & CONTAINER_INHERIT_ACE) == 0
        && (parent_flags & NO_PROPAGATE_INHERIT_ACE) == 0
    {
        flags |= INHERIT_ONLY_ACE;
    }
    if (parent_flags & NO_PROPAGATE_INHERIT_ACE) != 0 {
        flags &= !(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
    }

    flags
}

fn map_file_ace_mask(kind: AceKind<'_>) -> Result<u32, i32> {
    let mask = match kind {
        AceKind::SingleSid { mask, .. }
        | AceKind::Object { mask, .. }
        | AceKind::Callback { mask, .. }
        | AceKind::CallbackObject { mask, .. }
        | AceKind::ResourceAttribute { mask, .. } => mask,
        AceKind::Opaque => return Err(-EACCES),
    };

    FILE_GENERIC_MAPPING.map_mask(mask).map_err(|_| -EINVAL)
}

fn resolved_creator_ace_sid<'a>(
    sid: Sid<'a>,
    owner_sid: Sid<'a>,
    group_sid: Option<Sid<'a>>,
) -> Result<&'a [u8], i32> {
    if sid.as_bytes() == CREATOR_OWNER_SID_BYTES {
        Ok(owner_sid.as_bytes())
    } else if sid.as_bytes() == CREATOR_GROUP_SID_BYTES {
        group_sid.map(|sid| sid.as_bytes()).ok_or(-EINVAL)
    } else {
        Ok(sid.as_bytes())
    }
}

fn build_rewritten_file_ace_bytes(
    ace: crate::ace::Ace<'_>,
    new_flags: u8,
    owner_sid: Sid<'_>,
    group_sid: Option<Sid<'_>>,
) -> Result<Vec<u8>, i32> {
    let mut bytes = Vec::new();
    let mask;
    if ace.kind() == AceKind::Opaque {
        bytes
            .extend_from_slice(ace.bytes())
            .map_err(|_| -ENOMEM)?;
        bytes[1] = new_flags;
        return Ok(bytes);
    }

    mask = map_file_ace_mask(ace.kind())?;

    match ace.kind() {
        AceKind::SingleSid { sid, .. } => {
            let sid_bytes = resolved_creator_ace_sid(sid, owner_sid, group_sid)?;
            let ace_len = ACE_HEADER_LEN
                .checked_add(sid_bytes.len())
                .ok_or(-ERANGE)?;

            bytes
                .extend_from_slice(&[
                    ace.ace_type(),
                    new_flags,
                    (ace_len as u16).to_le_bytes()[0],
                    (ace_len as u16).to_le_bytes()[1],
                ])
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&mask.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
        }
        AceKind::Object {
            flags,
            object_type,
            inherited_object_type,
            sid,
            ..
        } => {
            let sid_bytes = resolved_creator_ace_sid(sid, owner_sid, group_sid)?;
            let ace_len = 12usize
                .checked_add(object_type.map_or(0, |_| 16))
                .and_then(|value| value.checked_add(inherited_object_type.map_or(0, |_| 16)))
                .and_then(|value| value.checked_add(sid_bytes.len()))
                .ok_or(-ERANGE)?;

            bytes
                .extend_from_slice(&[
                    ace.ace_type(),
                    new_flags,
                    (ace_len as u16).to_le_bytes()[0],
                    (ace_len as u16).to_le_bytes()[1],
                ])
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&mask.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&flags.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            if let Some(object_type) = object_type {
                bytes
                    .extend_from_slice(object_type.as_slice())
                    .map_err(|_| -ENOMEM)?;
            }
            if let Some(inherited_object_type) = inherited_object_type {
                bytes
                    .extend_from_slice(inherited_object_type.as_slice())
                    .map_err(|_| -ENOMEM)?;
            }
            bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
        }
        AceKind::Callback {
            sid,
            application_data,
            ..
        } => {
            let sid_bytes = resolved_creator_ace_sid(sid, owner_sid, group_sid)?;
            let ace_len = ACE_HEADER_LEN
                .checked_add(sid_bytes.len())
                .and_then(|value| value.checked_add(application_data.len()))
                .ok_or(-ERANGE)?;

            bytes
                .extend_from_slice(&[
                    ace.ace_type(),
                    new_flags,
                    (ace_len as u16).to_le_bytes()[0],
                    (ace_len as u16).to_le_bytes()[1],
                ])
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&mask.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(application_data)
                .map_err(|_| -ENOMEM)?;
        }
        AceKind::CallbackObject {
            flags,
            object_type,
            inherited_object_type,
            sid,
            application_data,
            ..
        } => {
            let sid_bytes = resolved_creator_ace_sid(sid, owner_sid, group_sid)?;
            let ace_len = 12usize
                .checked_add(object_type.map_or(0, |_| 16))
                .and_then(|value| value.checked_add(inherited_object_type.map_or(0, |_| 16)))
                .and_then(|value| value.checked_add(sid_bytes.len()))
                .and_then(|value| value.checked_add(application_data.len()))
                .ok_or(-ERANGE)?;

            bytes
                .extend_from_slice(&[
                    ace.ace_type(),
                    new_flags,
                    (ace_len as u16).to_le_bytes()[0],
                    (ace_len as u16).to_le_bytes()[1],
                ])
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&mask.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&flags.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            if let Some(object_type) = object_type {
                bytes
                    .extend_from_slice(object_type.as_slice())
                    .map_err(|_| -ENOMEM)?;
            }
            if let Some(inherited_object_type) = inherited_object_type {
                bytes
                    .extend_from_slice(inherited_object_type.as_slice())
                    .map_err(|_| -ENOMEM)?;
            }
            bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(application_data)
                .map_err(|_| -ENOMEM)?;
        }
        AceKind::ResourceAttribute {
            sid,
            application_data,
            ..
        } => {
            let sid_bytes = resolved_creator_ace_sid(sid, owner_sid, group_sid)?;
            let ace_len = ACE_HEADER_LEN
                .checked_add(sid_bytes.len())
                .and_then(|value| value.checked_add(application_data.len()))
                .ok_or(-ERANGE)?;

            bytes
                .extend_from_slice(&[
                    ace.ace_type(),
                    new_flags,
                    (ace_len as u16).to_le_bytes()[0],
                    (ace_len as u16).to_le_bytes()[1],
                ])
                .map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(&mask.to_le_bytes())
                .map_err(|_| -ENOMEM)?;
            bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
            bytes
                .extend_from_slice(application_data)
                .map_err(|_| -ENOMEM)?;
        }
        AceKind::Opaque => return Err(-EACCES),
    }

    Ok(bytes)
}

fn build_inherited_ace_bytes(
    ace: crate::ace::Ace<'_>,
    owner_sid: Sid<'_>,
    group_sid: Option<Sid<'_>>,
    child_is_container: bool,
) -> Result<Option<Vec<u8>>, i32> {
    let parent_flags = ace.ace_flags();

    if !ace_inherits_to_child(parent_flags, child_is_container) {
        return Ok(None);
    }

    build_rewritten_file_ace_bytes(
        ace,
        inherited_ace_flags(parent_flags, child_is_container),
        owner_sid,
        group_sid,
    )
    .map(Some)
}

fn inherit_acl_from_parent(
    parent_acl: Option<Acl<'_>>,
    owner_sid: Sid<'_>,
    group_sid: Option<Sid<'_>>,
    child_is_container: bool,
) -> Result<Option<Vec<u8>>, i32> {
    let mut inherited_aces = Vec::new();
    let Some(parent_acl) = parent_acl else {
        return Ok(None);
    };

    for ace in parent_acl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        let Some(ace_bytes) =
            build_inherited_ace_bytes(ace, owner_sid, group_sid, child_is_container)?
        else {
            continue;
        };
        inherited_aces.push(ace_bytes).map_err(|_| -ENOMEM)?;
    }

    if inherited_aces.is_empty() {
        return Ok(None);
    }

    let mut ace_refs = Vec::new();
    for ace in inherited_aces.iter() {
        ace_refs.push(ace.as_slice()).map_err(|_| -ENOMEM)?;
    }

    build_acl_bytes_from_aces_with_reserved(
        parent_acl.revision(),
        parent_acl.sbz1(),
        parent_acl.sbz2(),
        ace_refs.as_slice(),
    )
}

fn build_synthesized_file_sd_bytes(
    parent_sd_bytes: Option<&[u8]>,
    template_sd_bytes: Option<&[u8]>,
    child_is_container: bool,
) -> Result<(*mut u8, usize), i32> {
    let mut fallback_ptr = null_mut();
    let result;
    let template_bytes = if let Some(template_sd_bytes) = template_sd_bytes {
        template_sd_bytes
    } else {
        let (ptr, len) = build_mount_fallback_file_sd_bytes()?;
        fallback_ptr = ptr;
        unsafe { core::slice::from_raw_parts(ptr, len) }
    };
    let template_sd = match SecurityDescriptor::parse(template_bytes) {
        Ok(value) => value,
        Err(_) => {
            if !fallback_ptr.is_null() {
                free_allocated_bytes(fallback_ptr);
            }
            return Err(-EACCES);
        }
    };
    if template_sd.owner().is_none() {
        if !fallback_ptr.is_null() {
            free_allocated_bytes(fallback_ptr);
        }
        return Err(-EINVAL);
    }

    if let Some(parent_sd_bytes) = parent_sd_bytes {
        let owner_sid = match template_sd.owner() {
            Some(value) => value,
            None => {
                if !fallback_ptr.is_null() {
                    free_allocated_bytes(fallback_ptr);
                }
                return Err(-EACCES);
            }
        };
        let group_sid = template_sd.group();
        let parent_sd = match SecurityDescriptor::parse(parent_sd_bytes) {
            Ok(value) => value,
            Err(_) => {
                if !fallback_ptr.is_null() {
                    free_allocated_bytes(fallback_ptr);
                }
                return Err(-EACCES);
            }
        };
        let inherited_dacl =
            inherit_acl_from_parent(parent_sd.dacl(), owner_sid, group_sid, child_is_container)?;
        let inherited_sacl =
            inherit_acl_from_parent(parent_sd.sacl(), owner_sid, group_sid, child_is_container)?;
        let template_dacl = clone_optional_acl_bytes(template_sd.dacl())?;
        let base_control = if inherited_dacl.is_some() {
            template_sd.control() & SE_RM_CONTROL_VALID
        } else if template_dacl.is_some() {
            template_sd.control() & (SE_RM_CONTROL_VALID | SE_DACL_DEFAULTED)
        } else {
            template_sd.control() & SE_RM_CONTROL_VALID
        };

        result = build_sd_bytes_from_components(
            base_control,
            template_sd.resource_manager_control(),
            Some(owner_sid.as_bytes()),
            group_sid.map(|sid| sid.as_bytes()),
            inherited_sacl.as_deref(),
            inherited_dacl.as_deref().or(template_dacl.as_deref()),
        );
    } else {
        result = alloc_copy_bytes(template_bytes);
    }

    if !fallback_ptr.is_null() {
        free_allocated_bytes(fallback_ptr);
    }
    result
}

fn build_empty_acl_bytes(_revision: u8) -> Result<Option<Vec<u8>>, i32> {
    build_empty_acl_bytes_with_reserved(ACL_REVISION, 0, 0)
}

fn build_empty_acl_bytes_with_reserved(
    _revision: u8,
    sbz1: u8,
    sbz2: u16,
) -> Result<Option<Vec<u8>>, i32> {
    let mut bytes = Vec::with_capacity(ACL_HEADER_LEN).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[0u8; ACL_HEADER_LEN])
        .map_err(|_| -ENOMEM)?;
    bytes[0] = ACL_REVISION;
    bytes[1] = sbz1;
    bytes[2..4].copy_from_slice(&(ACL_HEADER_LEN as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&0u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&sbz2.to_le_bytes());
    Ok(Some(bytes))
}

fn build_explicit_acl_bytes(
    creator_acl: Option<Acl<'_>>,
    owner_sid: Sid<'_>,
    group_sid: Option<Sid<'_>>,
) -> Result<Option<Vec<u8>>, i32> {
    let Some(creator_acl) = creator_acl else {
        return Ok(None);
    };
    let mut explicit_aces = Vec::new();

    for ace in creator_acl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        let ace_bytes = build_rewritten_file_ace_bytes(
            ace,
            ace.ace_flags() & !INHERITED_ACE,
            owner_sid,
            group_sid,
        )?;
        explicit_aces.push(ace_bytes).map_err(|_| -ENOMEM)?;
    }

    if explicit_aces.is_empty() {
        return build_empty_acl_bytes_with_reserved(
            creator_acl.revision(),
            creator_acl.sbz1(),
            creator_acl.sbz2(),
        );
    }

    let mut ace_refs = Vec::new();
    for ace in explicit_aces.iter() {
        ace_refs.push(ace.as_slice()).map_err(|_| -ENOMEM)?;
    }

    build_acl_bytes_from_aces_with_reserved(
        creator_acl.revision(),
        creator_acl.sbz1(),
        creator_acl.sbz2(),
        ace_refs.as_slice(),
    )
}

fn append_acl_bytes(
    explicit_acl: Option<&[u8]>,
    inherited_acl: Option<&[u8]>,
    revision: u8,
    sbz1: u8,
    sbz2: u16,
) -> Result<Option<Vec<u8>>, i32> {
    let mut aces = Vec::new();

    if let Some(explicit_acl) = explicit_acl {
        let parsed = Acl::parse(explicit_acl).map_err(|_| -EINVAL)?;
        for ace in parsed.entries() {
            let ace = ace.map_err(|_| -EINVAL)?;
            let mut bytes = Vec::with_capacity(ace.bytes().len()).map_err(|_| -ENOMEM)?;
            bytes.extend_from_slice(ace.bytes()).map_err(|_| -ENOMEM)?;
            aces.push(bytes).map_err(|_| -ENOMEM)?;
        }
    }
    if let Some(inherited_acl) = inherited_acl {
        let parsed = Acl::parse(inherited_acl).map_err(|_| -EINVAL)?;
        for ace in parsed.entries() {
            let ace = ace.map_err(|_| -EINVAL)?;
            let mut bytes = Vec::with_capacity(ace.bytes().len()).map_err(|_| -ENOMEM)?;
            bytes.extend_from_slice(ace.bytes()).map_err(|_| -ENOMEM)?;
            aces.push(bytes).map_err(|_| -ENOMEM)?;
        }
    }

    if aces.is_empty() {
        return Ok(None);
    }

    let mut ace_refs = Vec::new();
    for ace in aces.iter() {
        ace_refs.push(ace.as_slice()).map_err(|_| -ENOMEM)?;
    }

    build_acl_bytes_from_aces_with_reserved(revision, sbz1, sbz2, ace_refs.as_slice())
}

fn find_explicit_label_ace_bytes(acl: Option<Acl<'_>>) -> Result<Option<Vec<u8>>, i32> {
    let Some(acl) = acl else {
        return Ok(None);
    };
    let mut found = None;

    for ace in acl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        if ace.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        if found.is_some() {
            return Err(-EINVAL);
        }
        let mut bytes = Vec::with_capacity(ace.bytes().len()).map_err(|_| -ENOMEM)?;
        bytes.extend_from_slice(ace.bytes()).map_err(|_| -ENOMEM)?;
        found = Some(bytes);
    }

    Ok(found)
}

fn build_created_file_acl_bytes(
    parent_acl: Option<Acl<'_>>,
    creator_acl: Option<Acl<'_>>,
    creator_control: u16,
    auto_inherit_req: u16,
    protected: u16,
    owner_sid: Sid<'_>,
    group_sid: Sid<'_>,
    child_is_container: bool,
    fallback_acl: Option<&[u8]>,
) -> Result<(Option<Vec<u8>>, bool, bool), i32> {
    let explicit_acl = build_explicit_acl_bytes(creator_acl, owner_sid, Some(group_sid))?;
    let explicit_present = creator_acl.is_some();

    if explicit_present {
        if (creator_control & protected) == protected {
            return Ok((explicit_acl, false, false));
        }
        if (creator_control & auto_inherit_req) == auto_inherit_req {
            let inherited_acl =
                inherit_acl_from_parent(parent_acl, owner_sid, Some(group_sid), child_is_container)?;
            let combined = append_acl_bytes(
                explicit_acl.as_deref(),
                inherited_acl.as_deref(),
                creator_acl.map(|acl| acl.revision()).unwrap_or(ACL_REVISION),
                creator_acl.map(|acl| acl.sbz1()).unwrap_or(0),
                creator_acl.map(|acl| acl.sbz2()).unwrap_or(0),
            )?;

            return Ok((combined.or(explicit_acl), inherited_acl.is_some(), false));
        }

        return Ok((explicit_acl, false, false));
    }

    let inherited_acl =
        inherit_acl_from_parent(parent_acl, owner_sid, Some(group_sid), child_is_container)?;
    if inherited_acl.is_some() {
        return Ok((inherited_acl, true, false));
    }

    if let Some(fallback_acl) = fallback_acl {
        let mut bytes = Vec::with_capacity(fallback_acl.len()).map_err(|_| -ENOMEM)?;
        bytes.extend_from_slice(fallback_acl).map_err(|_| -ENOMEM)?;
        return Ok((Some(bytes), false, true));
    }

    Ok((None, false, false))
}

fn build_created_file_sd_bytes(
    subject: &PkmKacsBootToken,
    parent_sd_bytes: &[u8],
    creator_sd_bytes: Option<&[u8]>,
    child_is_container: bool,
) -> Result<(*mut u8, usize), i32> {
    let parent_sd = SecurityDescriptor::parse(parent_sd_bytes).map_err(sd_parse_errno)?;
    let creator_sd = match creator_sd_bytes {
        Some(bytes) => Some(SecurityDescriptor::parse(bytes).map_err(sd_parse_errno)?),
        None => None,
    };
    let creator_control = creator_sd.map(|sd| sd.control()).unwrap_or(0);
    let creator_owner = creator_sd.and_then(|sd| sd.owner());
    let creator_group = creator_sd.and_then(|sd| sd.group());
    let creator_dacl = creator_sd.and_then(|sd| sd.dacl());
    let creator_sacl = creator_sd.and_then(|sd| sd.sacl());
    let owner_defaulted = creator_owner.is_none();
    let group_defaulted = creator_group.is_none();
    let owner_sid = if let Some(owner) = creator_owner {
        validate_owner_assignment(subject, owner, true)?;
        owner
    } else {
        subject
            .sid_by_index(subject.owner_sid_index.load(Ordering::Relaxed))
            .ok_or(-EACCES)?
    };
    let group_sid = if let Some(group) = creator_group {
        group
    } else {
        subject
            .sid_by_index(subject.primary_group_index.load(Ordering::Relaxed))
            .ok_or(-EACCES)?
    };
    let mut base_control = creator_control
        & (SE_DACL_TRUSTED
            | SE_DACL_AUTO_INHERIT_REQ
            | SE_SACL_AUTO_INHERIT_REQ
            | SE_DACL_PROTECTED
            | SE_SACL_PROTECTED);
    if creator_dacl.is_none() {
        base_control &= !SE_DACL_TRUSTED;
    }

    if (creator_control & SE_SERVER_SECURITY) == SE_SERVER_SECURITY {
        return Err(-EOPNOTSUPP);
    }

    if creator_sd.is_some() {
        if creator_sacl.is_some() {
            if !subject_has_enabled_privilege(subject, SE_SECURITY_PRIVILEGE) {
                return Err(-EACCES);
            }
            subject.mark_privileges_used(SE_SECURITY_PRIVILEGE);
        }
        let label_ace = find_explicit_label_ace_bytes(creator_sacl)?;
        validate_label_assignment(subject, label_ace.as_deref())?;
    }

    let token_default_dacl = subject.default_dacl_rcu_copy()?;
    let fallback_dacl = if token_default_dacl.is_empty() {
        None
    } else {
        Some(token_default_dacl.as_slice())
    };
    let (dacl, dacl_inherited, dacl_defaulted) = build_created_file_acl_bytes(
        parent_sd.dacl(),
        creator_dacl,
        creator_control,
        SE_DACL_AUTO_INHERIT_REQ,
        SE_DACL_PROTECTED,
        owner_sid,
        group_sid,
        child_is_container,
        fallback_dacl,
    )?;
    let (sacl, sacl_inherited, sacl_defaulted) = build_created_file_acl_bytes(
        parent_sd.sacl(),
        creator_sacl,
        creator_control,
        SE_SACL_AUTO_INHERIT_REQ,
        SE_SACL_PROTECTED,
        owner_sid,
        group_sid,
        child_is_container,
        None,
    )?;

    if dacl_inherited {
        base_control |= SE_DACL_AUTO_INHERITED;
    }
    if sacl_inherited {
        base_control |= SE_SACL_AUTO_INHERITED;
    }
    if owner_defaulted {
        base_control |= SE_OWNER_DEFAULTED;
    }
    if group_defaulted {
        base_control |= SE_GROUP_DEFAULTED;
    }
    if dacl_defaulted {
        base_control |= SE_DACL_DEFAULTED;
    }
    if sacl_defaulted {
        base_control |= SE_SACL_DEFAULTED;
    }

    build_sd_bytes_from_components(
        base_control,
        0,
        Some(owner_sid.as_bytes()),
        Some(group_sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    )
}

fn container_inheritance_errno(error: KacsError) -> i32 {
    match error {
        KacsError::AllocationFailure => -ENOMEM,
        KacsError::SecurityDescriptorTooLarge { .. } => -ERANGE,
        _ => -EINVAL,
    }
}

fn build_created_container_sd_bytes(
    subject: &PkmKacsBootToken,
    parent_sd_bytes: &[u8],
    generic_mapping: GenericMapping,
    valid_mapped_access_mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let parent_sd = SecurityDescriptor::parse(parent_sd_bytes).map_err(sd_parse_errno)?;
    let owner_sid = subject
        .sid_by_index(subject.owner_sid_index.load(Ordering::Relaxed))
        .ok_or(-EACCES)?;
    let group_sid = subject
        .sid_by_index(subject.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EACCES)?;
    let token_default_dacl_copy = subject.default_dacl_rcu_copy()?;
    let token_default_dacl = if token_default_dacl_copy.is_empty() {
        None
    } else {
        Some(Acl::parse(token_default_dacl_copy.as_slice()).map_err(sd_parse_errno)?)
    };
    let child_sd = inherit_registry_container_child_sd(RegistryContainerChildInheritance {
        parent_sd,
        token_owner: owner_sid,
        token_primary_group: group_sid,
        token_default_dacl,
        generic_mapping,
        valid_mapped_access_mask,
    })
    .map_err(container_inheritance_errno)?;

    alloc_copy_bytes(child_sd.as_slice())
}

fn validate_sd_bytes(sd_bytes: &[u8]) -> Result<(), i32> {
    SecurityDescriptor::parse(sd_bytes)
        .map(|_| ())
        .map_err(sd_parse_errno)
}

fn validate_stored_sd_bytes(sd_bytes: &[u8]) -> Result<(), i32> {
    let sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;

    if sd.owner().is_none() {
        return Err(-EINVAL);
    }

    Ok(())
}

fn build_kunit_single_opaque_acl_len(ace_len: usize) -> Result<usize, i32> {
    const OPAQUE_ACE_HEADER_LEN: usize = 4;

    if ace_len < OPAQUE_ACE_HEADER_LEN
        || ace_len > usize::from(u16::MAX)
        || (ace_len % 4) != 0
    {
        return Err(-EINVAL);
    }

    let mut ace = Vec::with_capacity(ace_len).map_err(|_| -ENOMEM)?;
    ace.push(0x87).map_err(|_| -ENOMEM)?;
    ace.push(0).map_err(|_| -ENOMEM)?;
    ace.extend_from_slice(&(ace_len as u16).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    for _ in OPAQUE_ACE_HEADER_LEN..ace_len {
        ace.push(0).map_err(|_| -ENOMEM)?;
    }

    let ace_refs = [ace.as_slice()];
    let Some(acl) = build_acl_bytes_from_aces(ACL_REVISION, &ace_refs)? else {
        return Err(-EINVAL);
    };

    Ok(acl.len())
}

fn sd_parse_errno(error: KacsError) -> i32 {
    match error {
        KacsError::SecurityDescriptorTooLarge { .. } => -ERANGE,
        _ => -EINVAL,
    }
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
    build_acl_bytes_from_aces_with_reserved(revision, 0, 0, aces)
}

fn build_acl_bytes_from_aces_with_reserved(
    revision: u8,
    sbz1: u8,
    sbz2: u16,
    aces: &[&[u8]],
) -> Result<Option<Vec<u8>>, i32> {
    if aces.is_empty() {
        return Ok(None);
    }
    let write_revision =
        minimum_acl_revision_with_source_floor_for_opaque(revision, aces).map_err(|_| -EINVAL)?;

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
    bytes[0] = write_revision;
    bytes[1] = sbz1;
    bytes[2..4].copy_from_slice(&(acl_len as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes[6..8].copy_from_slice(&sbz2.to_le_bytes());

    for ace in aces {
        bytes.extend_from_slice(ace).map_err(|_| -ENOMEM)?;
    }

    Ok(Some(bytes))
}

fn build_sd_bytes_from_components(
    base_control: u16,
    resource_manager_control: u8,
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
    if total_len > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(-ERANGE);
    }

    let mut bytes = Vec::with_capacity(total_len).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[0u8; SD_HEADER_LEN])
        .map_err(|_| -ENOMEM)?;
    bytes[0] = 1;
    bytes[1] = resource_manager_control;
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
        .extend_from_slice(&SYSTEM_MANDATORY_LABEL_NO_WRITE_UP.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&(integrity_level as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_system_success_audit_ace_bytes(mask: u32) -> Result<Vec<u8>, i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;
    let ace_len = ace_len_for_sid(system)?;
    let mut bytes = Vec::with_capacity(ace_len).map_err(|_| -ENOMEM)?;

    bytes
        .extend_from_slice(&[
            SYSTEM_AUDIT_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            (ace_len as u16).to_le_bytes()[0],
            (ace_len as u16).to_le_bytes()[1],
        ])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&mask.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(system.as_bytes())
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

fn build_mandatory_resource_attribute_ace_bytes(value: i64) -> Result<Vec<u8>, i32> {
    let application_data =
        build_int64_claim_entry("Mandatory", &[value], CLAIM_SECURITY_ATTRIBUTE_MANDATORY)?;
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let unpadded_ace_len = ACE_HEADER_LEN
        .checked_add(everyone.as_bytes().len())
        .and_then(|value| value.checked_add(application_data.len()))
        .ok_or(-ERANGE)?;
    let ace_len = unpadded_ace_len.checked_add(3).ok_or(-ERANGE)? & !3usize;
    if ace_len > usize::from(u16::MAX) {
        return Err(-EINVAL);
    }
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
    while bytes.len() < ace_len {
        bytes.push(0).map_err(|_| -ENOMEM)?;
    }
    Ok(bytes)
}

fn build_device_member_condition_bytes(device_sid: Sid<'_>) -> Result<Vec<u8>, i32> {
    let sid_bytes = device_sid.as_bytes();
    let mut bytes = Vec::with_capacity(
        4usize
            .checked_add(1)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(sid_bytes.len()))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(2))
            .ok_or(-ERANGE)?,
    )
    .map_err(|_| -ENOMEM)?;

    bytes.extend_from_slice(b"artx").map_err(|_| -ENOMEM)?;
    bytes.push(0x51).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes.extend_from_slice(sid_bytes).map_err(|_| -ENOMEM)?;
    bytes.push(0x8a).map_err(|_| -ENOMEM)?;
    bytes.push(0x00).map_err(|_| -ENOMEM)?;
    bytes.push(0x00).map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_claim_exists_condition_bytes(
    namespace_opcode: u8,
    claim_name: &str,
) -> Result<Vec<u8>, i32> {
    if !matches!(namespace_opcode, 0xf9 | 0xfa | 0xfb) {
        return Err(-EINVAL);
    }

    let utf16_len = claim_name
        .encode_utf16()
        .try_fold(0usize, |acc, _| acc.checked_add(2).ok_or(-ERANGE))?;
    let mut bytes = Vec::with_capacity(
        4usize
            .checked_add(1)
            .and_then(|value| value.checked_add(4))
            .and_then(|value| value.checked_add(utf16_len))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(2))
            .ok_or(-ERANGE)?,
    )
    .map_err(|_| -ENOMEM)?;

    bytes.extend_from_slice(b"artx").map_err(|_| -ENOMEM)?;
    bytes.push(namespace_opcode).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&(utf16_len as u32).to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    for unit in claim_name.encode_utf16() {
        bytes
            .extend_from_slice(&unit.to_le_bytes())
            .map_err(|_| -ENOMEM)?;
    }
    bytes.push(0x87).map_err(|_| -ENOMEM)?;
    bytes.push(0x00).map_err(|_| -ENOMEM)?;
    bytes.push(0x00).map_err(|_| -ENOMEM)?;
    Ok(bytes)
}

fn build_callback_allow_ace_bytes(
    mask: u32,
    sid: Sid<'_>,
    application_data: &[u8],
) -> Result<Vec<u8>, i32> {
    let unpadded_ace_len = ACE_HEADER_LEN
        .checked_add(sid.as_bytes().len())
        .and_then(|value| value.checked_add(application_data.len()))
        .ok_or(-ERANGE)?;
    let ace_len = unpadded_ace_len.checked_add(3).ok_or(-ERANGE)? & !3usize;

    if ace_len > usize::from(u16::MAX) {
        return Err(-EINVAL);
    }

    let mut bytes = Vec::with_capacity(ace_len).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&[
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            (ace_len as u16).to_le_bytes()[0],
            (ace_len as u16).to_le_bytes()[1],
        ])
        .map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(&mask.to_le_bytes())
        .map_err(|_| -ENOMEM)?;
    bytes.extend_from_slice(sid.as_bytes()).map_err(|_| -ENOMEM)?;
    bytes
        .extend_from_slice(application_data)
        .map_err(|_| -ENOMEM)?;
    while bytes.len() < ace_len {
        bytes.push(0).map_err(|_| -ENOMEM)?;
    }
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
        return build_acl_bytes_from_aces_with_reserved(
            sacl.revision(),
            sacl.sbz1(),
            sacl.sbz2(),
            &[ace.bytes()],
        );
    }

    Ok(None)
}

fn file_sd_integrity_label(sd_bytes: &[u8]) -> Result<IntegrityLevel, i32> {
    let sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;
    let Some(sacl) = sd.sacl() else {
        return Ok(IntegrityLevel::Medium);
    };

    for ace in sacl.entries() {
        let ace = ace.map_err(|_| -EINVAL)?;
        if ace.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
            continue;
        }
        return label_integrity_from_ace(ace.bytes());
    }

    Ok(IntegrityLevel::Medium)
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

fn validate_owner_assignment(
    subject: &PkmKacsBootToken,
    owner_sid: Sid<'_>,
    allow_restore_owner_assignment: bool,
) -> Result<(), i32> {
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

    if allow_restore_owner_assignment
        && subject_has_enabled_privilege(subject, SE_RESTORE_PRIVILEGE)
    {
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

fn sd_subset_control(base_control: u16, security_info: u32) -> u16 {
    let mut control = base_control & SE_RM_CONTROL_VALID;

    if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
        control |= base_control & SE_OWNER_DEFAULTED;
    }
    if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
        control |= base_control & SE_GROUP_DEFAULTED;
    }
    if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        control |= base_control
            & (SE_DACL_DEFAULTED
                | SE_DACL_TRUSTED
                | SE_DACL_AUTO_INHERIT_REQ
                | SE_DACL_AUTO_INHERITED
                | SE_DACL_PROTECTED);
    }
    if (security_info & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION)) != 0 {
        control |= base_control
            & (SE_SACL_DEFAULTED
                | SE_SACL_AUTO_INHERIT_REQ
                | SE_SACL_AUTO_INHERITED
                | SE_SACL_PROTECTED);
    }

    control
}

fn replace_control_bits(control: &mut u16, input_control: u16, bits: u16) {
    *control = (*control & !bits) | (input_control & bits);
}

fn merged_sd_control(current_control: u16, input_control: u16, security_info: u32) -> u16 {
    let mut control = current_control;

    if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
        replace_control_bits(&mut control, input_control, SE_OWNER_DEFAULTED);
    }
    if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
        replace_control_bits(&mut control, input_control, SE_GROUP_DEFAULTED);
    }
    if (security_info & DACL_SECURITY_INFORMATION) != 0 {
        replace_control_bits(
            &mut control,
            input_control,
            SE_DACL_DEFAULTED
                | SE_DACL_TRUSTED
                | SE_DACL_AUTO_INHERIT_REQ
                | SE_DACL_AUTO_INHERITED
                | SE_DACL_PROTECTED,
        );
    }
    if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        replace_control_bits(
            &mut control,
            input_control,
            SE_SACL_DEFAULTED
                | SE_SACL_AUTO_INHERIT_REQ
                | SE_SACL_AUTO_INHERITED
                | SE_SACL_PROTECTED,
        );
    }

    control
}

fn build_sd_subset_bytes(sd_bytes: &[u8], security_info: u32) -> Result<(*mut u8, usize), i32> {
    let sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;

    build_sd_subset_from_descriptor(&sd, security_info)
}

fn build_sd_subset_from_descriptor(
    sd: &SecurityDescriptor<'_>,
    security_info: u32,
) -> Result<(*mut u8, usize), i32> {
    validate_sd_security_info(security_info)?;

    let label_sacl = if (security_info & LABEL_SECURITY_INFORMATION) != 0 {
        extract_label_subset_sacl_bytes(sd)?
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
        sd_subset_control(sd.control(), security_info),
        sd.resource_manager_control(),
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
    allow_restore_owner_assignment: bool,
) -> Result<(*mut u8, usize), i32> {
    let current_sd = SecurityDescriptor::parse(current_sd_bytes).map_err(sd_parse_errno)?;

    merge_sd_with_current_descriptor(
        subject,
        &current_sd,
        security_info,
        input_sd_bytes,
        allow_restore_owner_assignment,
    )
}

fn merge_sd_with_current_descriptor(
    subject: &PkmKacsBootToken,
    current_sd: &SecurityDescriptor<'_>,
    security_info: u32,
    input_sd_bytes: &[u8],
    allow_restore_owner_assignment: bool,
) -> Result<(*mut u8, usize), i32> {
    let input_sd = SecurityDescriptor::parse(input_sd_bytes).map_err(sd_parse_errno)?;
    let mut sacl = clone_optional_acl_bytes(current_sd.sacl())?;
    let mut dacl = clone_optional_acl_bytes(current_sd.dacl())?;
    let owner = if (security_info & OWNER_SECURITY_INFORMATION) != 0 {
        let owner = input_sd.owner().ok_or(-EINVAL)?;
        validate_owner_assignment(subject, owner, allow_restore_owner_assignment)?;
        owner
    } else {
        current_sd.owner().ok_or(-EINVAL)?
    };
    let group = if (security_info & GROUP_SECURITY_INFORMATION) != 0 {
        input_sd.group()
    } else {
        current_sd.group()
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
        // KC-13: a full SACL write can smuggle a SYSTEM_MANDATORY_LABEL_ACE that
        // raises the object integrity label. Gate it on SE_RELABEL_PRIVILEGE,
        // mirroring the LABEL branch and the create path, so a sub-dominant
        // subject (only ACCESS_SYSTEM_SECURITY) cannot relabel via the SACL.
        let label_ace = find_explicit_label_ace_bytes(input_sd.sacl())?;
        validate_label_assignment(subject, label_ace.as_deref())?;
        sacl = clone_optional_acl_bytes(input_sd.sacl())?;
    } else if (security_info & LABEL_SECURITY_INFORMATION) != 0 {
        let label_ace = parse_label_subset_ace_bytes(&input_sd)?;
        validate_label_assignment(subject, label_ace.as_deref())?;

        let (current_revision, current_sbz1, current_sbz2) = current_sd
            .sacl()
            .map(|acl| (acl.revision(), acl.sbz1(), acl.sbz2()))
            .unwrap_or((ACL_REVISION, 0, 0));
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

        sacl = build_acl_bytes_from_aces_with_reserved(
            current_revision,
            current_sbz1,
            current_sbz2,
            ace_refs.as_slice(),
        )?;
    }

    build_sd_bytes_from_components(
        merged_sd_control(current_sd.control(), input_sd.control(), security_info),
        current_sd.resource_manager_control(),
        Some(owner.as_bytes()),
        group.map(|sid| sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    )
}

fn build_replacement_file_sd_bytes(
    subject: &PkmKacsBootToken,
    security_info: u32,
    input_sd_bytes: &[u8],
) -> Result<(*mut u8, usize), i32> {
    let required =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let input_sd = SecurityDescriptor::parse(input_sd_bytes).map_err(sd_parse_errno)?;
    let owner = input_sd.owner().ok_or(-EINVAL)?;
    let group = input_sd.group();
    let mut sacl = None;
    let dacl;

    validate_sd_security_info(security_info)?;
    if (security_info & required) != required {
        return Err(-EINVAL);
    }

    validate_owner_assignment(subject, owner, true)?;

    dacl = clone_optional_acl_bytes(input_sd.dacl())?;

    if (security_info & SACL_SECURITY_INFORMATION) != 0 {
        // KC-13: gate a smuggled SYSTEM_MANDATORY_LABEL_ACE in a full SACL write
        // on SE_RELABEL_PRIVILEGE (see merge_sd_with_current_descriptor).
        let label_ace = find_explicit_label_ace_bytes(input_sd.sacl())?;
        validate_label_assignment(subject, label_ace.as_deref())?;
        sacl = clone_optional_acl_bytes(input_sd.sacl())?;
    } else if (security_info & LABEL_SECURITY_INFORMATION) != 0 {
        let label_ace = parse_label_subset_ace_bytes(&input_sd)?;
        validate_label_assignment(subject, label_ace.as_deref())?;
        let mut ace_refs = Vec::new();
        let (input_sacl_revision, input_sacl_sbz1, input_sacl_sbz2) = input_sd
            .sacl()
            .map(|acl| (acl.revision(), acl.sbz1(), acl.sbz2()))
            .unwrap_or((ACL_REVISION, 0, 0));

        if let Some(label_ace) = label_ace.as_ref() {
            ace_refs.push(label_ace.as_slice()).map_err(|_| -ENOMEM)?;
        }
        sacl = build_acl_bytes_from_aces_with_reserved(
            input_sacl_revision,
            input_sacl_sbz1,
            input_sacl_sbz2,
            ace_refs.as_slice(),
        )?;
    }

    build_sd_bytes_from_components(
        input_sd.control(),
        input_sd.resource_manager_control(),
        Some(owner.as_bytes()),
        group.map(|sid| sid.as_bytes()),
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
        token.user_sid.sid,
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
        token.user_sid.sid,
        group_sid,
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        Some(GENERIC_ALL),
        None,
    )
}

fn build_default_session_sd_bytes(
    user_sid: Sid<'_>,
    group_sid: Sid<'_>,
) -> Result<(*mut u8, usize), i32> {
    build_process_sd_bytes(
        user_sid,
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
    let default_sd = SecurityDescriptor::parse(default_bytes).map_err(sd_parse_errno)?;
    let resource_ace = build_mandatory_resource_attribute_ace_bytes(1)?;
    let sacl = build_acl_bytes_from_aces(ACL_REVISION, &[resource_ace.as_slice()])?;
    let dacl = clone_optional_acl_bytes(default_sd.dacl())?;
    let result = build_sd_bytes_from_components(
        default_sd.control(),
        default_sd.resource_manager_control(),
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
    include_administrators: bool,
) -> Result<(*mut u8, usize), i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;
    let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).map_err(|_| -EINVAL)?;
    let owner_rights = Sid::parse(OWNER_RIGHTS_SID_BYTES).map_err(|_| -EINVAL)?;
    let suppress_owner_implicit = creator_sid.as_bytes() == token_user_sid.as_bytes()
        && creator_mask.is_some();
    let creator_mask = if creator_sid.as_bytes() == token_user_sid.as_bytes() {
        None
    } else {
        creator_mask
    };
    let administrators_mask = if include_administrators {
        Some(KACS_TOKEN_ALL_ACCESS)
    } else {
        None
    };
    let mut ace_count = 0usize;
    let mut dacl_len = ACL_HEADER_LEN;

    for (mask, sid) in [
        (suppress_owner_implicit.then_some(READ_CONTROL), owner_rights),
        (self_mask, token_user_sid),
        (creator_mask, creator_sid),
        (system_mask, system),
        (administrators_mask, administrators),
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
    if total_len > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(-ERANGE);
    }
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
        SE_SELF_RELATIVE
            | SE_OWNER_DEFAULTED
            | SE_GROUP_DEFAULTED
            | SE_DACL_DEFAULTED
            | SE_DACL_PRESENT,
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
        (suppress_owner_implicit.then_some(READ_CONTROL), owner_rights),
        (self_mask, token_user_sid),
        (creator_mask, creator_sid),
        (system_mask, system),
        (administrators_mask, administrators),
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
        token.user_sid.sid,
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
        token.user_sid.sid,
        group_sid,
        None,
        None,
        None,
        Some(PROCESS_QUERY_INFORMATION),
    )
}

fn build_everyone_mask_only_process_sd_bytes(
    token: &PkmKacsBootToken,
    everyone_mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid.sid,
        group_sid,
        None,
        None,
        None,
        Some(everyone_mask),
    )
}

fn build_read_only_socket_sd_bytes(token: &PkmKacsBootToken) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid.sid,
        group_sid,
        None,
        None,
        None,
        Some(READ_CONTROL),
    )
}

fn build_lcs_base_layer_default_sd_bytes() -> Result<(*mut u8, usize), i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;

    build_process_sd_bytes(
        system,
        system,
        None,
        Some(LCS_REGISTRY_KEY_ALL_ACCESS),
        Some(LCS_REGISTRY_KEY_ALL_ACCESS),
        None,
    )
}

fn mask_option(mask: u32) -> Option<u32> {
    (mask != 0).then_some(mask)
}

fn build_file_sd_bytes_from_masks(
    token: &PkmKacsBootToken,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_process_sd_bytes(
        token.user_sid.sid,
        group_sid,
        mask_option(self_mask),
        mask_option(admin_mask),
        mask_option(system_mask),
        mask_option(everyone_mask),
    )
}

fn build_file_sd_with_mandatory_resource_attribute_bytes(
    token: &PkmKacsBootToken,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    mandatory_value: i64,
) -> Result<(*mut u8, usize), i32> {
    let (default_ptr, default_len) =
        build_file_sd_bytes_from_masks(token, self_mask, admin_mask, system_mask, everyone_mask)?;
    let default_bytes = unsafe { core::slice::from_raw_parts(default_ptr, default_len) };
    let default_sd = SecurityDescriptor::parse(default_bytes).map_err(sd_parse_errno)?;
    let resource_ace = build_mandatory_resource_attribute_ace_bytes(mandatory_value)?;
    let sacl = build_acl_bytes_from_aces(ACL_REVISION, &[resource_ace.as_slice()])?;
    let dacl = clone_optional_acl_bytes(default_sd.dacl())?;
    let result = build_sd_bytes_from_components(
        default_sd.control(),
        default_sd.resource_manager_control(),
        default_sd.owner().map(|sid| sid.as_bytes()),
        default_sd.group().map(|sid| sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    );

    free_allocated_bytes(default_ptr);
    result
}

fn build_labeled_file_sd_bytes(
    token: &PkmKacsBootToken,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    integrity_level: IntegrityLevel,
    include_success_audit: bool,
) -> Result<(*mut u8, usize), i32> {
    let (default_ptr, default_len) =
        build_file_sd_bytes_from_masks(token, self_mask, admin_mask, system_mask, everyone_mask)?;
    let default_bytes = unsafe { core::slice::from_raw_parts(default_ptr, default_len) };
    let default_sd = SecurityDescriptor::parse(default_bytes).map_err(sd_parse_errno)?;
    let label_ace = build_label_ace_bytes(integrity_level)?;
    let audit_ace;
    let sacl = if include_success_audit {
        audit_ace = build_system_success_audit_ace_bytes(ACCESS_SYSTEM_SECURITY)?;
        build_acl_bytes_from_aces(ACL_REVISION, &[label_ace.as_slice(), audit_ace.as_slice()])?
    } else {
        build_acl_bytes_from_aces(ACL_REVISION, &[label_ace.as_slice()])?
    };
    let dacl = clone_optional_acl_bytes(default_sd.dacl())?;
    let result = build_sd_bytes_from_components(
        default_sd.control(),
        default_sd.resource_manager_control(),
        default_sd.owner().map(|sid| sid.as_bytes()),
        default_sd.group().map(|sid| sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    );

    free_allocated_bytes(default_ptr);
    result
}

fn build_device_member_file_sd_bytes(
    token: &PkmKacsBootToken,
    device_sid: Sid<'_>,
    mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let condition = build_device_member_condition_bytes(device_sid)?;
    let allow_ace = build_callback_allow_ace_bytes(mask, everyone, condition.as_slice())?;
    let dacl = build_acl_bytes_from_aces(ACL_REVISION_DS, &[allow_ace.as_slice()])?;
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_sd_bytes_from_components(
        SE_SELF_RELATIVE,
        0,
        Some(token.user_sid.sid.as_bytes()),
        Some(group_sid.as_bytes()),
        None,
        dacl.as_deref(),
    )
}

fn build_claim_exists_file_sd_bytes(
    token: &PkmKacsBootToken,
    namespace_opcode: u8,
    claim_name: &str,
    mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let condition = build_claim_exists_condition_bytes(namespace_opcode, claim_name)?;
    let allow_ace = build_callback_allow_ace_bytes(mask, everyone, condition.as_slice())?;
    let dacl = build_acl_bytes_from_aces(ACL_REVISION_DS, &[allow_ace.as_slice()])?;
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_sd_bytes_from_components(
        SE_SELF_RELATIVE,
        0,
        Some(token.user_sid.sid.as_bytes()),
        Some(group_sid.as_bytes()),
        None,
        dacl.as_deref(),
    )
}

fn build_resource_claim_exists_file_sd_bytes(
    token: &PkmKacsBootToken,
    claim_name: &str,
    mask: u32,
) -> Result<(*mut u8, usize), i32> {
    let everyone = Sid::parse(EVERYONE_SID_BYTES).map_err(|_| -EINVAL)?;
    let condition = build_claim_exists_condition_bytes(0xfa, claim_name)?;
    let allow_ace = build_callback_allow_ace_bytes(mask, everyone, condition.as_slice())?;
    let dacl = build_acl_bytes_from_aces(ACL_REVISION_DS, &[allow_ace.as_slice()])?;
    let resource_ace = build_mandatory_resource_attribute_ace_bytes(1)?;
    let sacl = build_acl_bytes_from_aces(ACL_REVISION, &[resource_ace.as_slice()])?;
    let _guard = token.lock_mutation();
    let group_sid = token
        .sid_by_index(token.primary_group_index.load(Ordering::Relaxed))
        .ok_or(-EINVAL)?;

    build_sd_bytes_from_components(
        SE_SELF_RELATIVE,
        0,
        Some(token.user_sid.sid.as_bytes()),
        Some(group_sid.as_bytes()),
        sacl.as_deref(),
        dacl.as_deref(),
    )
}

fn boot_system_session_ref() -> Result<*const PkmKacsSession, i32> {
    let system = Sid::parse(SYSTEM_SID_BYTES).map_err(|_| -EINVAL)?;

    get_or_create_published_session(
        0,
        0,
        LOGON_TYPE_SERVICE,
        AUTH_PACKAGE_NEGOTIATE,
        system,
        system,
    )
}

fn anonymous_session_ref() -> Result<*const PkmKacsSession, i32> {
    let anonymous = Sid::parse(ANONYMOUS_SID_BYTES).map_err(|_| -EINVAL)?;

    get_or_create_published_session(
        ANONYMOUS_LOGON_LUID,
        0,
        LOGON_TYPE_NETWORK,
        AUTH_PACKAGE_NEGOTIATE,
        anonymous,
        anonymous,
    )
}

fn kunit_local_service_session_ref() -> Result<*const PkmKacsSession, i32> {
    let local_service = Sid::parse(LOCAL_SERVICE_SID_BYTES).map_err(|_| -EINVAL)?;

    get_or_create_published_session(
        KUNIT_LOCAL_SERVICE_SESSION_LUID,
        0,
        LOGON_TYPE_SERVICE,
        AUTH_PACKAGE_NEGOTIATE,
        local_service,
        local_service,
    )
}

fn kunit_logon_type_session_ref(logon_type: u32) -> Result<*const PkmKacsSession, i32> {
    if !session_logon_type_valid(logon_type) {
        return Err(-EINVAL);
    }

    let local_service = Sid::parse(LOCAL_SERVICE_SID_BYTES).map_err(|_| -EINVAL)?;

    get_or_create_published_session(
        KUNIT_LOGON_TYPE_SESSION_LUID_BASE + u64::from(logon_type),
        0,
        logon_type,
        AUTH_PACKAGE_NEGOTIATE,
        local_service,
        local_service,
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
        first_group_sid: Option<Sid<'static>>,
        include_user_group: bool,
        include_administrators_own_sd: bool,
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
        // KC-14: build every fallible owned value before committing the raw heap
        // allocations below, so a build failure only drops the session ref instead
        // of leaking the SD buffers / token. The bare `.ok()?` sites that used to
        // follow the commits leaked all of them.
        let group_defaults = group_attributes.as_slice();
        let built = (|| {
            let owned_user_sid = build_owned_sid(user_sid.as_bytes()).ok()?;
            let first_group_sid = first_group_sid.unwrap_or(administrators);
            let group_sids_arr = [
                first_group_sid,
                if include_user_group {
                    owned_user_sid.sid
                } else {
                    everyone
                },
                authenticated_users,
                local,
                logon_sid,
            ];
            let groups = build_owned_group_entries(&[
                (group_sids_arr[0], group_defaults[0]),
                (group_sids_arr[1], group_defaults[1]),
                (authenticated_users, group_defaults[2]),
                (local, group_defaults[3]),
                (logon_sid, group_defaults[4]),
            ])
            .ok()?;
            let group_sids = slice_to_vec(group_sids_arr.as_slice()).ok()?;
            let group_default_attributes = slice_to_vec(group_defaults).ok()?;
            let group_views = build_group_views(group_sids.as_slice(), group_defaults).ok()?;
            let group_runtime_views =
                build_group_runtime_views(group_sids.as_slice(), group_defaults).ok()?;
            let group_attributes = build_atomic_u32_vec(group_defaults).ok()?;
            Some((
                owned_user_sid,
                groups,
                group_sids,
                group_default_attributes,
                group_views,
                group_runtime_views,
                group_attributes,
            ))
        })();
        let (
            owned_user_sid,
            groups,
            group_sids,
            group_default_attributes,
            group_views,
            group_runtime_views,
            group_attributes,
        ) = match built {
            Some(values) => values,
            None => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
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
            include_administrators_own_sd,
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

        let projected_id = if user_sid.as_bytes() == SYSTEM_SID_BYTES {
            0
        } else {
            ANONYMOUS_PROJECTED_ID
        };

        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: owned_user_sid,
            groups,
            group_count: group_default_attributes.len(),
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: 0,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(BOOT_SYSTEM_OWNER_SID_INDEX),
            primary_group_index: AtomicU32::new(BOOT_SYSTEM_PRIMARY_GROUP_INDEX),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups: Vec::new(),
            device_group_views: Vec::new(),
            restricted_device_groups: Vec::new(),
            restricted_device_group_views: Vec::new(),
            user_claims: Vec::new(),
            device_claims: Vec::new(),
            lcs_scope_guids: Vec::new(),
            lcs_private_layers: Vec::new(),
            confinement_sid: None,
            confinement_capabilities: Vec::new(),
            confinement_capability_views: Vec::new(),
            confinement_exempt: false,
            isolation_boundary: false,
            audit_policy,
            expiration: 0,
            source_name: *TOKEN_SOURCE_PEI_OS_KRN,
            source_id: 0,
            origin: 0,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: projected_id,
            projected_gid: projected_id,
            projected_supplementary_gids: Vec::new(),
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        PkmKacsSession::register_live_token(session);
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
            None,
            false,
            true,
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
            false,
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
        let user_sid = build_owned_sid(user_sid.as_bytes()).ok()?;
        let group_defaults = BOOT_SYSTEM_GROUP_ATTRIBUTES.as_slice();
        let group_sids = [administrators, everyone, authenticated_users, local, logon_sid];
        let groups = build_owned_group_entries(&[
            (administrators, group_defaults[0]),
            (everyone, group_defaults[1]),
            (authenticated_users, group_defaults[2]),
            (local, group_defaults[3]),
            (logon_sid, group_defaults[4]),
        ])
        .ok()?;
        let group_sids = slice_to_vec(group_sids.as_slice()).ok()?;
        let group_default_attributes = slice_to_vec(group_defaults).ok()?;
        let group_views = build_group_views(group_sids.as_slice(), group_defaults).ok()?;
        let group_runtime_views =
            build_group_runtime_views(group_sids.as_slice(), group_defaults).ok()?;
        let group_attributes = build_atomic_u32_vec(group_defaults).ok()?;
        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid,
            groups,
            group_count: group_defaults.len(),
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id: BOOT_SYSTEM_TOKEN_ID,
            created_at: 0,
            modified_id: AtomicU64::new(BOOT_SYSTEM_MODIFIED_ID),
            owner_sid_index: AtomicU32::new(BOOT_SYSTEM_OWNER_SID_INDEX),
            primary_group_index: AtomicU32::new(BOOT_SYSTEM_PRIMARY_GROUP_INDEX),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups: Vec::new(),
            device_group_views: Vec::new(),
            restricted_device_groups: Vec::new(),
            restricted_device_group_views: Vec::new(),
            user_claims: Vec::new(),
            device_claims: Vec::new(),
            lcs_scope_guids: Vec::new(),
            lcs_private_layers: Vec::new(),
            confinement_sid: None,
            confinement_capabilities: Vec::new(),
            confinement_capability_views: Vec::new(),
            confinement_exempt: false,
            isolation_boundary: false,
            audit_policy: 0,
            expiration: 0,
            source_name: *TOKEN_SOURCE_PEI_OS_KRN,
            source_id: 0,
            origin: 0,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: 0,
            projected_gid: 0,
            projected_supplementary_gids: Vec::new(),
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        PkmKacsSession::register_live_token(session);
        Some(token_ptr.cast())
    }

    fn create_without_tcb() -> Option<*const c_void> {
        let privileges =
            SYSTEM_PRIVILEGES_ALL & !(SE_TCB_PRIVILEGE | SE_CREATE_TOKEN_PRIVILEGE);
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
            None,
            false,
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
            None,
            true,
            false,
            0,
        )
    }

    fn create_local_administrator() -> Option<*const c_void> {
        let session = kunit_local_service_session_ref().ok()?;
        let token_id = allocate_dynamic_token_id().ok()?;

        Self::create_system_like(
            session,
            Sid::parse(LOCAL_SERVICE_SID_BYTES).ok()?,
            Sid::parse(SYSTEM_SID_BYTES).ok()?,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            token_id,
            token_id,
            0,
            0,
            0,
            BOOT_SYSTEM_GROUP_ATTRIBUTES,
            None,
            false,
            false,
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
            None,
            false,
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
            None,
            false,
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
        Self::create_kunit_variant_with_privileges(
            user_sid,
            integrity_level,
            token_type,
            impersonation_level,
            restricted,
            enabled_privileges,
            enabled_privileges,
            enabled_privileges,
        )
    }

    fn create_kunit_variant_with_privileges(
        user_sid: Sid<'static>,
        integrity_level: IntegrityLevel,
        token_type: TokenType,
        impersonation_level: ImpersonationLevel,
        restricted: bool,
        privileges_present: u64,
        privileges_enabled: u64,
        privileges_enabled_by_default: u64,
    ) -> Option<*const c_void> {
        if (privileges_enabled & !privileges_present) != 0
            || (privileges_enabled_by_default & !privileges_present) != 0
        {
            return None;
        }

        let token_id = allocate_dynamic_token_id().ok()?;
        let session = if user_sid.as_bytes() == SYSTEM_SID_BYTES {
            boot_system_session_ref().ok()?
        } else if user_sid.as_bytes() == LOCAL_SERVICE_SID_BYTES {
            kunit_local_service_session_ref().ok()?
        } else {
            return None;
        };
        let (group_attributes, first_group_sid, include_user_group) = if user_sid.as_bytes()
            == LOCAL_SERVICE_SID_BYTES
        {
            (
                KUNIT_LOCAL_SERVICE_GROUP_ATTRIBUTES,
                Some(Sid::parse(SERVICE_SID_BYTES).ok()?),
                false,
            )
        } else {
            (BOOT_SYSTEM_GROUP_ATTRIBUTES, None, false)
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
            privileges_present,
            privileges_enabled,
            privileges_enabled_by_default,
            group_attributes,
            first_group_sid,
            include_user_group,
            false,
            0,
        )
    }

    fn create_kunit_logon_type_token(
        logon_type: u32,
        enabled_privileges: u64,
    ) -> Option<*const c_void> {
        let user_sid = Sid::parse(LOCAL_SERVICE_SID_BYTES).ok()?;
        let creator_sid = Sid::parse(SYSTEM_SID_BYTES).ok()?;
        let service_sid = Sid::parse(SERVICE_SID_BYTES).ok()?;
        let session = kunit_logon_type_session_ref(logon_type).ok()?;
        let token_id = match allocate_dynamic_token_id() {
            Ok(token_id) => token_id,
            Err(_) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };

        Self::create_system_like(
            session,
            user_sid,
            creator_sid,
            IntegrityLevel::System,
            TokenType::Primary,
            ImpersonationLevel::Anonymous,
            false,
            token_id,
            token_id,
            enabled_privileges,
            enabled_privileges,
            enabled_privileges,
            KUNIT_LOCAL_SERVICE_GROUP_ATTRIBUTES,
            Some(service_sid),
            false,
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
        // KC-14: build every fallible owned value before committing the raw heap
        // allocations below. Only the session ref is live here, so a build failure
        // just drops it rather than leaking the SD buffers / token allocation. The
        // bare `.ok()?` sites that used to follow the commits leaked all of them.
        let built = (|| {
            let owned_anonymous = build_owned_sid(anonymous.as_bytes()).ok()?;
            let groups = build_owned_group_entries(&[(
                everyone,
                ANONYMOUS_ONLY_GROUP_ATTRIBUTES[0],
            )])
            .ok()?;
            let group_sids = slice_to_vec([everyone].as_slice()).ok()?;
            let group_default_attributes =
                slice_to_vec(&ANONYMOUS_ONLY_GROUP_ATTRIBUTES[..1]).ok()?;
            let group_views =
                build_group_views(group_sids.as_slice(), &ANONYMOUS_ONLY_GROUP_ATTRIBUTES[..1])
                    .ok()?;
            let group_runtime_views = build_group_runtime_views(
                group_sids.as_slice(),
                &ANONYMOUS_ONLY_GROUP_ATTRIBUTES[..1],
            )
            .ok()?;
            let group_attributes =
                build_atomic_u32_vec(&ANONYMOUS_ONLY_GROUP_ATTRIBUTES[..1]).ok()?;
            Some((
                owned_anonymous,
                groups,
                group_sids,
                group_default_attributes,
                group_views,
                group_runtime_views,
                group_attributes,
            ))
        })();
        let (
            owned_anonymous,
            groups,
            group_sids,
            group_default_attributes,
            group_views,
            group_runtime_views,
            group_attributes,
        ) = match built {
            Some(values) => values,
            None => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };

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
            false,
        ) {
            Ok(value) => value,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return None;
            }
        };
        // Allocate the token id before the token buffer so the id-allocation
        // failure path has nothing extra to free, and the buffer can't leak.
        let token_id = match allocate_dynamic_token_id() {
            Ok(token_id) => token_id,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
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
        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid: owned_anonymous,
            groups,
            group_count: 1,
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: 0,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(0),
            primary_group_index: AtomicU32::new(1),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups: Vec::new(),
            device_group_views: Vec::new(),
            restricted_device_groups: Vec::new(),
            restricted_device_group_views: Vec::new(),
            user_claims: Vec::new(),
            device_claims: Vec::new(),
            lcs_scope_guids: Vec::new(),
            lcs_private_layers: Vec::new(),
            confinement_sid: None,
            confinement_capabilities: Vec::new(),
            confinement_capability_views: Vec::new(),
            confinement_exempt: false,
            isolation_boundary: false,
            audit_policy: 0,
            expiration: 0,
            source_name: *TOKEN_SOURCE_PEI_OS_KRN,
            source_id: 0,
            origin: 0,
            interactive_session_id: AtomicU32::new(0),
            projected_uid: ANONYMOUS_PROJECTED_ID,
            projected_gid: ANONYMOUS_PROJECTED_ID,
            projected_supplementary_gids: Vec::new(),
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        PkmKacsSession::register_live_token(session);
        Some(token_ptr.cast())
    }

    fn create_from_spec(
        creator: &PkmKacsBootToken,
        spec: &[u8],
        created_at: u64,
    ) -> Result<*const c_void, i32> {
        let version = read_le_u32(spec, 0).ok_or(-EINVAL)?;
        let token_type = token_type_from_abi(u32::from(*spec.get(4).ok_or(-EINVAL)?))?;
        let impersonation_level =
            impersonation_level_from_abi(u32::from(*spec.get(5).ok_or(-EINVAL)?))?;
        let integrity_level = integrity_level_from_abi(read_le_u32(spec, 8).ok_or(-EINVAL)?)?;
        let mandatory_policy = read_le_u32(spec, 12).ok_or(-EINVAL)?;
        let privileges_present = read_le_u64(spec, 16).ok_or(-EINVAL)?;
        let privileges_enabled = read_le_u64(spec, 24).ok_or(-EINVAL)?;
        let projected_uid = read_le_u32(spec, 36).ok_or(-EINVAL)?;
        let projected_gid = read_le_u32(spec, 40).ok_or(-EINVAL)?;
        let audit_policy = read_le_u32(spec, 44).ok_or(-EINVAL)?;
        let expiration = read_le_u64(spec, 48).ok_or(-EINVAL)?;
        let session_id = read_le_u64(spec, 56).ok_or(-EINVAL)?;
        let owner_sid_index = read_le_u32(spec, 64).ok_or(-EINVAL)?;
        let primary_group_index = read_le_u32(spec, 68).ok_or(-EINVAL)?;
        let source_name = <[u8; TOKEN_SOURCE_NAME_LEN]>::try_from(
            spec.get(72..80).ok_or(-EINVAL)?,
        )
        .map_err(|_| -EINVAL)?;
        let source_id = read_le_u64(spec, 80).ok_or(-EINVAL)?;
        let user_sid_offset = read_le_u32(spec, 88).ok_or(-EINVAL)?;
        let groups_offset = read_le_u32(spec, 92).ok_or(-EINVAL)?;
        let groups_count = read_le_u32(spec, 96).ok_or(-EINVAL)?;
        let default_dacl_offset = read_le_u32(spec, 100).ok_or(-EINVAL)?;
        let default_dacl_len = read_le_u32(spec, 104).ok_or(-EINVAL)?;
        let user_claims_offset = read_le_u32(spec, 108).ok_or(-EINVAL)?;
        let user_claims_len = read_le_u32(spec, 112).ok_or(-EINVAL)?;
        let device_claims_offset = read_le_u32(spec, 116).ok_or(-EINVAL)?;
        let device_claims_len = read_le_u32(spec, 120).ok_or(-EINVAL)?;
        let device_groups_offset = read_le_u32(spec, 124).ok_or(-EINVAL)?;
        let device_groups_count = read_le_u32(spec, 128).ok_or(-EINVAL)?;
        let restricted_sids_offset = read_le_u32(spec, 132).ok_or(-EINVAL)?;
        let restricted_sids_count = read_le_u32(spec, 136).ok_or(-EINVAL)?;
        let confinement_sid_offset = read_le_u32(spec, 140).ok_or(-EINVAL)?;
        let confinement_sid_len = read_le_u32(spec, 144).ok_or(-EINVAL)?;
        let confinement_caps_offset = read_le_u32(spec, 148).ok_or(-EINVAL)?;
        let confinement_caps_count = read_le_u32(spec, 152).ok_or(-EINVAL)?;
        let confinement_exempt = read_bool_u8(spec, 156)?;
        let write_restricted = read_bool_u8(spec, 157)?;
        let user_deny_only = read_bool_u8(spec, 158)?;
        let isolation_boundary = read_bool_u8(spec, 159)?;
        let supp_gids_offset = read_le_u32(spec, 160).ok_or(-EINVAL)?;
        let supp_gids_count = read_le_u32(spec, 164).ok_or(-EINVAL)?;
        let restricted_device_groups_offset = read_le_u32(spec, 168).ok_or(-EINVAL)?;
        let restricted_device_groups_count = read_le_u32(spec, 172).ok_or(-EINVAL)?;
        let origin = read_le_u64(spec, 176).ok_or(-EINVAL)?;
        let interactive_session_id = read_le_u32(spec, 184).ok_or(-EINVAL)?;
        let lcs_credentials_offset = read_le_u32(spec, 188).ok_or(-EINVAL)?;
        let token_id;
        let modified_id;
        let session;
        let group_default_attributes;
        let group_sids;
        let group_attributes;
        let group_views;
        let group_runtime_views;
        let default_dacl_ptr;
        let default_dacl_alloc_len;
        let own_sd_ptr;
        let own_sd_len;
        let token_ptr;

        if spec.len() < TOKEN_SPEC_HEADER_LEN || spec.len() > MAX_TOKEN_SPEC_BYTES {
            return Err(-EINVAL);
        }
        if version != TOKEN_SPEC_VERSION {
            return Err(-EINVAL);
        }
        if spec[6] != 0 || spec[7] != 0 {
            return Err(-EINVAL);
        }
        if read_le_u32(spec, 32).ok_or(-EINVAL)? != 0 {
            return Err(-EINVAL);
        }
        if (mandatory_policy & !TOKEN_MANDATORY_POLICY_ALLOWED_MASK) != 0 {
            return Err(-EINVAL);
        }
        if (audit_policy & !TOKEN_AUDIT_POLICY_ALLOWED_MASK) != 0 {
            return Err(-EINVAL);
        }
        if (privileges_enabled & !privileges_present) != 0 {
            return Err(-EINVAL);
        }
        if token_type == TokenType::Primary
            && impersonation_level != ImpersonationLevel::Anonymous
        {
            return Err(-EINVAL);
        }
        if write_restricted && !user_deny_only {
            return Err(-EINVAL);
        }

        let sorted_offsets = sorted_active_section_offsets(
            spec,
            &[
                user_sid_offset,
                groups_offset,
                default_dacl_offset,
                user_claims_offset,
                device_claims_offset,
                device_groups_offset,
                restricted_sids_offset,
                confinement_sid_offset,
                confinement_caps_offset,
                supp_gids_offset,
                restricted_device_groups_offset,
                lcs_credentials_offset,
            ],
        )?;
        let user_sid = build_owned_sid(token_spec_unbounded_section(
            spec,
            &sorted_offsets,
            user_sid_offset,
        )?)?;
        if projected_uid == 0 && user_sid.sid.as_bytes() != SYSTEM_SID_BYTES {
            return Err(-EINVAL);
        }
        let default_dacl_bytes =
            token_spec_fixed_section(spec, &sorted_offsets, default_dacl_offset, default_dacl_len)?;
        let user_claims_bytes =
            token_spec_fixed_section(spec, &sorted_offsets, user_claims_offset, user_claims_len)?;
        let device_claims_bytes = token_spec_fixed_section(
            spec,
            &sorted_offsets,
            device_claims_offset,
            device_claims_len,
        )?;
        let groups_bytes = token_spec_count_section(spec, &sorted_offsets, groups_offset, groups_count)?;
        let device_groups_bytes = token_spec_count_section(
            spec,
            &sorted_offsets,
            device_groups_offset,
            device_groups_count,
        )?;
        let restricted_sids_bytes = token_spec_count_section(
            spec,
            &sorted_offsets,
            restricted_sids_offset,
            restricted_sids_count,
        )?;
        let confinement_sid = match token_spec_fixed_section(
            spec,
            &sorted_offsets,
            confinement_sid_offset,
            confinement_sid_len,
        )? {
            [] => None,
            bytes => Some(build_owned_sid(bytes)?),
        };
        let confinement_caps_bytes = token_spec_count_section(
            spec,
            &sorted_offsets,
            confinement_caps_offset,
            confinement_caps_count,
        )?;
        let supp_gids_bytes =
            token_spec_count_section(spec, &sorted_offsets, supp_gids_offset, supp_gids_count)?;
        let restricted_device_groups_bytes = token_spec_count_section(
            spec,
            &sorted_offsets,
            restricted_device_groups_offset,
            restricted_device_groups_count,
        )?;
        let (mut groups, _) = parse_sid_and_attributes_array(groups_bytes, groups_count)?;
        let (device_groups, device_group_views) =
            parse_sid_and_attributes_array(device_groups_bytes, device_groups_count)?;
        let (restricted_sids, restricted_sid_views) =
            parse_sid_and_attributes_array(restricted_sids_bytes, restricted_sids_count)?;
        let (confinement_capabilities, confinement_capability_views) =
            parse_sid_and_attributes_array(confinement_caps_bytes, confinement_caps_count)?;
        let (restricted_device_groups, restricted_device_group_views) =
            parse_sid_and_attributes_array(
                restricted_device_groups_bytes,
                restricted_device_groups_count,
            )?;
        let projected_supplementary_gids =
            parse_projected_supplementary_gids(supp_gids_bytes, supp_gids_count)?;
        let (lcs_scope_guids, lcs_private_layers) =
            parse_lcs_credential_extension(spec, &sorted_offsets, lcs_credentials_offset)?;
        let user_claims = if user_claims_bytes.is_empty() {
            Vec::new()
        } else {
            parse_claim_attribute_array(user_claims_bytes).map_err(|_| -EINVAL)?
        };
        let device_claims = if device_claims_bytes.is_empty() {
            Vec::new()
        } else {
            parse_claim_attribute_array(device_claims_bytes).map_err(|_| -EINVAL)?
        };

        normalize_group_entries_for_creation(&mut groups);
        let caller_group_count = groups.len();
        if caller_group_count >= MAX_TOKEN_GROUPS {
            return Err(-EINVAL);
        }

        if !default_dacl_bytes.is_empty() {
            Acl::parse(default_dacl_bytes).map_err(|_| -EINVAL)?;
        }
        if isolation_boundary && confinement_sid.is_none() {
            return Err(-EINVAL);
        }
        if owner_sid_index == 0 {
        } else {
            let owner_index = usize::try_from(owner_sid_index - 1).map_err(|_| -EINVAL)?;
            let Some(owner_group) = groups.get(owner_index) else {
                return Err(-EINVAL);
            };
            if (owner_group.attributes & SE_GROUP_OWNER) != SE_GROUP_OWNER {
                return Err(-EINVAL);
            }
        }
        if primary_group_index > u32::try_from(caller_group_count).map_err(|_| -EINVAL)? {
            return Err(-EINVAL);
        }

        session = published_session_ref_by_id(session_id)?;
        let session_ref = unsafe { PkmKacsSession::from_ptr(session.cast()) }.ok_or(-EINVAL)?;
        if groups
            .iter()
            .any(|entry| entry.sid.as_bytes() == session_ref.logon_sid.as_bytes())
        {
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
            return Err(-EINVAL);
        }

        let logon_sid = match build_owned_sid(session_ref.logon_sid.as_bytes()) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        if groups
            .push(OwnedSidAndAttributes {
                sid_bytes: logon_sid.sid_bytes,
                sid: logon_sid.sid,
                attributes: LOGON_GROUP_ATTRIBUTES,
            })
            .is_err()
        {
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
            return Err(-ENOMEM);
        }
        group_sids = match sid_vec_from_owned_entries(groups.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        group_default_attributes = match attributes_vec_from_owned_entries(groups.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        group_attributes = match build_atomic_u32_vec(group_default_attributes.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        group_views = match build_group_views(group_sids.as_slice(), group_default_attributes.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        group_runtime_views = match build_group_runtime_views(
            group_sids.as_slice(),
            group_default_attributes.as_slice(),
        ) {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        token_id = match allocate_dynamic_token_id() {
            Ok(value) => value,
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        };
        modified_id = token_id;
        match alloc_copy_bytes(default_dacl_bytes) {
            Ok(value) => {
                (default_dacl_ptr, default_dacl_alloc_len) = value;
            }
            Err(err) => {
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        }
        match build_token_sd_bytes(
            creator.user_sid.sid,
            user_sid.sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            false,
        ) {
            Ok(value) => {
                (own_sd_ptr, own_sd_len) = value;
            }
            Err(err) => {
                free_allocated_bytes(default_dacl_ptr);
                unsafe { PkmKacsSession::drop_ref(session.cast()) };
                return Err(err);
            }
        }
        token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            free_allocated_bytes(default_dacl_ptr);
            free_allocated_bytes(own_sd_ptr);
            unsafe { PkmKacsSession::drop_ref(session.cast()) };
            return Err(-ENOMEM);
        }

        let token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid,
            group_count: groups.len(),
            groups,
            group_sids,
            group_default_attributes,
            group_attributes,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(owner_sid_index),
            primary_group_index: AtomicU32::new(primary_group_index),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_alloc_len),
            default_dacl_seq: AtomicU64::new(0),
            privileges_present: AtomicU64::new(privileges_present),
            privileges_enabled: AtomicU64::new(privileges_enabled),
            privileges_enabled_by_default: AtomicU64::new(privileges_enabled),
            privileges_used: AtomicU64::new(0),
            integrity_level,
            mandatory_policy,
            token_type,
            impersonation_level,
            elevation_type: AtomicU32::new(TOKEN_ELEVATION_DEFAULT_ABI),
            restricted: !restricted_sid_views.is_empty()
                || !restricted_device_group_views.is_empty(),
            user_deny_only,
            write_restricted,
            restricted_sids,
            restricted_sid_views,
            device_groups,
            device_group_views,
            restricted_device_groups,
            restricted_device_group_views,
            user_claims,
            device_claims,
            lcs_scope_guids,
            lcs_private_layers,
            confinement_sid,
            confinement_capabilities,
            confinement_capability_views,
            confinement_exempt,
            isolation_boundary,
            audit_policy,
            expiration,
            source_name,
            source_id,
            origin,
            interactive_session_id: AtomicU32::new(interactive_session_id),
            projected_uid,
            projected_gid,
            projected_supplementary_gids,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, token) };
        PkmKacsSession::register_live_token(session);
        Ok(token_ptr.cast())
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
        let token_id = match allocate_dynamic_token_id() {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let _guard = token.lock_mutation();
        let privileges = token.privileges_snapshot_locked();
        let group_attributes = match token.current_group_attributes() {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let user_sid = match clone_owned_sid(&token.user_sid) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let groups = match clone_owned_sid_entries(token.groups.as_slice()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let group_sids = match sid_vec_from_owned_entries(groups.as_slice()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let group_default_attributes = match try_clone_vec(&token.group_default_attributes) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let group_attributes_atoms = match build_atomic_u32_vec(group_attributes.as_slice()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let group_views = match build_group_views(group_sids.as_slice(), group_attributes.as_slice())
        {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let group_runtime_views =
            match build_group_runtime_views(group_sids.as_slice(), group_attributes.as_slice()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let (restricted_sids, restricted_sid_views) =
            match build_owned_sid_entries_from_views(token.restricted_sid_views()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let device_groups = match clone_owned_sid_entries(token.device_groups.as_slice()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let device_group_views = match build_sid_and_attributes_views(device_groups.as_slice()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let restricted_device_groups =
            match clone_owned_sid_entries(token.restricted_device_groups.as_slice()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let restricted_device_group_views =
            match build_sid_and_attributes_views(restricted_device_groups.as_slice()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let confinement_sid = match clone_optional_owned_sid(token.confinement_sid.as_ref()) {
            Ok(value) => value,
            Err(_) => return null(),
        };
        let confinement_capabilities =
            match clone_owned_sid_entries(token.confinement_capabilities.as_slice()) {
                Ok(value) => value,
                Err(_) => return null(),
            };
        let confinement_capability_views =
            match build_sid_and_attributes_views(confinement_capabilities.as_slice()) {
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
            user_sid,
            groups,
            group_count: token.group_count,
            group_sids,
            group_default_attributes,
            group_attributes: group_attributes_atoms,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: token.created_at,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(token.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(token.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups,
            device_group_views,
            restricted_device_groups,
            restricted_device_group_views,
            user_claims: match try_clone_vec(&token.user_claims) {
                Ok(value) => value,
                Err(_) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return null();
                }
            },
            device_claims: match try_clone_vec(&token.device_claims) {
                Ok(value) => value,
                Err(_) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return null();
                }
            },
            lcs_scope_guids: match try_clone_vec(&token.lcs_scope_guids) {
                Ok(value) => value,
                Err(_) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return null();
                }
            },
            lcs_private_layers: match try_clone_vec(&token.lcs_private_layers) {
                Ok(value) => value,
                Err(_) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return null();
                }
            },
            confinement_sid,
            confinement_capabilities,
            confinement_capability_views,
            confinement_exempt: token.confinement_exempt,
            isolation_boundary: token.isolation_boundary,
            audit_policy: token.audit_policy,
            expiration: token.expiration,
            source_name: token.source_name,
            source_id: token.source_id,
            origin: token.origin,
            interactive_session_id: AtomicU32::new(
                token.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: token.projected_uid,
            projected_gid: token.projected_gid,
            projected_supplementary_gids: match try_clone_vec(
                &token.projected_supplementary_gids,
            ) {
                Ok(value) => value,
                Err(_) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return null();
                }
            },
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, copy) };
        PkmKacsSession::register_live_token(session);
        token_ptr.cast()
    }

    fn new_process_min_exec_clone(
        &self,
        file_integrity: IntegrityLevel,
    ) -> Result<Option<*const c_void>, i32> {
        if self.token_type != TokenType::Primary {
            return Err(-EACCES);
        }
        if (self.mandatory_policy & TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN) == 0 {
            return Ok(None);
        }
        if (file_integrity as u32) >= (self.integrity_level as u32) {
            return Ok(None);
        }

        let copy = Self::deep_copy((self as *const Self).cast());
        if copy.is_null() {
            return Err(-ENOMEM);
        }

        let lowered = copy as *mut Self;
        unsafe {
            (*lowered).integrity_level = file_integrity;
            (*lowered).token_type = TokenType::Primary;
            (*lowered).impersonation_level = ImpersonationLevel::Anonymous;
            (*lowered)
                .elevation_type
                .store(TOKEN_ELEVATION_DEFAULT_ABI, Ordering::Release);
        }

        Ok(Some(copy))
    }

    fn duplicate(
        &self,
        creator: &PkmKacsBootToken,
        new_type: TokenType,
        requested_level: ImpersonationLevel,
    ) -> Result<*const c_void, i32> {
        let _guard = self.lock_mutation();
        let privileges = self.privileges_snapshot_locked();
        let group_attributes = self.current_group_attributes()?;
        let group_default_attributes = group_attributes.try_clone().map_err(|_| -ENOMEM)?;
        let user_sid = clone_owned_sid(&self.user_sid)?;
        let groups = clone_owned_sid_entries(self.groups.as_slice())?;
        let group_sids = sid_vec_from_owned_entries(groups.as_slice())?;
        let group_attributes_atoms = build_atomic_u32_vec(group_attributes.as_slice())?;
        let group_views = build_group_views(group_sids.as_slice(), group_attributes.as_slice())?;
        let group_runtime_views =
            build_group_runtime_views(group_sids.as_slice(), group_attributes.as_slice())?;
        let (restricted_sids, restricted_sid_views) =
            build_owned_sid_entries_from_views(self.restricted_sid_views())?;
        let device_groups = clone_owned_sid_entries(self.device_groups.as_slice())?;
        let device_group_views = build_sid_and_attributes_views(device_groups.as_slice())?;
        let restricted_device_groups =
            clone_owned_sid_entries(self.restricted_device_groups.as_slice())?;
        let restricted_device_group_views =
            build_sid_and_attributes_views(restricted_device_groups.as_slice())?;
        let confinement_sid = clone_optional_owned_sid(self.confinement_sid.as_ref())?;
        let confinement_capabilities =
            clone_owned_sid_entries(self.confinement_capabilities.as_slice())?;
        let confinement_capability_views =
            build_sid_and_attributes_views(confinement_capabilities.as_slice())?;
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
        // KC-14: build every fallible leaf-Vec clone BEFORE committing any raw
        // allocation (default_dacl_ptr / own_sd_ptr / session ref / token_ptr) so
        // a clone failure unwinds via `?` while only owned Vecs are live — nothing
        // requiring manual freeing has been committed yet.
        let user_claims = try_clone_vec(&self.user_claims)?;
        let device_claims = try_clone_vec(&self.device_claims)?;
        let lcs_scope_guids = try_clone_vec(&self.lcs_scope_guids)?;
        let lcs_private_layers = try_clone_vec(&self.lcs_private_layers)?;
        let projected_supplementary_gids = try_clone_vec(&self.projected_supplementary_gids)?;
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let session = PkmKacsSession::clone_ref_ptr(self.session).ok_or(-EINVAL)?;
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            creator.user_sid.sid,
            self.user_sid.sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            false,
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
            user_sid,
            groups,
            group_count: self.group_count,
            group_sids,
            group_default_attributes,
            group_attributes: group_attributes_atoms,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(modified_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups,
            device_group_views,
            restricted_device_groups,
            restricted_device_group_views,
            user_claims,
            device_claims,
            lcs_scope_guids,
            lcs_private_layers,
            confinement_sid,
            confinement_capabilities,
            confinement_capability_views,
            confinement_exempt: self.confinement_exempt,
            isolation_boundary: self.isolation_boundary,
            audit_policy: self.audit_policy,
            expiration: self.expiration,
            source_name: self.source_name,
            source_id: self.source_id,
            origin: self.origin,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            projected_supplementary_gids,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, duplicate) };
        PkmKacsSession::register_live_token(session);
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
        let token_id = allocate_dynamic_token_id()?;
        let privileges = self.privileges_snapshot_locked();
        let group_attributes = self.current_group_attributes()?;
        let user_sid = clone_owned_sid(&self.user_sid)?;
        let groups = clone_owned_sid_entries(self.groups.as_slice())?;
        let group_sids = sid_vec_from_owned_entries(groups.as_slice())?;
        let group_default_attributes = try_clone_vec(&self.group_default_attributes)?;
        let group_attributes_atoms = build_atomic_u32_vec(group_attributes.as_slice())?;
        let group_views = build_group_views(group_sids.as_slice(), group_attributes.as_slice())?;
        let group_runtime_views =
            build_group_runtime_views(group_sids.as_slice(), group_attributes.as_slice())?;
        let (restricted_sids, restricted_sid_views) =
            build_owned_sid_entries_from_views(self.restricted_sid_views())?;
        let device_groups = clone_owned_sid_entries(self.device_groups.as_slice())?;
        let device_group_views = build_sid_and_attributes_views(device_groups.as_slice())?;
        let restricted_device_groups =
            clone_owned_sid_entries(self.restricted_device_groups.as_slice())?;
        let restricted_device_group_views =
            build_sid_and_attributes_views(restricted_device_groups.as_slice())?;
        let confinement_sid = clone_optional_owned_sid(self.confinement_sid.as_ref())?;
        let confinement_capabilities =
            clone_owned_sid_entries(self.confinement_capabilities.as_slice())?;
        let confinement_capability_views =
            build_sid_and_attributes_views(confinement_capabilities.as_slice())?;
        // KC-14: build every fallible leaf-Vec clone BEFORE committing any raw
        // allocation (default_dacl_ptr / own_sd_ptr / session ref / token_ptr) so
        // a clone failure unwinds via `?` while only owned Vecs are live — nothing
        // requiring manual freeing has been committed yet.
        let user_claims = try_clone_vec(&self.user_claims)?;
        let device_claims = try_clone_vec(&self.device_claims)?;
        let lcs_scope_guids = try_clone_vec(&self.lcs_scope_guids)?;
        let lcs_private_layers = try_clone_vec(&self.lcs_private_layers)?;
        let projected_supplementary_gids = try_clone_vec(&self.projected_supplementary_gids)?;
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
            user_sid,
            groups,
            group_count: self.group_count,
            group_sids,
            group_default_attributes,
            group_attributes: group_attributes_atoms,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups,
            device_group_views,
            restricted_device_groups,
            restricted_device_group_views,
            user_claims,
            device_claims,
            lcs_scope_guids,
            lcs_private_layers,
            confinement_sid,
            confinement_capabilities,
            confinement_capability_views,
            confinement_exempt: self.confinement_exempt,
            isolation_boundary: self.isolation_boundary,
            audit_policy: self.audit_policy,
            expiration: self.expiration,
            source_name: self.source_name,
            source_id: self.source_id,
            origin: self.origin,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            projected_supplementary_gids,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, derived) };
        PkmKacsSession::register_live_token(session);
        Ok(token_ptr.cast())
    }

    fn create_kunit_lcs_private_credential_token(
        scope_guids: *const [u8; KACS_LCS_SCOPE_GUID_BYTES],
        scope_count: usize,
        private_layer_name: *const c_char,
        private_layer_name_len: usize,
    ) -> Option<*const c_void> {
        if scope_count > KACS_LCS_MAX_SCOPE_GUIDS_PER_TOKEN {
            return None;
        }
        if scope_count != 0 && scope_guids.is_null() {
            return None;
        }
        if private_layer_name_len > KACS_LCS_MAX_PRIVATE_LAYER_NAME_BYTES {
            return None;
        }
        if private_layer_name_len != 0 && private_layer_name.is_null() {
            return None;
        }

        let token_ptr = Self::create_kunit_logon_type_token(
            LOGON_TYPE_SERVICE,
            SE_CREATE_TOKEN_PRIVILEGE | SE_TCB_PRIVILEGE,
        )?;
        let result = (|| -> Result<(), i32> {
            let token = unsafe { &mut *(token_ptr as *mut Self) };
            let scopes = if scope_count == 0 {
                &[][..]
            } else {
                unsafe { core::slice::from_raw_parts(scope_guids, scope_count) }
            };
            token.lcs_scope_guids = slice_to_vec(scopes).map_err(|_| -ENOMEM)?;

            let mut private_layers = Vec::new();
            if private_layer_name_len != 0 {
                let layer_bytes = unsafe {
                    core::slice::from_raw_parts(
                        private_layer_name.cast::<u8>(),
                        private_layer_name_len,
                    )
                };
                let layer = string_from_utf8_bytes(layer_bytes)?;
                private_layers.push(layer).map_err(|_| -ENOMEM)?;
            }
            token.lcs_private_layers = private_layers;
            Ok(())
        })();

        if result.is_err() {
            unsafe { Self::drop_ref(token_ptr) };
            return None;
        }

        Some(token_ptr)
    }

    unsafe fn drop_ref(ptr: *const c_void) {
        let Some(token) = (unsafe { Self::from_ptr(ptr) }) else {
            return;
        };
        let previous = token.refcount.fetch_sub(1, Ordering::Release);

        if previous == 1 {
            fence(Ordering::Acquire);
            let token_ptr = ptr as *mut Self;
            let session_ptr = token.session.cast();
            let remaining_live_tokens = PkmKacsSession::release_live_token(session_ptr);
            free_allocated_bytes(token.default_dacl_ptr.load(Ordering::Relaxed));
            free_allocated_bytes(token.own_sd_ptr.load(Ordering::Relaxed));
            unsafe { PkmKacsSession::drop_ref(session_ptr) };
            if remaining_live_tokens == 2 {
                PkmKacsSession::maybe_destroy_if_only_link_refs_remaining(session_ptr);
            }
            unsafe { core::ptr::drop_in_place(token_ptr) };
            unsafe { pkm_kacs_free(token_ptr.cast()) };
        } else if previous == 2 {
            PkmKacsSession::maybe_destroy_if_only_link_refs_remaining(token.session.cast());
        }
    }

    fn boot_snapshot(&self, out: &mut PkmKacsBootSnapshot) {
        let _guard = self.lock_mutation();
        let owner_sid_index = self.owner_sid_index.load(Ordering::Relaxed);
        let primary_group_index = self.primary_group_index.load(Ordering::Relaxed);
        let default_dacl = self.default_dacl_bytes();
        let own_sd = self.own_sd_bytes();
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
            token_guid: self.token_guid,
            modified_id: self.modified_id.load(Ordering::Relaxed),
            created_at: self.created_at,
            logon_type: session.logon_type,
            auth_pkg_ptr: session.auth_package_bytes().as_ptr(),
            auth_pkg_len: session.auth_package_bytes().len(),
            user_sid_ptr: self.user_sid.as_bytes().as_ptr(),
            user_sid_len: self.user_sid.as_bytes().len(),
            logon_sid_ptr: session.logon_sid.as_bytes().as_ptr(),
            logon_sid_len: session.logon_sid.as_bytes().len(),
            groups_ptr: group_views.as_ptr(),
            group_count: self.group_count as u32,
            owner_sid_index,
            primary_group_index,
            default_dacl_ptr: default_dacl.as_ptr(),
            default_dacl_len: default_dacl.len(),
            own_sd_ptr: own_sd.as_ptr(),
            own_sd_len: own_sd.len(),
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
            elevation_type: self.elevation_type(),
            restricted: if self.restricted { 1 } else { 0 },
            user_deny_only: if self.user_deny_only { 1 } else { 0 },
            write_restricted: if self.write_restricted { 1 } else { 0 },
            confinement_exempt: if self.confinement_exempt { 1 } else { 0 },
            isolation_boundary: if self.isolation_boundary { 1 } else { 0 },
            source_name_ptr: self.source_name.as_ptr(),
            source_name_len: TOKEN_SOURCE_NAME_LEN,
            source_id: self.source_id,
            expiration: self.expiration,
            origin: self.origin,
            restricted_sid_count: self.restricted_sids.len() as u32,
            confinement_sid_present: if self.confinement_sid.is_some() {
                1
            } else {
                0
            },
            confinement_capability_count: self.confinement_capabilities.len() as u32,
            projected_supplementary_gid_count: self.projected_supplementary_gids.len() as u32,
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

    fn default_dacl_rcu_copy(&self) -> Result<DefaultDaclCopy, i32> {
        loop {
            let sequence = self.default_dacl_seq.load(Ordering::Acquire);

            if (sequence & 1) != 0 {
                core::hint::spin_loop();
                continue;
            }

            let len = self.default_dacl_len.load(Ordering::Acquire);
            let copy_ptr = alloc_bytes(len)?;
            let mut retry = false;

            {
                let _guard = RcuReadGuard::new();
                let sequence_before = self.default_dacl_seq.load(Ordering::Acquire);

                if sequence_before != sequence || (sequence_before & 1) != 0 {
                    retry = true;
                } else if len != self.default_dacl_len.load(Ordering::Acquire) {
                    retry = true;
                } else if len == 0 {
                    retry = self.default_dacl_seq.load(Ordering::Acquire) != sequence;
                } else {
                    let src_ptr = self.default_dacl_ptr.load(Ordering::Acquire);

                    if src_ptr.is_null() {
                        retry = true;
                    } else {
                        unsafe { copy_nonoverlapping(src_ptr.cast_const(), copy_ptr, len) };
                        retry = self.default_dacl_seq.load(Ordering::Acquire) != sequence;
                    }
                }
            }

            if !retry {
                return Ok(DefaultDaclCopy::from_raw(copy_ptr, len));
            }

            free_allocated_bytes(copy_ptr);
        }
    }

    fn own_sd_bytes(&self) -> &[u8] {
        let ptr = self.own_sd_ptr.load(Ordering::Relaxed);
        let len = self.own_sd_len.load(Ordering::Relaxed);

        if len == 0 {
            return &[];
        }

        unsafe { core::slice::from_raw_parts(ptr.cast_const(), len) }
    }

    /// Returns an owned, RCU-safe copy of the token's own SD bytes for lockless
    /// readers. own_sd_bytes() borrows the live (own_sd_ptr, own_sd_len) pair,
    /// which replace_own_sd swaps and frees concurrently — a UAF / torn-read
    /// hazard for readers that hold the slice across a parse + access check.
    /// This mirrors default_dacl_rcu_copy: a seqlock retry loop under an RCU
    /// read guard pinned against replace_own_sd's deferred free.
    fn own_sd_rcu_copy(&self) -> Result<DefaultDaclCopy, i32> {
        loop {
            let sequence = self.own_sd_seq.load(Ordering::Acquire);

            if (sequence & 1) != 0 {
                core::hint::spin_loop();
                continue;
            }

            let len = self.own_sd_len.load(Ordering::Acquire);
            let copy_ptr = alloc_bytes(len)?;
            let mut retry = false;

            {
                let _guard = RcuReadGuard::new();
                let sequence_before = self.own_sd_seq.load(Ordering::Acquire);

                if sequence_before != sequence || (sequence_before & 1) != 0 {
                    retry = true;
                } else if len != self.own_sd_len.load(Ordering::Acquire) {
                    retry = true;
                } else if len == 0 {
                    retry = self.own_sd_seq.load(Ordering::Acquire) != sequence;
                } else {
                    let src_ptr = self.own_sd_ptr.load(Ordering::Acquire);

                    if src_ptr.is_null() {
                        retry = true;
                    } else {
                        unsafe { copy_nonoverlapping(src_ptr.cast_const(), copy_ptr, len) };
                        retry = self.own_sd_seq.load(Ordering::Acquire) != sequence;
                    }
                }
            }

            if !retry {
                return Ok(DefaultDaclCopy::from_raw(copy_ptr, len));
            }

            free_allocated_bytes(copy_ptr);
        }
    }

    fn current_group_attributes(&self) -> Result<Vec<u32>, i32> {
        let mut attributes = Vec::with_capacity(self.group_count).map_err(|_| -ENOMEM)?;

        for index in 0..self.group_count {
            attributes
                .push(self.group_attributes[index].load(Ordering::Relaxed))
                .map_err(|_| -ENOMEM)?;
        }

        Ok(attributes)
    }

    fn restricted_sid_views(&self) -> &[SidAndAttributes<'static>] {
        self.restricted_sid_views.as_slice()
    }

    fn sync_group_views_locked(&self, group_attributes: &[u32]) {
        let group_views = unsafe { &mut *self.group_views.get() };
        let group_runtime_views = unsafe { &mut *self.group_runtime_views.get() };

        for index in 0..group_views.len() {
            group_views[index].attributes = group_attributes[index];
            group_runtime_views[index].attributes = group_attributes[index];
        }
    }

    fn current_group_enabled_mask_locked(&self) -> [u64; GROUP_MASK_WORDS] {
        let mut mask = [0u64; GROUP_MASK_WORDS];

        for index in 0..self.group_count.min(MAX_TOKEN_GROUPS) {
            let attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if (attributes & SE_GROUP_ENABLED) == SE_GROUP_ENABLED {
                mask[index / 64] |= 1u64 << (index % 64);
            }
        }

        mask
    }

    fn has_enabled_group_sid_bytes(&self, sid_bytes: &[u8]) -> bool {
        let _guard = self.lock_mutation();

        for index in 0..self.group_count {
            let Some(group_sid) = self.group_sids.get(index) else {
                continue;
            };
            let attributes = self.group_attributes[index].load(Ordering::Relaxed);

            if (attributes & SE_GROUP_ENABLED) == SE_GROUP_ENABLED
                && (attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0
                && group_sid.as_bytes() == sid_bytes
            {
                return true;
            }
        }

        false
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
            let next_dacl_sequence = if dacl.is_some() {
                let sequence = self.default_dacl_seq.load(Ordering::Relaxed);
                let Some(next_sequence) = sequence.checked_add(2) else {
                    free_allocated_bytes(replacement_ptr);
                    return Err(-ERANGE);
                };

                Some((sequence, next_sequence))
            } else {
                None
            };

            if owner_index != TOKEN_INDEX_NO_CHANGE {
                self.owner_sid_index.store(owner_index, Ordering::Relaxed);
            }
            if group_index != TOKEN_INDEX_NO_CHANGE {
                self.primary_group_index
                    .store(group_index, Ordering::Relaxed);
            }

            old_default_dacl_ptr = if let Some((sequence, next_sequence)) = next_dacl_sequence {
                self.default_dacl_seq
                    .store(sequence + 1, Ordering::Release);
                let old = self
                    .default_dacl_ptr
                    .swap(replacement_ptr, Ordering::AcqRel);
                self.default_dacl_len
                    .store(replacement_len, Ordering::Release);
                self.default_dacl_seq
                    .store(next_sequence, Ordering::Release);
                old
            } else {
                null_mut()
            };
            self.modified_id.store(next_modified_id, Ordering::Relaxed);
        }

        free_allocated_bytes_after_rcu(old_default_dacl_ptr);
        Ok(())
    }

    fn sid_by_index(&self, index: u32) -> Option<Sid<'_>> {
        if index == 0 {
            return Some(self.user_sid.sid);
        }

        self.group_sid_at(index - 1)
    }

    fn with_access_token<T>(&self, f: impl FnOnce(AccessCheckToken<'_>) -> T) -> T {
        let _guard = self.lock_mutation();
        let groups = unsafe { &*self.group_runtime_views.get() };
        let privileges = self.privileges_snapshot_locked();
        let access_token = AccessCheckToken {
            subject: TokenView {
                user: self.user_sid.sid,
                user_deny_only: self.user_deny_only,
                groups: groups.as_slice(),
            },
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            audit_policy: self.audit_policy,
            privileges,
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            restricted: RestrictedTokenContext {
                restricted_sids: self.restricted_sid_views(),
                restricted_device_groups: self.restricted_device_group_views.as_slice(),
                write_restricted: self.write_restricted,
                privilege_granted: 0,
            },
            confinement: ConfinementTokenContext {
                confinement_sid: self.confinement_sid.as_ref().map(|sid| sid.sid),
                confinement_capabilities: self.confinement_capability_views.as_slice(),
                confinement_exempt: self.confinement_exempt,
            },
        };

        f(access_token)
    }

    fn access_check_conditional_context(&self) -> ConditionalContext<'_> {
        ConditionalContext {
            device_groups: self.device_group_views.as_slice(),
            user_claims: self.user_claims.as_slice(),
            device_claims: self.device_claims.as_slice(),
            ..ConditionalContext::default()
        }
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
        write_sid_and_attributes_query(self.restricted_sid_views(), writer)
    }
}

fn write_sid_and_attributes_query(
    entries: &[SidAndAttributes<'_>],
    writer: &mut QueryWriter,
) -> Result<(), i32> {
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

impl PkmKacsBootToken {
    fn adjust_groups(&self, entries: &[PkmKacsGroupAdjustEntry]) -> Result<[u64; GROUP_MASK_WORDS], i32> {
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

        for (entry_index, entry) in entries.iter().enumerate() {
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
            for previous in &entries[..entry_index] {
                if previous.index == entry.index {
                    return Err(-EINVAL);
                }
            }

            if (attributes & SE_GROUP_MANDATORY) == SE_GROUP_MANDATORY
                || (attributes & SE_GROUP_USE_FOR_DENY_ONLY) == SE_GROUP_USE_FOR_DENY_ONLY
                || (attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID
                || (entry.enable == 0 && group_sid.as_bytes() == self.user_sid.as_bytes())
            {
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

        let current_group_attributes = self.current_group_attributes()?;
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
        let mut group_attributes = self.current_group_attributes()?;
        let source_was_restricted = !self.restricted_sid_views().is_empty();
        let privileges_present = privileges.present & !privs_to_delete;
        let privileges_enabled = privileges.enabled & !privs_to_delete;
        let privileges_enabled_by_default = privileges.enabled_by_default & !privs_to_delete;
        let token_id = allocate_dynamic_token_id()?;
        let write_restricted = write_restricted_requested || self.write_restricted;
        let user_deny_only = write_restricted;
        let user_sid = clone_owned_sid(&self.user_sid)?;
        let mut groups = clone_owned_sid_entries(self.groups.as_slice())?;
        let group_sids = sid_vec_from_owned_entries(groups.as_slice())?;
        let (restricted_sids, restricted_sid_views) = if !source_was_restricted {
            build_owned_sid_entries_from_views(restrict_sids)?
        } else {
            intersect_restricted_sid_views(self.restricted_sid_views(), restrict_sids)?
        };
        let device_groups = clone_owned_sid_entries(self.device_groups.as_slice())?;
        let device_group_views = build_sid_and_attributes_views(device_groups.as_slice())?;
        let restricted_device_groups =
            clone_owned_sid_entries(self.restricted_device_groups.as_slice())?;
        let restricted_device_group_views =
            build_sid_and_attributes_views(restricted_device_groups.as_slice())?;
        let confinement_sid = clone_optional_owned_sid(self.confinement_sid.as_ref())?;
        let confinement_capabilities =
            clone_owned_sid_entries(self.confinement_capabilities.as_slice())?;
        let confinement_capability_views =
            build_sid_and_attributes_views(confinement_capabilities.as_slice())?;
        if source_was_restricted && restricted_sid_views.is_empty() {
            return Err(-EINVAL);
        }
        let restricted = !restricted_sid_views.is_empty()
            || !restricted_device_group_views.is_empty();
        // KC-14: build every fallible leaf-Vec clone BEFORE committing any raw
        // allocation (default_dacl_ptr / own_sd_ptr / session ref / token_ptr) so
        // a clone failure unwinds via `?` while only owned Vecs are live — nothing
        // requiring manual freeing has been committed yet.
        let user_claims = try_clone_vec(&self.user_claims)?;
        let device_claims = try_clone_vec(&self.device_claims)?;
        let lcs_scope_guids = try_clone_vec(&self.lcs_scope_guids)?;
        let lcs_private_layers = try_clone_vec(&self.lcs_private_layers)?;
        let projected_supplementary_gids = try_clone_vec(&self.projected_supplementary_gids)?;
        let (default_dacl_ptr, default_dacl_len) = alloc_copy_bytes(self.default_dacl_bytes())?;
        let session = PkmKacsSession::clone_ref_ptr(self.session).ok_or(-EINVAL)?;
        let (own_sd_ptr, own_sd_len) = match build_token_sd_bytes(
            creator.user_sid.sid,
            self.user_sid.sid,
            Some(KACS_TOKEN_DEFAULT_SELF_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            Some(KACS_TOKEN_ALL_ACCESS),
            false,
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

        for (deny_pos, deny_index) in deny_indices.iter().enumerate() {
            let index = usize::try_from(*deny_index).map_err(|_| -EINVAL)?;

            if index >= self.group_count {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                unsafe { pkm_kacs_free(token_ptr.cast()) };
                return Err(-EINVAL);
            }
            for previous in &deny_indices[..deny_pos] {
                if previous == deny_index {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return Err(-EINVAL);
                }
            }
            group_attributes[index] |= SE_GROUP_USE_FOR_DENY_ONLY;
        }
        for (index, entry) in groups.iter_mut().enumerate() {
            entry.attributes = group_attributes[index];
        }
        // KC-14: these finalization steps run after the raw allocations above are
        // committed, so a failure must free them explicitly (mirroring the
        // deny-index loop's cleanup) rather than leak via a bare `?`.
        let group_default_attributes = match group_attributes.try_clone() {
            Ok(value) => value,
            Err(_) => {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                unsafe { pkm_kacs_free(token_ptr.cast()) };
                return Err(-ENOMEM);
            }
        };
        let group_attributes_atoms = match build_atomic_u32_vec(group_attributes.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                free_allocated_bytes(default_dacl_ptr);
                free_allocated_bytes(own_sd_ptr);
                unsafe { PkmKacsSession::drop_ref(session) };
                unsafe { pkm_kacs_free(token_ptr.cast()) };
                return Err(err);
            }
        };
        let group_views =
            match build_group_views(group_sids.as_slice(), group_attributes.as_slice()) {
                Ok(value) => value,
                Err(err) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return Err(err);
                }
            };
        let group_runtime_views =
            match build_group_runtime_views(group_sids.as_slice(), group_attributes.as_slice()) {
                Ok(value) => value,
                Err(err) => {
                    free_allocated_bytes(default_dacl_ptr);
                    free_allocated_bytes(own_sd_ptr);
                    unsafe { PkmKacsSession::drop_ref(session) };
                    unsafe { pkm_kacs_free(token_ptr.cast()) };
                    return Err(err);
                }
            };

        let restricted_token = Self {
            refcount: AtomicUsize::new(1),
            mutation_lock: AtomicBool::new(false),
            session,
            user_sid,
            groups,
            group_count: self.group_count,
            group_sids,
            group_default_attributes,
            group_attributes: group_attributes_atoms,
            group_views: UnsafeCell::new(group_views),
            group_runtime_views: UnsafeCell::new(group_runtime_views),
            token_guid: new_uuid_v4(),
            token_id,
            created_at: self.created_at,
            modified_id: AtomicU64::new(token_id),
            owner_sid_index: AtomicU32::new(self.owner_sid_index.load(Ordering::Relaxed)),
            primary_group_index: AtomicU32::new(self.primary_group_index.load(Ordering::Relaxed)),
            default_dacl_ptr: AtomicPtr::new(default_dacl_ptr),
            default_dacl_len: AtomicUsize::new(default_dacl_len),
            default_dacl_seq: AtomicU64::new(0),
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
            device_groups,
            device_group_views,
            restricted_device_groups,
            restricted_device_group_views,
            user_claims,
            device_claims,
            lcs_scope_guids,
            lcs_private_layers,
            confinement_sid,
            confinement_capabilities,
            confinement_capability_views,
            confinement_exempt: self.confinement_exempt,
            isolation_boundary: self.isolation_boundary,
            audit_policy: self.audit_policy,
            expiration: self.expiration,
            source_name: self.source_name,
            source_id: self.source_id,
            origin: self.origin,
            interactive_session_id: AtomicU32::new(
                self.interactive_session_id.load(Ordering::Relaxed),
            ),
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            projected_supplementary_gids,
            own_sd_ptr: AtomicPtr::new(own_sd_ptr),
            own_sd_len: AtomicUsize::new(own_sd_len),
            own_sd_seq: AtomicU64::new(0),
        };

        unsafe { core::ptr::write(token_ptr, restricted_token) };
        PkmKacsSession::register_live_token(session);
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
            TOKEN_CLASS_DEVICE_GROUPS => {
                sid_and_attributes_query_len(self.device_group_views.as_slice()).ok_or(-EINVAL)
            }
            TOKEN_CLASS_APPCONTAINER_SID => Ok(self
                .confinement_sid
                .as_ref()
                .map(|sid| sid.as_bytes().len())
                .unwrap_or(0)),
            TOKEN_CLASS_CAPABILITIES => sid_and_attributes_query_len(
                self.confinement_capability_views.as_slice(),
            )
            .ok_or(-EINVAL),
            TOKEN_CLASS_MANDATORY_POLICY => Ok(4),
            TOKEN_CLASS_LOGON_TYPE => Ok(4),
            TOKEN_CLASS_LOGON_SID => self
                .session_ref()
                .map(|session| session.logon_sid.as_bytes().len())
                .ok_or(-EINVAL),
            TOKEN_CLASS_USER_CLAIMS => claim_array_query_len(self.user_claims.as_slice()),
            TOKEN_CLASS_DEVICE_CLAIMS => claim_array_query_len(self.device_claims.as_slice()),
            TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS => {
                u32_array_query_len(self.projected_supplementary_gids.as_slice())
            }
            TOKEN_CLASS_IMPERSONATION_LEVEL => Ok(4),
            0 => Err(-EINVAL),
            value if value > TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS => Err(-EINVAL),
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
                writer.write_bytes(&self.source_name) && writer.write_u64(self.source_id)
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
                    && writer.write_u64(self.expiration)
            }
            TOKEN_CLASS_ORIGIN => writer.write_u64(self.origin),
            TOKEN_CLASS_ELEVATION_TYPE => writer.write_u32(self.elevation_type()),
            TOKEN_CLASS_DEVICE_GROUPS => {
                write_sid_and_attributes_query(self.device_group_views.as_slice(), writer)?;
                true
            }
            TOKEN_CLASS_APPCONTAINER_SID => self
                .confinement_sid
                .as_ref()
                .map(|sid| writer.write_bytes(sid.as_bytes()))
                .unwrap_or(true),
            TOKEN_CLASS_CAPABILITIES => {
                write_sid_and_attributes_query(
                    self.confinement_capability_views.as_slice(),
                    writer,
                )?;
                true
            }
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
            TOKEN_CLASS_USER_CLAIMS => {
                write_claim_array_query(self.user_claims.as_slice(), writer)?;
                true
            }
            TOKEN_CLASS_DEVICE_CLAIMS => {
                write_claim_array_query(self.device_claims.as_slice(), writer)?;
                true
            }
            TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS => {
                write_u32_array_query(self.projected_supplementary_gids.as_slice(), writer)?;
                true
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

    fn replace_own_sd(
        &self,
        subject: &PkmKacsBootToken,
        security_info: u32,
        input_sd_bytes: &[u8],
    ) -> Result<(), i32> {
        let old_sd_ptr;
        {
            let _guard = self.lock_mutation();
            let modified_id = self.modified_id.load(Ordering::Relaxed);
            let Some(next_modified_id) = modified_id.checked_add(1) else {
                return Err(-ERANGE);
            };
            // Reading own_sd_bytes() here is safe: writers serialize on
            // mutation_lock, so no concurrent replace_own_sd is in flight.
            let (new_sd_ptr, new_sd_len) = merge_process_sd_bytes(
                subject,
                self.own_sd_bytes(),
                security_info,
                input_sd_bytes,
                true,
            )?;
            let sequence = self.own_sd_seq.load(Ordering::Relaxed);
            let Some(next_sequence) = sequence.checked_add(2) else {
                free_allocated_bytes(new_sd_ptr);
                return Err(-ERANGE);
            };

            // KC-15: publish under the seqlock (odd while swapping, even when
            // done) so own_sd_rcu_copy retries any snapshot overlapping the
            // swap, and defer the free past the RCU grace period so an in-flight
            // reader can never observe freed bytes (was an immediate free -> UAF).
            self.own_sd_seq.store(sequence + 1, Ordering::Release);
            old_sd_ptr = self.own_sd_ptr.swap(new_sd_ptr, Ordering::AcqRel);
            self.own_sd_len.store(new_sd_len, Ordering::Release);
            self.own_sd_seq.store(next_sequence, Ordering::Release);
            self.modified_id.store(next_modified_id, Ordering::Relaxed);
        }

        free_allocated_bytes_after_rcu(old_sd_ptr);
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
            device_groups: token.device_group_views.as_slice(),
            user_claims: token.user_claims.as_slice(),
            device_claims: token.device_claims.as_slice(),
            policies,
        };
        f(resolved)
    })
}

fn emit_internal_access_check_events(
    subject: &PkmKacsBootToken,
    access_token: &AccessCheckToken<'_>,
    state: &crate::access_check::AccessCheckCoreState<'_>,
    effective_pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
) -> Result<(), i32> {
    if state.audit_events.is_empty()
        && state.privilege_use_events.is_empty()
        && state.caap_diagnostic_events.is_empty()
    {
        return Ok(());
    }

    let audit_events = own_audit_events(state.audit_events.as_slice()).map_err(|err| match err {
        KacsError::AllocationFailure => -ENOMEM,
        _ => -EACCES,
    })?;
    let resolved = AccessCheckAbiResolved {
        token: access_token,
        default_pip: effective_pip,
        device_groups: subject.device_group_views.as_slice(),
        user_claims: subject.user_claims.as_slice(),
        device_claims: subject.device_claims.as_slice(),
        policies,
    };

    emit_access_check_events_to_kmes(
        audit_events.as_slice(),
        state.privilege_use_events.as_slice(),
        state.caap_diagnostic_events.as_slice(),
        resolved,
        effective_pip,
    )
    .map_err(|err| err as i32)
}

fn pip_context_from_abi(pip_type: u32, pip_trust: u32) -> PipContext {
    PipContext {
        pip_type,
        pip_trust,
    }
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

fn token_has_enabled_administrators(token_ptr: *const c_void) -> bool {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return false;
    };

    token.has_enabled_group_sid_bytes(ADMINISTRATORS_SID_BYTES)
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
    {
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
    }

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

    // KC-16: resolve the partner and take a reference to it UNDER the session-
    // table lock, then release the lock. The query-copy path below allocates
    // (GFP_KERNEL) and takes the partner's mutation lock — neither may run under
    // the IRQ-disabled session-table spinlock (sleep-in-atomic), and doing so
    // also created an AB-BA inversion against create_session. The clone_ref
    // keeps the partner alive once the lock is dropped.
    let partner_ref = {
        let _guard = lock_session_table();
        let Some(session) = token.session_ref() else {
            return Err(-EACCES);
        };

        let partner_ptr = match token.elevation_type() {
            TOKEN_ELEVATION_FULL_ABI => {
                if session.linked_elevated != token_ptr {
                    return Err(-ENOENT);
                }
                session.linked_filtered
            }
            TOKEN_ELEVATION_LIMITED_ABI => {
                if session.linked_filtered != token_ptr {
                    return Err(-ENOENT);
                }
                session.linked_elevated
            }
            TOKEN_ELEVATION_DEFAULT_ABI => return Err(-ENOENT),
            _ => return Err(-EINVAL),
        };

        if partner_ptr.is_null() {
            return Err(-ENOENT);
        }
        if (unsafe { PkmKacsBootToken::from_ptr(partner_ptr) }).is_none() {
            return Err(-ENOENT);
        }

        let partner_ref = PkmKacsBootToken::clone_ref(partner_ptr);
        if partner_ref.is_null() {
            return Err(-EACCES);
        }
        partner_ref
    };

    if return_actual {
        // Caller wants the actual partner token; we already hold a reference.
        Ok(partner_ref)
    } else {
        // The allocating query-copy now runs OUTSIDE the session-table lock.
        let result = match unsafe { PkmKacsBootToken::from_ptr(partner_ref) } {
            Some(partner) => partner.linked_query_copy(),
            None => Err(-ENOENT),
        };
        unsafe { PkmKacsBootToken::drop_ref(partner_ref) };
        result
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
    pip: PipContext,
) -> i32 {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return -EACCES;
    };
    let Some(target) = (unsafe { PkmKacsBootToken::from_ptr(target_token) }) else {
        return -EACCES;
    };
    // KC-15: snapshot the target's own SD into an owned, RCU-safe copy held for
    // the whole check; own_sd() borrowed the live buffer that replace_own_sd
    // may swap and free concurrently.
    let target_sd_copy = match target.own_sd_rcu_copy() {
        Ok(copy) => copy,
        Err(err) => return err,
    };
    let Some(target_sd) = SecurityDescriptor::parse(target_sd_copy.as_slice()).ok() else {
        return -EACCES;
    };
    let normalized = match TOKEN_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return -22,
        Err(_) => return -EACCES,
    };

    subject.with_access_token(|access_token| {
        let conditional_context = subject.access_check_conditional_context();

        match access_check_core(
            Some(&target_sd),
            &access_token,
            pip,
            desired,
            &TOKEN_GENERIC_MAPPING,
            AccessCheckMode::Scalar,
            None,
            &conditional_context,
            None,
            0,
            EMPTY_POLICIES,
        ) {
            Ok(result) => {
                subject.mark_privileges_used(result.updated_privileges.used);
                if let Err(err) = emit_internal_access_check_events(
                    subject,
                    &access_token,
                    &result,
                    pip,
                    EMPTY_POLICIES,
                ) {
                    return err;
                }
                let granted = result
                    .object_granted_list
                    .as_ref()
                    .and_then(|list| list.first().copied())
                    .unwrap_or(result.granted);
                let allowed = result.mapped_desired == 0
                    || (granted & result.mapped_desired) == result.mapped_desired;

                if !allowed {
                    return -EACCES;
                }
                if normalized.maximum_allowed {
                    granted as i32
                } else {
                    (granted & normalized.mapped) as i32
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
            | Err(KacsError::SecurityDescriptorTooLarge { .. })
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
    pip: PipContext,
) -> Result<u32, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let Some(target) = (unsafe { PkmKacsBootToken::from_ptr(target_token) }) else {
        return Err(-EACCES);
    };
    // KC-15: snapshot the target's own SD into an owned, RCU-safe copy (see
    // token_open_check_errno).
    let target_sd_copy = match target.own_sd_rcu_copy() {
        Ok(copy) => copy,
        Err(err) => return Err(err),
    };
    let Some(target_sd) = SecurityDescriptor::parse(target_sd_copy.as_slice()).ok() else {
        return Err(-EACCES);
    };
    let normalized = match TOKEN_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };

    subject.with_access_token(|access_token| {
        let conditional_context = subject.access_check_conditional_context();

        match access_check_core(
            Some(&target_sd),
            &access_token,
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
                emit_internal_access_check_events(
                    subject,
                    &access_token,
                    &result,
                    pip,
                    EMPTY_POLICIES,
                )?;
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

struct ProcessSdAccessOutcome {
    granted: u32,
    allowed: bool,
    pip_denied_requested: u32,
}

fn process_sd_access_outcome_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
) -> Result<ProcessSdAccessOutcome, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;
    let normalized = match PROCESS_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };

    subject.with_access_token(|access_token| {
        let conditional_context = subject.access_check_conditional_context();

        match access_check_core(
            Some(&target_sd),
            &access_token,
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
                emit_internal_access_check_events(
                    subject,
                    &access_token,
                    &result,
                    pip,
                    EMPTY_POLICIES,
                )?;
                let granted = result
                    .object_granted_list
                    .as_ref()
                    .and_then(|list| list.first().copied())
                    .unwrap_or(result.granted);
                let allowed = result.mapped_desired == 0
                    || (granted & result.mapped_desired) == result.mapped_desired;
                let granted = if normalized.maximum_allowed {
                    granted
                } else {
                    granted & normalized.mapped
                };

                Ok(ProcessSdAccessOutcome {
                    granted,
                    allowed,
                    pip_denied_requested: result.pip_decided & result.mapped_desired,
                })
            }
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EINVAL),
        }
    })
}

fn process_sd_access_check_errno_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
) -> Result<u32, i32> {
    let outcome = process_sd_access_outcome_with_intent(
        subject_token,
        sd_bytes,
        desired,
        privilege_intent,
        pip,
    )?;

    if !outcome.allowed {
        return Err(-EACCES);
    }

    Ok(outcome.granted)
}

struct FileSdAccessOutcome {
    granted: u32,
    continuous_audit_mask: u32,
    allowed: bool,
}

fn file_sd_access_outcome_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
) -> Result<FileSdAccessOutcome, i32> {
    file_sd_access_outcome_with_intent_and_policies(
        subject_token,
        sd_bytes,
        desired,
        privilege_intent,
        pip,
        EMPTY_POLICIES,
    )
}

fn file_sd_access_outcome_with_intent_and_policies(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
) -> Result<FileSdAccessOutcome, i32> {
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;

    file_sd_access_outcome_for_descriptor(
        subject_token,
        &target_sd,
        desired,
        privilege_intent,
        pip,
        policies,
    )
}

fn file_sd_access_outcome_for_descriptor(
    subject_token: *const c_void,
    target_sd: &SecurityDescriptor<'_>,
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
) -> Result<FileSdAccessOutcome, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let normalized = match FILE_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };

    subject.with_access_token(|access_token| {
        let conditional_context = subject.access_check_conditional_context();

        match access_check_core(
            Some(target_sd),
            &access_token,
            pip,
            desired,
            &FILE_GENERIC_MAPPING,
            AccessCheckMode::Scalar,
            None,
            &conditional_context,
            None,
            privilege_intent,
            policies,
        ) {
            Ok(result) => {
                subject.mark_privileges_used(result.updated_privileges.used);
                emit_internal_access_check_events(subject, &access_token, &result, pip, policies)?;
                let granted = result
                    .object_granted_list
                    .as_ref()
                    .and_then(|list| list.first().copied())
                    .unwrap_or(result.granted);
                let allowed = result.mapped_desired == 0
                    || (granted & result.mapped_desired) == result.mapped_desired;
                let granted = if normalized.maximum_allowed {
                    granted
                } else {
                    granted & normalized.mapped
                };

                Ok(FileSdAccessOutcome {
                    granted,
                    continuous_audit_mask: result.continuous_audit_mask,
                    allowed,
                })
            }
            Err(KacsError::AllocationFailure) => Err(-ENOMEM),
            Err(KacsError::ReservedAccessMaskBits(_)) => Err(-EINVAL),
            Err(_) => Err(-EINVAL),
        }
    })
}

fn file_sd_access_check_errno_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
) -> Result<FileSdAccessOutcome, i32> {
    let outcome = file_sd_access_outcome_with_intent(
        subject_token,
        sd_bytes,
        desired,
        privilege_intent,
        pip,
    )?;

    if !outcome.allowed {
        return Err(-EACCES);
    }

    Ok(outcome)
}

fn file_sd_access_check_errno_with_intent_and_policies(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
) -> Result<FileSdAccessOutcome, i32> {
    let outcome = file_sd_access_outcome_with_intent_and_policies(
        subject_token,
        sd_bytes,
        desired,
        privilege_intent,
        pip,
        policies,
    )?;

    if !outcome.allowed {
        return Err(-EACCES);
    }

    Ok(outcome)
}

fn emit_file_set_sd_audit_events(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    pip: PipContext,
) -> Result<(), i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;
    let Some(sacl) = target_sd.sacl() else {
        return Ok(());
    };
    let owner = target_sd.owner().ok_or(-EINVAL)?;
    let normalized = match FILE_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };
    let metadata = extract_sacl_metadata(&target_sd).map_err(|err| match err {
        KacsError::AllocationFailure => -ENOMEM,
        _ => -EINVAL,
    })?;

    subject.with_access_token(|access_token| {
        let mut conditional_context = subject.access_check_conditional_context();
        conditional_context.resource_claims = metadata.resource_attributes.as_slice();

        let state = evaluate_sacl(
            &sacl,
            &access_token.subject,
            owner,
            conditional_context.self_sid,
            None,
            normalized.mapped,
            normalized.mapped,
            &FILE_GENERIC_MAPPING,
            &conditional_context,
            None,
        )
        .map_err(|err| match err {
            KacsError::AllocationFailure => -ENOMEM,
            KacsError::ReservedAccessMaskBits(_) => -EINVAL,
            _ => -EINVAL,
        })?;
        if state.audit_events.is_empty() {
            return Ok(());
        }

        let audit_events = own_audit_events(state.audit_events.as_slice()).map_err(|err| match err {
            KacsError::AllocationFailure => -ENOMEM,
            _ => -EACCES,
        })?;
        let resolved = AccessCheckAbiResolved {
            token: &access_token,
            default_pip: pip,
            device_groups: subject.device_group_views.as_slice(),
            user_claims: subject.user_claims.as_slice(),
            device_claims: subject.device_claims.as_slice(),
            policies: EMPTY_POLICIES,
        };

        emit_access_check_events_to_kmes(audit_events.as_slice(), &[], &[], resolved, pip)
            .map_err(|err| err as i32)
    })
}

#[no_mangle]
/// Emits post-success file set-security SACL audit events for the merged SD.
pub extern "C" fn kacs_rust_emit_file_set_sd_audit(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    pip_type: u32,
    pip_trust: u32,
) -> i32 {
    if subject_token_ptr.is_null() || sd_ptr.is_null() || sd_len == 0 || desired == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match emit_file_set_sd_audit_events(
        subject_token_ptr,
        sd_bytes,
        desired,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

fn file_sd_granted_mask_errno_with_intent(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
) -> Result<FileSdAccessOutcome, i32> {
    file_sd_access_outcome_with_intent(subject_token, sd_bytes, desired, privilege_intent, pip)
}

fn file_sd_granted_mask_errno_with_intent_and_policies(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    privilege_intent: u32,
    pip: PipContext,
    policies: &[crate::caap::CaapPolicyEntry<'_>],
) -> Result<FileSdAccessOutcome, i32> {
    file_sd_access_outcome_with_intent_and_policies(
        subject_token,
        sd_bytes,
        desired,
        privilege_intent,
        pip,
        policies,
    )
}

fn process_sd_access_check_errno(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    pip: PipContext,
) -> Result<u32, i32> {
    process_sd_access_check_errno_with_intent(subject_token, sd_bytes, desired, 0, pip)
}

fn socket_sd_access_check_errno(
    subject_token: *const c_void,
    sd_bytes: &[u8],
    desired: u32,
    pip: PipContext,
) -> Result<u32, i32> {
    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token) }) else {
        return Err(-EACCES);
    };
    let target_sd = SecurityDescriptor::parse(sd_bytes).map_err(sd_parse_errno)?;
    let normalized = match SOCKET_GENERIC_MAPPING.normalize_desired_access(desired) {
        Ok(normalized) => normalized,
        Err(KacsError::ReservedAccessMaskBits(_)) => return Err(-EINVAL),
        Err(_) => return Err(-EINVAL),
    };

    subject.with_access_token(|access_token| {
        let conditional_context = subject.access_check_conditional_context();

        match access_check_core(
            Some(&target_sd),
            &access_token,
            pip,
            desired,
            &SOCKET_GENERIC_MAPPING,
            AccessCheckMode::Scalar,
            None,
            &conditional_context,
            None,
            0,
            EMPTY_POLICIES,
        ) {
            Ok(result) => {
                subject.mark_privileges_used(result.updated_privileges.used);
                emit_internal_access_check_events(
                    subject,
                    &access_token,
                    &result,
                    pip,
                    EMPTY_POLICIES,
                )?;
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

#[no_mangle]
/// Creates the boot SYSTEM token object described by Appendix A step 3.
pub extern "C" fn kacs_rust_create_boot_system_token() -> *const c_void {
    PkmKacsBootToken::create_system().unwrap_or(null())
}

#[no_mangle]
/// Creates the canonical boot Anonymous impersonation token object.
pub extern "C" fn kacs_rust_create_boot_anonymous_token() -> *const c_void {
    PkmKacsBootToken::create_anonymous().unwrap_or(null())
}

#[no_mangle]
/// Creates one published logon-session object from the exact `v0.20`
/// wire-format session specification.
pub extern "C" fn kacs_rust_create_session(
    creator_token: *const c_void,
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
    let Some(creator_token) = (unsafe { PkmKacsBootToken::from_ptr(creator_token) }) else {
        return -EACCES;
    };

    let spec = unsafe { core::slice::from_raw_parts(spec, spec_len) };
    let (logon_type, auth_package, user_sid) = match parse_session_spec(spec) {
        Ok(parsed) => parsed,
        Err(err) => return err,
    };
    let _guard = creator_token.lock_mutation();
    let Some(group_sid) =
        creator_token.sid_by_index(creator_token.primary_group_index.load(Ordering::Relaxed))
    else {
        return -EINVAL;
    };

    match create_published_dynamic_session(
        created_at,
        logon_type,
        auth_package,
        user_sid,
        group_sid,
    ) {
        Ok(session_id) => {
            *session_id_out = session_id;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Destroys a published logon-session object that never acquired any live token
/// or in-flight kernel reference.
pub extern "C" fn kacs_rust_destroy_empty_session(session_id: u64) -> i32 {
    PkmKacsSession::destroy_empty_published_session(session_id)
}

#[no_mangle]
/// Creates one new token object from the exact `v0.20` token wire format.
pub extern "C" fn kacs_rust_create_token(
    creator_token: *const c_void,
    spec: *const u8,
    spec_len: usize,
    created_at: u64,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(creator_token) = (unsafe { PkmKacsBootToken::from_ptr(creator_token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };

    *out_token = null();

    if spec.is_null() || spec_len < TOKEN_SPEC_HEADER_LEN || spec_len > MAX_TOKEN_SPEC_BYTES {
        return -EINVAL;
    }

    match PkmKacsBootToken::create_from_spec(
        creator_token,
        unsafe { core::slice::from_raw_parts(spec, spec_len) },
        created_at,
    ) {
        Ok(token) => {
            *out_token = token;
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
/// Borrows the immutable user SID bytes from a live token object.
pub extern "C" fn kacs_rust_token_user_sid(
    token: *const c_void,
    out_sid_ptr: *mut *const u8,
    out_sid_len: *mut usize,
) -> i32 {
    let Some(out_sid_ptr) = (unsafe { out_sid_ptr.as_mut() }) else {
        return -EINVAL;
    };
    let Some(out_sid_len) = (unsafe { out_sid_len.as_mut() }) else {
        return -EINVAL;
    };

    *out_sid_ptr = null();
    *out_sid_len = 0;

    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let sid_bytes = token.user_sid.as_bytes();
    *out_sid_ptr = sid_bytes.as_ptr();
    *out_sid_len = sid_bytes.len();
    0
}

#[no_mangle]
/// Copies the immutable token GUID from a live token object.
pub extern "C" fn kacs_rust_token_guid(token: *const c_void, out: *mut u8) -> i32 {
    if out.is_null() {
        return -EINVAL;
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };

    unsafe { core::ptr::copy_nonoverlapping(token.token_guid.as_ptr(), out, KACS_UUID_BYTES) };
    0
}

#[no_mangle]
/// Returns the number of LCS private hive scope GUIDs carried by a live token.
pub extern "C" fn kacs_rust_token_lcs_scope_guid_count(token: *const c_void) -> u32 {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .and_then(|token| u32::try_from(token.lcs_scope_guids.len()).ok())
        .unwrap_or(0)
}

#[no_mangle]
/// Copies one LCS private hive scope GUID from a live token.
pub extern "C" fn kacs_rust_token_lcs_scope_guid(
    token: *const c_void,
    index: u32,
    out: *mut u8,
) -> i32 {
    if out.is_null() {
        return -EINVAL;
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Ok(index) = usize::try_from(index) else {
        return -EINVAL;
    };
    let Some(guid) = token.lcs_scope_guids.as_slice().get(index) else {
        return -EINVAL;
    };

    unsafe {
        core::ptr::copy_nonoverlapping(guid.as_ptr(), out, KACS_LCS_SCOPE_GUID_BYTES);
    }
    0
}

#[no_mangle]
/// Returns the number of LCS private layer names carried by a live token.
pub extern "C" fn kacs_rust_token_lcs_private_layer_count(token: *const c_void) -> u32 {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .and_then(|token| u32::try_from(token.lcs_private_layers.len()).ok())
        .unwrap_or(0)
}

#[no_mangle]
/// Borrows one LCS private layer name from a live token.
pub extern "C" fn kacs_rust_token_lcs_private_layer(
    token: *const c_void,
    index: u32,
    name_out: *mut *const c_char,
    len_out: *mut u32,
) -> i32 {
    let Some(name_out) = (unsafe { name_out.as_mut() }) else {
        return -EINVAL;
    };
    let Some(len_out) = (unsafe { len_out.as_mut() }) else {
        return -EINVAL;
    };

    *name_out = null();
    *len_out = 0;

    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let Ok(index) = usize::try_from(index) else {
        return -EINVAL;
    };
    let Some(name) = token.lcs_private_layers.as_slice().get(index) else {
        return -EINVAL;
    };
    let Ok(name_len) = u32::try_from(name.len()) else {
        return -ERANGE;
    };

    *name_out = name.as_bytes().as_ptr().cast::<c_char>();
    *len_out = name_len;
    0
}

#[no_mangle]
/// Borrows bounded token identity fields for production audit payloads.
pub extern "C" fn kacs_rust_token_audit_summary(
    token: *const c_void,
    out: *mut PkmKacsTokenAuditSummary,
) -> i32 {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -EINVAL;
    };
    *out = PkmKacsTokenAuditSummary {
        token_guid: [0; KACS_UUID_BYTES],
        user_sid_ptr: null(),
        user_sid_len: 0,
        auth_id: 0,
        token_id: 0,
        token_type: 0,
        impersonation_level: 0,
        integrity_level: 0,
    };

    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EACCES;
    };
    let _guard = token.lock_mutation();
    let Some(session) = token.session_ref() else {
        return -EACCES;
    };

    *out = PkmKacsTokenAuditSummary {
        token_guid: token.token_guid,
        user_sid_ptr: token.user_sid.as_bytes().as_ptr(),
        user_sid_len: token.user_sid.as_bytes().len(),
        auth_id: session.session_id,
        token_id: token.token_id,
        token_type: token_type_abi(token.token_type),
        impersonation_level: impersonation_level_abi(token.impersonation_level),
        integrity_level: token.integrity_level as u32,
    };
    0
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
/// Returns whether the token has enabled, non-deny-only BUILTIN\Administrators
/// membership.
pub extern "C" fn kacs_rust_token_has_enabled_administrators(token: *const c_void) -> bool {
    token_has_enabled_administrators(token)
}

#[no_mangle]
/// Returns 1 when the token's logon type requires remote-shutdown privilege,
/// 0 for local logon types, or a negative errno when the token/session is invalid.
pub extern "C" fn kacs_rust_token_is_remote_shutdown_origin(token: *const c_void) -> i32 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EINVAL;
    };
    let Some(session) = token.session_ref() else {
        return -EINVAL;
    };

    match session.logon_type {
        LOGON_TYPE_NETWORK | LOGON_TYPE_NETWORK_CLEARTEXT | LOGON_TYPE_NEW_CREDENTIALS => 1,
        LOGON_TYPE_INTERACTIVE | LOGON_TYPE_BATCH | LOGON_TYPE_SERVICE => 0,
        _ => -EINVAL,
    }
}

#[no_mangle]
/// Returns whether the live token carries the NEW_PROCESS_MIN mandatory
/// policy bit.
pub extern "C" fn kacs_rust_token_has_new_process_min(token: *const c_void) -> bool {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .map(|value| {
            (value.mandatory_policy & TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN) != 0
        })
        .unwrap_or(false)
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
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    let result = token_open_check_errno(
        subject_token,
        target_token,
        desired_access,
        pip_context_from_abi(pip_type, pip_trust),
    );
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
/// Applies the v0.20 NEW_PROCESS_MIN exec lowering rule to a primary token.
/// `out_token` is set to null when no replacement is required.
pub extern "C" fn kacs_rust_token_new_process_min_exec(
    source_token: *const c_void,
    file_integrity_level: u32,
    out_token: *mut *const c_void,
) -> i32 {
    let Some(source_token) = (unsafe { PkmKacsBootToken::from_ptr(source_token) }) else {
        return -EACCES;
    };
    let Some(out_token) = (unsafe { out_token.as_mut() }) else {
        return -EINVAL;
    };
    let file_integrity = match integrity_level_from_abi(file_integrity_level) {
        Ok(value) => value,
        Err(err) => return err,
    };

    *out_token = null();
    match source_token.new_process_min_exec_clone(file_integrity) {
        Ok(Some(token)) => {
            *out_token = token;
            0
        }
        Ok(None) => 0,
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

    *out_token = null();
    let canonical = unsafe { pkm_kacs_boot_anonymous_token_ptr() };
    if canonical.is_null() {
        return -EACCES;
    }

    let token = PkmKacsBootToken::clone_ref(canonical);
    if token.is_null() {
        -EACCES
    } else {
        *out_token = token;
        0
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
/// Builds a restrictive KUnit-only process SD with only Everyone
/// `everyone_mask`.
pub extern "C" fn kacs_rust_kunit_create_process_sd_with_everyone_mask(
    token_ptr: *const c_void,
    everyone_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) =
        build_everyone_mask_only_process_sd_bytes(token, everyone_mask)
    else {
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
/// Builds the PSD-005 first-boot base-layer metadata SD.
pub extern "C" fn kacs_rust_create_lcs_base_layer_default_sd(
    len_out: *mut usize,
) -> *const u8 {
    let Ok((ptr, len)) = build_lcs_base_layer_default_sd_bytes() else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD with caller-selected allow masks for self,
/// Administrators, SYSTEM, and Everyone.
pub extern "C" fn kacs_rust_kunit_create_file_sd(
    token_ptr: *const c_void,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) =
        build_file_sd_bytes_from_masks(token, self_mask, admin_mask, system_mask, everyone_mask)
    else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying one mandatory resource-attribute ACE
/// in the SACL.
pub extern "C" fn kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr(
    token_ptr: *const c_void,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Ok((ptr, len)) = build_file_sd_with_mandatory_resource_attribute_bytes(
        token,
        self_mask,
        admin_mask,
        system_mask,
        everyone_mask,
        1,
    ) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying one mandatory resource-attribute ACE
/// with a caller-selected INT64 value in the SACL.
pub extern "C" fn kacs_rust_kunit_create_file_sd_with_mandatory_resource_attr_value(
    token_ptr: *const c_void,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    mandatory_value: u64,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    if mandatory_value > i64::MAX as u64 {
        return null();
    }
    let mandatory_value = mandatory_value as i64;
    let Ok((ptr, len)) = build_file_sd_with_mandatory_resource_attribute_bytes(
        token,
        self_mask,
        admin_mask,
        system_mask,
        everyone_mask,
        mandatory_value,
    ) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying one mandatory-label ACE in the SACL.
pub extern "C" fn kacs_rust_kunit_create_labeled_file_sd(
    token_ptr: *const c_void,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    integrity_level: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Some(integrity_level) = integrity_level_from_abi(integrity_level).ok() else {
        return null();
    };
    let Ok((ptr, len)) = build_labeled_file_sd_bytes(
        token,
        self_mask,
        admin_mask,
        system_mask,
        everyone_mask,
        integrity_level,
        false,
    ) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying a mandatory-label ACE and a
/// non-label success-audit ACE in the SACL.
pub extern "C" fn kacs_rust_kunit_create_labeled_audit_file_sd(
    token_ptr: *const c_void,
    self_mask: u32,
    admin_mask: u32,
    system_mask: u32,
    everyone_mask: u32,
    integrity_level: u32,
    len_out: *mut usize,
) -> *const u8 {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let Some(integrity_level) = integrity_level_from_abi(integrity_level).ok() else {
        return null();
    };
    let Ok((ptr, len)) = build_labeled_file_sd_bytes(
        token,
        self_mask,
        admin_mask,
        system_mask,
        everyone_mask,
        integrity_level,
        true,
    ) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying an Everyone callback allow ACE guarded
/// by a `Device_Member_of` condition.
pub extern "C" fn kacs_rust_kunit_create_device_member_file_sd(
    token_ptr: *const c_void,
    device_sid_ptr: *const u8,
    device_sid_len: usize,
    allow_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    if device_sid_ptr.is_null() || device_sid_len == 0 || allow_mask == 0 {
        return null();
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let device_sid_bytes = unsafe { core::slice::from_raw_parts(device_sid_ptr, device_sid_len) };
    let Ok(device_sid) = Sid::parse(device_sid_bytes) else {
        return null();
    };
    let Ok((ptr, len)) = build_device_member_file_sd_bytes(token, device_sid, allow_mask) else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying an Everyone callback allow ACE guarded
/// by an `Exists` condition over a user, resource, or device claim namespace.
pub extern "C" fn kacs_rust_kunit_create_claim_exists_file_sd(
    token_ptr: *const c_void,
    namespace_opcode: u8,
    claim_name_ptr: *const u8,
    claim_name_len: usize,
    allow_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    if claim_name_ptr.is_null() || claim_name_len == 0 || allow_mask == 0 {
        return null();
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let claim_name_bytes = unsafe { core::slice::from_raw_parts(claim_name_ptr, claim_name_len) };
    let Ok(claim_name) = core::str::from_utf8(claim_name_bytes) else {
        return null();
    };
    let Ok((ptr, len)) =
        build_claim_exists_file_sd_bytes(token, namespace_opcode, claim_name, allow_mask)
    else {
        return null();
    };

    if let Some(len_out) = unsafe { len_out.as_mut() } {
        *len_out = len;
    }
    ptr.cast_const()
}

#[no_mangle]
/// Builds a KUnit-only file SD carrying an Everyone callback allow ACE guarded
/// by an `Exists` condition over a SACL resource attribute.
pub extern "C" fn kacs_rust_kunit_create_resource_claim_exists_file_sd(
    token_ptr: *const c_void,
    claim_name_ptr: *const u8,
    claim_name_len: usize,
    allow_mask: u32,
    len_out: *mut usize,
) -> *const u8 {
    if claim_name_ptr.is_null() || claim_name_len == 0 || allow_mask == 0 {
        return null();
    }
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return null();
    };
    let claim_name_bytes = unsafe { core::slice::from_raw_parts(claim_name_ptr, claim_name_len) };
    let Ok(claim_name) = core::str::from_utf8(claim_name_bytes) else {
        return null();
    };
    let Ok((ptr, len)) =
        build_resource_claim_exists_file_sd_bytes(token, claim_name, allow_mask)
    else {
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
        build_sd_bytes_from_components(SE_SELF_RELATIVE, 0, None, None, sacl.as_deref(), None)
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
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match process_sd_access_check_errno(
        subject_token_ptr,
        sd_bytes,
        desired,
        pip_context_from_abi(pip_type, pip_trust),
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
/// Runs AccessCheck against one process SD using the supplied caller token and
/// privilege-intent flags.
pub extern "C" fn kacs_rust_check_process_sd_with_intent(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
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
        pip_context_from_abi(pip_type, pip_trust),
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
/// Runs process-SD AccessCheck and reports whether PIP denied requested bits.
pub extern "C" fn kacs_rust_check_process_sd_with_intent_status(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
    pip_denied_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match process_sd_access_outcome_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(outcome) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            if let Some(pip_denied_out) = unsafe { pip_denied_out.as_mut() } {
                *pip_denied_out = outcome.pip_denied_requested;
            }
            if outcome.allowed {
                0
            } else {
                -EACCES
            }
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one file SD using the supplied caller token and
/// privilege-intent flags.
pub extern "C" fn kacs_rust_check_file_sd_with_intent(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match file_sd_access_check_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(outcome) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one cached file SD using its prevalidated component
/// layout.
pub extern "C" fn kacs_rust_check_cached_file_sd_with_intent(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let target_sd = match cached_file_sd_descriptor(sd_bytes, layout) {
        Ok(target_sd) => target_sd,
        Err(err) => return err,
    };
    match file_sd_access_outcome_for_descriptor(
        subject_token_ptr,
        &target_sd,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
        EMPTY_POLICIES,
    ) {
        Ok(outcome) => {
            if !outcome.allowed {
                return -EACCES;
            }
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one file SD and also returns the continuous-audit
/// mask accumulated from matched alarm ACEs.
pub extern "C" fn kacs_rust_check_file_sd_with_intent_audit(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match file_sd_access_check_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(outcome) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            if let Some(continuous_audit_out) =
                unsafe { continuous_audit_out.as_mut() }
            {
                *continuous_audit_out = outcome.continuous_audit_mask;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one file SD using the supplied CAAP policy cache
/// and also returns the continuous-audit mask accumulated from matched alarm
/// ACEs.
pub extern "C" fn kacs_rust_check_file_sd_with_intent_audit_caap(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        match file_sd_access_check_errno_with_intent_and_policies(
            subject_token_ptr,
            sd_bytes,
            desired,
            privilege_intent,
            pip_context_from_abi(pip_type, pip_trust),
            policies,
        ) {
            Ok(outcome) => {
                if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                    *granted_out = outcome.granted;
                }
                if let Some(continuous_audit_out) = unsafe { continuous_audit_out.as_mut() } {
                    *continuous_audit_out = outcome.continuous_audit_mask;
                }
                Ok(0)
            }
            Err(err) => Ok(err as c_long),
        }
    }) {
        Ok(ret) => ret as i32,
        Err(err) => err as i32,
    }
}

#[no_mangle]
/// Runs AccessCheck against one cached file SD using the supplied CAAP policy
/// cache and cached SD component layout.
pub extern "C" fn kacs_rust_check_cached_file_sd_with_intent_audit_caap(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let target_sd = match cached_file_sd_descriptor(sd_bytes, layout) {
        Ok(target_sd) => target_sd,
        Err(err) => return err,
    };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        match file_sd_access_outcome_for_descriptor(
            subject_token_ptr,
            &target_sd,
            desired,
            privilege_intent,
            pip_context_from_abi(pip_type, pip_trust),
            policies,
        ) {
            Ok(outcome) => {
                if !outcome.allowed {
                    return Ok(-EACCES as c_long);
                }
                if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                    *granted_out = outcome.granted;
                }
                if let Some(continuous_audit_out) = unsafe { continuous_audit_out.as_mut() } {
                    *continuous_audit_out = outcome.continuous_audit_mask;
                }
                Ok(0)
            }
            Err(err) => Ok(err as c_long),
        }
    }) {
        Ok(ret) => ret as i32,
        Err(err) => err as i32,
    }
}

#[no_mangle]
/// Extracts the v0.20 file-object integrity label, defaulting valid unlabeled
/// descriptors to Medium.
pub extern "C" fn kacs_rust_file_sd_integrity_label(
    sd_ptr: *const u8,
    sd_len: usize,
    integrity_level_out: *mut u32,
) -> i32 {
    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }
    let Some(integrity_level_out) = (unsafe { integrity_level_out.as_mut() }) else {
        return -EINVAL;
    };

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match file_sd_integrity_label(sd_bytes) {
        Ok(integrity_level) => {
            *integrity_level_out = integrity_level as u32;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Extracts the v0.20 file-object integrity label from a cached file SD.
pub extern "C" fn kacs_rust_cached_file_sd_integrity_label(
    sd_ptr: *const u8,
    sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
    integrity_level_out: *mut u32,
) -> i32 {
    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }
    let Some(integrity_level_out) = (unsafe { integrity_level_out.as_mut() }) else {
        return -EINVAL;
    };

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let sd = match cached_file_sd_descriptor(sd_bytes, layout) {
        Ok(sd) => sd,
        Err(err) => return err,
    };
    let integrity_level = match sd.sacl() {
        Some(sacl) => {
            let mut level = IntegrityLevel::Medium;
            for ace in sacl.entries() {
                let ace = match ace {
                    Ok(ace) => ace,
                    Err(_) => return -EINVAL,
                };
                if ace.ace_type() != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                    continue;
                }
                if (ace.ace_flags() & INHERIT_ONLY_ACE) != 0 {
                    continue;
                }
                level = match label_integrity_from_ace(ace.bytes()) {
                    Ok(level) => level,
                    Err(err) => return err,
                };
                break;
            }
            level
        }
        None => IntegrityLevel::Medium,
    };

    *integrity_level_out = integrity_level as u32;
    0
}

#[no_mangle]
/// Runs AccessCheck for the bounded `/sys/kernel/security/kacs/sessions`
/// listing SD.
pub extern "C" fn kacs_rust_check_securityfs_sessions_read(
    subject_token_ptr: *const c_void,
    pip_type: u32,
    pip_trust: u32,
) -> i32 {
    if subject_token_ptr.is_null() {
        return -EACCES;
    }

    let Ok((sd_ptr, sd_len)) = build_securityfs_sessions_sd_bytes() else {
        return -ENOMEM;
    };
    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let ret = match file_sd_access_check_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        FILE_READ_DATA,
        0,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(_) => 0,
        Err(err) => err,
    };

    free_allocated_bytes(sd_ptr);
    ret
}

#[no_mangle]
/// Serializes active published sessions for
/// `/sys/kernel/security/kacs/sessions`.
pub extern "C" fn kacs_rust_securityfs_sessions_listing(
    out: *mut u8,
    out_len: usize,
    required_out: *mut usize,
) -> i32 {
    let Some(required_out) = (unsafe { required_out.as_mut() }) else {
        return -EINVAL;
    };
    let _guard = lock_session_table();
    let required = match sessions_listing_len_locked() {
        Ok(required) => required,
        Err(err) => return err,
    };

    *required_out = required;
    if out_len == 0 {
        return 0;
    }
    if out.is_null() {
        return -EINVAL;
    }
    if out_len < required {
        return -ERANGE;
    }

    match write_sessions_listing_locked(out, out_len) {
        Ok(written) if written == required => 0,
        Ok(_) => -EINVAL,
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck against one file SD and returns the granted subset of the
/// requested mask without requiring the entire request to succeed.
pub extern "C" fn kacs_rust_granted_file_sd_with_intent(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match file_sd_granted_mask_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(outcome) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck for a file SD, returning the granted subset and the
/// continuous-audit mask without requiring the whole requested mask to pass.
pub extern "C" fn kacs_rust_granted_file_sd_with_intent_audit(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match file_sd_granted_mask_errno_with_intent(
        subject_token_ptr,
        sd_bytes,
        desired,
        privilege_intent,
        pip_context_from_abi(pip_type, pip_trust),
    ) {
        Ok(outcome) => {
            if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                *granted_out = outcome.granted;
            }
            if let Some(continuous_audit_out) =
                unsafe { continuous_audit_out.as_mut() }
            {
                *continuous_audit_out = outcome.continuous_audit_mask;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Runs AccessCheck for a file SD against the supplied CAAP policy cache,
/// returning the granted subset and continuous-audit mask without requiring
/// the whole requested mask to pass.
pub extern "C" fn kacs_rust_granted_file_sd_with_intent_audit_caap(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        match file_sd_granted_mask_errno_with_intent_and_policies(
            subject_token_ptr,
            sd_bytes,
            desired,
            privilege_intent,
            pip_context_from_abi(pip_type, pip_trust),
            policies,
        ) {
            Ok(outcome) => {
                if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                    *granted_out = outcome.granted;
                }
                if let Some(continuous_audit_out) = unsafe { continuous_audit_out.as_mut() } {
                    *continuous_audit_out = outcome.continuous_audit_mask;
                }
                Ok(0)
            }
            Err(err) => Ok(err as c_long),
        }
    }) {
        Ok(ret) => ret as i32,
        Err(err) => err as i32,
    }
}

#[no_mangle]
/// Runs AccessCheck for a cached file SD against the supplied CAAP policy
/// cache, returning the granted subset and continuous-audit mask without
/// requiring the whole requested mask to pass.
pub extern "C" fn kacs_rust_granted_cached_file_sd_with_intent_audit_caap(
    subject_token_ptr: *const c_void,
    sd_ptr: *const u8,
    sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
    caap_cache: *const c_void,
    granted_out: *mut u32,
    continuous_audit_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let target_sd = match cached_file_sd_descriptor(sd_bytes, layout) {
        Ok(target_sd) => target_sd,
        Err(err) => return err,
    };
    match crate::caap_cache::with_caap_policies(caap_cache, |policies| {
        match file_sd_access_outcome_for_descriptor(
            subject_token_ptr,
            &target_sd,
            desired,
            privilege_intent,
            pip_context_from_abi(pip_type, pip_trust),
            policies,
        ) {
            Ok(outcome) => {
                if let Some(granted_out) = unsafe { granted_out.as_mut() } {
                    *granted_out = outcome.granted;
                }
                if let Some(continuous_audit_out) = unsafe { continuous_audit_out.as_mut() } {
                    *continuous_audit_out = outcome.continuous_audit_mask;
                }
                Ok(0)
            }
            Err(err) => Ok(err as c_long),
        }
    }) {
        Ok(ret) => ret as i32,
        Err(err) => err as i32,
    }
}

#[no_mangle]
/// Emits one file-handle continuous-audit event for an already classified
/// operation-time enforcement decision.
pub extern "C" fn kacs_rust_emit_file_continuous_audit(
    subject_token_ptr: *const c_void,
    pip_type: u32,
    pip_trust: u32,
    operation_ptr: *const u8,
    operation_len: usize,
    requested_access: u32,
    matched_access: u32,
    granted_access: u32,
    success: u8,
) -> i32 {
    if subject_token_ptr.is_null()
        || operation_ptr.is_null()
        || operation_len == 0
        || requested_access == 0
        || matched_access == 0
        || (matched_access & requested_access) != matched_access
    {
        return -EINVAL;
    }

    let Some(subject) = (unsafe { PkmKacsBootToken::from_ptr(subject_token_ptr) }) else {
        return -EACCES;
    };
    let operation = unsafe { core::slice::from_raw_parts(operation_ptr, operation_len) };
    let pip = pip_context_from_abi(pip_type, pip_trust);

    subject.with_access_token(|access_token| {
        match emit_continuous_audit_to_kmes(
            &access_token,
            pip,
            operation,
            requested_access,
            matched_access,
            granted_access,
            success != 0,
        ) {
            Ok(()) => 0,
            Err(err) => i32::try_from(err).unwrap_or(-EIO),
        }
    })
}

#[no_mangle]
/// Runs live AccessCheck against one token's own SD using the supplied caller
/// token and privilege-intent flags.
pub extern "C" fn kacs_rust_check_token_sd_with_intent(
    subject_token_ptr: *const c_void,
    target_token_ptr: *const c_void,
    desired: u32,
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
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
        pip_context_from_abi(pip_type, pip_trust),
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
/// Validates one self-relative SD blob structurally without running
/// AccessCheck.
pub extern "C" fn kacs_rust_validate_sd_bytes(sd_ptr: *const u8, sd_len: usize) -> i32 {
    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    match validate_sd_bytes(unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) }) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[no_mangle]
/// Validates one complete stored/effective self-relative SD blob.
pub extern "C" fn kacs_rust_validate_stored_sd_bytes(
    sd_ptr: *const u8,
    sd_len: usize,
) -> i32 {
    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    match validate_stored_sd_bytes(unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) }) {
        Ok(()) => 0,
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn kacs_rust_kunit_build_single_opaque_acl_len(
    ace_len: usize,
    out_len: *mut usize,
) -> i32 {
    let Some(out_len) = (unsafe { out_len.as_mut() }) else {
        return -EINVAL;
    };

    *out_len = 0;
    match build_kunit_single_opaque_acl_len(ace_len) {
        Ok(len) => {
            *out_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Parses one structurally valid file SD and returns a reusable cached
/// component layout for inode-cache readers.
pub extern "C" fn kacs_rust_parse_file_sd_layout(
    sd_ptr: *const u8,
    sd_len: usize,
    layout_out: *mut KacsRustCachedSdLayout,
) -> i32 {
    let Some(layout_out) = (unsafe { layout_out.as_mut() }) else {
        return -EINVAL;
    };
    if sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    let layout = match SecurityDescriptor::parse_layout(sd_bytes).map_err(sd_parse_errno) {
        Ok(layout) => layout,
        Err(err) => return err,
    };

    *layout_out = cached_layout_from_core(&layout);
    0
}

#[no_mangle]
/// Parses one complete stored/effective file SD and returns a reusable cached
/// component layout for inode-cache readers.
pub extern "C" fn kacs_rust_parse_stored_file_sd_layout(
    sd_ptr: *const u8,
    sd_len: usize,
    layout_out: *mut KacsRustCachedSdLayout,
) -> i32 {
    if layout_out.is_null() {
        return -EINVAL;
    }
    let ret = kacs_rust_parse_file_sd_layout(sd_ptr, sd_len, layout_out);
    if ret != 0 {
        return ret;
    }

    // Read back through the raw pointer instead of holding a `&mut` across the
    // call above — that call re-borrows and writes the same memory, which would
    // invalidate the outer `&mut` under Stacked/Tree Borrows. A zero return
    // guarantees layout_out was non-null and fully written.
    if unsafe { (*layout_out).owner_present } == 0 {
        return -EINVAL;
    }
    0
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
/// Serializes a requested subset of one file SD into one self-relative
/// descriptor buffer.
pub extern "C" fn kacs_rust_query_file_sd_subset(
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
/// Serializes a requested subset of one cached file SD into one self-relative
/// descriptor buffer.
pub extern "C" fn kacs_rust_query_cached_file_sd_subset(
    sd_ptr: *const u8,
    sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
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
    let sd = match cached_file_sd_descriptor(sd_bytes, layout) {
        Ok(sd) => sd,
        Err(err) => return err,
    };
    match build_sd_subset_from_descriptor(&sd, security_info) {
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

    // KC-15: snapshot the own SD into an owned, RCU-safe copy; own_sd_bytes()
    // borrows the live buffer that replace_own_sd may swap/free concurrently,
    // which can tear the (ptr, len) pair into an out-of-bounds slice.
    let own_sd_copy = match token.own_sd_rcu_copy() {
        Ok(copy) => copy,
        Err(err) => return err,
    };
    match build_sd_subset_bytes(own_sd_copy.as_slice(), security_info) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Merges one caller-supplied subset descriptor into the current live file SD
/// using the generic set-security rules.
pub extern "C" fn kacs_rust_merge_file_sd(
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
    match merge_process_sd_bytes(subject, current_sd_bytes, security_info, input_sd_bytes, true) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Merges one caller-supplied subset descriptor into the current cached live
/// file SD using the generic set-security rules.
pub extern "C" fn kacs_rust_merge_cached_file_sd(
    subject_token_ptr: *const c_void,
    current_sd_ptr: *const u8,
    current_sd_len: usize,
    layout: *const KacsRustCachedSdLayout,
    security_info: u32,
    input_sd_ptr: *const u8,
    input_sd_len: usize,
    allow_restore_owner_assignment: u32,
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

    let current_sd_bytes =
        unsafe { core::slice::from_raw_parts(current_sd_ptr, current_sd_len) };
    let current_sd = match cached_file_sd_descriptor(current_sd_bytes, layout) {
        Ok(sd) => sd,
        Err(err) => return err,
    };
    let input_sd_bytes = unsafe { core::slice::from_raw_parts(input_sd_ptr, input_sd_len) };
    match merge_sd_with_current_descriptor(
        subject,
        &current_sd,
        security_info,
        input_sd_bytes,
        allow_restore_owner_assignment != 0,
    ) {
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
    match merge_process_sd_bytes(subject, current_sd_bytes, security_info, input_sd_bytes, true) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Builds one complete replacement file SD from an input subset for the
/// missing/corrupt repair path.
pub extern "C" fn kacs_rust_build_replacement_file_sd(
    subject_token_ptr: *const c_void,
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

    if input_sd_ptr.is_null() || input_sd_len == 0 {
        return -EINVAL;
    }

    let input_sd_bytes = unsafe { core::slice::from_raw_parts(input_sd_ptr, input_sd_len) };
    match build_replacement_file_sd_bytes(subject, security_info, input_sd_bytes) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Builds one complete file SD for `kacs_open` creation from the parent SD,
/// optional creator SD, and the caller token's default owner/group/DACL.
pub extern "C" fn kacs_rust_build_created_file_sd(
    subject_token_ptr: *const c_void,
    parent_sd_ptr: *const u8,
    parent_sd_len: usize,
    creator_sd_ptr: *const u8,
    creator_sd_len: usize,
    child_is_directory: u32,
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

    if parent_sd_ptr.is_null() || parent_sd_len == 0 {
        return -EINVAL;
    }

    let parent_sd_bytes = unsafe { core::slice::from_raw_parts(parent_sd_ptr, parent_sd_len) };
    let creator_sd_bytes = if creator_sd_ptr.is_null() || creator_sd_len == 0 {
        None
    } else {
        Some(unsafe { core::slice::from_raw_parts(creator_sd_ptr, creator_sd_len) })
    };

    match build_created_file_sd_bytes(
        subject,
        parent_sd_bytes,
        creator_sd_bytes,
        child_is_directory != 0,
    ) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Builds one complete container-child SD from a parent SD, the caller token's
/// default owner/group/DACL, and caller-supplied object generic mapping.
pub extern "C" fn kacs_rust_build_created_container_sd(
    subject_token_ptr: *const c_void,
    parent_sd_ptr: *const u8,
    parent_sd_len: usize,
    generic_read: u32,
    generic_write: u32,
    generic_execute: u32,
    generic_all: u32,
    valid_mapped_access_mask: u32,
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
    let generic_mapping = GenericMapping {
        read: generic_read,
        write: generic_write,
        execute: generic_execute,
        all: generic_all,
    };

    *out_sd_ptr = null();
    *out_sd_len = 0;

    if parent_sd_ptr.is_null() || parent_sd_len == 0 || valid_mapped_access_mask == 0 {
        return -EINVAL;
    }
    if ((generic_read | generic_write | generic_execute | generic_all) & !valid_mapped_access_mask)
        != 0
    {
        return -EINVAL;
    }

    let parent_sd_bytes = unsafe { core::slice::from_raw_parts(parent_sd_ptr, parent_sd_len) };
    match build_created_container_sd_bytes(
        subject,
        parent_sd_bytes,
        generic_mapping,
        valid_mapped_access_mask,
    ) {
        Ok((ptr, len)) => {
            *out_sd_ptr = ptr.cast_const();
            *out_sd_len = len;
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
/// Synthesizes one complete file SD for a missing-SD foreign object from the
/// parent SD (if any) plus the mount template or fallback system policy.
pub extern "C" fn kacs_rust_synthesize_file_sd(
    parent_sd_ptr: *const u8,
    parent_sd_len: usize,
    template_sd_ptr: *const u8,
    template_sd_len: usize,
    child_is_directory: u32,
    out_sd_ptr: *mut *const u8,
    out_sd_len: *mut usize,
) -> i32 {
    let Some(out_sd_ptr) = (unsafe { out_sd_ptr.as_mut() }) else {
        return -EINVAL;
    };
    let Some(out_sd_len) = (unsafe { out_sd_len.as_mut() }) else {
        return -EINVAL;
    };
    let parent_sd_bytes = if parent_sd_ptr.is_null() || parent_sd_len == 0 {
        None
    } else {
        Some(unsafe { core::slice::from_raw_parts(parent_sd_ptr, parent_sd_len) })
    };
    let template_sd_bytes = if template_sd_ptr.is_null() || template_sd_len == 0 {
        None
    } else {
        Some(unsafe { core::slice::from_raw_parts(template_sd_ptr, template_sd_len) })
    };

    *out_sd_ptr = null();
    *out_sd_len = 0;

    match build_synthesized_file_sd_bytes(
        parent_sd_bytes,
        template_sd_bytes,
        child_is_directory != 0,
    ) {
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
    pip_type: u32,
    pip_trust: u32,
    granted_out: *mut u32,
) -> i32 {
    if desired == 0 || sd_ptr.is_null() || sd_len == 0 {
        return -EINVAL;
    }

    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_ptr, sd_len) };
    match socket_sd_access_check_errno(
        subject_token_ptr,
        sd_bytes,
        desired,
        pip_context_from_abi(pip_type, pip_trust),
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
    if previous_state_out.is_null() {
        return -EINVAL;
    }
    if count as usize > MAX_TOKEN_GROUPS {
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
            unsafe {
                core::ptr::copy_nonoverlapping(
                    previous_state.as_ptr(),
                    previous_state_out,
                    GROUP_MASK_WORDS,
                );
            }
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
/// Returns whether the token's projected UID satisfies the UID0/SYSTEM invariant.
pub extern "C" fn kacs_rust_token_allows_uid0_projection(token: *const c_void) -> bool {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return false;
    };

    token.projected_uid != 0 || token.user_sid.sid.as_bytes() == SYSTEM_SID_BYTES
}

#[no_mangle]
/// Returns the number of precomputed supplementary GIDs stored on the token.
pub extern "C" fn kacs_rust_token_projected_supplementary_gid_count(
    token: *const c_void,
) -> usize {
    unsafe { PkmKacsBootToken::from_ptr(token) }
        .map(|value| value.projected_supplementary_gids.len())
        .unwrap_or(0)
}

#[no_mangle]
/// Copies one precomputed supplementary GID by index.
pub extern "C" fn kacs_rust_token_projected_supplementary_gid(
    token: *const c_void,
    index: usize,
    out: *mut u32,
) -> i32 {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -EINVAL;
    };
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token) }) else {
        return -EINVAL;
    };
    let Some(value) = token.projected_supplementary_gids.as_slice().get(index) else {
        return -EINVAL;
    };

    *out = *value;
    0
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
/// Builds the derived logon SID for an arbitrary session ID for KUnit vectors.
pub extern "C" fn kacs_rust_kunit_build_logon_sid(session_id: u64, out: *mut u8) -> i32 {
    let Some(out) = (unsafe { out.as_mut() }) else {
        return -EINVAL;
    };
    let sid = build_logon_sid_bytes(session_id);

    unsafe { copy_nonoverlapping(sid.as_ptr(), out, sid.len()) };
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
/// Creates a KUnit-only LocalService token with enabled Administrators
/// membership and no standalone privileges.
pub extern "C" fn kacs_rust_kunit_create_local_administrator_token() -> *const c_void {
    PkmKacsBootToken::create_local_administrator().unwrap_or(null())
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
/// Creates a KUnit-only primary token for exercising logon-type sensitive
/// standalone privilege gates.
pub extern "C" fn kacs_rust_kunit_create_logon_type_token(
    logon_type: u32,
    enabled_privileges: u64,
) -> *const c_void {
    PkmKacsBootToken::create_kunit_logon_type_token(logon_type, enabled_privileges)
        .unwrap_or(null())
}

#[no_mangle]
/// Creates a KUnit-only token carrying one bounded LCS private credential set.
pub extern "C" fn kacs_rust_kunit_create_lcs_private_credential_token(
    scope_guids: *const [u8; KACS_LCS_SCOPE_GUID_BYTES],
    scope_count: usize,
    private_layer_name: *const c_char,
    private_layer_name_len: usize,
) -> *const c_void {
    PkmKacsBootToken::create_kunit_lcs_private_credential_token(
        scope_guids,
        scope_count,
        private_layer_name,
        private_layer_name_len,
    )
    .unwrap_or(null())
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

#[no_mangle]
/// Creates a bounded KUnit-only token variant with independent privilege masks.
pub extern "C" fn kacs_rust_kunit_create_impersonation_variant_token_with_privileges(
    user_kind: u32,
    token_type: u32,
    impersonation_level: u32,
    integrity_level: u32,
    restricted: u32,
    privileges_present: u64,
    privileges_enabled: u64,
    privileges_enabled_by_default: u64,
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

    PkmKacsBootToken::create_kunit_variant_with_privileges(
        user_sid,
        integrity_level,
        token_type,
        impersonation_level,
        restricted != 0,
        privileges_present,
        privileges_enabled,
        privileges_enabled_by_default,
    )
    .unwrap_or(null())
}
