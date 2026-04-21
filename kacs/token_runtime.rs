// SPDX-License-Identifier: GPL-2.0-only

//! Boot-time PKM token/session runtime substrate.
//!
//! Slice 22 still keeps this module narrower than a full token-handle
//! implementation. It provides:
//! - the boot Session 0 / SYSTEM token object
//! - reference management for that live token pointer
//! - current-token conversion into the closed Slice 20 AccessCheck context
//! - bounded token-own-SD material for the first self-open token-fd slice
//! - a small KUnit snapshot seam for bootstrap verification
//!
//! Token-own security descriptors and broader mutable token state remain
//! deferred to later token-handle slices.

#![allow(unreachable_pub)]

use crate::access_check::access_check;
use crate::access_check_abi::AccessCheckAbiResolved;
use crate::access_mask::{GenericMapping, READ_CONTROL, WRITE_DAC};
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
    SidAndAttributes, TokenType, TokenView,
};
use core::ffi::c_void;
use core::ptr::null;
use core::sync::atomic::{fence, AtomicU64, AtomicUsize, Ordering};

const SYSTEM_PRIVILEGES_ALL: u64 = 0xC000_000F_FFFF_FFFC;
const LOGON_TYPE_SERVICE: u32 = 5;
const TOKEN_TYPE_PRIMARY_ABI: u32 = 1;
const IMPERSONATION_LEVEL_ANONYMOUS_ABI: u32 = 0;
const MAX_TOKEN_SD_BYTES: usize = 104;

const EACCES: i32 = 13;
const ENOMEM: i32 = 12;

const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_OWNER: u32 = 0x0000_0008;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

const KACS_TOKEN_IMPERSONATE: u32 = 0x0004;
const KACS_TOKEN_QUERY: u32 = 0x0008;
const KACS_TOKEN_QUERY_SOURCE: u32 = 0x0010;
const KACS_TOKEN_ADJUST_PRIVS: u32 = 0x0020;
const KACS_TOKEN_ADJUST_GROUPS: u32 = 0x0040;
const KACS_TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
const KACS_TOKEN_ALL_ACCESS: u32 = 0x000F_01FF;
const TOKEN_SELF_QUERY_ADJUST_MASK: u32 = KACS_TOKEN_QUERY
    | KACS_TOKEN_QUERY_SOURCE
    | KACS_TOKEN_ADJUST_PRIVS
    | KACS_TOKEN_ADJUST_GROUPS
    | KACS_TOKEN_ADJUST_DEFAULT;

const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const EVERYONE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const AUTHENTICATED_USERS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const LOCAL_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
const LOGON_SID_BYTES: &[u8] = &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const AUTH_PACKAGE_NEGOTIATE: &[u8] = b"Negotiate";
const SYSTEM_TOKEN_OWN_SD_BYTES: &[u8] = &[
    1, 0, 4, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0,
    0, 0, 2, 0, 72, 0, 3, 0, 0, 0, 0, 0, 20, 0, 248, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    0, 0, 20, 0, 255, 1, 15, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 24, 0, 255, 1, 15, 0, 1,
    2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
];
const QUERY_ONLY_TOKEN_OWN_SD_BYTES: &[u8] = &[
    1, 0, 4, 128, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0,
    0, 0, 2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, 248, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
];
const EMPTY_DEVICE_GROUPS: &[SidAndAttributes<'static>] = &[];
const EMPTY_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const EMPTY_POLICIES: &[crate::caap::CaapPolicyEntry<'static>] = &[];
const TOKEN_GENERIC_MAPPING: GenericMapping = GenericMapping {
    read: KACS_TOKEN_QUERY | READ_CONTROL,
    write: KACS_TOKEN_ADJUST_PRIVS
        | KACS_TOKEN_ADJUST_GROUPS
        | KACS_TOKEN_ADJUST_DEFAULT
        | WRITE_DAC,
    execute: KACS_TOKEN_IMPERSONATE,
    all: KACS_TOKEN_ALL_ACCESS,
};

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
/// C-visible snapshot of the boot Session 0 / SYSTEM token state exercised by
/// Slice 21.
pub struct PkmKacsBootSnapshot {
    /// Opaque live token pointer.
    pub token_ptr: *const c_void,
    /// Boot session identifier.
    pub session_id: u64,
    /// Token auth_id / logon session LUID.
    pub auth_id: u64,
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
    session: PkmKacsBootSession,
    user_sid: Sid<'static>,
    logon_sid: Sid<'static>,
    groups: [SidAndAttributes<'static>; 5],
    group_views: [PkmKacsBootGroupView; 5],
    privileges_present: u64,
    privileges_enabled: u64,
    privileges_enabled_by_default: u64,
    privileges_used: AtomicU64,
    integrity_level: IntegrityLevel,
    mandatory_policy: u32,
    token_type: TokenType,
    impersonation_level: ImpersonationLevel,
    audit_policy: u32,
    interactive_session_id: u32,
    projected_uid: u32,
    projected_gid: u32,
    own_sd_len: usize,
    own_sd: [u8; MAX_TOKEN_SD_BYTES],
}

impl PkmKacsBootToken {
    fn create_system_like(own_sd_bytes: &[u8]) -> Option<*const c_void> {
        let user_sid = Sid::parse(SYSTEM_SID_BYTES).ok()?;
        let logon_sid = Sid::parse(LOGON_SID_BYTES).ok()?;
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;
        let mut own_sd = [0u8; MAX_TOKEN_SD_BYTES];

        if own_sd_bytes.len() > own_sd.len() {
            return None;
        }
        own_sd[..own_sd_bytes.len()].copy_from_slice(own_sd_bytes);
        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            return None;
        }

        let groups = [
            SidAndAttributes {
                sid: administrators,
                attributes: SE_GROUP_MANDATORY
                    | SE_GROUP_ENABLED_BY_DEFAULT
                    | SE_GROUP_ENABLED
                    | SE_GROUP_OWNER,
            },
            SidAndAttributes {
                sid: everyone,
                attributes: SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
            },
            SidAndAttributes {
                sid: authenticated_users,
                attributes: SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
            },
            SidAndAttributes {
                sid: local,
                attributes: SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
            },
            SidAndAttributes {
                sid: logon_sid,
                attributes: SE_GROUP_MANDATORY
                    | SE_GROUP_ENABLED_BY_DEFAULT
                    | SE_GROUP_ENABLED
                    | SE_GROUP_LOGON_ID,
            },
        ];
        let group_views = groups.map(|group| PkmKacsBootGroupView {
            sid_ptr: group.sid.as_bytes().as_ptr(),
            sid_len: group.sid.as_bytes().len(),
            attributes: group.attributes,
        });

        let token = Self {
            refcount: AtomicUsize::new(1),
            session: PkmKacsBootSession {
                session_id: 0,
                logon_type: LOGON_TYPE_SERVICE,
                user_sid,
                auth_package: AUTH_PACKAGE_NEGOTIATE,
                logon_sid,
            },
            user_sid,
            logon_sid,
            groups,
            group_views,
            privileges_present: SYSTEM_PRIVILEGES_ALL,
            privileges_enabled: SYSTEM_PRIVILEGES_ALL,
            privileges_enabled_by_default: SYSTEM_PRIVILEGES_ALL,
            privileges_used: AtomicU64::new(0),
            integrity_level: IntegrityLevel::System,
            mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            token_type: TokenType::Primary,
            impersonation_level: ImpersonationLevel::Anonymous,
            audit_policy: 0,
            interactive_session_id: 0,
            projected_uid: 0,
            projected_gid: 0,
            own_sd_len: own_sd_bytes.len(),
            own_sd,
        };

        unsafe { core::ptr::write(token_ptr, token) };
        Some(token_ptr.cast())
    }

    fn create_system() -> Option<*const c_void> {
        Self::create_system_like(SYSTEM_TOKEN_OWN_SD_BYTES)
    }

    fn create_query_only_system() -> Option<*const c_void> {
        Self::create_system_like(QUERY_ONLY_TOKEN_OWN_SD_BYTES)
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

        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            return null();
        }

        let privileges = token.privileges_snapshot();
        let copy = Self {
            refcount: AtomicUsize::new(1),
            session: token.session,
            user_sid: token.user_sid,
            logon_sid: token.logon_sid,
            groups: token.groups,
            group_views: token.group_views,
            privileges_present: privileges.present,
            privileges_enabled: privileges.enabled,
            privileges_enabled_by_default: privileges.enabled_by_default,
            privileges_used: AtomicU64::new(privileges.used),
            integrity_level: token.integrity_level,
            mandatory_policy: token.mandatory_policy,
            token_type: token.token_type,
            impersonation_level: token.impersonation_level,
            audit_policy: token.audit_policy,
            interactive_session_id: token.interactive_session_id,
            projected_uid: token.projected_uid,
            projected_gid: token.projected_gid,
            own_sd_len: token.own_sd_len,
            own_sd: token.own_sd,
        };

        unsafe { core::ptr::write(token_ptr, copy) };
        token_ptr.cast()
    }

    unsafe fn drop_ref(ptr: *const c_void) {
        let Some(token) = (unsafe { Self::from_ptr(ptr) }) else {
            return;
        };
        if token.refcount.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            let token_ptr = ptr as *mut Self;
            unsafe { core::ptr::drop_in_place(token_ptr) };
            unsafe { pkm_kacs_free(token_ptr.cast()) };
        }
    }

    fn boot_snapshot(&self, out: &mut PkmKacsBootSnapshot) {
        *out = PkmKacsBootSnapshot {
            token_ptr: (self as *const Self).cast(),
            session_id: self.session.session_id,
            auth_id: self.session.session_id,
            logon_type: self.session.logon_type,
            auth_pkg_ptr: self.session.auth_package.as_ptr(),
            auth_pkg_len: self.session.auth_package.len(),
            user_sid_ptr: self.session.user_sid.as_bytes().as_ptr(),
            user_sid_len: self.session.user_sid.as_bytes().len(),
            logon_sid_ptr: self.session.logon_sid.as_bytes().as_ptr(),
            logon_sid_len: self.session.logon_sid.as_bytes().len(),
            groups_ptr: self.group_views.as_ptr(),
            group_count: self.group_views.len() as u32,
            privileges_present: self.privileges_present,
            privileges_enabled: self.privileges_enabled,
            privileges_enabled_by_default: self.privileges_enabled_by_default,
            privileges_used: self.privileges_used.load(Ordering::Acquire),
            integrity_level: self.integrity_level as u32,
            token_type: TOKEN_TYPE_PRIMARY_ABI,
            impersonation_level: IMPERSONATION_LEVEL_ANONYMOUS_ABI,
            mandatory_policy: self.mandatory_policy,
            interactive_session_id: self.interactive_session_id,
            projected_uid: self.projected_uid,
            projected_gid: self.projected_gid,
            audit_policy: self.audit_policy,
        };
    }

    fn privileges_snapshot(&self) -> TokenPrivileges {
        TokenPrivileges {
            present: self.privileges_present,
            enabled: self.privileges_enabled,
            enabled_by_default: self.privileges_enabled_by_default,
            used: self.privileges_used.load(Ordering::Acquire),
        }
    }

    fn mark_privileges_used(&self, used_mask: u64) {
        self.privileges_used.fetch_or(used_mask, Ordering::AcqRel);
    }

    fn access_token(&self) -> AccessCheckToken<'_> {
        AccessCheckToken {
            subject: TokenView {
                user: self.user_sid,
                user_deny_only: false,
                groups: &self.groups,
            },
            token_type: self.token_type,
            impersonation_level: self.impersonation_level,
            audit_policy: self.audit_policy,
            privileges: self.privileges_snapshot(),
            integrity_level: self.integrity_level,
            mandatory_policy: self.mandatory_policy,
            restricted: RestrictedTokenContext::default(),
            confinement: ConfinementTokenContext::default(),
        }
    }

    fn own_sd(&self) -> Option<SecurityDescriptor<'_>> {
        SecurityDescriptor::parse(&self.own_sd[..self.own_sd_len]).ok()
    }
}

pub(crate) fn with_access_check_resolved_from_token<T>(
    token_ptr: *const c_void,
    f: impl FnOnce(AccessCheckAbiResolved<'_>) -> Result<T, core::ffi::c_long>,
) -> Result<T, core::ffi::c_long> {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return Err(-22);
    };
    let access_token = token.access_token();
    let resolved = AccessCheckAbiResolved {
        token: &access_token,
        default_pip: PipContext {
            pip_type: 0,
            pip_trust: 0,
        },
        device_groups: EMPTY_DEVICE_GROUPS,
        user_claims: EMPTY_CLAIMS,
        device_claims: EMPTY_CLAIMS,
        policies: EMPTY_POLICIES,
    };
    f(resolved)
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
    let subject_token = subject.access_token();
    let conditional_context = ConditionalContext::default();
    let pip = PipContext {
        pip_type: 0,
        pip_trust: 0,
    };

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

    if let Some(granted_out) = (unsafe { granted_out.as_mut() }) {
        *granted_out = result as u32;
    }
    0
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
