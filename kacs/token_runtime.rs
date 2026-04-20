// SPDX-License-Identifier: GPL-2.0-only

//! Boot-time PKM token/session runtime substrate.
//!
//! Slice 21 deliberately keeps this module narrower than a full token-handle
//! implementation. It provides only:
//! - the boot Session 0 / SYSTEM token object
//! - reference management for that live token pointer
//! - current-token conversion into the closed Slice 20 AccessCheck context
//! - a small KUnit snapshot seam for bootstrap verification
//!
//! Token-own security descriptors and broader mutable token state remain
//! deferred to later token-handle slices.

#![allow(unreachable_pub)]

use crate::access_check_abi::AccessCheckAbiResolved;
use crate::mic::{
    IntegrityLevel, TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN, TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};
use crate::pip::PipContext;
use crate::privilege::TokenPrivileges;
use crate::sid::Sid;
use crate::token::{
    AccessCheckToken, ConfinementTokenContext, ImpersonationLevel, RestrictedTokenContext,
    SidAndAttributes, TokenType, TokenView,
};
use core::ffi::c_void;
use core::ptr::null;
use core::sync::atomic::{fence, AtomicUsize, Ordering};

const SYSTEM_PRIVILEGES_ALL: u64 = 0xC000_000F_FFFF_FFFC;
const LOGON_TYPE_SERVICE: u32 = 5;
const TOKEN_TYPE_PRIMARY_ABI: u32 = 1;
const IMPERSONATION_LEVEL_ANONYMOUS_ABI: u32 = 0;

const SE_GROUP_MANDATORY: u32 = 0x0000_0001;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_OWNER: u32 = 0x0000_0008;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const EVERYONE_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const AUTHENTICATED_USERS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const LOCAL_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
const LOGON_SID_BYTES: &[u8] = &[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const AUTH_PACKAGE_NEGOTIATE: &[u8] = b"Negotiate";
const EMPTY_DEVICE_GROUPS: &[SidAndAttributes<'static>] = &[];
const EMPTY_CLAIMS: &[crate::claims::ClaimAttribute] = &[];
const EMPTY_POLICIES: &[crate::caap::CaapPolicyEntry<'static>] = &[];

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
    privileges: TokenPrivileges,
    integrity_level: IntegrityLevel,
    mandatory_policy: u32,
    token_type: TokenType,
    impersonation_level: ImpersonationLevel,
    audit_policy: u32,
    interactive_session_id: u32,
    projected_uid: u32,
    projected_gid: u32,
}

impl PkmKacsBootToken {
    fn create_system() -> Option<*const c_void> {
        let user_sid = Sid::parse(SYSTEM_SID_BYTES).ok()?;
        let logon_sid = Sid::parse(LOGON_SID_BYTES).ok()?;
        let administrators = Sid::parse(ADMINISTRATORS_SID_BYTES).ok()?;
        let everyone = Sid::parse(EVERYONE_SID_BYTES).ok()?;
        let authenticated_users = Sid::parse(AUTHENTICATED_USERS_SID_BYTES).ok()?;
        let local = Sid::parse(LOCAL_SID_BYTES).ok()?;

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
            privileges: TokenPrivileges {
                present: SYSTEM_PRIVILEGES_ALL,
                enabled: SYSTEM_PRIVILEGES_ALL,
                enabled_by_default: SYSTEM_PRIVILEGES_ALL,
                used: 0,
            },
            integrity_level: IntegrityLevel::System,
            mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP
                | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN,
            token_type: TokenType::Primary,
            impersonation_level: ImpersonationLevel::Anonymous,
            audit_policy: 0,
            interactive_session_id: 0,
            projected_uid: 0,
            projected_gid: 0,
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

        let token_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<Self>()) } as *mut Self;
        if token_ptr.is_null() {
            return null();
        }

        let copy = Self {
            refcount: AtomicUsize::new(1),
            session: token.session,
            user_sid: token.user_sid,
            logon_sid: token.logon_sid,
            groups: token.groups,
            group_views: token.group_views,
            privileges: token.privileges,
            integrity_level: token.integrity_level,
            mandatory_policy: token.mandatory_policy,
            token_type: token.token_type,
            impersonation_level: token.impersonation_level,
            audit_policy: token.audit_policy,
            interactive_session_id: token.interactive_session_id,
            projected_uid: token.projected_uid,
            projected_gid: token.projected_gid,
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
            privileges_present: self.privileges.present,
            privileges_enabled: self.privileges.enabled,
            privileges_enabled_by_default: self.privileges.enabled_by_default,
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
}

pub(crate) fn with_access_check_resolved_from_token<T>(
    token_ptr: *const c_void,
    f: impl FnOnce(AccessCheckAbiResolved<'_>) -> Result<T, core::ffi::c_long>,
) -> Result<T, core::ffi::c_long> {
    let Some(token) = (unsafe { PkmKacsBootToken::from_ptr(token_ptr) }) else {
        return Err(-22);
    };
    let access_token = AccessCheckToken {
        subject: TokenView {
            user: token.user_sid,
            user_deny_only: false,
            groups: &token.groups,
        },
        token_type: token.token_type,
        impersonation_level: token.impersonation_level,
        audit_policy: token.audit_policy,
        privileges: token.privileges,
        integrity_level: token.integrity_level,
        mandatory_policy: token.mandatory_policy,
        restricted: RestrictedTokenContext::default(),
        confinement: ConfinementTokenContext::default(),
    };
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
