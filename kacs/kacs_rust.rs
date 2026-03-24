// SPDX-License-Identifier: GPL-2.0

//! KACS kernel module — Rust implementation.
//!
//! Contains the kacs-core evaluation engine as a submodule and the
//! kernel-specific FFI exports called from lsm.c. All token lifecycle,
//! AccessCheck evaluation, and query logic lives here.

#![no_std]
#![allow(elided_lifetimes_in_paths)]

mod kacs_core;

// Re-export kacs_core modules at crate root so that `use crate::sid::Sid`
// works inside kacs_core files (they were written as a standalone crate
// where `crate::` pointed to their own root).
pub use kacs_core::*;

use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Global token ID counter. Each token gets a unique ID.
static NEXT_TOKEN_ID: AtomicU64 = AtomicU64::new(1);

use kacs_core::compat::{self, AllocError, TryClone};
use kacs_core::token::{Token, TokenType, ImpersonationLevel, IntegrityLevel};

// ── Heap-allocated refcounted token ───────────────────────────────────────

/// A kernel token object: the kacs-core Token + a reference count.
/// Allocated on the heap, passed through FFI as `*const ()`.
///
/// Refcounting follows Arc semantics:
/// - clone: fetch_add(1, Relaxed)
/// - drop: fetch_sub(1, Release) + acquire fence + free on zero
struct KacsToken {
    token: Token,
    refcount: AtomicUsize,
}

impl KacsToken {
    /// Allocate a new token on the heap with refcount 1.
    fn new(mut token: Token) -> Result<*const (), AllocError> {
        // Assign a unique token ID.
        token.token_id = kacs_core::luid::Luid(NEXT_TOKEN_ID.fetch_add(1, Ordering::Relaxed));

        // Generate a default token SD (§7.9) if one wasn't set.
        if token.security_descriptor.is_none() {
            if let Ok(sd) = build_default_token_sd(&token) {
                token.security_descriptor = Some(sd);
            }
        }

        // Increment session refcount
        let session_id = token.auth_id.0;

        let mut v = compat::vec_with_capacity::<KacsToken>(1)?;
        compat::vec_push(&mut v, KacsToken {
            token,
            refcount: AtomicUsize::new(1),
        })?;
        let ptr = v.as_ptr();
        core::mem::forget(v);

        // Addref AFTER successful allocation
        kacs_session_addref(session_id);

        Ok(ptr as *const ())
    }

    /// Get a reference from an opaque pointer.
    ///
    /// # Safety
    /// `ptr` must be a valid pointer returned by `KacsToken::new`.
    unsafe fn from_ptr<'a>(ptr: *const ()) -> &'a Self {
        unsafe { &*(ptr as *const KacsToken) }
    }

    /// Increment refcount.
    fn clone_ref(ptr: *const ()) -> *const () {
        let token = unsafe { Self::from_ptr(ptr) };
        token.refcount.fetch_add(1, Ordering::Relaxed);
        ptr
    }

    /// Decrement refcount. Frees if it reaches zero.
    ///
    /// # Safety
    /// `ptr` must be a valid pointer returned by `KacsToken::new`.
    unsafe fn drop_ref(ptr: *const ()) {
        let token = unsafe { Self::from_ptr(ptr) };
        if token.refcount.fetch_sub(1, Ordering::Release) == 1 {
            core::sync::atomic::fence(Ordering::Acquire);
            // Release session refcount before freeing
            let session_id = token.token.auth_id.0;
            let ptr_mut = ptr as *mut KacsToken;
            drop(unsafe { compat::Vec::from_raw_parts(ptr_mut, 1, 1) });
            kacs_session_release(session_id);
        }
    }
}

// ── FFI exports (called from lsm.c) ──────────────────────────────────────

/// Create the SYSTEM token (S-1-5-18, all privileges, System integrity).
/// Returns an opaque pointer. Caller owns one reference.
/// Returns null on allocation failure.
#[no_mangle]
pub extern "C" fn kacs_token_create_system() -> *const () {
    match Token::system_token() {
        Ok(token) => match KacsToken::new(token) {
            Ok(ptr) => ptr,
            Err(_) => core::ptr::null(),
        },
        Err(_) => core::ptr::null(),
    }
}

/// Create a bootstrap SD for the rootfs root inode.
/// Owner/group = SYSTEM, DACL = Allow SYSTEM GENERIC_ALL with full
/// inheritance (CONTAINER_INHERIT | OBJECT_INHERIT) so every child
/// created during initramfs extraction inherits an SD.
/// Returns an opaque parsed SD pointer, or null on failure.
#[no_mangle]
pub extern "C" fn kacs_create_root_sd() -> *const () {
    use kacs_core::ace::*;
    use kacs_core::acl::*;
    use kacs_core::mask::GENERIC_ALL;
    use kacs_core::sd::*;

    let system_sid = match kacs_core::well_known::system() {
        Ok(s) => s,
        Err(_) => return core::ptr::null(),
    };

    let mut aces = compat::Vec::new();
    if compat::vec_push(&mut aces, Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        mask: GENERIC_ALL,
        sid: match system_sid.try_clone() {
            Ok(s) => s,
            Err(_) => return core::ptr::null(),
        },
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    }).is_err() {
        return core::ptr::null();
    }

    let dacl = Acl {
        revision: ACL_REVISION,
        aces,
    };

    let sd = SecurityDescriptor {
        control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
        owner: Some(match system_sid.try_clone() {
            Ok(s) => s,
            Err(_) => return core::ptr::null(),
        }),
        group: Some(system_sid),
        dacl: Some(dacl),
        sacl: None,
    };

    let mut v = match compat::vec_with_capacity::<SecurityDescriptor>(1) {
        Ok(v) => v,
        Err(_) => return core::ptr::null(),
    };
    if compat::vec_push(&mut v, sd).is_err() {
        return core::ptr::null();
    }
    let ptr = v.as_ptr();
    core::mem::forget(v);
    ptr as *const ()
}

/// Create an Anonymous impersonation token (S-1-5-7 only, §12.3).
/// No real identity, no privileges, no groups. Medium integrity.
/// Returns an opaque pointer. Caller owns one reference.
#[no_mangle]
pub extern "C" fn kacs_token_create_anonymous() -> *const () {
    let anon_sid = match kacs_core::well_known::anonymous() {
        Ok(sid) => sid,
        Err(_) => return core::ptr::null(),
    };
    let token = Token {
        user_sid: anon_sid,
        groups: compat::Vec::new(),
        privileges: kacs_core::privilege::Privileges::new_all_enabled(0),
        token_type: kacs_core::token::TokenType::Impersonation,
        impersonation_level: kacs_core::token::ImpersonationLevel::Anonymous,
        integrity_level: kacs_core::token::IntegrityLevel::Medium,
        mandatory_policy: kacs_core::token::mandatory_policy::NO_WRITE_UP,
        elevation_type: kacs_core::token::ElevationType::Default,
        source: kacs_core::token::TokenSource {
            name: *b"AnonTkn\0",
            source_id: kacs_core::luid::Luid(0),
        },
        auth_id: kacs_core::luid::Luid(0),
        token_id: kacs_core::luid::Luid(0),
        modified_id: 0,
        logon_sid: match kacs_core::well_known::anonymous() {
            Ok(sid) => sid,
            Err(_) => return core::ptr::null(),
        },
        owner_sid_index: 0,
        primary_group_index: 0,
        restricted_sids: None,
        write_restricted: false,
        confinement_sid: None,
        confinement_capabilities: compat::Vec::new(),
        confinement_exempt: false,
        user_claims: compat::Vec::new(),
        device_claims: compat::Vec::new(),
        device_groups: None,
        restricted_device_groups: None,
        security_descriptor: None,
        default_dacl: None,
        projected_uid: 65534, // nobody
        projected_gid: 65534,
        projected_supplementary_gids: compat::Vec::new(),
        audit_policy: 0,
        interactive_session_id: 0,
        isolation_boundary: false,
        origin: kacs_core::luid::Luid(0),
        created_at: 0,
        expiration: 0,
        user_deny_only: false,
    };
    match KacsToken::new(token) {
        Ok(ptr) => ptr,
        Err(_) => core::ptr::null(),
    }
}

/// Clone a token (increment refcount). Returns the same pointer.
#[no_mangle]
pub extern "C" fn kacs_token_clone(ptr: *const ()) -> *const () {
    if ptr.is_null() {
        return core::ptr::null();
    }
    KacsToken::clone_ref(ptr)
}

/// Drop a token reference. Frees when refcount reaches zero.
#[no_mangle]
pub extern "C" fn kacs_token_drop(ptr: *const ()) {
    if ptr.is_null() {
        return;
    }
    unsafe { KacsToken::drop_ref(ptr) }
}

/// Format token info into a caller-provided buffer.
/// Returns bytes written on success, or negative errno.
#[no_mangle]
pub extern "C" fn kacs_token_format(
    ptr: *const (),
    buf: *mut u8,
    buf_len: usize,
) -> i64 {
    if ptr.is_null() || buf.is_null() {
        return -22; // -EINVAL
    }

    let kt = unsafe { KacsToken::from_ptr(ptr) };
    let token = &kt.token;

    // Build text representation into a stack buffer.
    // Format: "User: S-1-5-18\nType: Primary\nIntegrity: System\n..."
    let mut out = FormatBuf::new();
    out.str("User:      ");
    format_sid(&mut out, &token.user_sid);
    out.str("\nType:      ");
    out.str(match token.token_type {
        TokenType::Primary => "Primary",
        TokenType::Impersonation => "Impersonation",
    });
    out.str("\nIntegrity: ");
    out.str(match token.integrity_level {
        IntegrityLevel::Untrusted => "Untrusted",
        IntegrityLevel::Low => "Low",
        IntegrityLevel::Medium => "Medium",
        IntegrityLevel::High => "High",
        IntegrityLevel::System => "System",
    });
    out.str("\nGroups:    ");
    out.usize(token.groups.len());
    out.str("\nPrivs:     0x");
    out.hex64(token.privileges.enabled.load(Ordering::SeqCst));
    out.byte(b'\n');

    let data = out.as_bytes();
    if data.len() > buf_len {
        return -34; // -ERANGE
    }

    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    data.len() as i64
}

// ── Token query (KACS_IOC_QUERY) ──────────────────────────────────────────

/// Query token information by class. Returns binary data.
///
/// If buf is NULL, returns the required buffer size.
/// If buf is non-NULL, writes binary data and returns bytes written.
/// Returns negative errno on error.
///
/// All 19 query classes from §15.2. Output is binary structures
/// (SID bytes, u32/u64 values in little-endian) for programmatic use.
#[no_mangle]
pub extern "C" fn kacs_token_query(
    ptr: *const (),
    class: u32,
    buf: *mut u8,
    buf_len: u32,
) -> i32 {
    if ptr.is_null() {
        return -22; // -EINVAL
    }

    let kt = unsafe { KacsToken::from_ptr(ptr) };
    let token = &kt.token;

    let mut out = FormatBuf::new();
    match class {
        1 => { // TokenUser — binary SID
            if let Ok(bytes) = token.user_sid.to_bytes() {
                for &b in bytes.iter() { out.byte(b); }
            }
        }
        2 => { // TokenGroups — [count:u32le][{sid_len:u32le, sid_bytes, attrs:u32le}...]
            let count = token.groups.len() as u32;
            for &b in &count.to_le_bytes() { out.byte(b); }
            for g in token.groups.iter() {
                if let Ok(sid_bytes) = g.sid.to_bytes() {
                    let len = sid_bytes.len() as u32;
                    for &b in &len.to_le_bytes() { out.byte(b); }
                    for &b in sid_bytes.iter() { out.byte(b); }
                }
                for &b in &g.attributes.to_le_bytes() { out.byte(b); }
            }
        }
        3 => { // TokenPrivileges — [present:u64le, enabled:u64le, default:u64le, used:u64le]
            for &b in &token.privileges.present.load(Ordering::SeqCst).to_le_bytes() { out.byte(b); }
            for &b in &token.privileges.enabled.load(Ordering::SeqCst).to_le_bytes() { out.byte(b); }
            for &b in &token.privileges.enabled_by_default.load(Ordering::SeqCst).to_le_bytes() { out.byte(b); }
            for &b in &token.privileges.used.load(Ordering::SeqCst).to_le_bytes() { out.byte(b); }
        }
        4 => { // TokenType — [type:u32le] (1=Primary, 2=Impersonation)
            let t = match token.token_type { TokenType::Primary => 1u32, TokenType::Impersonation => 2u32 };
            for &b in &t.to_le_bytes() { out.byte(b); }
        }
        5 => { // TokenIntegrityLevel — binary integrity SID
            let rid = token.integrity_level.rid();
            if let Ok(sid) = kacs_core::sid::Sid::new(16, &[rid]) {
                if let Ok(bytes) = sid.to_bytes() {
                    for &b in bytes.iter() { out.byte(b); }
                }
            }
        }
        6 => { // TokenOwner — binary SID (user_sid as default owner)
            if let Ok(bytes) = token.user_sid.to_bytes() {
                for &b in bytes.iter() { out.byte(b); }
            }
        }
        7 => { // TokenPrimaryGroup — binary SID (first group or user_sid)
            let sid = if !token.groups.is_empty() {
                &token.groups[0].sid
            } else {
                &token.user_sid
            };
            if let Ok(bytes) = sid.to_bytes() {
                for &b in bytes.iter() { out.byte(b); }
            }
        }
        8 => { // TokenSessionId — [session_id:u64le] (from auth_id)
            for &b in &token.auth_id.0.to_le_bytes() { out.byte(b); }
        }
        9 => { // TokenRestrictedSids — same format as groups
            if let Some(ref rsids) = token.restricted_sids {
                let count = rsids.len() as u32;
                for &b in &count.to_le_bytes() { out.byte(b); }
                for g in rsids.iter() {
                    if let Ok(sid_bytes) = g.sid.to_bytes() {
                        let len = sid_bytes.len() as u32;
                        for &b in &len.to_le_bytes() { out.byte(b); }
                        for &b in sid_bytes.iter() { out.byte(b); }
                    }
                    for &b in &g.attributes.to_le_bytes() { out.byte(b); }
                }
            } else {
                for &b in &0u32.to_le_bytes() { out.byte(b); }
            }
        }
        10 => { // TokenSource — [name:8bytes, source_id:u64le]
            for &b in &token.source.name { out.byte(b); }
            for &b in &token.source.source_id.0.to_le_bytes() { out.byte(b); }
        }
        11 => { // TokenStatistics — [token_id:u64, auth_id:u64, modified_id:u64, type:u32]
            for &b in &token.token_id.0.to_le_bytes() { out.byte(b); }
            for &b in &token.auth_id.0.to_le_bytes() { out.byte(b); }
            for &b in &token.modified_id.to_le_bytes() { out.byte(b); }
            let t = match token.token_type { TokenType::Primary => 1u32, TokenType::Impersonation => 2u32 };
            for &b in &t.to_le_bytes() { out.byte(b); }
        }
        12 => { // TokenOrigin — [origin:u64le]
            for &b in &token.origin.0.to_le_bytes() { out.byte(b); }
        }
        13 => { // TokenElevationType — [type:u32le]
            let t = match token.elevation_type {
                kacs_core::token::ElevationType::Default => 1u32,
                kacs_core::token::ElevationType::Full => 2u32,
                kacs_core::token::ElevationType::Limited => 3u32,
            };
            for &b in &t.to_le_bytes() { out.byte(b); }
        }
        14 => { // TokenDeviceGroups — same format as groups
            if let Some(ref dgroups) = token.device_groups {
                let count = dgroups.len() as u32;
                for &b in &count.to_le_bytes() { out.byte(b); }
                for g in dgroups.iter() {
                    if let Ok(sid_bytes) = g.sid.to_bytes() {
                        let len = sid_bytes.len() as u32;
                        for &b in &len.to_le_bytes() { out.byte(b); }
                        for &b in sid_bytes.iter() { out.byte(b); }
                    }
                    for &b in &g.attributes.to_le_bytes() { out.byte(b); }
                }
            } else {
                for &b in &0u32.to_le_bytes() { out.byte(b); }
            }
        }
        15 => { // TokenAppContainerSid — confinement SID (§11.14)
            if let Some(ref csid) = token.confinement_sid {
                if let Ok(bytes) = csid.to_bytes() {
                    for &b in bytes.iter() { out.byte(b); }
                }
            }
        }
        16 => { // TokenCapabilities — confinement capabilities
            let count = token.confinement_capabilities.len() as u32;
            for &b in &count.to_le_bytes() { out.byte(b); }
            for g in token.confinement_capabilities.iter() {
                if let Ok(sid_bytes) = g.sid.to_bytes() {
                    let len = sid_bytes.len() as u32;
                    for &b in &len.to_le_bytes() { out.byte(b); }
                    for &b in sid_bytes.iter() { out.byte(b); }
                }
                for &b in &g.attributes.to_le_bytes() { out.byte(b); }
            }
        }
        17 => { // TokenMandatoryPolicy — [policy:u32le]
            for &b in &token.mandatory_policy.to_le_bytes() { out.byte(b); }
        }
        18 => { // TokenLogonType — look up from session table
            let logon_type: u32 = {
                let guard = SESSION_TABLE.lock();
                match guard.as_ref() {
                    Some(table) => match table.get(token.auth_id.0) {
                        Some(session) => session.logon_type as u32,
                        None => 0,
                    },
                    None => 0,
                }
            };
            for &b in &logon_type.to_le_bytes() { out.byte(b); }
        }
        19 => { // TokenLogonSid — binary SID
            if let Ok(bytes) = token.logon_sid.to_bytes() {
                for &b in bytes.iter() { out.byte(b); }
            }
        }
        20 => { // TokenDefaultDacl — self-relative binary SD fragment
            if let Some(ref dacl) = token.default_dacl {
                if let Ok(bytes) = dacl.to_bytes() {
                    for &b in bytes.iter() { out.byte(b); }
                }
            }
        }
        21 => { // TokenImpersonationLevel — [level:u32le]
            let level = match token.impersonation_level {
                kacs_core::token::ImpersonationLevel::Anonymous => 0u32,
                kacs_core::token::ImpersonationLevel::Identification => 1u32,
                kacs_core::token::ImpersonationLevel::Impersonation => 2u32,
                kacs_core::token::ImpersonationLevel::Delegation => 3u32,
            };
            for &b in &level.to_le_bytes() { out.byte(b); }
        }
        _ => return -22, // -EINVAL
    };

    let data = out.as_bytes();

    if buf.is_null() {
        return data.len() as i32;
    }

    if (buf_len as usize) < data.len() {
        return data.len() as i32;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    data.len() as i32
}

// ── Token creation from wire format ───────────────────────────────────────

/// Parse a binary token spec and return a new heap-allocated token.
/// Returns a valid pointer on success, null on failure (bad format or OOM).
#[no_mangle]
pub extern "C" fn kacs_token_from_spec(data: *const u8, len: usize) -> *const () {
    if data.is_null() || len < 64 || len > 65536 {
        return core::ptr::null();
    }

    let spec = unsafe { core::slice::from_raw_parts(data, len) };

    match kacs_core::token_spec::parse_token_spec(spec) {
        Ok(Some(mut token)) => {
            // Inject the logon SID into the groups with SE_GROUP_LOGON_ID.
            let logon_sid_entry = kacs_core::group::GroupEntry::new(
                token.logon_sid.try_clone().unwrap_or_else(|_| {
                    kacs_core::sid::Sid::new(5, &[5, 0, 0]).unwrap()
                }),
                kacs_core::group::SE_GROUP_MANDATORY
                    | kacs_core::group::SE_GROUP_ENABLED_BY_DEFAULT
                    | kacs_core::group::SE_GROUP_ENABLED
                    | kacs_core::group::SE_GROUP_LOGON_ID,
            );
            let _ = compat::vec_push(&mut token.groups, logon_sid_entry);

            match KacsToken::new(token) {
                Ok(ptr) => ptr,
                Err(_) => core::ptr::null(),
            }
        }
        _ => core::ptr::null(),
    }
}

// ── AccessCheck syscall ───────────────────────────────────────────────────

/// Evaluate a Security Descriptor against a token.
///
/// Called from the kacs_access_check syscall (nr 1023). Parses the SD
/// from binary, runs the full AccessCheck pipeline, returns the granted
/// access mask (>= 0) or negative errno.
///
/// This is the core of KACS — the 11-stage pipeline from §11 of the
/// proposal, running in kernel context against the calling thread's token.
///
/// Parameters added in the §15.1 expansion:
/// - self_sid/self_sid_len: optional PRINCIPAL_SELF substitution SID
/// - privilege_intent: KACS_BACKUP_INTENT | KACS_RESTORE_INTENT
/// - granted_out: always written with the granted mask (even on denial)
#[no_mangle]
pub extern "C" fn kacs_access_check_sd(
    token_ptr: *const (),
    sd_data: *const u8,
    sd_len: usize,
    desired: u32,
    generic_read: u32,
    generic_write: u32,
    generic_execute: u32,
    generic_all: u32,
    self_sid_ptr: *const u8,
    self_sid_len: u32,
    privilege_intent: u32,
    granted_out: *mut u32,
) -> i64 {
    if token_ptr.is_null() || sd_data.is_null() {
        return -22; // -EINVAL
    }

    let kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let sd_bytes = unsafe { core::slice::from_raw_parts(sd_data, sd_len) };

    // Parse the binary SD.
    let sd = match kacs_core::sd::SecurityDescriptor::from_bytes(sd_bytes) {
        Ok(Some(sd)) => sd,
        Ok(None) => return -22,  // -EINVAL: malformed SD
        Err(_) => return -12,    // -ENOMEM: allocation failed during parse
    };

    let mapping = kacs_core::mask::GenericMapping {
        read: generic_read,
        write: generic_write,
        execute: generic_execute,
        all: generic_all,
    };

    // Parse the PRINCIPAL_SELF substitution SID if provided.
    let self_sid = if !self_sid_ptr.is_null() && self_sid_len > 0 {
        let self_sid_bytes = unsafe {
            core::slice::from_raw_parts(self_sid_ptr, self_sid_len as usize)
        };
        kacs_core::sid::Sid::from_bytes(self_sid_bytes)
    } else {
        None
    };

    // Run the full AccessCheck pipeline.
    let result = kacs_core::access_check::access_check(
        &sd,
        &kt.token,
        desired,
        &mapping,
        None,                       // object tree
        self_sid.as_ref(),          // PRINCIPAL_SELF substitution
        &[],                        // local claims
        &[],                        // no central access policies
        privilege_intent,           // backup/restore intent
        0, 0,                       // PIP type/trust (from PSB, passed by C caller)
    );

    let ret = match result {
        Ok(ref r) => {
            if r.allowed {
                r.granted as i64
            } else {
                -13 // -EACCES: access denied
            }
        }
        Err(kacs_core::access_check::AccessCheckError::IdentificationLevel) => -1,  // -EPERM
        Err(kacs_core::access_check::AccessCheckError::InvalidSecurityDescriptor) => -22, // -EINVAL
        Err(kacs_core::access_check::AccessCheckError::InvalidObjectTypeList) => -22, // -EINVAL
        Err(kacs_core::access_check::AccessCheckError::AllocationFailed) => -12, // -ENOMEM
    };

    // Always write the granted mask to granted_out (even on denial/error).
    if !granted_out.is_null() {
        let granted = match result {
            Ok(ref r) if r.allowed => r.granted,
            _ => 0,
        };
        unsafe { *granted_out = granted; }
    }

    ret
}

// ── Token type query ──────────────────────────────────────────────────────

/// Returns the token type: 1 = Primary, 2 = Impersonation.
#[no_mangle]
pub extern "C" fn kacs_token_get_type(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    match kt.token.token_type {
        TokenType::Primary => 1,
        TokenType::Impersonation => 2,
    }
}

/// Returns the impersonation level: 0=Anonymous, 1=Identification,
/// 2=Impersonation, 3=Delegation.
#[no_mangle]
pub extern "C" fn kacs_token_get_impersonation_level(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    kt.token.impersonation_level as c_int
}

/// Set the impersonation level on a token (for capping during connect/impersonate).
///
/// Uses raw pointer write to avoid creating &mut (which would be UB if any
/// shared references exist). In practice this is called on freshly-cloned
/// tokens before they're shared, but the raw write is safe regardless.
#[no_mangle]
pub extern "C" fn kacs_token_set_impersonation_level(ptr: *const (), level: c_int) {
    if ptr.is_null() {
        return;
    }
    let new_level = match level {
        0 => ImpersonationLevel::Anonymous,
        1 => ImpersonationLevel::Identification,
        2 => ImpersonationLevel::Impersonation,
        3 => ImpersonationLevel::Delegation,
        _ => return,
    };
    let kt = ptr as *mut KacsToken;
    unsafe {
        let field = core::ptr::addr_of_mut!((*kt).token.impersonation_level);
        core::ptr::write(field, new_level);
    }
}

/// Check if a privilege is present AND enabled on a token.
/// Returns 1 if the privilege is active, 0 otherwise.
#[no_mangle]
pub extern "C" fn kacs_token_check_privilege(ptr: *const (), priv_mask: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    if kt.token.privileges.check(priv_mask) { 1 } else { 0 }
}

/// Returns the projected UID from the token.
#[no_mangle]
pub extern "C" fn kacs_token_get_projected_uid(ptr: *const ()) -> u32 {
    if ptr.is_null() { return 65534; } // nobody
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    kt.token.projected_uid
}

/// Returns the projected GID from the token.
#[no_mangle]
pub extern "C" fn kacs_token_get_projected_gid(ptr: *const ()) -> u32 {
    if ptr.is_null() { return 65534; }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    kt.token.projected_gid
}

/// Extract the owner SID from a raw SD blob. Returns the SID bytes and
/// length, or 0 if no owner.
#[no_mangle]
pub extern "C" fn kacs_sd_get_owner_sid(
    sd_data: *const u8, sd_len: usize,
    out_sid: *mut u8, out_max: usize,
) -> c_int {
    if sd_data.is_null() || sd_len == 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(sd_data, sd_len) };
    let sd = match kacs_core::sd::SecurityDescriptor::from_bytes(bytes) {
        Ok(Some(sd)) => sd,
        _ => return 0,
    };
    let owner = match sd.owner {
        Some(ref s) => s,
        None => return 0,
    };
    let sid_bytes = match owner.to_bytes() {
        Ok(b) => b,
        Err(_) => return 0,
    };
    if out_sid.is_null() || out_max < sid_bytes.len() {
        return sid_bytes.len() as c_int; // size query
    }
    unsafe {
        core::ptr::copy_nonoverlapping(sid_bytes.as_ptr(), out_sid, sid_bytes.len());
    }
    sid_bytes.len() as c_int
}

/// Check if a SID is the token's user_sid or a group with SE_GROUP_OWNER.
/// Used for ownership constraints in kacs_set_sd (§14.2).
/// Returns 1 if allowed, 0 if not.
#[no_mangle]
pub extern "C" fn kacs_token_can_own(token_ptr: *const (), sid_data: *const u8, sid_len: usize) -> c_int {
    if token_ptr.is_null() || sid_data.is_null() || sid_len == 0 {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let sid_bytes = unsafe { core::slice::from_raw_parts(sid_data, sid_len) };
    let target_sid = match kacs_core::sid::Sid::from_bytes(sid_bytes) {
        Some(s) => s,
        None => return 0,
    };

    // Caller's own SID.
    if kt.token.user_sid == target_sid {
        return 1;
    }

    // A group with SE_GROUP_OWNER.
    for group in kt.token.groups.iter() {
        if group.sid == target_sid
            && (group.attributes & kacs_core::group::SE_GROUP_OWNER) != 0
        {
            return 1;
        }
    }

    0
}

/// Returns the integrity level as a RID (0, 4096, 8192, 12288, 16384).
/// Used by the integrity ceiling check in the two-gate model.
#[no_mangle]
pub extern "C" fn kacs_token_get_integrity(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    kt.token.integrity_level.rid() as c_int
}

/// Check if two tokens have the same user SID.
/// Used by the identity gate fallback in the two-gate model.
/// Returns 1 if same user, 0 otherwise.
#[no_mangle]
pub extern "C" fn kacs_token_same_user(a: *const (), b: *const ()) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let ka = unsafe { KacsToken::from_ptr(a) };
    let kb = unsafe { KacsToken::from_ptr(b) };
    if ka.token.user_sid == kb.token.user_sid { 1 } else { 0 }
}

// ── Group adjustment ──────────────────────────────────────────────────────

/// Enable or disable a group entry by index.
/// Mandatory groups (SE_GROUP_MANDATORY) cannot be disabled.
/// Returns 0 on success, -EINVAL on bad index or mandatory violation.
#[no_mangle]
pub extern "C" fn kacs_token_adjust_group(
    ptr: *const (),
    index: u32,
    enable: c_int,
    prev_attrs_out: *mut u32,
) -> c_int {
    if ptr.is_null() {
        return -22;
    }
    // Safety: use raw pointers throughout to avoid &mut aliasing UB.
    // The C side holds a mutex, but multiple fds may alias this token.
    let kt = ptr as *mut KacsToken;
    unsafe {
        let groups_ptr = core::ptr::addr_of_mut!((*kt).token.groups);
        let idx = index as usize;
        if idx >= (*groups_ptr).len() {
            return -22; // -EINVAL
        }

        let attrs_ptr = core::ptr::addr_of_mut!((*groups_ptr)[idx].attributes);
        let attrs = core::ptr::read(attrs_ptr);

        // Capture previous state.
        if !prev_attrs_out.is_null() {
            *prev_attrs_out = attrs;
        }

        if enable != 0 {
            core::ptr::write(attrs_ptr, attrs | kacs_core::group::SE_GROUP_ENABLED);
        } else {
            // Mandatory groups cannot be disabled
            if attrs & kacs_core::group::SE_GROUP_MANDATORY != 0 {
                return -22; // -EINVAL
            }
            core::ptr::write(attrs_ptr, attrs & !kacs_core::group::SE_GROUP_ENABLED);
        }
        // Bump modified_id (§15.2)
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }
    0
}

// ── Default adjustment (§7.6 AdjustDefault) ──────────────────────────────

/// Set the default DACL on a token from binary ACL data.
/// Returns 0 on success, -EINVAL on malformed ACL, -ENOMEM on OOM.
#[no_mangle]
pub extern "C" fn kacs_token_set_default_dacl(
    ptr: *const (),
    acl_data: *const u8,
    acl_len: u32,
) -> c_int {
    if ptr.is_null() || acl_data.is_null() || acl_len == 0 {
        return -22; // -EINVAL
    }
    let kt = ptr as *mut KacsToken;
    let data = unsafe { core::slice::from_raw_parts(acl_data, acl_len as usize) };
    match kacs_core::acl::Acl::from_bytes(data) {
        Ok(Some(acl)) => unsafe {
            let dacl = core::ptr::addr_of_mut!((*kt).token.default_dacl);
            core::ptr::write(dacl, Some(acl));
            let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
            core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
            0
        },
        Ok(None) => -22, // -EINVAL: malformed ACL
        Err(_) => -12,   // -ENOMEM
    }
}

/// Clear the default DACL (set to None).
/// Returns 0.
#[no_mangle]
pub extern "C" fn kacs_token_clear_default_dacl(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return -22;
    }
    let kt = ptr as *mut KacsToken;
    unsafe {
        let dacl = core::ptr::addr_of_mut!((*kt).token.default_dacl);
        core::ptr::write(dacl, None);
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }
    0
}

/// Set the owner SID index. Must be 0 (user SID) or index+1 into groups
/// where that group has SE_GROUP_OWNER.
/// Returns 0 on success, -EINVAL on bad index or non-owner group.
#[no_mangle]
pub extern "C" fn kacs_token_set_owner_index(
    ptr: *const (),
    index: u16,
) -> c_int {
    if ptr.is_null() {
        return -22;
    }
    let kt = ptr as *mut KacsToken;
    unsafe {
        // Index 0 = user SID (always valid as owner).
        if index == 0 {
            let field = core::ptr::addr_of_mut!((*kt).token.owner_sid_index);
            core::ptr::write(field, 0);
            let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
            core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
            return 0;
        }
        // Index 1..N = groups[0..N-1]. Must have SE_GROUP_OWNER.
        let groups_ptr = core::ptr::addr_of!((*kt).token.groups);
        let group_idx = (index - 1) as usize;
        if group_idx >= (*groups_ptr).len() {
            return -22; // -EINVAL: out of bounds
        }
        let attrs = core::ptr::read(core::ptr::addr_of!((*groups_ptr)[group_idx].attributes));
        if attrs & kacs_core::group::SE_GROUP_OWNER == 0 {
            return -22; // -EINVAL: not an owner group
        }
        let field = core::ptr::addr_of_mut!((*kt).token.owner_sid_index);
        core::ptr::write(field, index);
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }
    0
}

/// Set the primary group SID index. Must be 0 (user SID) or index+1
/// into groups (any group is valid as primary group).
/// Returns 0 on success, -EINVAL on bad index.
#[no_mangle]
pub extern "C" fn kacs_token_set_primary_group_index(
    ptr: *const (),
    index: u16,
) -> c_int {
    if ptr.is_null() {
        return -22;
    }
    let kt = ptr as *mut KacsToken;
    unsafe {
        if index == 0 {
            let field = core::ptr::addr_of_mut!((*kt).token.primary_group_index);
            core::ptr::write(field, 0);
            let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
            core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
            return 0;
        }
        let groups_ptr = core::ptr::addr_of!((*kt).token.groups);
        let group_idx = (index - 1) as usize;
        if group_idx >= (*groups_ptr).len() {
            return -22;
        }
        let field = core::ptr::addr_of_mut!((*kt).token.primary_group_index);
        core::ptr::write(field, index);
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }
    0
}

/// Reset all groups to their creation-time enabled/disabled state.
/// SE_GROUP_USE_FOR_DENY_ONLY groups are skipped (cannot be re-enabled).
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn kacs_token_reset_groups(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return -22;
    }
    let kt = ptr as *mut KacsToken;
    unsafe {
        let groups_ptr = core::ptr::addr_of_mut!((*kt).token.groups);
        for i in 0..(*groups_ptr).len() {
            let attrs_ptr = core::ptr::addr_of_mut!((*groups_ptr)[i].attributes);
            let attrs = core::ptr::read(attrs_ptr);
            // Deny-only groups cannot be re-enabled (§7.6).
            if attrs & kacs_core::group::SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                continue;
            }
            if attrs & kacs_core::group::SE_GROUP_ENABLED_BY_DEFAULT != 0 {
                core::ptr::write(attrs_ptr, attrs | kacs_core::group::SE_GROUP_ENABLED);
            } else {
                core::ptr::write(attrs_ptr, attrs & !kacs_core::group::SE_GROUP_ENABLED);
            }
        }
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }
    0
}

/// Check if a token has restricting SIDs (is a restricted token).
/// Returns 1 if restricted, 0 if not.
#[no_mangle]
pub extern "C" fn kacs_token_is_restricted(ptr: *const ()) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };
    if kt.token.restricted_sids.is_some() { 1 } else { 0 }
}

// ── Privilege adjustment ──────────────────────────────────────────────────

/// Adjust privileges on a token: enable, disable, or permanently remove.
/// Writes the previous enabled mask to *prev_out (if non-null).
/// Returns 0 on success, negative errno on error.
#[no_mangle]
pub extern "C" fn kacs_token_adjust_privs(
    ptr: *const (),
    enable_mask: u64,
    disable_mask: u64,
    remove_mask: u64,
    prev_out: *mut u64,
) -> c_int {
    if ptr.is_null() {
        return -22; // -EINVAL
    }
    // Safety: privileges use AtomicU64 so concurrent reads are safe.
    // We only need raw pointers for modified_id (non-atomic).
    let kt = ptr as *mut KacsToken;
    let privs = unsafe { &(*kt).token.privileges };

    // Capture previous state before any changes.
    let previous = privs.enabled.load(core::sync::atomic::Ordering::Relaxed);
    if !prev_out.is_null() {
        unsafe { *prev_out = previous; }
    }

    // Remove first (irreversible)
    if remove_mask != 0 {
        let mut mask = remove_mask;
        while mask != 0 {
            let bit = 1u64 << mask.trailing_zeros();
            privs.remove(bit);
            mask &= !bit;
        }
    }

    // Disable
    if disable_mask != 0 {
        let mut mask = disable_mask;
        while mask != 0 {
            let bit = 1u64 << mask.trailing_zeros();
            privs.disable(bit);
            mask &= !bit;
        }
    }

    // Enable (can't enable removed privileges — enable() checks present)
    if enable_mask != 0 {
        let mut mask = enable_mask;
        while mask != 0 {
            let bit = 1u64 << mask.trailing_zeros();
            if !privs.enable(bit) {
                return -22; // -EINVAL: privilege not present
            }
            mask &= !bit;
        }
    }

    // Bump modified_id (§15.2)
    unsafe {
        let mid = core::ptr::addr_of_mut!((*kt).token.modified_id);
        core::ptr::write(mid, core::ptr::read(mid).wrapping_add(1));
    }

    0
}

// ── Token duplication ────────────────────────────────────────────────────

/// Deep-clone a token with a new type and impersonation level.
/// Returns a new opaque pointer (caller owns one reference), or null on failure.
#[no_mangle]
pub extern "C" fn kacs_token_deep_clone(
    ptr: *const (),
    new_type: c_int,
    new_level: c_int,
) -> *const () {
    if ptr.is_null() {
        return core::ptr::null();
    }
    let kt = unsafe { KacsToken::from_ptr(ptr) };

    let mut cloned = match kt.token.try_clone() {
        Ok(t) => t,
        Err(_) => return core::ptr::null(),
    };

    // Apply new type if specified
    match new_type {
        1 => cloned.token_type = TokenType::Primary,
        2 => cloned.token_type = TokenType::Impersonation,
        _ => {} // -1 or other = keep original
    }

    // Apply new impersonation level if specified
    match new_level {
        0 => cloned.impersonation_level = ImpersonationLevel::Anonymous,
        1 => cloned.impersonation_level = ImpersonationLevel::Identification,
        2 => cloned.impersonation_level = ImpersonationLevel::Impersonation,
        3 => cloned.impersonation_level = ImpersonationLevel::Delegation,
        _ => {} // -1 or other = keep original
    }

    match KacsToken::new(cloned) {
        Ok(ptr) => ptr,
        Err(_) => core::ptr::null(),
    }
}

// ── Process Security Descriptors ──────────────────────────────────────────

/// Create a default process SD for a newly forked process.
///
/// Default DACL (§8.4):
/// - Creator's user SID → GENERIC_ALL
/// - Administrators → GENERIC_ALL
/// - SYSTEM → GENERIC_ALL
/// - Everyone → PROCESS_QUERY_LIMITED (0x1000)
///
/// Returns an opaque pointer to the SD, or null on failure.
/// Caller is responsible for freeing via kacs_proc_sd_drop.
#[no_mangle]
pub extern "C" fn kacs_create_default_proc_sd(token_ptr: *const ()) -> *const () {
    if token_ptr.is_null() {
        return core::ptr::null();
    }

    let kt = unsafe { KacsToken::from_ptr(token_ptr) };

    let sd = match build_default_proc_sd(&kt.token) {
        Ok(sd) => sd,
        Err(_) => return core::ptr::null(),
    };

    // Box it via Vec trick (same as KacsToken)
    let mut v = match compat::vec_with_capacity::<kacs_core::sd::SecurityDescriptor>(1) {
        Ok(v) => v,
        Err(_) => return core::ptr::null(),
    };
    if compat::vec_push(&mut v, sd).is_err() {
        return core::ptr::null();
    }
    let ptr = v.as_ptr();
    core::mem::forget(v);
    ptr as *const ()
}

/// Free a process SD.
#[no_mangle]
pub extern "C" fn kacs_proc_sd_drop(ptr: *const ()) {
    if ptr.is_null() {
        return;
    }
    let ptr_mut = ptr as *mut kacs_core::sd::SecurityDescriptor;
    drop(unsafe { compat::Vec::from_raw_parts(ptr_mut, 1, 1) });
}

/// Parse a binary SD (self-relative format) and return a heap-allocated
/// parsed SecurityDescriptor. Used by the inode SD cache.
/// Returns an opaque pointer on success, null on parse failure or OOM.
#[no_mangle]
pub extern "C" fn kacs_sd_from_bytes(data: *const u8, len: usize) -> *const () {
    if data.is_null() || len == 0 || len > 65536 {
        return core::ptr::null();
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    let sd = match kacs_core::sd::SecurityDescriptor::from_bytes(bytes) {
        Ok(Some(sd)) => sd,
        _ => return core::ptr::null(),
    };
    // Heap-allocate via Vec trick
    let mut v = match compat::vec_with_capacity::<kacs_core::sd::SecurityDescriptor>(1) {
        Ok(v) => v,
        Err(_) => return core::ptr::null(),
    };
    if compat::vec_push(&mut v, sd).is_err() {
        return core::ptr::null();
    }
    let ptr = v.as_ptr();
    core::mem::forget(v);
    ptr as *const ()
}

/// Serialize a parsed SD back to self-relative binary format.
/// If buf is null, returns the required size.
/// Otherwise writes to buf (up to buf_len) and returns bytes written.
/// Returns negative on error.
#[no_mangle]
pub extern "C" fn kacs_sd_to_bytes(sd_ptr: *const (), buf: *mut u8, buf_len: c_int) -> c_int {
    if sd_ptr.is_null() {
        return -22; // -EINVAL
    }
    let sd = unsafe { &*(sd_ptr as *const kacs_core::sd::SecurityDescriptor) };
    let bytes = match sd.to_bytes() {
        Ok(b) => b,
        Err(_) => return -12, // -ENOMEM
    };
    if buf.is_null() || buf_len <= 0 {
        return bytes.len() as c_int;
    }
    let copy_len = core::cmp::min(bytes.len(), buf_len as usize);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
    }
    copy_len as c_int
}

/// Compute an inherited SD for a newly created inode (§9.5).
/// parent_sd_ptr may be null (no parent SD to inherit from).
/// Returns a heap-allocated parsed SD, or null on failure.
#[no_mangle]
pub extern "C" fn kacs_create_inherited_sd(
    token_ptr: *const (),
    parent_sd_ptr: *const (),
    is_container: c_int,
) -> *const () {
    if token_ptr.is_null() {
        return core::ptr::null();
    }
    let kt = unsafe { KacsToken::from_ptr(token_ptr) };

    let parent_sd = if parent_sd_ptr.is_null() {
        None
    } else {
        Some(unsafe { &*(parent_sd_ptr as *const kacs_core::sd::SecurityDescriptor) })
    };

    let object_class = if is_container != 0 {
        kacs_core::inherit::ObjectClass::Container
    } else {
        kacs_core::inherit::ObjectClass::NonContainer
    };

    let sd = match kacs_core::inherit::compute_inherited_sd(
        parent_sd,
        None, // no creator-supplied SD
        &kt.token,
        object_class,
        &kacs_core::mask::FILE_GENERIC_MAPPING,
        None, // no child type GUID (files are untyped)
    ) {
        Ok(sd) => sd,
        Err(_) => return core::ptr::null(),
    };

    // Heap-allocate via Vec trick
    let mut v = match compat::vec_with_capacity::<kacs_core::sd::SecurityDescriptor>(1) {
        Ok(v) => v,
        Err(_) => return core::ptr::null(),
    };
    if compat::vec_push(&mut v, sd).is_err() {
        return core::ptr::null();
    }
    let ptr = v.as_ptr();
    core::mem::forget(v);
    ptr as *const ()
}

/// Extract SD components per security_info mask and serialize.
/// Returns the serialized SD (only requested components) as bytes.
/// If buf is null, returns the required size.
/// security_info: OWNER=0x01, GROUP=0x02, DACL=0x04, SACL=0x08, LABEL=0x10
#[no_mangle]
pub extern "C" fn kacs_sd_get_components(
    sd_ptr: *const (),
    security_info: u32,
    buf: *mut u8,
    buf_len: c_int,
) -> c_int {
    if sd_ptr.is_null() {
        return -22; // -EINVAL
    }
    let sd = unsafe { &*(sd_ptr as *const kacs_core::sd::SecurityDescriptor) };

    // Build a filtered SD containing only the requested components.
    let mut filtered = kacs_core::sd::SecurityDescriptor {
        control: kacs_core::sd::SE_SELF_RELATIVE,
        owner: None,
        group: None,
        dacl: None,
        sacl: None,
    };

    if security_info & 0x01 != 0 { // OWNER
        filtered.owner = sd.owner.as_ref().and_then(|s| s.try_clone().ok());
    }
    if security_info & 0x02 != 0 { // GROUP
        filtered.group = sd.group.as_ref().and_then(|s| s.try_clone().ok());
    }
    if security_info & 0x04 != 0 { // DACL
        filtered.dacl = sd.dacl.as_ref().and_then(|d| d.try_clone().ok());
        filtered.control |= sd.control & (kacs_core::sd::SE_DACL_PRESENT
            | kacs_core::sd::SE_DACL_PROTECTED
            | kacs_core::sd::SE_DACL_AUTO_INHERITED);
    }
    if security_info & 0x08 != 0 { // SACL (full)
        filtered.sacl = sd.sacl.as_ref().and_then(|s| s.try_clone().ok());
        filtered.control |= sd.control & (kacs_core::sd::SE_SACL_PRESENT
            | kacs_core::sd::SE_SACL_PROTECTED
            | kacs_core::sd::SE_SACL_AUTO_INHERITED);
    } else if security_info & 0x10 != 0 { // LABEL only (from SACL)
        // Extract only mandatory label ACEs from the SACL.
        if let Some(ref sacl) = sd.sacl {
            let mut label_aces = compat::Vec::new();
            for ace in sacl.aces.iter() {
                if ace.ace_type == kacs_core::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                    if let Ok(a) = ace.try_clone() {
                        let _ = compat::vec_push(&mut label_aces, a);
                    }
                }
            }
            if !label_aces.is_empty() {
                filtered.sacl = Some(kacs_core::acl::Acl {
                    revision: kacs_core::acl::ACL_REVISION,
                    aces: label_aces,
                });
                filtered.control |= kacs_core::sd::SE_SACL_PRESENT;
            }
        }
    }

    let bytes = match filtered.to_bytes() {
        Ok(b) => b,
        Err(_) => return -12,
    };

    if buf.is_null() || buf_len <= 0 {
        return bytes.len() as c_int;
    }
    if (buf_len as usize) < bytes.len() {
        return bytes.len() as c_int; // caller checks and uses -ERANGE
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    }
    bytes.len() as c_int
}

/// Merge SD components from a new SD into an existing SD per security_info.
/// Returns a new heap-allocated merged SD, or null on failure.
#[no_mangle]
pub extern "C" fn kacs_sd_merge_components(
    existing_sd_ptr: *const (),
    new_sd_data: *const u8,
    new_sd_len: usize,
    security_info: u32,
) -> *const () {
    if existing_sd_ptr.is_null() || new_sd_data.is_null() || new_sd_len == 0 {
        return core::ptr::null();
    }
    let existing = unsafe { &*(existing_sd_ptr as *const kacs_core::sd::SecurityDescriptor) };
    let new_bytes = unsafe { core::slice::from_raw_parts(new_sd_data, new_sd_len) };

    let new_sd = match kacs_core::sd::SecurityDescriptor::from_bytes(new_bytes) {
        Ok(Some(sd)) => sd,
        _ => return core::ptr::null(),
    };

    // Start with a clone of the existing SD.
    let mut merged = match existing.try_clone() {
        Ok(sd) => sd,
        Err(_) => return core::ptr::null(),
    };

    // Merge only the indicated components.
    if security_info & 0x01 != 0 { // OWNER
        merged.owner = new_sd.owner;
    }
    if security_info & 0x02 != 0 { // GROUP
        merged.group = new_sd.group;
    }
    if security_info & 0x04 != 0 { // DACL
        merged.dacl = new_sd.dacl;
        // Transfer DACL control flags from new SD.
        merged.control &= !(kacs_core::sd::SE_DACL_PRESENT
            | kacs_core::sd::SE_DACL_PROTECTED
            | kacs_core::sd::SE_DACL_AUTO_INHERITED);
        merged.control |= new_sd.control & (kacs_core::sd::SE_DACL_PRESENT
            | kacs_core::sd::SE_DACL_PROTECTED
            | kacs_core::sd::SE_DACL_AUTO_INHERITED);
    }
    if security_info & 0x08 != 0 { // SACL — full replacement
        merged.sacl = new_sd.sacl;
        merged.control &= !(kacs_core::sd::SE_SACL_PRESENT
            | kacs_core::sd::SE_SACL_PROTECTED
            | kacs_core::sd::SE_SACL_AUTO_INHERITED);
        merged.control |= new_sd.control & (kacs_core::sd::SE_SACL_PRESENT
            | kacs_core::sd::SE_SACL_PROTECTED
            | kacs_core::sd::SE_SACL_AUTO_INHERITED);
    } else if security_info & 0x10 != 0 { // LABEL only — merge labels
        // Replace mandatory label ACEs in existing SACL with new ones.
        // Keep other SACL ACEs (audit, trust labels, etc.).
        if let Some(ref new_sacl) = new_sd.sacl {
            let mut aces = compat::Vec::new();
            // Keep non-label ACEs from existing SACL.
            if let Some(ref existing_sacl) = merged.sacl {
                for ace in existing_sacl.aces.iter() {
                    if ace.ace_type != kacs_core::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                        if let Ok(a) = ace.try_clone() {
                            let _ = compat::vec_push(&mut aces, a);
                        }
                    }
                }
            }
            // Add label ACEs from new SACL.
            for ace in new_sacl.aces.iter() {
                if ace.ace_type == kacs_core::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE {
                    if let Ok(a) = ace.try_clone() {
                        let _ = compat::vec_push(&mut aces, a);
                    }
                }
            }
            merged.sacl = Some(kacs_core::acl::Acl {
                revision: kacs_core::acl::ACL_REVISION,
                aces,
            });
            merged.control |= kacs_core::sd::SE_SACL_PRESENT;
        }
    }

    // Heap-allocate.
    let mut v = match compat::vec_with_capacity::<kacs_core::sd::SecurityDescriptor>(1) {
        Ok(v) => v,
        Err(_) => return core::ptr::null(),
    };
    if compat::vec_push(&mut v, merged).is_err() {
        return core::ptr::null();
    }
    let ptr = v.as_ptr();
    core::mem::forget(v);
    ptr as *const ()
}

/// Build the default process SD from the creator's token.
fn build_default_proc_sd(
    token: &Token,
) -> Result<kacs_core::sd::SecurityDescriptor, AllocError> {
    use kacs_core::ace::{self, Ace};
    use kacs_core::acl::Acl;
    use kacs_core::mask;
    use kacs_core::sd::SecurityDescriptor;

    let owner = token.user_sid.try_clone()?;
    let group = token.user_sid.try_clone()?;

    // Build DACL with 4 ACEs
    let mut aces = compat::vec_with_capacity::<Ace>(4)?;

    // Creator → GENERIC_ALL (mapped to PROCESS_ALL_ACCESS)
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: mask::GENERIC_ALL,
        sid: token.user_sid.try_clone()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    // Administrators → GENERIC_ALL
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: mask::GENERIC_ALL,
        sid: kacs_core::well_known::administrators()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    // SYSTEM → GENERIC_ALL
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: mask::GENERIC_ALL,
        sid: kacs_core::well_known::system()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    // Everyone → PROCESS_QUERY_LIMITED
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: mask::PROCESS_QUERY_LIMITED,
        sid: kacs_core::well_known::everyone()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    let dacl = Acl {
        revision: kacs_core::acl::ACL_REVISION,
        aces,
    };

    Ok(SecurityDescriptor::new(owner, group, dacl))
}

/// Build the default token SD (§7.9) — controls who can open this token.
///
/// DACL:
/// - Token user → TOKEN_SELF_ACCESS (non-escalating rights only)
/// - Administrators (S-1-5-32-544) → TOKEN_ALL_ACCESS
/// - SYSTEM (S-1-5-18) → TOKEN_ALL_ACCESS
fn build_default_token_sd(
    token: &Token,
) -> Result<kacs_core::sd::SecurityDescriptor, AllocError> {
    use kacs_core::ace::{self, Ace};
    use kacs_core::acl::Acl;
    use kacs_core::sd::SecurityDescriptor;

    const TOKEN_ALL_ACCESS: u32 = 0x00EF;
    // Self-access: query + adjust, but NOT duplicate/impersonate/assign (§7.9).
    const TOKEN_SELF_ACCESS: u32 = 0x00E8; // QUERY | ADJUST_PRIVS | ADJUST_GROUPS | ADJUST_DEFAULT

    let owner = token.user_sid.try_clone()?;
    let group = token.user_sid.try_clone()?;

    // Build DACL with 3 ACEs
    let mut aces = compat::vec_with_capacity::<Ace>(3)?;

    // Token user → limited self-access (non-escalating rights, §7.9)
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: TOKEN_SELF_ACCESS,
        sid: token.user_sid.try_clone()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    // Administrators → TOKEN_ALL_ACCESS
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: TOKEN_ALL_ACCESS,
        sid: kacs_core::well_known::administrators()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    // SYSTEM → TOKEN_ALL_ACCESS
    compat::vec_push(&mut aces, Ace {
        ace_type: ace::ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: TOKEN_ALL_ACCESS,
        sid: kacs_core::well_known::system()?,
        object_type: None,
        inherited_object_type: None,
        condition: None,
        application_data: None,
    })?;

    let dacl = Acl {
        revision: kacs_core::acl::ACL_REVISION,
        aces,
    };

    Ok(SecurityDescriptor::new(owner, group, dacl))
}

/// Check a process SD against a token for a desired access mask.
/// Returns 1 if access is granted, 0 if denied.
#[no_mangle]
pub extern "C" fn kacs_check_proc_sd(
    token_ptr: *const (),
    sd_ptr: *const (),
    desired: u32,
) -> c_int {
    if token_ptr.is_null() || sd_ptr.is_null() || desired == 0 {
        return 0;
    }

    let kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let sd = unsafe { &*(sd_ptr as *const kacs_core::sd::SecurityDescriptor) };

    match kacs_core::access_check::access_check(
        sd,
        &kt.token,
        desired,
        &kacs_core::mask::PROCESS_GENERIC_MAPPING,
        None,
        None,
        &[],
        &[],
        0, 0, 0,
    ) {
        Ok(result) => if result.allowed { 1 } else { 0 },
        Err(_) => 0,
    }
}

/// Run AccessCheck on a parsed file SD. Returns the GRANTED MASK (not
/// boolean). Used by security_file_open for legacy subset mode.
/// Returns -1 on error (e.g., Identification-level token).
#[no_mangle]
pub extern "C" fn kacs_file_access_check(
    token_ptr: *const (),
    sd_ptr: *const (),
    desired: u32,
) -> i64 {
    if token_ptr.is_null() || sd_ptr.is_null() {
        return -1;
    }

    let kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let sd = unsafe { &*(sd_ptr as *const kacs_core::sd::SecurityDescriptor) };

    // Use MAXIMUM_ALLOWED to get the full granted mask for subset mode.
    let check_desired = desired | kacs_core::mask::MAXIMUM_ALLOWED;

    match kacs_core::access_check::access_check(
        sd,
        &kt.token,
        check_desired,
        &kacs_core::mask::FILE_GENERIC_MAPPING,
        None,
        None,
        &[],
        &[],
        0, 0, 0,
    ) {
        Ok(result) => (result.granted & desired) as i64,
        Err(_) => -1,
    }
}

/// Same as kacs_file_access_check but uses DIRECTORY_GENERIC_MAPPING.
#[no_mangle]
pub extern "C" fn kacs_dir_access_check(
    token_ptr: *const (),
    sd_ptr: *const (),
    desired: u32,
) -> i64 {
    if token_ptr.is_null() || sd_ptr.is_null() {
        return -1;
    }

    let kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let sd = unsafe { &*(sd_ptr as *const kacs_core::sd::SecurityDescriptor) };

    let check_desired = desired | kacs_core::mask::MAXIMUM_ALLOWED;

    match kacs_core::access_check::access_check(
        sd,
        &kt.token,
        check_desired,
        &kacs_core::mask::DIRECTORY_GENERIC_MAPPING,
        None,
        None,
        &[],
        &[],
        0, 0, 0,
    ) {
        Ok(result) => (result.granted & desired) as i64,
        Err(_) => -1,
    }
}

/// Check a token's own SD against a caller's token for a desired access mask.
///
/// Returns 1 if access is granted, 0 if denied.
/// If the target token has no SD, access is granted (unrestricted).
#[no_mangle]
pub extern "C" fn kacs_check_token_sd(
    token_ptr: *const (),
    caller_token_ptr: *const (),
    desired: u32,
) -> c_int {
    if token_ptr.is_null() || caller_token_ptr.is_null() || desired == 0 {
        return 0;
    }

    let target_kt = unsafe { KacsToken::from_ptr(token_ptr) };
    let caller_kt = unsafe { KacsToken::from_ptr(caller_token_ptr) };

    // If the target token has no SD (OOM at creation), fail-secure: deny.
    let sd = match target_kt.token.security_descriptor.as_ref() {
        Some(sd) => sd,
        None => return 0,
    };

    match kacs_core::access_check::access_check(
        sd,
        &caller_kt.token,
        desired,
        &kacs_core::mask::TOKEN_GENERIC_MAPPING,
        None,
        None,
        &[],
        &[],
        0, 0, 0,
    ) {
        Ok(result) => if result.allowed { 1 } else { 0 },
        Err(_) => 0,
    }
}

// ── Token restriction ─────────────────────────────────────────────────────

/// Create a restricted (sandboxed) copy of a token.
///
/// data layout: [deny_indices: u32 × num_deny] [restrict_sids: binary SIDs]
/// Each binary SID is self-describing (revision + sub_authority_count → length).
///
/// Returns a new token pointer or null on failure.
#[no_mangle]
pub extern "C" fn kacs_token_restrict(
    ptr: *const (),
    privs_to_delete: u64,
    data: *const u8,
    data_len: u32,
    num_deny_indices: u32,
    num_restrict_sids: u32,
) -> *const () {
    if ptr.is_null() {
        return core::ptr::null();
    }

    let kt = unsafe { KacsToken::from_ptr(ptr) };
    let mut token = match kt.token.try_clone() {
        Ok(t) => t,
        Err(_) => return core::ptr::null(),
    };

    // 1. Remove privileges
    if privs_to_delete != 0 {
        let mut mask = privs_to_delete;
        while mask != 0 {
            let bit = 1u64 << mask.trailing_zeros();
            token.privileges.remove(bit);
            mask &= !bit;
        }
    }

    // Parse the variable data
    let var_data = if !data.is_null() && data_len > 0 {
        unsafe { core::slice::from_raw_parts(data, data_len as usize) }
    } else {
        &[]
    };

    // 2. Flip groups to deny-only
    let deny_end = (num_deny_indices as usize) * 4;
    if deny_end > var_data.len() {
        return core::ptr::null();
    }
    for i in 0..num_deny_indices as usize {
        let offset = i * 4;
        let idx = u32::from_le_bytes([
            var_data[offset], var_data[offset + 1],
            var_data[offset + 2], var_data[offset + 3],
        ]) as usize;
        if idx >= token.groups.len() {
            return core::ptr::null();
        }
        // Clear ENABLED, set USE_FOR_DENY_ONLY
        token.groups[idx].attributes &= !kacs_core::group::SE_GROUP_ENABLED;
        token.groups[idx].attributes |= kacs_core::group::SE_GROUP_USE_FOR_DENY_ONLY;
    }

    // 3. Parse and add restricting SIDs
    if num_restrict_sids > 0 {
        let mut sids = match compat::vec_with_capacity::<kacs_core::group::GroupEntry>(
            num_restrict_sids as usize,
        ) {
            Ok(v) => v,
            Err(_) => return core::ptr::null(),
        };

        let mut pos = deny_end;
        for _ in 0..num_restrict_sids {
            if pos + 8 > var_data.len() {
                return core::ptr::null();
            }
            let sub_count = var_data[pos + 1] as usize;
            if sub_count > 15 {
                return core::ptr::null(); // SID_MAX_SUB_AUTHORITIES
            }
            let sid_len = 8 + sub_count * 4;
            if pos + sid_len > var_data.len() {
                return core::ptr::null();
            }
            let sid = match kacs_core::sid::Sid::from_bytes(&var_data[pos..pos + sid_len]) {
                Some(s) => s,
                None => return core::ptr::null(),
            };
            if compat::vec_push(&mut sids, kacs_core::group::GroupEntry::new(
                sid,
                kacs_core::group::SE_GROUP_MANDATORY
                    | kacs_core::group::SE_GROUP_ENABLED_BY_DEFAULT
                    | kacs_core::group::SE_GROUP_ENABLED,
            )).is_err() {
                return core::ptr::null();
            }
            pos += sid_len;
        }

        token.restricted_sids = Some(sids);
    }

    match KacsToken::new(token) {
        Ok(ptr) => ptr,
        Err(_) => core::ptr::null(),
    }
}

// ── Session management ────────────────────────────────────────────────────

// ── Kernel mutex via FFI ──────────────────────────────────────────────────
//
// The session table and linked-token list are protected by kernel struct
// mutexes declared in lsm.c. Mutexes (not spinlocks) because the protected
// paths allocate memory (vec_push → GFP_KERNEL → may sleep).

extern "C" {
    fn kacs_mutex_lock_session();
    fn kacs_mutex_unlock_session();
    fn kacs_mutex_lock_linked();
    fn kacs_mutex_unlock_linked();
}

/// Sleeping mutex backed by a kernel `struct mutex` in lsm.c.
/// Each instance wraps an UnsafeCell and calls a specific C lock/unlock pair.
struct KernelMutex<T> {
    data: core::cell::UnsafeCell<T>,
    lock_fn: unsafe extern "C" fn(),
    unlock_fn: unsafe extern "C" fn(),
}

unsafe impl<T: Send> Sync for KernelMutex<T> {}
unsafe impl<T: Send> Send for KernelMutex<T> {}

impl<T> KernelMutex<T> {
    const fn new(
        data: T,
        lock_fn: unsafe extern "C" fn(),
        unlock_fn: unsafe extern "C" fn(),
    ) -> Self {
        KernelMutex {
            data: core::cell::UnsafeCell::new(data),
            lock_fn,
            unlock_fn,
        }
    }

    fn lock(&self) -> KernelMutexGuard<'_, T> {
        unsafe { (self.lock_fn)(); }
        KernelMutexGuard { mutex: self }
    }
}

struct KernelMutexGuard<'a, T> {
    mutex: &'a KernelMutex<T>,
}

impl<T> core::ops::Deref for KernelMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for KernelMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for KernelMutexGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { (self.mutex.unlock_fn)(); }
    }
}

/// Global session table, protected by kernel mutex.
static SESSION_TABLE: KernelMutex<Option<kacs_core::session::SessionTable>> =
    KernelMutex::new(None, kacs_mutex_lock_session, kacs_mutex_unlock_session);

/// Wrapper to make *const () Send (we manage lifetime manually via refcounting).
#[derive(Clone, Copy)]
struct SendPtr(*const ());
unsafe impl Send for SendPtr {}

/// Linked token pairs, protected by kernel mutex.
static LINKED_TOKENS: KernelMutex<Option<compat::Vec<(u64, SendPtr, SendPtr)>>> =
    KernelMutex::new(None, kacs_mutex_lock_linked, kacs_mutex_unlock_linked);

/// Initialize the session table and create the SYSTEM session (session 0).
/// Called once from kacs_init.
#[no_mangle]
pub extern "C" fn kacs_init_session_table(system_token: *const ()) {
    let mut table = kacs_core::session::SessionTable::new();

    if !system_token.is_null() {
        let kt = unsafe { KacsToken::from_ptr(system_token) };
        let _ = table.create_system_session(kt.token.user_sid.try_clone().unwrap_or_else(|_| {
            kacs_core::sid::Sid::new(5, &[18]).unwrap()
        }));
    }

    *SESSION_TABLE.lock() = Some(table);
    *LINKED_TOKENS.lock() = Some(compat::Vec::new());
}

/// Create a new logon session from a wire-format spec.
/// Returns session ID (>= 0) or negative errno.
#[no_mangle]
pub extern "C" fn kacs_create_session_impl(data: *const u8, len: usize) -> i64 {
    if data.is_null() {
        return -22; // -EINVAL
    }

    let spec = unsafe { core::slice::from_raw_parts(data, len) };

    let (logon_type, user_sid) = match kacs_core::session::parse_session_spec(spec) {
        Some(result) => result,
        None => return -22, // -EINVAL
    };

    let mut guard = SESSION_TABLE.lock();
    let table = match guard.as_mut() {
        Some(t) => t,
        None => return -22,
    };

    match table.create(logon_type, user_sid) {
        Ok(id) => id as i64,
        Err(_) => -12, // -ENOMEM
    }
}

/// Link an elevated/filtered token pair on a logon session.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub extern "C" fn kacs_session_link_tokens(
    session_id: u64,
    elevated: *const (),
    filtered: *const (),
) -> c_int {
    if elevated.is_null() || filtered.is_null() {
        return -22; // -EINVAL
    }

    // Verify the session exists
    let expected_logon_sid = {
        let guard = SESSION_TABLE.lock();
        let table = match guard.as_ref() {
            Some(t) => t,
            None => return -22,
        };
        let session = match table.get(session_id) {
            Some(s) => s,
            None => return -22,
        };
        match session.logon_sid() {
            Ok(sid) => sid,
            Err(_) => return -12,
        }
    };

    // Verify both tokens belong to this session (§15.2).
    let e_kt = unsafe { KacsToken::from_ptr(elevated) };
    let f_kt = unsafe { KacsToken::from_ptr(filtered) };
    if e_kt.token.logon_sid != expected_logon_sid
        || f_kt.token.logon_sid != expected_logon_sid
    {
        return -22; // -EINVAL: tokens don't belong to this session
    }

    // Clone both tokens (bump refcount)
    let e = kacs_token_clone(elevated);
    let f = kacs_token_clone(filtered);

    // Stash old pointers to drop AFTER releasing the lock — drop_ref
    // calls session_release which re-acquires LINKED_TOKENS.
    let mut deferred_drop: Option<(SendPtr, SendPtr)> = None;

    let ret = {
        let mut guard = LINKED_TOKENS.lock();
        let links = match guard.as_mut() {
            Some(l) => l,
            None => return -22,
        };

        // Replace existing link for this session, or add new
        let mut replaced = false;
        for entry in links.iter_mut() {
            if entry.0 == session_id {
                deferred_drop = Some((entry.1, entry.2));
                entry.1 = SendPtr(e);
                entry.2 = SendPtr(f);
                replaced = true;
                break;
            }
        }

        if replaced {
            0
        } else if compat::vec_push(links, (session_id, SendPtr(e), SendPtr(f))).is_err() {
            -12 // -ENOMEM (tokens dropped below)
        } else {
            0
        }
    }; // guard dropped — LINKED_TOKENS released

    if ret == -12 {
        kacs_token_drop(e);
        kacs_token_drop(f);
    }
    if let Some((old_e, old_f)) = deferred_drop {
        unsafe {
            KacsToken::drop_ref(old_e.0);
            KacsToken::drop_ref(old_f.0);
        }
    }
    ret
}

/// Get the linked partner token for a given token.
/// If the token is the elevated half, returns the filtered half (and vice versa).
/// Returns a cloned token pointer (caller owns one ref), or null if not linked.
#[no_mangle]
pub extern "C" fn kacs_session_get_linked_token(token_ptr: *const ()) -> *const () {
    if token_ptr.is_null() {
        return core::ptr::null();
    }

    let guard = LINKED_TOKENS.lock();
    let links = match guard.as_ref() {
        Some(l) => l,
        None => return core::ptr::null(),
    };

    // Find which side this token is on
    for &(_, elevated, filtered) in links.iter() {
        if core::ptr::eq(token_ptr as *const u8, elevated.0 as *const u8) {
            return kacs_token_clone(filtered.0);
        }
        if core::ptr::eq(token_ptr as *const u8, filtered.0 as *const u8) {
            return kacs_token_clone(elevated.0);
        }
    }

    core::ptr::null()
}

/// Format all active sessions into a caller-provided buffer.
/// Returns bytes written or negative errno.
#[no_mangle]
pub extern "C" fn kacs_format_sessions(buf: *mut u8, buf_len: usize) -> i64 {
    if buf.is_null() {
        return -22; // -EINVAL
    }

    let guard = SESSION_TABLE.lock();
    let table = match guard.as_ref() {
        Some(t) => t,
        None => return -22,
    };

    let mut out = FormatBuf::new();
    out.str("Sessions: ");
    out.usize(table.len());
    out.byte(b'\n');

    for i in 0..table.len() {
        // Linear scan since we don't have index access
        let mut idx = 0;
        for session in table.iter_sessions() {
            if idx == i {
                out.str("  ");
                out.u64(session.session_id);
                out.str(": ");
                format_sid(&mut out, &session.user_sid);
                out.str(" (");
                out.str(match session.logon_type {
                    kacs_core::session::LogonType::Interactive => "Interactive",
                    kacs_core::session::LogonType::Network => "Network",
                    kacs_core::session::LogonType::Batch => "Batch",
                    kacs_core::session::LogonType::Service => "Service",
                    kacs_core::session::LogonType::NetworkCleartext => "NetworkCleartext",
                    kacs_core::session::LogonType::NewCredentials => "NewCredentials",
                });
                out.str(")\n");
                break;
            }
            idx += 1;
        }
    }

    let data = out.as_bytes();
    if data.len() > buf_len {
        return -34; // -ERANGE
    }
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    data.len() as i64
}

/// Increment session refcount when a token is created.
#[no_mangle]
pub extern "C" fn kacs_session_addref(session_id: u64) {
    let guard = SESSION_TABLE.lock();
    if let Some(table) = guard.as_ref() {
        table.addref(session_id);
    }
}

/// Decrement session refcount. If it hits zero, remove the session
/// and clean up linked tokens.
#[no_mangle]
pub extern "C" fn kacs_session_release(session_id: u64) {
    let should_remove = {
        let guard = SESSION_TABLE.lock();
        match guard.as_ref() {
            Some(table) => table.release(session_id),
            None => false,
        }
    };

    if should_remove {
        // Collect token refs to drop AFTER releasing LINKED_TOKENS —
        // drop_ref calls session_release which re-acquires the lock.
        // Fixed-size array: sessions have exactly 1 linked pair in practice.
        // If a session somehow had >4 pairs, extras would be removed from
        // the list but their refs would leak. Acceptable: the real invariant
        // is 1 pair per session.
        let mut deferred_drops: [(SendPtr, SendPtr); 4] =
            [(SendPtr(core::ptr::null()), SendPtr(core::ptr::null())); 4];
        let mut drop_count = 0usize;

        // Remove linked tokens for this session
        {
            let mut guard = LINKED_TOKENS.lock();
            if let Some(links) = guard.as_mut() {
                let mut i = 0;
                while i < links.len() {
                    if links[i].0 == session_id {
                        let entry = links[i];
                        if drop_count < deferred_drops.len() {
                            deferred_drops[drop_count] = (entry.1, entry.2);
                            drop_count += 1;
                        }
                        let last = links.len() - 1;
                        if i < last {
                            links[i] = links[last];
                        }
                        links.truncate(last);
                    } else {
                        i += 1;
                    }
                }
            }
        } // guard dropped — LINKED_TOKENS released

        // Now safe to drop token refs (may cascade into session_release).
        for i in 0..drop_count {
            unsafe {
                KacsToken::drop_ref(deferred_drops[i].0.0);
                KacsToken::drop_ref(deferred_drops[i].1.0);
            }
        }

        // Remove session from table
        let mut guard = SESSION_TABLE.lock();
        if let Some(table) = guard.as_mut() {
            table.remove(session_id);
        }
    }
}

/// Called from C during LSM initialization.
#[no_mangle]
pub extern "C" fn kacs_rust_init() -> c_int {
    0
}

// ── Stack-based formatting (no allocation) ────────────────────────────────
//
// We can't use format!() or alloc::string::String in kernel context for
// simple text output. This tiny buffer handles the formatting needs of
// token display and query responses without any heap allocation.

/// Dynamically-growing format buffer for token display.
/// Uses compat::Vec<u8> — allocates in kernel via KVec.
struct FormatBuf {
    data: compat::Vec<u8>,
}

impl FormatBuf {
    fn new() -> Self {
        FormatBuf {
            data: compat::Vec::new(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    fn byte(&mut self, b: u8) {
        let _ = compat::vec_push(&mut self.data, b);
    }

    fn str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            self.byte(b);
        }
    }

    fn usize(&mut self, mut n: usize) {
        if n == 0 {
            self.byte(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut i = 0;
        while n > 0 {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            self.byte(digits[i]);
        }
    }

    fn u32(&mut self, n: u32) {
        self.usize(n as usize);
    }

    fn u64(&mut self, n: u64) {
        // For large numbers, format directly
        if n == 0 {
            self.byte(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut val = n;
        let mut i = 0;
        while val > 0 {
            digits[i] = b'0' + (val % 10) as u8;
            val /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            self.byte(digits[i]);
        }
    }

    fn hex64(&mut self, n: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if n == 0 {
            self.byte(b'0');
            return;
        }
        let mut started = false;
        for shift in (0..16).rev() {
            let nibble = ((n >> (shift * 4)) & 0xF) as usize;
            if nibble != 0 || started {
                self.byte(HEX[nibble]);
                started = true;
            }
        }
    }
}

/// Format a SID as "S-1-{authority}-{sub1}-{sub2}-..." into the buffer.
fn format_sid(out: &mut FormatBuf, sid: &kacs_core::sid::Sid) {
    out.str("S-1-");
    // Authority is a 6-byte big-endian value. If high bytes are zero,
    // print as decimal (common case). Otherwise print as hex.
    let auth = (sid.authority[0] as u64) << 40
        | (sid.authority[1] as u64) << 32
        | (sid.authority[2] as u64) << 24
        | (sid.authority[3] as u64) << 16
        | (sid.authority[4] as u64) << 8
        | (sid.authority[5] as u64);
    if auth <= 0xFFFF_FFFF {
        out.u64(auth);
    } else {
        out.str("0x");
        out.hex64(auth);
    }
    for &sa in sid.sub_authorities.iter() {
        out.byte(b'-');
        out.u32(sa);
    }
}
