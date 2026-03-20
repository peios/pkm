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
use core::sync::atomic::{AtomicUsize, Ordering};

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
    fn new(token: Token) -> Result<*const (), AllocError> {
        // Use kernel's allocator via compat::Vec trick — allocate a
        // Vec<KacsToken> of capacity 1, push, then leak the pointer.
        // This is the simplest way to heap-allocate without alloc::boxed::Box.
        let mut v = compat::vec_with_capacity::<KacsToken>(1)?;
        compat::vec_push(&mut v, KacsToken {
            token,
            refcount: AtomicUsize::new(1),
        })?;
        let ptr = v.as_ptr();
        core::mem::forget(v); // leak — we manage lifetime via refcount
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
            let ptr_mut = ptr as *mut KacsToken;
            drop(unsafe { compat::Vec::from_raw_parts(ptr_mut, 1, 1) });
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
    out.hex64(token.privileges.enabled);
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

const TOKEN_CLASS_USER: u32 = 1;
const TOKEN_CLASS_GROUPS: u32 = 2;
const TOKEN_CLASS_PRIVILEGES: u32 = 3;
const TOKEN_CLASS_TYPE: u32 = 4;
const TOKEN_CLASS_INTEGRITY_LEVEL: u32 = 5;
const TOKEN_CLASS_ELEVATION_TYPE: u32 = 13;
const TOKEN_CLASS_MANDATORY_POLICY: u32 = 17;

/// Query token information by class.
/// If buf is NULL, returns the required buffer size.
/// If buf is non-NULL, writes data and returns bytes written.
/// Returns negative errno on error.
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

    // Format the response for this query class into a stack buffer.
    let mut out = FormatBuf::new();
    match class {
        TOKEN_CLASS_USER => format_sid(&mut out, &token.user_sid),
        TOKEN_CLASS_GROUPS => {
            out.usize(token.groups.len());
            for g in token.groups.iter() {
                out.byte(b'\n');
                format_sid(&mut out, &g.sid);
                out.str(" attrs=0x");
                out.hex64(g.attributes as u64);
            }
        }
        TOKEN_CLASS_PRIVILEGES => {
            out.str("present=0x");
            out.hex64(token.privileges.present);
            out.str("\nenabled=0x");
            out.hex64(token.privileges.enabled);
        }
        TOKEN_CLASS_TYPE => out.str(match token.token_type {
            TokenType::Primary => "Primary",
            TokenType::Impersonation => "Impersonation",
        }),
        TOKEN_CLASS_INTEGRITY_LEVEL => out.str(match token.integrity_level {
            IntegrityLevel::Untrusted => "Untrusted",
            IntegrityLevel::Low => "Low",
            IntegrityLevel::Medium => "Medium",
            IntegrityLevel::High => "High",
            IntegrityLevel::System => "System",
        }),
        TOKEN_CLASS_ELEVATION_TYPE => out.str(match token.elevation_type {
            kacs_core::token::ElevationType::Default => "Default",
            kacs_core::token::ElevationType::Full => "Full",
            kacs_core::token::ElevationType::Limited => "Limited",
        }),
        TOKEN_CLASS_MANDATORY_POLICY => {
            out.str("0x");
            out.hex64(token.mandatory_policy as u64);
        }
        _ => return -22, // -EINVAL: unsupported class
    };

    let data = out.as_bytes();

    // Size query
    if buf.is_null() {
        return data.len() as i32;
    }

    // Buffer too small
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
    if data.is_null() || len < 56 {
        return core::ptr::null();
    }

    let spec = unsafe { core::slice::from_raw_parts(data, len) };

    match kacs_core::token_spec::parse_token_spec(spec) {
        Ok(Some(token)) => match KacsToken::new(token) {
            Ok(ptr) => ptr,
            Err(_) => core::ptr::null(),
        },
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

    // Run the full AccessCheck pipeline.
    match kacs_core::access_check::access_check(
        &sd,
        &kt.token,
        desired,
        &mapping,
        None,           // no object type tree
        None,           // no PRINCIPAL_SELF SID
        &[],            // no local claims
        &[],            // no central access policies
        0,              // no privilege intent (backup/restore)
    ) {
        Ok(result) => {
            if result.allowed {
                result.granted as i64
            } else {
                0 // denied — no bits granted
            }
        }
        Err(kacs_core::access_check::AccessCheckError::IdentificationLevel) => -1,  // -EPERM
        Err(kacs_core::access_check::AccessCheckError::InvalidSecurityDescriptor) => -22, // -EINVAL
        Err(kacs_core::access_check::AccessCheckError::AllocationFailed) => -12, // -ENOMEM
    }
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
/// # Safety
/// Caller must ensure exclusive access. In practice this is called on
/// freshly-cloned tokens before they're shared.
#[no_mangle]
pub extern "C" fn kacs_token_set_impersonation_level(ptr: *const (), level: c_int) {
    if ptr.is_null() {
        return;
    }
    let kt = unsafe { &mut *(ptr as *mut KacsToken) };
    kt.token.impersonation_level = match level {
        0 => ImpersonationLevel::Anonymous,
        1 => ImpersonationLevel::Identification,
        2 => ImpersonationLevel::Impersonation,
        3 => ImpersonationLevel::Delegation,
        _ => return,
    };
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

// ── Privilege adjustment ──────────────────────────────────────────────────

/// Adjust privileges on a token: enable, disable, or permanently remove.
/// Returns 0 on success, negative errno on error.
#[no_mangle]
pub extern "C" fn kacs_token_adjust_privs(
    ptr: *const (),
    enable_mask: u64,
    disable_mask: u64,
    remove_mask: u64,
) -> c_int {
    if ptr.is_null() {
        return -22; // -EINVAL
    }
    // Safety: privilege adjustment needs &mut. In the kernel, the real
    // implementation will use interior atomics on the Privileges fields.
    // For now, we use unsafe mutable access — safe because privilege
    // adjustment is serialized by the ioctl path (one caller at a time).
    let kt = unsafe { &mut *(ptr as *mut KacsToken) };
    let privs = &mut kt.token.privileges;

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

// ── Session management ────────────────────────────────────────────────────

/// Global session table. Initialized at boot.
/// Safety: accessed from syscall context (serialized by kernel locks).
static mut SESSION_TABLE: Option<kacs_core::session::SessionTable> = None;

/// Initialize the session table and create the SYSTEM session (session 0).
/// Called once from kacs_init.
#[no_mangle]
pub extern "C" fn kacs_init_session_table(system_token: *const ()) {
    let mut table = kacs_core::session::SessionTable::new();

    if !system_token.is_null() {
        let kt = unsafe { KacsToken::from_ptr(system_token) };
        let _ = table.create_system_session(kt.token.user_sid.try_clone().unwrap_or_else(|_| {
            // Fallback: if clone fails at boot, system is dying
            kacs_core::sid::Sid::new(5, &[18]).unwrap()
        }));
    }

    unsafe { SESSION_TABLE = Some(table); }
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

    let table = unsafe {
        match SESSION_TABLE.as_mut() {
            Some(t) => t,
            None => return -22,
        }
    };

    match table.create(logon_type, user_sid) {
        Ok(id) => id as i64,
        Err(_) => -12, // -ENOMEM
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

/// Fixed-size buffer for formatting token info without allocation.
struct FormatBuf {
    data: [u8; 512],
    pos: usize,
}

impl FormatBuf {
    fn new() -> Self {
        FormatBuf {
            data: [0u8; 512],
            pos: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    fn byte(&mut self, b: u8) {
        if self.pos < self.data.len() {
            self.data[self.pos] = b;
            self.pos += 1;
        }
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
