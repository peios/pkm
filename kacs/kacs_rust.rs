// SPDX-License-Identifier: GPL-2.0

//! KACS kernel module — Rust implementation.
//!
//! Phase 1: minimal token object with SYSTEM identity, reference counting,
//! and text formatting. No heap allocation — the SYSTEM token is a static.
//! kacs-core integration comes in Phase 3 when we need AccessCheck.

#![no_std]

use core::ffi::c_int;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Token object ──────────────────────────────────────────────────────────

/// Minimal kernel token. Replaced by kacs-core Token in Phase 3.
struct KacsToken {
    user_sid: &'static str,
    integrity: &'static str,
    token_type: u8,
    refcount: AtomicUsize,
}

/// The SYSTEM token. Lives for the lifetime of the kernel.
/// Refcount starts at 1 (owned by init_cred).
static SYSTEM_TOKEN: KacsToken = KacsToken {
    user_sid: "S-1-5-18",
    integrity: "System",
    token_type: 1, // Primary
    refcount: AtomicUsize::new(0), // set to 1 on first use
};

/// Fixed text output for the SYSTEM token.
const SYSTEM_TOKEN_INFO: &[u8] = b"User:      S-1-5-18\nType:      Primary\nIntegrity: System\n";

// ── FFI exports (called from lsm.c) ──────────────────────────────────────

/// Create the SYSTEM token. Returns a pointer to the static token.
/// Caller owns one reference.
#[no_mangle]
pub extern "C" fn kacs_token_create_system() -> *const () {
    SYSTEM_TOKEN.refcount.store(1, Ordering::Relaxed);
    &SYSTEM_TOKEN as *const KacsToken as *const ()
}

/// Clone a token (increment refcount). Returns the same pointer.
#[no_mangle]
pub extern "C" fn kacs_token_clone(ptr: *const ()) -> *const () {
    if ptr.is_null() {
        return core::ptr::null();
    }
    let token = unsafe { &*(ptr as *const KacsToken) };
    token.refcount.fetch_add(1, Ordering::Relaxed);
    ptr
}

/// Drop a token reference.
/// For the static SYSTEM token, refcount just decrements (never freed).
/// Dynamic tokens (Phase 3+) will actually free on zero.
#[no_mangle]
pub extern "C" fn kacs_token_drop(ptr: *const ()) {
    if ptr.is_null() {
        return;
    }
    let token = unsafe { &*(ptr as *const KacsToken) };
    token.refcount.fetch_sub(1, Ordering::Release);
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

    // Phase 1: all tokens are the SYSTEM token
    let info = SYSTEM_TOKEN_INFO;
    if info.len() > buf_len {
        return -34; // -ERANGE
    }

    unsafe {
        core::ptr::copy_nonoverlapping(info.as_ptr(), buf, info.len());
    }
    info.len() as i64
}

// ── Token query (KACS_IOC_QUERY) ──────────────────────────────────────────

// Query class constants (must match lsm.c)
const TOKEN_CLASS_USER: u32 = 1;
const TOKEN_CLASS_TYPE: u32 = 4;
const TOKEN_CLASS_INTEGRITY_LEVEL: u32 = 5;

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

    let token = unsafe { &*(ptr as *const KacsToken) };

    // Get the response bytes for this query class
    let data: &[u8] = match class {
        TOKEN_CLASS_USER => token.user_sid.as_bytes(),
        TOKEN_CLASS_TYPE => match token.token_type {
            1 => b"Primary",
            2 => b"Impersonation",
            _ => b"Unknown",
        },
        TOKEN_CLASS_INTEGRITY_LEVEL => token.integrity.as_bytes(),
        _ => return -22, // -EINVAL: unsupported class
    };

    // Size query
    if buf.is_null() {
        return data.len() as i32;
    }

    // Buffer too small — return required size
    if (buf_len as usize) < data.len() {
        return data.len() as i32;
    }

    // Write data
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
    }
    data.len() as i32
}

/// Called from C during LSM initialization.
#[no_mangle]
pub extern "C" fn kacs_rust_init() -> c_int {
    0
}
