// SPDX-License-Identifier: GPL-2.0-only

//! Kernel-owned CAAP policy cache glue.
//!
//! This module keeps the kernel cache as an opaque Rust object so the kernel
//! path reuses the pure `kacs-core` CAAP parser/cache semantics directly.

#![allow(unreachable_pub)]

use crate::caap::{CaapPolicyCache, CaapPolicyEntry};
use crate::error::KacsError;
use core::ffi::{c_int, c_long, c_void};

const EINVAL: c_int = -22;
const ENOMEM: c_int = -12;

extern "C" {
    fn pkm_kacs_zalloc(size: usize) -> *mut c_void;
    fn pkm_kacs_free(ptr: *mut c_void);
}

struct PkmKacsCaapCache {
    cache: CaapPolicyCache,
}

impl PkmKacsCaapCache {
    unsafe fn from_ptr<'a>(ptr: *const c_void) -> Option<&'a Self> {
        unsafe { (ptr as *const Self).as_ref() }
    }

    unsafe fn from_mut_ptr<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        unsafe { (ptr as *mut Self).as_mut() }
    }
}

#[no_mangle]
/// Allocates an empty kernel CAAP policy cache.
pub extern "C" fn kacs_rust_caap_cache_create() -> *mut c_void {
    let cache_ptr = unsafe { pkm_kacs_zalloc(core::mem::size_of::<PkmKacsCaapCache>()) }
        as *mut PkmKacsCaapCache;
    if cache_ptr.is_null() {
        return core::ptr::null_mut();
    }

    let cache = PkmKacsCaapCache {
        cache: CaapPolicyCache::default(),
    };
    unsafe { core::ptr::write(cache_ptr, cache) };
    cache_ptr.cast()
}

#[no_mangle]
/// Frees a kernel CAAP policy cache allocated by `kacs_rust_caap_cache_create`.
pub extern "C" fn kacs_rust_caap_cache_destroy(cache: *mut c_void) {
    if cache.is_null() {
        return;
    }

    let cache_ptr = cache as *mut PkmKacsCaapCache;
    unsafe { core::ptr::drop_in_place(cache_ptr) };
    unsafe { pkm_kacs_free(cache_ptr.cast()) };
}

#[no_mangle]
/// Applies internal `kacs_set_caap` replace/remove semantics to a kernel cache.
pub extern "C" fn kacs_rust_caap_cache_set(
    cache: *mut c_void,
    policy_sid_ptr: *const u8,
    policy_sid_len: usize,
    spec_ptr: *const u8,
    spec_len: usize,
) -> c_int {
    let Some(cache) = (unsafe { PkmKacsCaapCache::from_mut_ptr(cache) }) else {
        return EINVAL;
    };
    let Ok(policy_sid) = kernel_slice(policy_sid_ptr, policy_sid_len) else {
        return EINVAL;
    };
    let spec = if spec_ptr.is_null() || spec_len == 0 {
        None
    } else {
        match kernel_slice(spec_ptr, spec_len) {
            Ok(spec) => Some(spec),
            Err(errno) => return errno,
        }
    };

    match cache.cache.set_policy_spec(policy_sid, spec) {
        Ok(()) => 0,
        Err(error) => map_kacs_error(error),
    }
}

#[no_mangle]
/// Returns the number of policies currently installed in a kernel CAAP cache.
pub extern "C" fn kacs_rust_caap_cache_len(cache: *const c_void) -> usize {
    let Some(cache) = (unsafe { PkmKacsCaapCache::from_ptr(cache) }) else {
        return 0;
    };
    cache.cache.entries().len()
}

/// Borrows policy entries from a locked cache for one AccessCheck execution.
pub(crate) fn with_caap_policies<T>(
    cache: *const c_void,
    f: impl FnOnce(&[CaapPolicyEntry<'_>]) -> Result<T, c_long>,
) -> Result<T, c_long> {
    let Some(cache) = (unsafe { PkmKacsCaapCache::from_ptr(cache) }) else {
        return Err(EINVAL as c_long);
    };
    let entries = cache.cache.borrowed_entries().map_err(map_kacs_error_long)?;
    f(entries.as_slice())
}

fn kernel_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(EINVAL);
    }
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn map_kacs_error(error: KacsError) -> c_int {
    match error {
        KacsError::AllocationFailure => ENOMEM,
        _ => EINVAL,
    }
}

fn map_kacs_error_long(error: KacsError) -> c_long {
    map_kacs_error(error) as c_long
}
