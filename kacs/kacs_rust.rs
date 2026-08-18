// SPDX-License-Identifier: GPL-2.0-only

//! Slow-track PKM kernel Rust scaffold.
//!
//! This file intentionally exports only a tiny init function so the first
//! kernel-facing slice can prove that Rust code is compiled, linked, and
//! invoked by the built-in PKM LSM path.

#![allow(elided_lifetimes_in_paths)]
// The semantic cores (`kacs_core`, `lcs_core`) and the LCS ingress glue are
// `pub`-API crates in their own right — their public items are exercised by
// their standalone integration-test suites, so the `pub` is load-bearing
// there. Vendored here as private modules of a crate that has no Rust
// consumers (it is linked via `#[no_mangle]` C ABI), every such `pub`
// collapses to effectively `pub(crate)`, tripping `unreachable_pub`. Both
// crates already opt out in their own `lib.rs`; staging strips that when it
// renames `lib.rs` -> `mod.rs`, so restore the opt-out at the vendoring root.
#![allow(unreachable_pub)]

// Generated UAPI constants — the ABI single source of truth, vendored by
// stage-sources.sh from uapi/generated/rust/src/zconst.rs. The semantic cores
// reference these as `crate::peios_uapi::<CONST>` (rewritten from bare
// `peios_uapi::` paths by stage-rust-core.sh). Most are unused in this build,
// so the whole module opts out of dead-code analysis.
#[allow(dead_code)]
mod peios_uapi;

#[path = "access_check.rs"]
mod access_check_ingress;
mod caap_cache;
mod kacs_core;
// `lcs_core` is the standalone LCS semantic-core crate (0 warnings on its own
// `cargo` build + 268 integration tests) vendored here as a private module.
// The kernel glue only drives a fraction of its surface so far, so the bulk of
// its API reads as dead/unused in this build only; the dead-code and
// unused-import checks have teeth in its standalone build, not here.
#[allow(dead_code, unused_imports)]
#[path = "../lcs/lcs_core/mod.rs"]
mod lcs_core;
#[path = "../lcs/rust_ingress.rs"]
mod lcs_rust_ingress;
mod kmes_payload;
#[allow(dead_code)]
#[path = "../stratafs_core/mod.rs"]
mod stratafs_core;
#[path = "../kmes/kmes_validate.rs"]
mod kmes_validate;
// KACS token-runtime scaffolding: constants, fields, and helpers for
// token-query paths not yet wired, plus a few benign local bindings (each
// individually reviewed — none are bugs). Allowed rather than deleted so the
// in-flight slow-track scaffold is preserved.
#[allow(dead_code, unused_variables, unused_assignments)]
mod token_runtime;

#[allow(hidden_glob_reexports)]
pub use kacs_core::*;

use core::ffi::c_int;

#[no_mangle]
/// Kernel-side PKM Rust init entry invoked by the built-in LSM scaffold.
pub extern "C" fn kacs_rust_init() -> c_int {
    let _ = kacs_core::kernel_compile_probe();
    let _ = lcs_core::kernel_compile_probe();
    0
}

#[no_mangle]
/// Tiny Rust probe used by PKM KUnit scaffolding to prove the staged
/// `kacs-core` tree is linked and callable.
pub extern "C" fn kacs_rust_kunit_probe() -> usize {
    kacs_core::kernel_compile_probe()
}

#[no_mangle]
/// Tiny Rust probe used by LCS KUnit scaffolding to prove the staged
/// `lcs-core` tree is linked and callable.
pub extern "C" fn lcs_rust_kunit_probe() -> usize {
    lcs_core::kernel_compile_probe()
}

#[no_mangle]
/// Validate a bounded C array of StrataFS stratum flags.
pub unsafe extern "C" fn stratafs_rust_validate_flags(
    flags: *const u32,
    count: usize,
    create_index: *mut i32,
) -> i32 {
    if flags.is_null() || create_index.is_null() || count > stratafs_core::MAX_STRATA {
        return -1;
    }
    let values = unsafe { core::slice::from_raw_parts(flags, count) };
    match stratafs_core::validate_flags(values) {
        Ok(create) => {
            unsafe { *create_index = create.map_or(-1, |index| index as i32) };
            0
        }
        Err(error) => -(error as i32),
    }
}

#[no_mangle]
/// Return the highest-precedence present stratum, or -1.
pub extern "C" fn stratafs_rust_provider(present: u64, count: usize) -> i32 {
    stratafs_core::provider(present, count).map_or(-1, |index| index as i32)
}

#[no_mangle]
/// Route one existing-object mutation under PSD-011 section 5.1.
pub extern "C" fn stratafs_rust_route_existing(
    provider: usize,
    provider_accepts: bool,
    create_index: i32,
    create_present: bool,
    copyable: bool,
    mount_read_only: bool,
) -> i32 {
    let create = (create_index >= 0).then_some(create_index as usize);
    stratafs_core::route_existing(
        provider,
        provider_accepts,
        create,
        create_present,
        copyable,
        mount_read_only,
    ) as i32
}
