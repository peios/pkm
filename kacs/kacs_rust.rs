// SPDX-License-Identifier: GPL-2.0-only

//! Slow-track PKM kernel Rust scaffold.
//!
//! This file intentionally exports only a tiny init function so the first
//! kernel-facing slice can prove that Rust code is compiled, linked, and
//! invoked by the built-in PKM LSM path.

#![allow(elided_lifetimes_in_paths)]

#[path = "access_check.rs"]
mod access_check_ingress;
mod caap_cache;
mod kacs_core;
#[path = "../lcs/lcs_core/mod.rs"]
mod lcs_core;
#[path = "../lcs/rust_ingress.rs"]
mod lcs_rust_ingress;
mod kmes_payload;
#[path = "../kmes/kmes_validate.rs"]
mod kmes_validate;
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
