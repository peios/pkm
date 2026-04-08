// SPDX-License-Identifier: GPL-2.0-only

//! Slow-track PKM kernel Rust scaffold.
//!
//! This file intentionally exports only a tiny init function so the first
//! kernel-facing slice can prove that Rust code is compiled, linked, and
//! invoked by the built-in PKM LSM path.

#![allow(elided_lifetimes_in_paths)]

mod kacs_core;

#[allow(hidden_glob_reexports)]
pub use kacs_core::*;

use core::ffi::c_int;

#[no_mangle]
pub extern "C" fn kacs_rust_init() -> c_int {
    let _ = kacs_core::kernel_compile_probe();
    0
}
