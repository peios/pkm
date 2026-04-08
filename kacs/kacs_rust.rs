// SPDX-License-Identifier: GPL-2.0-only

//! Slow-track PKM kernel Rust scaffold.
//!
//! This file intentionally exports only a tiny init function so the first
//! kernel-facing slice can prove that Rust code is compiled, linked, and
//! invoked by the built-in PKM LSM path.

#![no_std]

use core::ffi::c_int;

#[no_mangle]
pub extern "C" fn kacs_rust_init() -> c_int {
    0
}
