// SPDX-License-Identifier: GPL-2.0-only

//! PNP kernel bridge: the C ABI between net/pnp's hooks and the staged
//! `pnp-core` semantic crate.
//!
//! v0 surface: the compile probe and the policy generation counter.
//! Generation 0 = no policy has ever ingested; the engine is loudly
//! permissive (ratified). The evaluator entry points and the registry
//! policy builder land with the LCS ingestion path — evaluation in packet
//! context needs the atomic-allocation treatment before it can be called
//! from a softirq, which is that change's first order of business.

use core::sync::atomic::{AtomicU64, Ordering};

/// Current policy generation. 0 until the first registry ingestion commits.
static PNP_GENERATION: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
/// Proves the staged `pnp-core` tree is linked and callable; returns its
/// known constant (`MAX_PROMPT_CHAIN`).
pub extern "C" fn pnp_rust_kunit_probe() -> usize {
    crate::pnp_core::kernel_compile_probe()
}

#[no_mangle]
/// The current policy generation (0 = permissive, nothing ever ingested).
pub extern "C" fn pnp_rust_generation() -> u64 {
    PNP_GENERATION.load(Ordering::Acquire)
}
