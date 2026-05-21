// Raw KMES syscall wrappers.
//
// Thin, `unsafe` translations of the three KMES syscalls onto the
// `peios-uapi::sys` syscall primitives. The safe API in `emit` and `ring`
// builds on these. `KmesEmitEntry` is re-exported so callers building an
// `emit_batch` array do not need a separate `peios-uapi` import.

use libp_sys::{syscall3, syscall4};

pub use crate::abi::KmesEmitEntry;

const SYS_KMES_EMIT: i64 = peios_uapi::SYS_KMES_EMIT as i64;
const SYS_KMES_ATTACH: i64 = peios_uapi::SYS_KMES_ATTACH as i64;
const SYS_KMES_EMIT_BATCH: i64 = peios_uapi::SYS_KMES_EMIT_BATCH as i64;

/// `kmes_emit(event_type, event_type_len, payload, payload_len)`.
///
/// Returns 0 on success or `-errno`.
///
/// # Safety
/// `event_type` must point to `event_type_len` readable bytes and
/// `payload` to `payload_len` readable bytes.
#[inline]
pub unsafe fn emit(
    event_type: *const u8,
    event_type_len: u16,
    payload: *const u8,
    payload_len: u32,
) -> i64 {
    unsafe {
        syscall4(
            SYS_KMES_EMIT,
            event_type as u64,
            event_type_len as u64,
            payload as u64,
            payload_len as u64,
        )
    }
}

/// `kmes_attach(fds, count, capacity)`.
///
/// Returns 0 on success or `-errno` (notably `-ERANGE` when the `fds`
/// buffer is too small — `*count` is then set to the required length).
///
/// # Safety
/// `count` must point to a writable `i32` holding the number of slots in
/// the `fds` buffer; `fds` must point to that many writable `i32`s.
/// `capacity` must point to a writable `u64`.
#[inline]
pub unsafe fn attach(fds: *mut i32, count: *mut i32, capacity: *mut u64) -> i64 {
    unsafe { syscall3(SYS_KMES_ATTACH, fds as u64, count as u64, capacity as u64) }
}

/// `kmes_emit_batch(entries, count, emitted_out)`.
///
/// Returns 0 on full success or `-errno`; `*emitted_out` carries the
/// number of events accepted before any failure.
///
/// # Safety
/// `entries` must point to `count` valid [`KmesEmitEntry`] values, each
/// with live `event_type`/`payload` pointers. `emitted_out` must point to
/// a writable `u32`.
#[inline]
pub unsafe fn emit_batch(entries: *const KmesEmitEntry, count: u32, emitted_out: *mut u32) -> i64 {
    unsafe {
        syscall3(
            SYS_KMES_EMIT_BATCH,
            entries as u64,
            count as u64,
            emitted_out as u64,
        )
    }
}
