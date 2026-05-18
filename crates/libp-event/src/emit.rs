// Userspace event emission: `kmes_emit` and `kmes_emit_batch`.

use alloc::vec::Vec;
use peios_uapi::Errno;
use peios_uapi::errno::{self, eintr_retry};
use peios_uapi::kmes::{KMES_MAX_BATCH, KmesEmitEntry};

use crate::Result;
use crate::error::Error;
use crate::raw;

/// Emit a single event into KMES.
///
/// `event_type` is an arbitrary UTF-8 type tag; `payload` must be a valid
/// msgpack-encoded value (the kernel rejects a non-msgpack or empty
/// payload with `EINVAL`). The caller's effective token must hold
/// `SeAuditPrivilege`.
///
/// The event lands in the ring buffer of whichever CPU the calling thread
/// is running on.
pub fn emit(event_type: &str, payload: &[u8]) -> Result<()> {
    let et = event_type.as_bytes();
    if et.len() > u16::MAX as usize || payload.len() > u32::MAX as usize {
        return Err(Error::FieldTooLong);
    }
    let rc = eintr_retry(|| unsafe {
        raw::emit(
            et.as_ptr(),
            et.len() as u16,
            payload.as_ptr(),
            payload.len() as u32,
        )
    });
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(())
    }
}

/// One event to emit as part of an [`emit_batch`] call.
#[derive(Debug, Clone, Copy)]
pub struct EmitEntry<'a> {
    event_type: &'a str,
    payload: &'a [u8],
}

impl<'a> EmitEntry<'a> {
    /// Build an entry from a type tag and a msgpack payload.
    pub fn new(event_type: &'a str, payload: &'a [u8]) -> Self {
        Self {
            event_type,
            payload,
        }
    }
}

/// Emit several events as a single `kmes_emit_batch` syscall.
///
/// All events share one timestamp and amortise the privilege check and
/// notification over the whole batch. `entries` must hold between 1 and
/// [`KMES_MAX_BATCH`] events.
///
/// The kernel processes entries in order and stops at the first rejected
/// one: if entry *N* fails, entries `0..N` are emitted and the call
/// returns [`Error::PartialBatch`] carrying *N* and the reason.
pub fn emit_batch(entries: &[EmitEntry<'_>]) -> Result<()> {
    if entries.is_empty() || entries.len() > KMES_MAX_BATCH as usize {
        return Err(Error::Syscall(Errno::new(errno::EINVAL)));
    }

    // Each `KmesEmitEntry` holds raw pointers into the caller's slices;
    // `entries` outlives this call, so the pointers stay valid for the
    // syscall below.
    let mut raw_entries: Vec<KmesEmitEntry> = Vec::with_capacity(entries.len());
    for e in entries {
        let et = e.event_type.as_bytes();
        if et.len() > u16::MAX as usize || e.payload.len() > u32::MAX as usize {
            return Err(Error::FieldTooLong);
        }
        raw_entries.push(KmesEmitEntry::new(
            et.as_ptr(),
            et.len() as u16,
            e.payload.as_ptr(),
            e.payload.len() as u32,
        ));
    }

    let mut emitted: u32 = 0;
    let rc = eintr_retry(|| unsafe {
        raw::emit_batch(raw_entries.as_ptr(), raw_entries.len() as u32, &mut emitted)
    });
    if rc < 0 {
        let errno = Errno::from_raw(rc);
        if emitted > 0 {
            return Err(Error::PartialBatch { emitted, errno });
        }
        return Err(Error::Syscall(errno));
    }
    Ok(())
}
