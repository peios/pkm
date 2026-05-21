// KMES ring + emit ABI surface for libp-event: per-CPU ring-buffer layout
// (metadata page offsets, magic, sizes), the batch-emit descriptor, the
// origin classes, and the batch limit.
//
// Constant *values* come from the generated `peios-uapi` crate; this module
// re-exposes the ring-layout offsets under the historical short names the
// `Ring` consumer uses. The event-header parser and `Origin` newtype live in
// `libp-wire` (the shared on-wire-primitives crate); this module is the
// KMES-specific ring/emit half.

// ---------------------------------------------------------------------------
// Origin classes.
// ---------------------------------------------------------------------------

pub const KMES_ORIGIN_USERSPACE: u8 = peios_uapi::KMES_ORIGIN_USERSPACE as u8;
pub const KMES_ORIGIN_KMES: u8 = peios_uapi::KMES_ORIGIN_KMES as u8;
pub const KMES_ORIGIN_KACS: u8 = peios_uapi::KMES_ORIGIN_KACS as u8;
pub const KMES_ORIGIN_LCS: u8 = peios_uapi::KMES_ORIGIN_LCS as u8;

// ---------------------------------------------------------------------------
// Page sizes and producer-metadata offsets.
// ---------------------------------------------------------------------------

pub const METADATA_PAGE_SIZE: usize = peios_uapi::KMES_METADATA_PAGE_SIZE as usize;
pub const METADATA_TOTAL_SIZE: usize = peios_uapi::KMES_METADATA_TOTAL_SIZE as usize;

/// Magic identifying a KMES ring metadata page ("KMESRING").
pub const RING_MAGIC: [u8; 8] = *peios_uapi::KMES_RING_MAGIC;

pub const P_MAGIC: usize = peios_uapi::KMES_PRODUCER_MAGIC_OFFSET as usize;
pub const P_VERSION: usize = peios_uapi::KMES_PRODUCER_VERSION_OFFSET as usize;
pub const P_CPU_ID: usize = peios_uapi::KMES_PRODUCER_CPU_ID_OFFSET as usize;
pub const P_CAPACITY: usize = peios_uapi::KMES_PRODUCER_CAPACITY_OFFSET as usize;
pub const P_DATA_OFFSET: usize = peios_uapi::KMES_PRODUCER_DATA_OFFSET_OFFSET as usize;
pub const P_GENERATION: usize = peios_uapi::KMES_PRODUCER_GENERATION_OFFSET as usize;
pub const P_WRITE_POS: usize = peios_uapi::KMES_PRODUCER_WRITE_POS_OFFSET as usize;
pub const P_TAIL_POS: usize = peios_uapi::KMES_PRODUCER_TAIL_POS_OFFSET as usize;
pub const P_FUTEX_COUNTER: usize = peios_uapi::KMES_PRODUCER_FUTEX_COUNTER_OFFSET as usize;

pub const C_NEED_WAKE: usize = peios_uapi::KMES_CONSUMER_NEED_WAKE_OFFSET as usize;

/// Ring-buffer format version this crate understands (PSD-003 §8: v0.20
/// uses version 1).
pub const RING_VERSION: u32 = peios_uapi::KMES_RING_VERSION;

/// Total mmap size for a ring with the given capacity (in bytes).
pub fn ring_mapping_size(capacity: u64) -> usize {
    METADATA_TOTAL_SIZE + 2 * (capacity as usize)
}

// ---------------------------------------------------------------------------
// Event header base size — the byte offset of the event-type string within
// a header. The header parser itself is `libp_wire::EventHeader`.
// ---------------------------------------------------------------------------

pub const HDR_BASE: usize = peios_uapi::KMES_EVENT_HEADER_BASE_SIZE as usize;

// ---------------------------------------------------------------------------
// kmes_emit_batch — batch event emission (syscall 1092).
// ---------------------------------------------------------------------------

/// Maximum number of entries accepted by a single `kmes_emit_batch` call.
pub const KMES_MAX_BATCH: u32 = peios_uapi::KMES_BATCH_MAX_ENTRIES;

/// One descriptor in a `kmes_emit_batch` entry array.
///
/// Mirrors `struct kmes_emit_entry` — C-ABI natural alignment, 32 bytes on
/// x86-64 (layout cross-checked against the generated `peios_uapi`
/// definition in the tests below). The two pointer fields are stored as raw
/// address bits so the struct is `Copy` and FFI-trivial.
///
/// | Offset | Size | Field            |
/// |--------|------|------------------|
/// | 0      | 8    | `event_type` ptr |
/// | 8      | 2    | `event_type_len` |
/// | 10     | 6    | padding          |
/// | 16     | 8    | `payload` ptr    |
/// | 24     | 4    | `payload_len`    |
/// | 28     | 4    | padding          |
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KmesEmitEntry {
    /// Address bits of the event type string.
    pub event_type: u64,
    /// Length of the event type string in bytes.
    pub event_type_len: u16,
    _pad0: [u8; 6],
    /// Address bits of the msgpack payload.
    pub payload: u64,
    /// Length of the payload in bytes.
    pub payload_len: u32,
    _pad1: [u8; 4],
}

impl KmesEmitEntry {
    /// Build an entry from raw pointers and lengths. The pointers must
    /// remain valid for the duration of the `kmes_emit_batch` call that
    /// consumes the entry array.
    #[inline]
    pub fn new(
        event_type: *const u8,
        event_type_len: u16,
        payload: *const u8,
        payload_len: u32,
    ) -> Self {
        Self {
            event_type: event_type as u64,
            event_type_len,
            _pad0: [0; 6],
            payload: payload as u64,
            payload_len,
            _pad1: [0; 4],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        // The kernel writes this exact byte sequence at producer offset 0.
        assert_eq!(RING_MAGIC, [0x4b, 0x4d, 0x45, 0x53, 0x52, 0x49, 0x4e, 0x47]);
    }

    #[test]
    fn emit_entry_layout() {
        use core::mem::{align_of, offset_of, size_of};
        // Must match `struct kmes_emit_entry` byte-for-byte (PSD-003 §4.3).
        assert_eq!(size_of::<KmesEmitEntry>(), 32);
        assert_eq!(align_of::<KmesEmitEntry>(), 8);
        assert_eq!(offset_of!(KmesEmitEntry, event_type), 0);
        assert_eq!(offset_of!(KmesEmitEntry, event_type_len), 8);
        assert_eq!(offset_of!(KmesEmitEntry, payload), 16);
        assert_eq!(offset_of!(KmesEmitEntry, payload_len), 24);
    }

    /// The hand-rolled `KmesEmitEntry` must stay byte-compatible with the
    /// generated `kmes_emit_entry` mirror of the kernel struct.
    #[test]
    fn emit_entry_matches_generated() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(
            size_of::<KmesEmitEntry>(),
            size_of::<peios_uapi::kmes_emit_entry>()
        );
        assert_eq!(
            align_of::<KmesEmitEntry>(),
            align_of::<peios_uapi::kmes_emit_entry>()
        );
        assert_eq!(
            offset_of!(KmesEmitEntry, event_type),
            offset_of!(peios_uapi::kmes_emit_entry, event_type)
        );
        assert_eq!(
            offset_of!(KmesEmitEntry, event_type_len),
            offset_of!(peios_uapi::kmes_emit_entry, event_type_len)
        );
        assert_eq!(
            offset_of!(KmesEmitEntry, payload),
            offset_of!(peios_uapi::kmes_emit_entry, payload)
        );
        assert_eq!(
            offset_of!(KmesEmitEntry, payload_len),
            offset_of!(peios_uapi::kmes_emit_entry, payload_len)
        );
    }
}
