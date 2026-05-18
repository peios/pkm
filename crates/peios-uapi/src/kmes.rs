// KMES — Kernel-Mediated Event Stream. Per-CPU ring buffers, attached via
// syscall(1091) returning one fd per CPU. Each fd is mmap-only.

use crate::parse::ParseError;
//
// mmap layout (page-sized, page=4096):
//   page 0           : producer metadata (read-only)
//   page 1           : consumer metadata (read-write)
//   pages 2..2+cap   : ring data (read-only)
//   pages 2+cap..    : same ring data, mirror-mapped (lets readers
//   2+2*cap            consume an event that wraps the end of the buffer
//                      as a single contiguous memcpy)
//
// Event header (29 bytes, little-endian):
//   u32 event_size      — total bytes including header
//   u32 header_size     — bytes before the payload (header_base + type)
//   u64 timestamp       — ktime_get_real_ns() at emit time
//   u64 sequence        — monotonic per ring
//   u16 cpu_id
//   u8  origin_class    — KMES_ORIGIN_*
//   u16 event_type_len
//   then event_type bytes
//   then payload bytes  — kernel validator requires this to parse as msgpack

// ---------------------------------------------------------------------------
// Origin classes — kmes/kmes.h.
// ---------------------------------------------------------------------------

pub const KMES_ORIGIN_USERSPACE: u8 = 0;
pub const KMES_ORIGIN_KMES: u8 = 1;
pub const KMES_ORIGIN_KACS: u8 = 2;
pub const KMES_ORIGIN_LCS: u8 = 3;

pub fn origin_name(o: u8) -> &'static str {
    match o {
        KMES_ORIGIN_USERSPACE => "USER",
        KMES_ORIGIN_KMES => "KMES",
        KMES_ORIGIN_KACS => "KACS",
        KMES_ORIGIN_LCS => "LCS",
        _ => "????",
    }
}

// ---------------------------------------------------------------------------
// Page sizes and producer-metadata offsets (from kmes.c #defines).
// ---------------------------------------------------------------------------

pub const PAGE_SIZE: usize = 4096;
pub const METADATA_PAGE_SIZE: usize = 4096;
pub const METADATA_TOTAL_SIZE: usize = 2 * METADATA_PAGE_SIZE;

/// Magic identifying a KMES ring metadata page ("KMESRING").
pub const RING_MAGIC: [u8; 8] = *b"KMESRING";

pub const P_MAGIC: usize = 0;
pub const P_VERSION: usize = 8;
pub const P_CPU_ID: usize = 12;
pub const P_CAPACITY: usize = 16;
pub const P_DATA_OFFSET: usize = 24;
pub const P_GENERATION: usize = 32;
pub const P_WRITE_POS: usize = 64;
pub const P_TAIL_POS: usize = 72;
pub const P_FUTEX_COUNTER: usize = 128;

pub const C_NEED_WAKE: usize = 0;

/// Total mmap size for a ring with the given capacity (in bytes).
pub fn ring_mapping_size(capacity: u64) -> usize {
    METADATA_TOTAL_SIZE + 2 * (capacity as usize)
}

// ---------------------------------------------------------------------------
// Event header offsets within the 29-byte base.
// ---------------------------------------------------------------------------

pub const H_EVENT_SIZE: usize = 0;
pub const H_HEADER_SIZE: usize = 4;
pub const H_TIMESTAMP: usize = 8;
pub const H_SEQUENCE: usize = 16;
pub const H_CPU_ID: usize = 24;
pub const H_ORIGIN: usize = 26;
pub const H_EVENT_TYPE_LEN: usize = 27;
pub const HDR_BASE: usize = 29;

/// Parsed KMES event header.
pub struct EventHeader<'a> {
    pub event_size: u32,
    pub header_size: u32,
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub cpu_id: u16,
    pub origin: u8,
    pub event_type: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> EventHeader<'a> {
    /// Parse one event laid out at the start of `bytes`. The slice must be at
    /// least `event_size` bytes long.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HDR_BASE {
            return Err(ParseError::EventHeaderTruncated);
        }
        let event_size =
            u32::from_le_bytes(bytes[H_EVENT_SIZE..H_EVENT_SIZE + 4].try_into().unwrap());
        let header_size =
            u32::from_le_bytes(bytes[H_HEADER_SIZE..H_HEADER_SIZE + 4].try_into().unwrap());
        let timestamp_ns =
            u64::from_le_bytes(bytes[H_TIMESTAMP..H_TIMESTAMP + 8].try_into().unwrap());
        let sequence = u64::from_le_bytes(bytes[H_SEQUENCE..H_SEQUENCE + 8].try_into().unwrap());
        let cpu_id = u16::from_le_bytes(bytes[H_CPU_ID..H_CPU_ID + 2].try_into().unwrap());
        let origin = bytes[H_ORIGIN];
        let etlen = u16::from_le_bytes(
            bytes[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
                .try_into()
                .unwrap(),
        ) as usize;

        let type_start = HDR_BASE;
        let type_end = type_start + etlen;
        let total = event_size as usize;
        let hdr = header_size as usize;
        // Structural validation. The payload is located via `header_size`,
        // not the end of the event type string: PSD-003 §2.2 mandates this
        // so consumers stay correct if a future header revision inserts
        // reserved fields between the type string and the payload.
        if total < HDR_BASE
            || total > bytes.len()
            || hdr < HDR_BASE
            || hdr > total
            || type_end > hdr
        {
            return Err(ParseError::EventSizeInvalid);
        }
        Ok(Self {
            event_size,
            header_size,
            timestamp_ns,
            sequence,
            cpu_id,
            origin,
            event_type: &bytes[type_start..type_end],
            payload: &bytes[hdr..total],
        })
    }
}

// ---------------------------------------------------------------------------
// kmes_emit_batch — batch event emission (syscall 1092).
// ---------------------------------------------------------------------------

/// Maximum number of entries accepted by a single `kmes_emit_batch` call.
pub const KMES_MAX_BATCH: u32 = 256;

/// One descriptor in a `kmes_emit_batch` entry array.
///
/// Mirrors `struct kmes_emit_entry` — C-ABI natural alignment, 32 bytes on
/// x86-64. The two pointer fields are stored as raw address bits so the
/// struct is `Copy` and FFI-trivial.
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

    /// Build a synthetic event with `header_size == HDR_BASE + type_len`
    /// (the v0.20 minimum) and round-trip it through `EventHeader::parse`.
    #[test]
    fn parse_minimal_event() {
        let type_str = b"test.event";
        let payload = b"\x81\xa1k\x01";
        let header_size = HDR_BASE + type_str.len();
        let event_size = header_size + payload.len();

        let mut buf = alloc::vec![0u8; event_size];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(event_size as u32).to_le_bytes());
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4].copy_from_slice(&(header_size as u32).to_le_bytes());
        buf[H_TIMESTAMP..H_TIMESTAMP + 8].copy_from_slice(&123u64.to_le_bytes());
        buf[H_SEQUENCE..H_SEQUENCE + 8].copy_from_slice(&7u64.to_le_bytes());
        buf[H_CPU_ID..H_CPU_ID + 2].copy_from_slice(&2u16.to_le_bytes());
        buf[H_ORIGIN] = KMES_ORIGIN_KACS;
        buf[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
            .copy_from_slice(&(type_str.len() as u16).to_le_bytes());
        buf[HDR_BASE..HDR_BASE + type_str.len()].copy_from_slice(type_str);
        buf[header_size..].copy_from_slice(payload);

        let ev = EventHeader::parse(&buf).unwrap();
        assert_eq!(ev.event_size, event_size as u32);
        assert_eq!(ev.timestamp_ns, 123);
        assert_eq!(ev.sequence, 7);
        assert_eq!(ev.cpu_id, 2);
        assert_eq!(ev.origin, KMES_ORIGIN_KACS);
        assert_eq!(ev.event_type, type_str);
        assert_eq!(ev.payload, payload);
    }

    /// `header_size` larger than `HDR_BASE + type_len` — a reserved gap.
    /// The payload MUST still be located via `header_size`.
    #[test]
    fn parse_uses_header_size_for_payload() {
        let type_str = b"x";
        let gap = 8usize;
        let header_size = HDR_BASE + type_str.len() + gap;
        let payload = b"\xc3";
        let event_size = header_size + payload.len();

        let mut buf = alloc::vec![0u8; event_size];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(event_size as u32).to_le_bytes());
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4].copy_from_slice(&(header_size as u32).to_le_bytes());
        buf[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
            .copy_from_slice(&(type_str.len() as u16).to_le_bytes());
        buf[HDR_BASE..HDR_BASE + type_str.len()].copy_from_slice(type_str);
        buf[header_size..].copy_from_slice(payload);

        let ev = EventHeader::parse(&buf).unwrap();
        assert_eq!(ev.event_type, type_str);
        assert_eq!(ev.payload, payload);
    }

    #[test]
    fn parse_rejects_header_size_past_event() {
        let mut buf = alloc::vec![0u8; HDR_BASE];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(HDR_BASE as u32).to_le_bytes());
        // header_size declares more bytes than the event has.
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4]
            .copy_from_slice(&(HDR_BASE as u32 + 16).to_le_bytes());
        assert!(matches!(
            EventHeader::parse(&buf),
            Err(crate::parse::ParseError::EventSizeInvalid)
        ));
    }
}
