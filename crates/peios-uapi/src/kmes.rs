// KMES — Kernel-Mediated Event Stream. Per-CPU ring buffers, attached via
// syscall(1091) returning one fd per CPU. Each fd is mmap-only.
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
// Origin classes — pkm_new/kacs/kmes.h.
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
    pub fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < HDR_BASE {
            return Err("event header truncated");
        }
        let event_size = u32::from_le_bytes(bytes[H_EVENT_SIZE..H_EVENT_SIZE + 4].try_into().unwrap());
        let header_size = u32::from_le_bytes(bytes[H_HEADER_SIZE..H_HEADER_SIZE + 4].try_into().unwrap());
        let timestamp_ns = u64::from_le_bytes(bytes[H_TIMESTAMP..H_TIMESTAMP + 8].try_into().unwrap());
        let sequence = u64::from_le_bytes(bytes[H_SEQUENCE..H_SEQUENCE + 8].try_into().unwrap());
        let cpu_id = u16::from_le_bytes(bytes[H_CPU_ID..H_CPU_ID + 2].try_into().unwrap());
        let origin = bytes[H_ORIGIN];
        let etlen = u16::from_le_bytes(bytes[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2].try_into().unwrap()) as usize;

        let type_start = HDR_BASE;
        let type_end = type_start + etlen;
        let total = event_size as usize;
        if total < HDR_BASE || total > bytes.len() || type_end > total {
            return Err("event size or type-length invalid");
        }
        Ok(Self {
            event_size,
            header_size,
            timestamp_ns,
            sequence,
            cpu_id,
            origin,
            event_type: &bytes[type_start..type_end],
            payload: &bytes[type_end..total],
        })
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
}
