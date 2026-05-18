// Event types: the borrowed `Event` view and the owned `OwnedEvent` copy.

use alloc::vec::Vec;
use peios_uapi::kmes;

/// A parsed KMES event borrowed directly from a ring buffer's mapped
/// memory.
///
/// This is [`peios_uapi::kmes::EventHeader`] — a zero-copy view whose
/// `event_type` and `payload` slices point into the ring. It is valid
/// only until the read cursor advances; copy it with [`OwnedEvent::from`]
/// to keep it longer or move it across a thread boundary.
pub type Event<'a> = kmes::EventHeader<'a>;

/// The subsystem an event originated from (`origin_class`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Emitted from userspace via the `kmes_emit` syscall.
    Userspace,
    /// Emitted by KMES itself.
    Kmes,
    /// Emitted by KACS.
    Kacs,
    /// Emitted by LCS.
    Lcs,
    /// An origin class this build does not recognise.
    Other(u8),
}

impl Origin {
    /// Classify a raw `origin_class` byte.
    pub fn from_raw(o: u8) -> Self {
        match o {
            kmes::KMES_ORIGIN_USERSPACE => Origin::Userspace,
            kmes::KMES_ORIGIN_KMES => Origin::Kmes,
            kmes::KMES_ORIGIN_KACS => Origin::Kacs,
            kmes::KMES_ORIGIN_LCS => Origin::Lcs,
            other => Origin::Other(other),
        }
    }

    /// The raw `origin_class` byte.
    pub fn as_raw(self) -> u8 {
        match self {
            Origin::Userspace => kmes::KMES_ORIGIN_USERSPACE,
            Origin::Kmes => kmes::KMES_ORIGIN_KMES,
            Origin::Kacs => kmes::KMES_ORIGIN_KACS,
            Origin::Lcs => kmes::KMES_ORIGIN_LCS,
            Origin::Other(o) => o,
        }
    }
}

/// A KMES event copied out of the ring buffer into owned memory.
///
/// Produced by [`OwnedEvent::from`] on a borrowed [`Event`], or returned
/// by the blocking [`Ring::read`](crate::Ring::read). An owned event has
/// no tie to the ring's mapped memory, so it survives cursor advances and
/// can be sent to another thread — which PSD-008 §2.2 requires before an
/// event crosses the drain-thread boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEvent {
    /// Total event size in bytes (header + payload).
    pub event_size: u32,
    /// Header size in bytes; the payload begins at this offset.
    pub header_size: u32,
    /// Wall-clock emission time, nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// Per-CPU, per-boot monotonic sequence number.
    pub sequence: u64,
    /// CPU the event was emitted on.
    pub cpu_id: u16,
    /// Raw `origin_class` byte; see [`Origin`].
    pub origin: u8,
    /// The event type string (UTF-8, not NUL-terminated).
    pub event_type: Vec<u8>,
    /// The msgpack-encoded payload.
    pub payload: Vec<u8>,
}

impl OwnedEvent {
    /// The origin subsystem, classified.
    pub fn origin(&self) -> Origin {
        Origin::from_raw(self.origin)
    }

    /// The event type as a string, if it is valid UTF-8.
    pub fn event_type_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.event_type).ok()
    }
}

impl From<&Event<'_>> for OwnedEvent {
    fn from(e: &Event<'_>) -> Self {
        OwnedEvent {
            event_size: e.event_size,
            header_size: e.header_size,
            timestamp_ns: e.timestamp_ns,
            sequence: e.sequence,
            cpu_id: e.cpu_id,
            origin: e.origin,
            event_type: e.event_type.to_vec(),
            payload: e.payload.to_vec(),
        }
    }
}
