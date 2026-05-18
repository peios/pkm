// Errors from libp-event.

use peios_uapi::{Errno, ParseError};
use thiserror::Error;

/// Errors from libp-event's safe-API surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A KMES syscall (`kmes_emit`, `kmes_attach`, `kmes_emit_batch`)
    /// returned `-errno`.
    #[error("KMES syscall failed: {0}")]
    Syscall(Errno),

    /// `mmap` of a ring buffer file descriptor failed.
    #[error("mapping the ring buffer failed: {0}")]
    Map(Errno),

    /// A futex notification wait was interrupted by a signal. Per PSD-003
    /// the ring-read path treats a signal as cancellation and does not
    /// retry — the caller decides whether to resume.
    #[error("event wait interrupted by a signal")]
    Interrupted,

    /// The mapped region's magic bytes are not `KMESRING` — the file
    /// descriptor is not a KMES ring buffer.
    #[error("ring buffer magic mismatch")]
    BadMagic,

    /// The ring buffer format version is not the one this crate supports.
    #[error("unsupported ring buffer version {found} (expected {expected})")]
    Version {
        /// Version word read from the producer metadata page.
        found: u32,
        /// Version this build of libp-event understands.
        expected: u32,
    },

    /// The ring buffer was resized: its generation counter advanced. The
    /// caller must re-attach (`Ring::attach_all`) to obtain fresh file
    /// descriptors. Surfaced only once the old buffer is fully drained.
    #[error("ring buffer generation changed; re-attach required")]
    GenerationChanged,

    /// An event read from the ring buffer could not be parsed.
    #[error("malformed event: {0}")]
    Parse(ParseError),

    /// An event type string or payload exceeded the length the KMES ABI
    /// can express (`u16` for the type, `u32` for the payload).
    #[error("event field too long for the KMES ABI")]
    FieldTooLong,

    /// `emit_batch` emitted some — but not all — of the requested events
    /// before the kernel rejected an entry.
    #[error("emit_batch emitted {emitted} event(s) then failed: {errno}")]
    PartialBatch {
        /// Number of events the kernel accepted before the failure.
        emitted: u32,
        /// Why the failing entry was rejected.
        errno: Errno,
    },
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Syscall(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Syscall(errno) | Error::Map(errno) => std::io::Error::from(errno),
            other => std::io::Error::other(other.to_string()),
        }
    }
}
