// libp-event: safe Rust wrappers for the Peios KMES event stream.
//
// KMES (Kernel-Mediated Event Stream) carries events from kernel and
// userspace emitters to consumers through per-CPU, double-mapped,
// shared-memory ring buffers. This crate wraps both halves of the ABI:
//
//   - `emit` / `emit_batch` — push events into KMES from userspace.
//   - `Ring`               — attach to one per-CPU ring buffer and drain
//                            it following the PSD-003 §5.1 read protocol.
//   - `Event` / `OwnedEvent` — a parsed event, either borrowed directly
//                            from the ring (zero-copy) or copied out.
//
// ## Reading: borrowed vs owned
//
// `Ring::next` is the hot path: a lock-free, syscall-free drain that
// yields an `Event<'_>` borrowing the ring's mapped memory. The borrow is
// tied to `&mut Ring`, so the read cursor cannot advance while the event
// is held. To keep an event past the next drain step — in particular to
// hand it to another thread — copy it with `OwnedEvent::from`.
//
// `Ring::read` blocks (futex notification wait) and returns an
// `OwnedEvent`: once you have blocked you are no longer in a tight drain
// loop, and an owned copy frees the caller from the cursor borrow.
//
// Per PSD-003 the ring-read wait treats a signal as cancellation — it
// does *not* retry `EINTR`, surfacing it as `Error::Interrupted`.
//
// `no_std + alloc` by default; the `std` feature adds
// `From<Error> for std::io::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod abi;
mod emit;
mod error;
mod event;
pub mod raw;
mod ring;

pub use emit::{EmitEntry, emit, emit_batch};
pub use error::Error;
pub use event::{Event, Origin, OwnedEvent};
pub use ring::Ring;

/// Crate-local `Result<T, Error>` alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Re-exported KMES ring + emit ABI surface for callers (origin classes,
/// batch limit, ring-layout offsets). Values are sourced from the generated
/// `peios-uapi` crate; see [`crate::abi`].
pub mod consts {
    pub use crate::abi::*;
}
