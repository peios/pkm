// peios-uapi: constants, types, parsers, and raw syscall stubs for the
// Peios kernel ABI.
//
// This crate is the shared ground truth for userspace code that talks to
// KACS, KMES, and (eventually) LCS. It is intentionally narrow:
//
//   - Numeric constants (syscall numbers, ioctl numbers, bit values, struct
//     offsets) so they only live in one place.
//   - Pure parsers/serializers for on-wire formats (SID, SECURITY_DESCRIPTOR,
//     ACL, ACE, KMES event header, msgpack).
//   - Well-known SID / privilege / access-mask lookup tables.
//   - Raw syscall invocation primitives (`sys` module — direct inline asm,
//     no libc).
//
// It deliberately does NOT contain typed safe-API wrappers or RAII handles.
// That higher-level ergonomic layer lives in the `libp-*` crates and
// consumes this crate's surface.
//
// `no_std + alloc` by default. The `std` feature (enabled by default)
// adds `From<Errno> for std::io::Error` and other std-only conveniences;
// disabling it produces a libc-free build suitable for unusual targets
// (recovery shells, embedded contexts, future Tier 3).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod access;
pub mod errno;
pub mod file;
pub mod kmes;
pub mod msgpack;
pub mod parse;
pub mod process;
pub mod sd;
pub mod sid;
pub mod sys;
pub mod syscall;
pub mod token;

pub use errno::Errno;
pub use parse::ParseError;
