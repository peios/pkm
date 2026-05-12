// peios-abi: constants, types, and parsers for the Peios kernel ABI.
//
// This crate is the shared ground truth for userspace code that talks to KACS,
// KMES, and (eventually) LCS. It is intentionally narrow:
//
//   - Numeric constants (syscall numbers, ioctl numbers, bit values, struct
//     offsets) so they only live in one place.
//   - Pure parsers/serializers for on-wire formats (SID, SECURITY_DESCRIPTOR,
//     ACL, ACE, KMES event header, msgpack).
//   - Well-known SID / privilege / access-mask lookup tables.
//
// It deliberately does NOT contain typed syscall wrappers or `unsafe` extern
// declarations. That higher-level ergonomic layer lives in libpeios-rs and
// will be added when we have enough tools to know what shape it wants.
//
// All types are pure data. The crate uses std (for Vec, String) but no
// platform-specific dependencies.

pub mod kmes;
pub mod msgpack;
pub mod sd;
pub mod sid;
pub mod syscall;
pub mod token;
