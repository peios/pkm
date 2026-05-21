// libp-token: safe Rust wrappers for the Peios KACS token API.
//
// Covers the userspace surface for KACS tokens — opens (self / process /
// thread / peer), creation, sessions, impersonation, all token-fd ioctls
// (query, adjust_*, duplicate, install, restrict, link, etc.).
//
// Layered as:
//
//   `raw::*`    — numeric-return wrappers over `libp_sys`. Caller
//                  inspects the return code, no EINTR retry, no RAII.
//   crate root  — safe API: `Token` (owned fd with Drop), typed errors,
//                  `Result<T, Error>` returns, EINTR retry on syscalls.
//
// Two-layer split: tests and tools that want raw semantics drop into
// `raw::`; everyday consumers use the safe top-level.
//
// `no_std + alloc` by default; the `std` feature (enabled by default)
// adds `Token::as_fd()` and `From<Error> for std::io::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod abi;
mod error;
mod query;
pub mod raw;
mod token;

pub use error::Error;
pub use query::{ElevationType, ImpersonationLevel, QueryClass, TokenType};
pub use token::{SelfOpenFlags, Token};

// Free functions for syscalls that don't naturally hang off a Token.
mod free;
pub use free::{
    create_session, destroy_empty_session, impersonate_peer, revert, set_impersonation_level,
    set_psb,
};

/// Re-exports of the KACS token ABI surface (constants, ioctl numbers, arg
/// structs) plus the shared `Errno` / SID types, for callers that want them
/// without an extra dependency. Values are sourced from the generated
/// `peios-uapi` crate; see [`crate::abi`].
pub mod uapi {
    pub use crate::abi::*;
    pub use libp_errno::Errno;
    pub use libp_wire::{Sid, SidRef};
}

/// Crate-local `Result<T, Error>` alias.
pub type Result<T> = core::result::Result<T, Error>;
