// Errors produced by the safe layer.

use peios_uapi::{Errno, ParseError};
use thiserror::Error;

/// Errors from libp-token's safe-API surface.
///
/// `Errno` covers any failure path from a KACS syscall or ioctl
/// (essentially every operation the kernel can refuse). Other variants
/// cover library-side validation, decoding, and lifecycle problems.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A syscall or ioctl returned `-errno`.
    #[error("kacs syscall failed: {0}")]
    Syscall(Errno),

    /// A token-info query returned bytes that couldn't be decoded into
    /// the requested shape (e.g. truncated SID, malformed group entry).
    #[error("token query response did not decode: {0}")]
    Decode(#[from] ParseError),

    /// The buffer returned by a query was shorter than the kernel
    /// promised in the probe step.
    #[error("token query buffer truncated: kernel said {expected} bytes, got {got}")]
    QueryTruncated { expected: u32, got: usize },

    /// A `Token` argument was the wrong kind for the operation — e.g.
    /// `install()` called on an impersonation token, or `impersonate()`
    /// on a primary token. The kernel returns -EINVAL for these but
    /// some library-side helpers pre-check.
    #[error("operation incompatible with token type: {0}")]
    WrongTokenType(&'static str),

    /// A typed enum field in a query response had an unexpected
    /// discriminant. Indicates the kernel grew a new variant we don't
    /// know about; consider upgrading peios-uapi.
    #[error("unknown {kind} discriminant: {value}")]
    UnknownDiscriminant { kind: &'static str, value: u32 },
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Syscall(e)
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Syscall(errno) => std::io::Error::from(errno),
            other => std::io::Error::other(other.to_string()),
        }
    }
}
