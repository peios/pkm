// Errors from libp-files.

use libp_errno::Errno;
use thiserror::Error;

/// Errors from libp-files' safe-API surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// The `kacs_open` syscall returned `-errno`.
    #[error("kacs_open failed: {0}")]
    Syscall(Errno),

    /// A path argument contained an interior NUL byte.
    #[error("path contains an interior NUL byte")]
    PathHasNul,

    /// The kernel reported an open-status word libp-files doesn't
    /// recognize — indicates a kernel/library version skew.
    #[error("unknown open-status word: {0}")]
    UnknownStatus(u32),
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
