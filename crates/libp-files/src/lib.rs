// libp-files: safe Rust wrappers for the Peios KACS native file open.
//
// `kacs_open` is the NtCreateFile-shaped open — it takes a desired
// access mask, a create disposition, create options, and an optional
// security descriptor for newly-created files. This crate wraps it as:
//
//   - `OpenOptions` — a fluent builder for the open parameters.
//   - `FileHandle`  — an owned fd, closed on drop.
//   - `OpenStatus`  — what actually happened (opened/created/...).
//
// `no_std + alloc` by default; the `std` feature adds
// `FileHandle::as_fd()` and `From<Error> for std::io::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod open;
pub mod raw;

pub use error::Error;
pub use open::{Disposition, FileHandle, OpenOptions, OpenStatus};

/// Re-exported access-mask + create-option constants for callers
/// building `OpenOptions`.
pub mod consts {
    pub use peios_uapi::file::{
        KACS_BACKUP_INTENT, KACS_CREATE_OPT_DELETE_ON_CLOSE, KACS_CREATE_OPT_DIRECTORY,
        KACS_RESTORE_INTENT,
    };
    pub use peios_uapi::sd::{
        ACCESS_DELETE, ACCESS_GENERIC_ALL, ACCESS_GENERIC_EXECUTE, ACCESS_GENERIC_READ,
        ACCESS_GENERIC_WRITE, ACCESS_READ_CONTROL, ACCESS_SYNCHRONIZE, ACCESS_WRITE_DAC,
        ACCESS_WRITE_OWNER,
    };
}

/// Crate-local `Result<T, Error>` alias.
pub type Result<T> = core::result::Result<T, Error>;
