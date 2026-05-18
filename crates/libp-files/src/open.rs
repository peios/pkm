// `OpenOptions` builder, `FileHandle`, and the safe `kacs_open` wrapper.

use crate::Result;
use crate::error::Error;
use crate::raw;
use alloc::ffi::CString;
use alloc::vec::Vec;
use core::mem::size_of;
use peios_uapi::errno::{Errno, eintr_retry};
use peios_uapi::file::{
    KACS_BACKUP_INTENT, KACS_CREATE_OPT_DELETE_ON_CLOSE, KACS_CREATE_OPT_DIRECTORY,
    KACS_FILE_CREATE, KACS_FILE_OPEN, KACS_FILE_OPEN_IF, KACS_FILE_OVERWRITE,
    KACS_FILE_OVERWRITE_IF, KACS_FILE_SUPERSEDE, KACS_RESTORE_INTENT, KACS_STATUS_CREATED,
    KACS_STATUS_OPENED, KACS_STATUS_OVERWRITTEN, KACS_STATUS_SUPERSEDED, KacsOpenHow,
};
use peios_uapi::sys;

/// How `kacs_open` should behave when the target does / doesn't exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Replace the file wholesale if present; create it if absent.
    Supersede,
    /// Open an existing file; fail with `ENOENT` if absent.
    Open,
    /// Create a new file; fail with `EEXIST` if present.
    Create,
    /// Open if present, create if absent.
    OpenIf,
    /// Open + truncate an existing file; fail if absent.
    Overwrite,
    /// Open + truncate if present, create if absent.
    OverwriteIf,
}

impl Disposition {
    fn to_u32(self) -> u32 {
        match self {
            Disposition::Supersede => KACS_FILE_SUPERSEDE,
            Disposition::Open => KACS_FILE_OPEN,
            Disposition::Create => KACS_FILE_CREATE,
            Disposition::OpenIf => KACS_FILE_OPEN_IF,
            Disposition::Overwrite => KACS_FILE_OVERWRITE,
            Disposition::OverwriteIf => KACS_FILE_OVERWRITE_IF,
        }
    }
}

/// What `kacs_open` actually did, reported alongside the handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStatus {
    /// An existing file was opened.
    Opened,
    /// A new file was created.
    Created,
    /// An existing file was opened and truncated.
    Overwritten,
    /// An existing file was replaced wholesale.
    Superseded,
}

impl OpenStatus {
    fn from_u32(v: u32) -> Result<Self> {
        match v {
            KACS_STATUS_OPENED => Ok(OpenStatus::Opened),
            KACS_STATUS_CREATED => Ok(OpenStatus::Created),
            KACS_STATUS_OVERWRITTEN => Ok(OpenStatus::Overwritten),
            KACS_STATUS_SUPERSEDED => Ok(OpenStatus::Superseded),
            other => Err(Error::UnknownStatus(other)),
        }
    }
}

/// An owned KACS file handle. Closes its fd on drop.
#[derive(Debug)]
pub struct FileHandle {
    fd: i32,
}

impl FileHandle {
    /// Wrap an existing fd.
    ///
    /// # Safety
    /// `fd` must be a valid open file descriptor exclusively owned by
    /// this `FileHandle`.
    pub unsafe fn from_raw_fd(fd: i32) -> Self {
        FileHandle { fd }
    }

    /// The raw fd. The `FileHandle` retains ownership.
    #[inline]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    /// Borrowed fd for std I/O APIs.
    #[cfg(feature = "std")]
    #[inline]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // Safety: `self.fd` is valid for the lifetime of `&self`.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) }
    }

    /// Consume the handle, returning the bare fd. The caller becomes
    /// responsible for closing it.
    #[inline]
    pub fn into_raw_fd(self) -> i32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        // Safety: we own `fd` exclusively.
        unsafe {
            let _ = sys::close(self.fd);
        }
    }
}

/// Fluent builder for a `kacs_open` call.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    desired_access: u32,
    disposition: Disposition,
    create_options: u32,
    flags: u32,
    sd: Option<Vec<u8>>,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions {
            desired_access: 0,
            disposition: Disposition::Open,
            create_options: 0,
            flags: 0,
            sd: None,
        }
    }
}

impl OpenOptions {
    /// A fresh builder: `Open` disposition, no access bits, no options.
    pub fn new() -> Self {
        OpenOptions::default()
    }

    /// Set the desired-access mask (MS-DTYP access bits).
    pub fn desired_access(mut self, mask: u32) -> Self {
        self.desired_access = mask;
        self
    }

    /// Set the create disposition.
    pub fn disposition(mut self, d: Disposition) -> Self {
        self.disposition = d;
        self
    }

    /// Require the target to be (or be created as) a directory.
    pub fn directory(mut self) -> Self {
        self.create_options |= KACS_CREATE_OPT_DIRECTORY;
        self
    }

    /// Delete the file when the last handle to it closes.
    pub fn delete_on_close(mut self) -> Self {
        self.create_options |= KACS_CREATE_OPT_DELETE_ON_CLOSE;
        self
    }

    /// Open with backup intent.
    pub fn backup_intent(mut self) -> Self {
        self.flags |= KACS_BACKUP_INTENT;
        self
    }

    /// Open with restore intent.
    pub fn restore_intent(mut self) -> Self {
        self.flags |= KACS_RESTORE_INTENT;
        self
    }

    /// Attach a self-relative security descriptor applied to the file
    /// if this open creates it. Ignored for opens of existing files.
    pub fn security_descriptor(mut self, sd: Vec<u8>) -> Self {
        self.sd = Some(sd);
        self
    }

    /// Open `path` relative to the current working directory.
    pub fn open(&self, path: &str) -> Result<(FileHandle, OpenStatus)> {
        self.open_at(raw::AT_FDCWD, path)
    }

    /// Open `path` relative to `dirfd` (use [`raw::AT_FDCWD`] for cwd).
    pub fn open_at(&self, dirfd: i32, path: &str) -> Result<(FileHandle, OpenStatus)> {
        let cpath = CString::new(path).map_err(|_| Error::PathHasNul)?;
        let (sd_ptr, sd_len) = match &self.sd {
            Some(bytes) if !bytes.is_empty() => (bytes.as_ptr() as u64, bytes.len() as u32),
            _ => (0, 0),
        };
        let how = KacsOpenHow {
            desired_access: self.desired_access,
            create_disposition: self.disposition.to_u32(),
            create_options: self.create_options,
            flags: self.flags,
            sd_ptr,
            sd_len,
            __pad: 0,
        };
        let mut status: u32 = 0;
        let rc = eintr_retry(|| unsafe {
            raw::open(
                dirfd,
                cpath.as_ptr() as *const u8,
                &how,
                size_of::<KacsOpenHow>(),
                &mut status,
            )
        });
        if rc < 0 {
            return Err(Error::Syscall(Errno::from_raw(rc)));
        }
        let handle = FileHandle { fd: rc as i32 };
        let status = OpenStatus::from_u32(status)?;
        Ok((handle, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_values_match_uapi() {
        assert_eq!(Disposition::Open.to_u32(), KACS_FILE_OPEN);
        assert_eq!(Disposition::Create.to_u32(), KACS_FILE_CREATE);
        assert_eq!(Disposition::OverwriteIf.to_u32(), KACS_FILE_OVERWRITE_IF);
    }

    #[test]
    fn create_options_accumulate() {
        let opts = OpenOptions::new().directory().delete_on_close();
        assert_eq!(
            opts.create_options,
            KACS_CREATE_OPT_DIRECTORY | KACS_CREATE_OPT_DELETE_ON_CLOSE
        );
    }

    #[test]
    fn status_decode_rejects_unknown() {
        assert_eq!(OpenStatus::from_u32(1).unwrap(), OpenStatus::Opened);
        assert!(matches!(
            OpenStatus::from_u32(99),
            Err(Error::UnknownStatus(99))
        ));
    }
}
