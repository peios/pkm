// Raw `kacs_open` syscall wrapper.

use crate::abi::KacsOpenHow;
use libp_sys::syscall5;

const SYS_KACS_OPEN: i64 = peios_uapi::SYS_KACS_OPEN as i64;

/// `AT_FDCWD` — dirfd value meaning "current working directory". A generic
/// Linux at-family constant (-100), not part of the KACS ABI headers.
pub const AT_FDCWD: i32 = -100;

/// `kacs_open(dirfd, path, how, howsize, status_out)`.
///
/// Returns a file descriptor on success or `-errno`. On success the
/// kernel writes a `KACS_STATUS_*` word into `*status_out`.
///
/// # Safety
/// `path` must point to a NUL-terminated string. `how` must point to a
/// valid `KacsOpenHow` of at least `howsize` bytes. If `status_out` is
/// non-null it must point to a writable `u32`. If `how.sd_ptr` is set
/// it must point to `how.sd_len` readable bytes.
#[inline]
pub unsafe fn open(
    dirfd: i32,
    path: *const u8,
    how: *const KacsOpenHow,
    howsize: usize,
    status_out: *mut u32,
) -> i64 {
    unsafe {
        syscall5(
            SYS_KACS_OPEN,
            dirfd as u64,
            path as u64,
            how as u64,
            howsize as u64,
            status_out as u64,
        )
    }
}
