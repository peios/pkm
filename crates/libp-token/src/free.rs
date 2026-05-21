// Free functions — KACS syscalls that don't naturally hang off a Token.

use crate::Result;
use crate::error::Error;
use crate::query::ImpersonationLevel;
use crate::raw;
use libp_errno::Errno;
use libp_sys::eintr_retry;

/// Restore the calling thread's effective token to its primary,
/// dropping any active impersonation.
pub fn revert() -> Result<()> {
    let rc = eintr_retry(|| unsafe { raw::revert() });
    check_ok(rc)
}

/// Begin impersonating the peer of an AF_UNIX socket. Pair with
/// [`revert`].
pub fn impersonate_peer(sock_fd: i32) -> Result<()> {
    let rc = eintr_retry(|| unsafe { raw::impersonate_peer(sock_fd) });
    check_ok(rc)
}

/// Set the impersonation level the peer of `sock_fd` will be granted
/// when the other side calls `impersonate_peer`.
pub fn set_impersonation_level(sock_fd: i32, level: ImpersonationLevel) -> Result<()> {
    let rc = eintr_retry(|| unsafe { raw::set_impersonation_level(sock_fd, level.as_u32()) });
    check_ok(rc)
}

/// Set the Process Security Block mitigation flags for the process
/// named by `pidfd`. `mitigations` is a bitmask defined by the KACS
/// UAPI.
pub fn set_psb(pidfd: i32, mitigations: u32) -> Result<()> {
    let rc = eintr_retry(|| unsafe { raw::set_psb(pidfd, mitigations) });
    check_ok(rc)
}

/// Create a new session from a msgpack-encoded spec. Returns the
/// new session id.
pub fn create_session(spec: &[u8]) -> Result<u64> {
    let rc = eintr_retry(|| unsafe { raw::create_session(spec.as_ptr(), spec.len()) });
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(rc as u64)
    }
}

/// Destroy an empty session. The session must have no remaining
/// occupants or the kernel returns -EBUSY.
pub fn destroy_empty_session(session_id: u64) -> Result<()> {
    let rc = eintr_retry(|| unsafe { raw::destroy_empty_session(session_id) });
    check_ok(rc)
}

#[inline]
fn check_ok(rc: i64) -> Result<()> {
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(())
    }
}
