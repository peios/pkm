// Raw syscall + ioctl wrappers for KACS tokens.
//
// Every function here is `unsafe`, returns the raw signed kernel return
// code, and does NOT retry on EINTR. Callers that want typed errors,
// RAII, and EINTR-transparent behavior should use the safe top-level
// API instead.
//
// These exist for:
//   - The safe layer to call into.
//   - Validation tools that want direct control (e.g. whoami-token).
//   - Tests that need to assert specific errno paths.

use crate::abi::*;
use libp_sys::{ioctl, syscall1, syscall2, syscall3};

// KACS syscall numbers. `libp_sys::syscallN` take an `i64` number; the
// generated `peios-uapi` constants are `u32`, so they are narrowed to `i64`
// here once rather than at every call site.
const SYS_KACS_OPEN_SELF_TOKEN: i64 = peios_uapi::SYS_KACS_OPEN_SELF_TOKEN as i64;
const SYS_KACS_OPEN_PROCESS_TOKEN: i64 = peios_uapi::SYS_KACS_OPEN_PROCESS_TOKEN as i64;
const SYS_KACS_OPEN_THREAD_TOKEN: i64 = peios_uapi::SYS_KACS_OPEN_THREAD_TOKEN as i64;
const SYS_KACS_OPEN_PEER_TOKEN: i64 = peios_uapi::SYS_KACS_OPEN_PEER_TOKEN as i64;
const SYS_KACS_CREATE_TOKEN: i64 = peios_uapi::SYS_KACS_CREATE_TOKEN as i64;
const SYS_KACS_CREATE_SESSION: i64 = peios_uapi::SYS_KACS_CREATE_SESSION as i64;
const SYS_KACS_DESTROY_EMPTY_SESSION: i64 = peios_uapi::SYS_KACS_DESTROY_EMPTY_SESSION as i64;
const SYS_KACS_SET_PSB: i64 = peios_uapi::SYS_KACS_SET_PSB as i64;
const SYS_KACS_IMPERSONATE_PEER: i64 = peios_uapi::SYS_KACS_IMPERSONATE_PEER as i64;
const SYS_KACS_REVERT: i64 = peios_uapi::SYS_KACS_REVERT as i64;
const SYS_KACS_SET_IMPERSONATION_LEVEL: i64 = peios_uapi::SYS_KACS_SET_IMPERSONATION_LEVEL as i64;

// ---------------------------------------------------------------------------
// Syscalls — token opens, creation, sessions, impersonation control.
// ---------------------------------------------------------------------------

/// `kacs_open_self_token(flags, access_mask)`. Returns fd or `-errno`.
///
/// # Safety
/// The kernel does no validation that the caller is allowed to receive
/// the access_mask requested beyond standard KACS rules; the returned
/// fd carries whatever the kernel granted.
#[inline]
pub unsafe fn open_self_token(flags: u32, access_mask: u32) -> i64 {
    unsafe { syscall2(SYS_KACS_OPEN_SELF_TOKEN, flags as u64, access_mask as u64) }
}

/// `kacs_open_process_token(pidfd, access_mask)`. Returns fd or `-errno`.
///
/// # Safety
/// `pidfd` must be a valid pidfd open in the caller's process. The
/// kernel validates the requested access_mask against the caller's
/// rights over the target process.
#[inline]
pub unsafe fn open_process_token(pidfd: i32, access_mask: u32) -> i64 {
    unsafe {
        syscall2(
            SYS_KACS_OPEN_PROCESS_TOKEN,
            pidfd as u64,
            access_mask as u64,
        )
    }
}

/// `kacs_open_thread_token(pidfd, tid, access_mask)`. Returns fd or `-errno`.
///
/// # Safety
/// See `open_process_token`. `tid` must be a valid thread id within
/// the process named by `pidfd`.
#[inline]
pub unsafe fn open_thread_token(pidfd: i32, tid: i32, access_mask: u32) -> i64 {
    unsafe {
        syscall3(
            SYS_KACS_OPEN_THREAD_TOKEN,
            pidfd as u64,
            tid as u64,
            access_mask as u64,
        )
    }
}

/// `kacs_open_peer_token(sock_fd)`. Returns fd or `-errno`.
///
/// # Safety
/// `sock_fd` must reference a connected AF_UNIX socket whose peer the
/// kernel has captured a token for.
#[inline]
pub unsafe fn open_peer_token(sock_fd: i32) -> i64 {
    unsafe { syscall1(SYS_KACS_OPEN_PEER_TOKEN, sock_fd as u64) }
}

/// `kacs_create_token(spec, spec_len)`. Returns fd or `-errno`.
///
/// # Safety
/// `spec` must point to a valid byte buffer of at least `spec_len`
/// bytes encoding a token-creation spec (msgpack per the KACS UAPI).
#[inline]
pub unsafe fn create_token(spec: *const u8, spec_len: usize) -> i64 {
    unsafe { syscall2(SYS_KACS_CREATE_TOKEN, spec as u64, spec_len as u64) }
}

/// `kacs_create_session(spec, spec_len)`. Returns session_id on
/// success (>= 0) or `-errno`.
///
/// # Safety
/// `spec` must point to a valid byte buffer encoding a session spec.
#[inline]
pub unsafe fn create_session(spec: *const u8, spec_len: usize) -> i64 {
    unsafe { syscall2(SYS_KACS_CREATE_SESSION, spec as u64, spec_len as u64) }
}

/// `kacs_destroy_empty_session(session_id)`. Returns 0 or `-errno`.
///
/// # Safety
/// `session_id` must be a session the caller has rights to destroy and
/// which must have no remaining occupants.
#[inline]
pub unsafe fn destroy_empty_session(session_id: u64) -> i64 {
    unsafe { syscall1(SYS_KACS_DESTROY_EMPTY_SESSION, session_id) }
}

/// `kacs_set_psb(pidfd, mitigations)`. Returns 0 or `-errno`.
///
/// # Safety
/// `pidfd` must be a valid pidfd. `mitigations` is a bit-vector of
/// PSB activation flags whose meaning is defined by the KACS UAPI.
#[inline]
pub unsafe fn set_psb(pidfd: i32, mitigations: u32) -> i64 {
    unsafe { syscall2(SYS_KACS_SET_PSB, pidfd as u64, mitigations as u64) }
}

/// `kacs_impersonate_peer(sock_fd)`. Returns 0 or `-errno`.
///
/// # Safety
/// `sock_fd` must be a connected AF_UNIX socket. On success the
/// caller's effective token is set to the peer's; restore with
/// `revert()` when done.
#[inline]
pub unsafe fn impersonate_peer(sock_fd: i32) -> i64 {
    unsafe { syscall1(SYS_KACS_IMPERSONATE_PEER, sock_fd as u64) }
}

/// `kacs_revert()`. Returns 0 or `-errno`. Drops the calling thread's
/// impersonation state, restoring the real token.
///
/// # Safety
/// Safe in itself (no pointer args, no resource lifecycle), but
/// declared `unsafe` for ABI consistency with the rest of `raw::`.
#[inline]
pub unsafe fn revert() -> i64 {
    unsafe { libp_sys::syscall0(SYS_KACS_REVERT) }
}

/// `kacs_set_impersonation_level(sock_fd, level)`. Returns 0 or `-errno`.
///
/// # Safety
/// `sock_fd` must be a connected AF_UNIX socket the caller controls.
/// `level` must be one of `KACS_LEVEL_*`.
#[inline]
pub unsafe fn set_impersonation_level(sock_fd: i32, level: u32) -> i64 {
    unsafe {
        syscall2(
            SYS_KACS_SET_IMPERSONATION_LEVEL,
            sock_fd as u64,
            level as u64,
        )
    }
}

// ---------------------------------------------------------------------------
// Token-fd ioctls.
//
// Each ioctl below builds the struct argument inline. Most expect a
// pointer to a struct laid out in `peios_uapi::token`; some are
// argument-less (`KACS_IOC_INSTALL`, `KACS_IOC_IMPERSONATE`).
// ---------------------------------------------------------------------------

/// `KACS_IOC_QUERY` on a token fd. Probes (with `buf_len = 0`) to learn
/// the required size, then fetches with the caller-provided buffer.
///
/// `args` points to a fully-initialized `KacsQueryArgs` (caller sets
/// `token_class`, `buf_len`, `buf_ptr` as appropriate).
///
/// # Safety
/// `fd` must be an open KACS token fd held with `KACS_TOKEN_QUERY`
/// access. `args` must be a valid mutable pointer. If `buf_ptr` is
/// nonzero, it must point to at least `buf_len` writable bytes.
#[inline]
pub unsafe fn query(fd: i32, args: *mut KacsQueryArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_QUERY, args as u64) }
}

/// `KACS_IOC_ADJUST_PRIVS` on a token fd. `args` references a
/// pre-populated `kacs_adjust_privs_args` from `peios_uapi::token`.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ADJUST_PRIVS`. `args.data_ptr` must
/// point to `args.count` `kacs_priv_entry` records.
#[inline]
pub unsafe fn adjust_privs(fd: i32, args: *mut KacsAdjustPrivsArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_ADJUST_PRIVS, args as u64) }
}

/// `KACS_IOC_DUPLICATE` on a token fd. Writes the new fd into
/// `args.result_fd` on success.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_DUPLICATE`. `args` is a valid mutable
/// pointer to a `kacs_duplicate_args` with `access_mask`,
/// `token_type`, and `impersonation_level` set.
#[inline]
pub unsafe fn duplicate(fd: i32, args: *mut KacsDuplicateArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_DUPLICATE, args as u64) }
}

/// `KACS_IOC_INSTALL` on a token fd. No arguments.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ASSIGN_PRIMARY`. On success, the
/// calling task's primary token is replaced by the one referenced
/// by `fd`.
#[inline]
pub unsafe fn install(fd: i32) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_INSTALL, 0) }
}

/// `KACS_IOC_RESTRICT` on a token fd. Writes the new fd into
/// `args.result_fd` on success.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_DUPLICATE`. `args.data_ptr` must
/// point to a buffer of `args.data_len` bytes holding the
/// concatenated deny-index / restricted-SID payload.
#[inline]
pub unsafe fn restrict(fd: i32, args: *mut KacsRestrictArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_RESTRICT, args as u64) }
}

/// `KACS_IOC_LINK_TOKENS` on a token fd.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ADJUST_DEFAULT` (per the KACS spec).
/// `args.elevated_fd` and `args.filtered_fd` must be valid token fds.
#[inline]
pub unsafe fn link_tokens(fd: i32, args: *mut KacsLinkTokensArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_LINK_TOKENS, args as u64) }
}

/// `KACS_IOC_GET_LINKED_TOKEN` on a token fd. Writes the linked fd
/// into `args.result_fd` on success.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_QUERY`. The token must have a linked
/// counterpart or the kernel returns `-ENOENT`.
#[inline]
pub unsafe fn get_linked_token(fd: i32, args: *mut KacsGetLinkedTokenArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_GET_LINKED_TOKEN, args as u64) }
}

/// `KACS_IOC_ADJUST_GROUPS` on a token fd.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ADJUST_GROUPS`. `args.data_ptr` must
/// point to `args.count` `kacs_group_entry` records.
#[inline]
pub unsafe fn adjust_groups(fd: i32, args: *mut KacsAdjustGroupsArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_ADJUST_GROUPS, args as u64) }
}

/// `KACS_IOC_IMPERSONATE` on a token fd. No arguments.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_IMPERSONATE` and reference an
/// impersonation-type token. On success the calling thread's
/// effective token is set; restore with `revert()`.
#[inline]
pub unsafe fn impersonate(fd: i32) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_IMPERSONATE, 0) }
}

/// `KACS_IOC_ADJUST_DEFAULT` on a token fd.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ADJUST_DEFAULT`. `args.dacl_ptr` must
/// point to `args.dacl_len` bytes encoding a self-relative DACL,
/// or be zero with `args.dacl_len == 0` to leave the DACL alone.
#[inline]
pub unsafe fn adjust_default(fd: i32, args: *mut KacsAdjustDefaultArgs) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_ADJUST_DEFAULT, args as u64) }
}

/// `KACS_IOC_ADJUST_SESSIONID` on a token fd. `arg` points to a `u32`
/// holding the new session id.
///
/// # Safety
/// `fd` must hold `KACS_TOKEN_ADJUST_SESSIONID`. `arg` must point to
/// a writable `u32`.
#[inline]
pub unsafe fn adjust_session_id(fd: i32, arg: *mut u32) -> i64 {
    unsafe { ioctl(fd, KACS_IOC_ADJUST_SESSIONID, arg as u64) }
}

// Re-exports for callers that want to construct the ioctl arg structs
// without an extra `use crate::abi::...` line.
pub use crate::abi::{
    KacsAdjustDefaultArgs, KacsAdjustGroupsArgs, KacsAdjustPrivsArgs, KacsDuplicateArgs,
    KacsGetLinkedTokenArgs, KacsGroupEntry, KacsLinkTokensArgs, KacsPrivEntry, KacsQueryArgs,
    KacsRestrictArgs,
};
