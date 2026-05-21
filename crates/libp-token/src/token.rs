// `Token` — owned KACS token handle.
//
// Wraps a file descriptor returned by one of the `kacs_open_*_token`
// syscalls or by `kacs_create_token`. Closes the fd on drop.
//
// Borrowing: take `&Token` (Rust reference, lifetime-checked); there is
// no separate "BorrowedToken" type. NT's HANDLE model is owned-only and
// Peios echoes it.

use crate::Result;
use crate::error::Error;
use crate::query::{ElevationType, ImpersonationLevel, QueryClass, TokenType};
use crate::raw;
use alloc::vec;
use alloc::vec::Vec;
use crate::abi::{
    KACS_REAL_TOKEN, KacsAdjustDefaultArgs, KacsAdjustGroupsArgs, KacsAdjustPrivsArgs,
    KacsDuplicateArgs, KacsGetLinkedTokenArgs, KacsGroupEntry, KacsLinkTokensArgs, KacsPrivEntry,
    KacsQueryArgs, KacsRestrictArgs,
};
use libp_errno::Errno;
use libp_sys::{self as sys, eintr_retry};
use libp_wire::{Sid, SidRef};

/// An owned KACS token handle.
///
/// `Token` closes its file descriptor in `Drop`. To pass a token to a
/// function without giving up ownership, take `&Token`.
#[derive(Debug)]
pub struct Token {
    fd: i32,
}

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

impl Token {
    /// Wrap an existing file descriptor known to be a KACS token.
    ///
    /// # Safety
    /// `fd` must reference a KACS token (the kernel will reject ioctls
    /// otherwise) and must be exclusively owned by this `Token` —
    /// closing it elsewhere is a use-after-free.
    pub unsafe fn from_raw_fd(fd: i32) -> Self {
        Token { fd }
    }

    /// Raw fd. Caller must not close it; the `Token` retains ownership.
    #[inline]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }

    /// Borrowed fd suitable for handing to std I/O APIs. The lifetime
    /// is bounded by `&self`.
    #[cfg(feature = "std")]
    #[inline]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        // Safety: `self.fd` is valid for the lifetime of `&self`.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(self.fd) }
    }

    /// Consume the `Token` and return the bare fd. The caller becomes
    /// responsible for closing it.
    #[inline]
    pub fn into_raw_fd(self) -> i32 {
        let fd = self.fd;
        core::mem::forget(self);
        fd
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // Safety: we own `fd` exclusively; no one else is using it.
        // close() return is ignored — a failure here can't be reported.
        unsafe {
            let _ = sys::close(self.fd);
        }
    }
}

// ---------------------------------------------------------------------------
// Opens.
// ---------------------------------------------------------------------------

/// Flags for `Token::open_self`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfOpenFlags {
    /// Open the real (primary) token rather than the effective
    /// (impersonation) token when the two differ.
    pub real_token: bool,
}

impl SelfOpenFlags {
    fn to_u32(self) -> u32 {
        let mut v = 0;
        if self.real_token {
            v |= KACS_REAL_TOKEN;
        }
        v
    }
}

impl Token {
    /// Open the caller's token. `access_mask` is a bitwise-OR of
    /// `KACS_TOKEN_*` rights.
    pub fn open_self(flags: SelfOpenFlags, access_mask: u32) -> Result<Token> {
        let rc = eintr_retry(|| unsafe { raw::open_self_token(flags.to_u32(), access_mask) });
        check_fd(rc).map(|fd| Token { fd })
    }

    /// Open the token of the process named by `pidfd`.
    pub fn open_process(pidfd: i32, access_mask: u32) -> Result<Token> {
        let rc = eintr_retry(|| unsafe { raw::open_process_token(pidfd, access_mask) });
        check_fd(rc).map(|fd| Token { fd })
    }

    /// Open the impersonation token of thread `tid` in process `pidfd`.
    pub fn open_thread(pidfd: i32, tid: i32, access_mask: u32) -> Result<Token> {
        let rc = eintr_retry(|| unsafe { raw::open_thread_token(pidfd, tid, access_mask) });
        check_fd(rc).map(|fd| Token { fd })
    }

    /// Open the captured peer token for an AF_UNIX socket.
    pub fn open_peer(sock_fd: i32) -> Result<Token> {
        let rc = eintr_retry(|| unsafe { raw::open_peer_token(sock_fd) });
        check_fd(rc).map(|fd| Token { fd })
    }

    /// Create a new token from a msgpack-encoded spec.
    pub fn create(spec: &[u8]) -> Result<Token> {
        let rc = eintr_retry(|| unsafe { raw::create_token(spec.as_ptr(), spec.len()) });
        check_fd(rc).map(|fd| Token { fd })
    }

    /// Duplicate this token, optionally changing the access mask, the
    /// type (primary vs impersonation), or the impersonation level.
    pub fn duplicate(
        &self,
        access_mask: u32,
        token_type: TokenType,
        level: ImpersonationLevel,
    ) -> Result<Token> {
        let mut args = KacsDuplicateArgs {
            access_mask,
            token_type: token_type.as_u32(),
            impersonation_level: level.as_u32(),
            result_fd: -1,
        };
        let rc = eintr_retry(|| unsafe { raw::duplicate(self.fd, &mut args) });
        check_ok(rc)?;
        Ok(Token { fd: args.result_fd })
    }

    /// Restrict this token: remove privileges, add deny-only SIDs,
    /// add restricted SIDs. Returns a new (restricted) token.
    pub fn restrict(
        &self,
        privs_to_delete: u64,
        num_deny_indices: u32,
        num_restrict_sids: u32,
        payload: &[u8],
        flags: u32,
    ) -> Result<Token> {
        let mut args = KacsRestrictArgs {
            privs_to_delete,
            num_deny_indices,
            num_restrict_sids,
            data_len: payload.len() as u32,
            flags,
            data_ptr: payload.as_ptr() as u64,
            result_fd: -1,
            _pad: 0,
        };
        let rc = eintr_retry(|| unsafe { raw::restrict(self.fd, &mut args) });
        check_ok(rc)?;
        Ok(Token { fd: args.result_fd })
    }
}

// ---------------------------------------------------------------------------
// Query (the generic ioctl over all TOKEN_CLASS_*) and typed accessors.
// ---------------------------------------------------------------------------

impl Token {
    /// Query a token-info class. Returns the raw response bytes; use
    /// the typed accessors below or `peios_uapi` parsers for shape.
    ///
    /// Two-step protocol: probe with `buf_len = 0` to learn the
    /// required size, then fetch with a sized buffer.
    pub fn query(&self, class: QueryClass) -> Result<Vec<u8>> {
        // Probe.
        let mut probe = KacsQueryArgs {
            token_class: class.as_u32(),
            buf_len: 0,
            buf_ptr: 0,
        };
        let rc = eintr_retry(|| unsafe { raw::query(self.fd, &mut probe) });
        check_ok(rc)?;

        // Allocate and fetch. The kernel writes the required size into
        // `probe.buf_len` during the probe step.
        let expected = probe.buf_len;
        let mut buf: Vec<u8> = vec![0u8; expected as usize];
        let mut fetch = KacsQueryArgs {
            token_class: class.as_u32(),
            buf_len: expected,
            buf_ptr: buf.as_mut_ptr() as u64,
        };
        let rc = eintr_retry(|| unsafe { raw::query(self.fd, &mut fetch) });
        check_ok(rc)?;

        // `buf_len` after fetch is the number of bytes actually written.
        let got = fetch.buf_len as usize;
        if got > buf.len() {
            return Err(Error::QueryTruncated { expected, got });
        }
        buf.truncate(got);
        Ok(buf)
    }

    // ----- typed convenience accessors over `query()` -----

    /// Owner SID (the user the token represents).
    pub fn user_sid(&self) -> Result<Sid> {
        let bytes = self.query(QueryClass::User)?;
        let (sref, _) = SidRef::parse(&bytes)?;
        Ok(sref.to_owned())
    }

    /// Primary group SID.
    pub fn primary_group_sid(&self) -> Result<Sid> {
        let bytes = self.query(QueryClass::PrimaryGroup)?;
        let (sref, _) = SidRef::parse(&bytes)?;
        Ok(sref.to_owned())
    }

    /// Owner SID (used for newly-created objects' DACL inheritance).
    pub fn owner_sid(&self) -> Result<Sid> {
        let bytes = self.query(QueryClass::Owner)?;
        let (sref, _) = SidRef::parse(&bytes)?;
        Ok(sref.to_owned())
    }

    /// Integrity-level SID.
    pub fn integrity_level(&self) -> Result<Sid> {
        let bytes = self.query(QueryClass::IntegrityLevel)?;
        let (sref, _) = SidRef::parse(&bytes)?;
        Ok(sref.to_owned())
    }

    /// Token type — primary or impersonation.
    pub fn token_type(&self) -> Result<TokenType> {
        let bytes = self.query(QueryClass::Type)?;
        TokenType::try_from_u32(decode_u32(&bytes)?)
    }

    /// Impersonation level (meaningful only for impersonation tokens).
    pub fn impersonation_level(&self) -> Result<ImpersonationLevel> {
        let bytes = self.query(QueryClass::ImpersonationLevel)?;
        ImpersonationLevel::try_from_u32(decode_u32(&bytes)?)
    }

    /// Elevation type.
    pub fn elevation_type(&self) -> Result<ElevationType> {
        let bytes = self.query(QueryClass::ElevationType)?;
        ElevationType::try_from_u32(decode_u32(&bytes)?)
    }

    /// Session id this token belongs to. Sessions are identified by
    /// `u32` per the KACS UAPI (see `KACS_IOC_ADJUST_SESSIONID`).
    pub fn session_id(&self) -> Result<u32> {
        let bytes = self.query(QueryClass::SessionId)?;
        decode_u32(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Mutation ioctls.
// ---------------------------------------------------------------------------

impl Token {
    /// Adjust the privilege set on this token. `entries` is an array
    /// of (luid, attributes) — `attributes` is a bitmask of
    /// `SE_PRIVILEGE_*` flags.
    ///
    /// Returns the kernel's reported `previous_enabled` mask (which
    /// privileges were previously enabled).
    ///
    /// The kernel rejects empty `entries` with `-EINVAL`; callers
    /// should skip the call instead of passing a zero-length slice.
    pub fn adjust_privs(&self, entries: &[KacsPrivEntry]) -> Result<u64> {
        let mut args = KacsAdjustPrivsArgs {
            count: entries.len() as u32,
            _pad: 0, // kernel rejects nonzero values with -EINVAL
            data_ptr: entries.as_ptr() as u64,
            previous_enabled: 0,
        };
        let rc = eintr_retry(|| unsafe { raw::adjust_privs(self.fd, &mut args) });
        check_ok(rc)?;
        Ok(args.previous_enabled)
    }

    /// Adjust group enable/disable state by index.
    pub fn adjust_groups(&self, entries: &[KacsGroupEntry]) -> Result<u64> {
        let mut args = KacsAdjustGroupsArgs {
            count: entries.len() as u32,
            _pad: 0,
            data_ptr: entries.as_ptr() as u64,
            previous_state: 0,
        };
        let rc = eintr_retry(|| unsafe { raw::adjust_groups(self.fd, &mut args) });
        check_ok(rc)?;
        Ok(args.previous_state)
    }

    /// Change the token's default DACL plus owner/primary-group
    /// indices into the group list.
    ///
    /// Pass `dacl = None` to leave the DACL unchanged.
    pub fn adjust_default(
        &self,
        dacl: Option<&[u8]>,
        owner_index: u16,
        group_index: u16,
    ) -> Result<()> {
        let (ptr, len) = dacl
            .map(|d| (d.as_ptr() as u64, d.len() as u32))
            .unwrap_or((0, 0));
        let mut args = KacsAdjustDefaultArgs {
            dacl_ptr: ptr,
            dacl_len: len,
            owner_index,
            group_index,
        };
        let rc = eintr_retry(|| unsafe { raw::adjust_default(self.fd, &mut args) });
        check_ok(rc)
    }

    /// Replace the token's session id.
    pub fn adjust_session_id(&self, session_id: u32) -> Result<()> {
        let mut id = session_id;
        let rc = eintr_retry(|| unsafe { raw::adjust_session_id(self.fd, &mut id) });
        check_ok(rc)
    }

    /// Install this token as the calling task's primary token.
    pub fn install(&self) -> Result<()> {
        let rc = eintr_retry(|| unsafe { raw::install(self.fd) });
        check_ok(rc)
    }

    /// Start impersonating using this token. Restore with the free
    /// function `revert()`.
    pub fn impersonate(&self) -> Result<()> {
        let rc = eintr_retry(|| unsafe { raw::impersonate(self.fd) });
        check_ok(rc)
    }

    /// Link this token to a filtered counterpart. Used to express the
    /// elevation pair (UAC-style).
    pub fn link_tokens(&self, filtered: &Token, session_id: u64) -> Result<()> {
        let mut args = KacsLinkTokensArgs {
            elevated_fd: self.fd,
            filtered_fd: filtered.fd,
            session_id,
        };
        let rc = eintr_retry(|| unsafe { raw::link_tokens(self.fd, &mut args) });
        check_ok(rc)
    }

    /// Retrieve the linked counterpart token, if one exists.
    pub fn linked_token(&self) -> Result<Token> {
        let mut args = KacsGetLinkedTokenArgs { result_fd: -1 };
        let rc = eintr_retry(|| unsafe { raw::get_linked_token(self.fd, &mut args) });
        check_ok(rc)?;
        Ok(Token { fd: args.result_fd })
    }
}

// ---------------------------------------------------------------------------
// Helpers — convert a raw syscall return into a typed Result.
// ---------------------------------------------------------------------------

#[inline]
fn check_fd(rc: i64) -> Result<i32> {
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(rc as i32)
    }
}

#[inline]
fn check_ok(rc: i64) -> Result<()> {
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(())
    }
}

fn decode_u32(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 4 {
        return Err(Error::QueryTruncated {
            expected: 4,
            got: bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
