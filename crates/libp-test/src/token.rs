// `libp-test token <subcommand>` — token API integration probes.

use clap::Subcommand;
use libp_token::uapi::{Sid, SidRef};
use libp_token::{ImpersonationLevel, QueryClass, SelfOpenFlags, Token, TokenType};
use libp_token::uapi::{
    KACS_TOKEN_ADJUST_DEFAULT, KACS_TOKEN_ADJUST_GROUPS, KACS_TOKEN_ADJUST_PRIVS,
    KACS_TOKEN_ADJUST_SESSIONID, KACS_TOKEN_ALL_ACCESS, KACS_TOKEN_DUPLICATE,
    KACS_TOKEN_IMPERSONATE, KACS_TOKEN_QUERY, KacsGroupEntry, KacsPrivEntry, PRIVILEGES,
    SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED,
};
use serde::Serialize;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Open self token, query the common info classes, dump as JSON.
    /// The "show me everything" command — the libp-token-equivalent of
    /// whoami(1).
    Whoami,

    /// Open the calling process's token at the given access mask.
    /// Reports whether the open succeeded; the fd is dropped before
    /// printing the result (otherwise it'd be lost when the process
    /// exits anyway).
    OpenSelf {
        /// Open the real (primary) token rather than the effective one.
        #[arg(long)]
        real: bool,
        /// Hex / decimal access mask. Defaults to KACS_TOKEN_ALL_ACCESS.
        #[arg(long, default_value_t = KACS_TOKEN_ALL_ACCESS)]
        access: u32,
    },

    /// Open self token and query the given class. Output: raw bytes in
    /// hex plus a short note if the class has a typed accessor.
    Query {
        /// Numeric TOKEN_CLASS_* value (e.g. 1 = USER, 4 = TYPE, ...).
        #[arg(long)]
        class: u32,
    },

    /// Open self token, query USER class, parse as SID, output canonical
    /// SID text plus well-known label if any.
    QueryUserSid,

    /// Open self token, query PRIVILEGES class, decode + name the
    /// privileges that are present, output sorted list.
    QueryPrivileges,

    /// Open the process token of a specific pidfd. Caller is responsible
    /// for opening the pidfd first (use `--pidfd-self` to derive it from
    /// /proc/self).
    OpenProcess {
        /// pidfd referencing the target process. Omit + pass
        /// `--pidfd-self` to use the calling process's own pidfd.
        #[arg(long)]
        pidfd: Option<i32>,
        /// Convenience: open a pidfd to the calling process and use it.
        #[arg(long)]
        pidfd_self: bool,
        #[arg(long, default_value_t = KACS_TOKEN_QUERY)]
        access: u32,
    },

    /// Like `whoami` but go through `open_process_token(pidfd_self)`.
    /// Used to assert the two paths produce equivalent tokens.
    WhoamiViaProcess,

    /// Like `whoami` but go through `open_thread_token`.
    WhoamiViaThread,

    /// Open self, duplicate at the requested type/level/access, dump
    /// the duplicate's token_type / impersonation_level / session_id.
    DuplicateSelf {
        /// "primary" or "impersonation"
        #[arg(long, default_value = "impersonation")]
        kind: String,
        /// "anonymous" | "identification" | "impersonation" | "delegation"
        #[arg(long, default_value = "impersonation")]
        level: String,
        #[arg(long, default_value_t = KACS_TOKEN_ALL_ACCESS)]
        access: u32,
    },

    /// Open self with ADJUST_PRIVS, enable/disable the named
    /// privileges, return previous_enabled mask + post-adjust query of
    /// the enabled mask. Privilege names: see PRIVILEGES table.
    AdjustPrivs {
        /// Comma-separated privilege names to enable (e.g.
        /// "SeChangeNotify,SeAudit").
        #[arg(long, default_value = "")]
        enable: String,
        /// Comma-separated privilege names to disable.
        #[arg(long, default_value = "")]
        disable: String,
    },

    /// Open self with ADJUST_GROUPS, toggle the named groups, return
    /// previous_state mask + post-adjust query.
    AdjustGroups {
        /// Comma-separated group indices to enable.
        #[arg(long, default_value = "")]
        enable: String,
        /// Comma-separated group indices to disable.
        #[arg(long, default_value = "")]
        disable: String,
    },

    /// Open self with ADJUST_DEFAULT, change the default owner/group
    /// indices (no DACL change). Reports kernel return only — pre/post
    /// state isn't trivially queryable.
    AdjustDefault {
        #[arg(long, default_value_t = 0)]
        owner_index: u16,
        #[arg(long, default_value_t = 0)]
        group_index: u16,
    },

    /// Open self with ADJUST_SESSIONID, change the session id, then
    /// re-query SESSION_ID to confirm. Reports before/after.
    AdjustSessionId {
        /// New session id to set.
        #[arg(long)]
        to: u32,
    },

    /// Open self, duplicate as impersonation, call impersonate(), call
    /// revert(). Reports success/failure at each step.
    ImpersonateRoundtrip,

    /// Open self, ask for the linked token. Reports whether one exists.
    /// Typically there isn't one on a fresh task → -ENOENT is expected.
    LinkedToken,

    /// Create a session from a msgpack-encoded spec (hex-encoded on
    /// the CLI). Returns the new session id on success.
    CreateSession {
        /// Hex-encoded msgpack spec bytes.
        #[arg(long)]
        spec_hex: String,
    },

    /// Destroy an empty session.
    DestroySession {
        #[arg(long)]
        id: u64,
    },

    /// Set Process Security Block mitigations on the calling process.
    SetPsbSelf {
        #[arg(long)]
        mitigations: u32,
    },

    /// Call `kacs_revert` directly. With no active impersonation this
    /// typically returns -EINVAL; the subcommand surfaces the errno
    /// rather than failing the test.
    Revert,
}

pub fn run(cmd: Cmd) {
    let out = match cmd {
        Cmd::Whoami => whoami(),
        Cmd::OpenSelf { real, access } => open_self(real, access),
        Cmd::Query { class } => query(class),
        Cmd::QueryUserSid => query_user_sid(),
        Cmd::QueryPrivileges => query_privileges(),
        Cmd::OpenProcess {
            pidfd,
            pidfd_self,
            access,
        } => open_process(pidfd, pidfd_self, access),
        Cmd::WhoamiViaProcess => whoami_via_process(),
        Cmd::WhoamiViaThread => whoami_via_thread(),
        Cmd::DuplicateSelf {
            kind,
            level,
            access,
        } => duplicate_self(&kind, &level, access),
        Cmd::AdjustPrivs { enable, disable } => adjust_privs(&enable, &disable),
        Cmd::AdjustGroups { enable, disable } => adjust_groups(&enable, &disable),
        Cmd::AdjustDefault {
            owner_index,
            group_index,
        } => adjust_default(owner_index, group_index),
        Cmd::AdjustSessionId { to } => adjust_session_id(to),
        Cmd::ImpersonateRoundtrip => impersonate_roundtrip(),
        Cmd::LinkedToken => linked_token(),
        Cmd::CreateSession { spec_hex } => create_session(&spec_hex),
        Cmd::DestroySession { id } => destroy_session(id),
        Cmd::SetPsbSelf { mitigations } => set_psb_self(mitigations),
        Cmd::Revert => revert_cmd(),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}

// ---------------------------------------------------------------------------
// Output envelope. Each subcommand fills `ok` + extra fields.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Ok<T: Serialize> {
    ok: bool, // always true; included for symmetry with errors
    #[serde(flatten)]
    data: T,
}

#[derive(Serialize)]
struct Err {
    ok: bool, // always false
    error: String,
    /// When the error is a syscall failure, the errno name + number.
    #[serde(skip_serializing_if = "Option::is_none")]
    errno: Option<ErrnoFields>,
}

#[derive(Serialize)]
struct ErrnoFields {
    name: &'static str,
    raw: i32,
}

fn ok<T: Serialize>(data: T) -> serde_json::Value {
    serde_json::to_value(Ok { ok: true, data }).unwrap()
}

fn err(e: libp_token::Error) -> serde_json::Value {
    let errno = match &e {
        libp_token::Error::Syscall(errno) => Some(ErrnoFields {
            name: errno.name(),
            raw: errno.raw(),
        }),
        _ => None,
    };
    serde_json::to_value(Err {
        ok: false,
        error: e.to_string(),
        errno,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// Subcommand implementations.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Whoami {
    user_sid: String,
    user_label: &'static str,
    owner_sid: String,
    primary_group_sid: String,
    integrity_level_sid: String,
    integrity_level_label: &'static str,
    token_type: String,
    /// Only present for impersonation tokens. Omitted from the JSON
    /// (rather than serialized as `null`) when the token is primary,
    /// since some Lua JSON decoders surface JSON-null as a non-nil
    /// userdata that's awkward to assert against.
    #[serde(skip_serializing_if = "Option::is_none")]
    impersonation_level: Option<String>,
    elevation_type: String,
    session_id: u32,
}

fn whoami() -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let user_sid = match tok.user_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let owner_sid = match tok.owner_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let primary_group_sid = match tok.primary_group_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let il = match tok.integrity_level() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let token_type = match tok.token_type() {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let impersonation_level = if matches!(token_type, libp_token::TokenType::Impersonation) {
        match tok.impersonation_level() {
            Result::Ok(l) => Some(format!("{:?}", l)),
            Result::Err(e) => return err(e),
        }
    } else {
        None
    };
    let elevation_type = match tok.elevation_type() {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let session_id = match tok.session_id() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };

    ok(Whoami {
        user_label: libp_wire::well_known_label(&user_sid.to_string()),
        integrity_level_label: libp_wire::well_known_label(&il.to_string()),
        user_sid: user_sid.to_string(),
        owner_sid: owner_sid.to_string(),
        primary_group_sid: primary_group_sid.to_string(),
        integrity_level_sid: il.to_string(),
        token_type: format!("{:?}", token_type),
        impersonation_level,
        elevation_type: format!("{:?}", elevation_type),
        session_id,
    })
}

#[derive(Serialize)]
struct OpenSelfResult {
    /// True if open returned a valid fd. The fd itself isn't reported —
    /// it gets closed at function exit since it can't outlive the
    /// process anyway.
    opened: bool,
    flags: u32,
    access_mask: u32,
}

fn open_self(real: bool, access_mask: u32) -> serde_json::Value {
    let flags = SelfOpenFlags { real_token: real };
    match Token::open_self(flags, access_mask) {
        Result::Ok(_tok) => ok(OpenSelfResult {
            opened: true,
            flags: if real { 1 } else { 0 },
            access_mask,
        }),
        Result::Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct QueryResult {
    class: u32,
    bytes_hex: String,
    byte_len: usize,
}

fn query(class: u32) -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    // Cast the raw numeric class into the enum by transmuting through
    // the all-variants map; if the value isn't a known class, fall back
    // to constructing an unsafe-cast call.
    let bytes = match query_dispatch(&tok, class) {
        Result::Ok(b) => b,
        Result::Err(e) => return err(e),
    };
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    ok(QueryResult {
        class,
        byte_len: bytes.len(),
        bytes_hex: hex,
    })
}

/// Map a raw class number to the `QueryClass` enum and call `query`. If
/// the number doesn't match a known class we surface an error rather
/// than transmuting — callers passing junk classes should get a clear
/// message.
fn query_dispatch(tok: &Token, class: u32) -> Result<Vec<u8>, libp_token::Error> {
    use libp_token::uapi::*;
    let c = match class {
        TOKEN_CLASS_USER => QueryClass::User,
        TOKEN_CLASS_GROUPS => QueryClass::Groups,
        TOKEN_CLASS_PRIVILEGES => QueryClass::Privileges,
        TOKEN_CLASS_TYPE => QueryClass::Type,
        TOKEN_CLASS_INTEGRITY_LEVEL => QueryClass::IntegrityLevel,
        TOKEN_CLASS_OWNER => QueryClass::Owner,
        TOKEN_CLASS_PRIMARY_GROUP => QueryClass::PrimaryGroup,
        TOKEN_CLASS_SESSION_ID => QueryClass::SessionId,
        TOKEN_CLASS_RESTRICTED_SIDS => QueryClass::RestrictedSids,
        TOKEN_CLASS_SOURCE => QueryClass::Source,
        TOKEN_CLASS_STATISTICS => QueryClass::Statistics,
        TOKEN_CLASS_ORIGIN => QueryClass::Origin,
        TOKEN_CLASS_ELEVATION_TYPE => QueryClass::ElevationType,
        TOKEN_CLASS_DEVICE_GROUPS => QueryClass::DeviceGroups,
        TOKEN_CLASS_APPCONTAINER_SID => QueryClass::AppContainerSid,
        TOKEN_CLASS_CAPABILITIES => QueryClass::Capabilities,
        TOKEN_CLASS_MANDATORY_POLICY => QueryClass::MandatoryPolicy,
        TOKEN_CLASS_LOGON_TYPE => QueryClass::LogonType,
        TOKEN_CLASS_LOGON_SID => QueryClass::LogonSid,
        TOKEN_CLASS_DEFAULT_DACL => QueryClass::DefaultDacl,
        TOKEN_CLASS_IMPERSONATION_LEVEL => QueryClass::ImpersonationLevel,
        TOKEN_CLASS_USER_CLAIMS => QueryClass::UserClaims,
        TOKEN_CLASS_DEVICE_CLAIMS => QueryClass::DeviceClaims,
        TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS => QueryClass::ProjectedSupplementaryGids,
        other => {
            return Err(libp_token::Error::UnknownDiscriminant {
                kind: "TokenClass",
                value: other,
            });
        }
    };
    tok.query(c)
}

#[derive(Serialize)]
struct UserSidResult {
    sid: String,
    well_known: &'static str,
}

fn query_user_sid() -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let bytes = match tok.query(QueryClass::User) {
        Result::Ok(b) => b,
        Result::Err(e) => return err(e),
    };
    let (sref, _) = match SidRef::parse(&bytes) {
        Result::Ok(p) => p,
        Result::Err(e) => return err(libp_token::Error::Decode(e)),
    };
    let owned: Sid = sref.to_owned();
    let text = owned.to_string();
    let label = libp_wire::well_known_label(&text);
    ok(UserSidResult {
        sid: text,
        well_known: label,
    })
}

#[derive(Serialize)]
struct PrivilegesResult {
    raw_bytes_hex: String,
    /// Raw bitmasks straight off the wire.
    masks: PrivMasks,
    /// One entry per privilege bit that's set in `present`.
    decoded: Vec<DecodedPriv>,
}

/// u64 bitmasks serialized as hex strings.
///
/// JSON numbers go through Lua's f64; bit 53+ of a u64 lose precision.
/// Tests parse these with `tonumber(s, 16)` which Lua handles as a
/// proper 64-bit integer.
#[derive(Serialize)]
struct PrivMasks {
    present: HexU64,
    enabled: HexU64,
    default_enabled: HexU64,
    used: HexU64,
}

#[derive(Clone, Copy)]
struct HexU64(u64);

impl Serialize for HexU64 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#x}", self.0))
    }
}

#[derive(Serialize)]
struct DecodedPriv {
    bit: u32,
    name: &'static str,
    enabled: bool,
    default_enabled: bool,
    used: bool,
}

fn query_privileges() -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let bytes = match tok.query(QueryClass::Privileges) {
        Result::Ok(b) => b,
        Result::Err(e) => return err(e),
    };
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in &bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    // Wire layout (see KACS spec Appendix A): four u64 little-endian
    // bitmasks back-to-back —
    //   bytes 0..8   present
    //   bytes 8..16  enabled
    //   bytes 16..24 default_enabled
    //   bytes 24..32 used
    // Each bit N corresponds to a privilege whose bit-index is N in the
    // `PRIVILEGES` table in peios-uapi.
    if bytes.len() < 32 {
        return err(libp_token::Error::QueryTruncated {
            expected: 32,
            got: bytes.len(),
        });
    }
    let mask = |off: usize| {
        u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ])
    };
    let masks_present = mask(0);
    let masks_enabled = mask(8);
    let masks_default = mask(16);
    let masks_used = mask(24);
    let masks = PrivMasks {
        present: HexU64(masks_present),
        enabled: HexU64(masks_enabled),
        default_enabled: HexU64(masks_default),
        used: HexU64(masks_used),
    };
    let mut decoded = Vec::new();
    for &(bit, name) in PRIVILEGES {
        let m = 1u64 << bit;
        if masks_present & m == 0 {
            continue;
        }
        decoded.push(DecodedPriv {
            bit,
            name,
            enabled: masks_enabled & m != 0,
            default_enabled: masks_default & m != 0,
            used: masks_used & m != 0,
        });
    }
    ok(PrivilegesResult {
        raw_bytes_hex: hex,
        masks,
        decoded,
    })
}

// ---------------------------------------------------------------------------
// New subcommands (token API completeness).
// ---------------------------------------------------------------------------

/// Open a pidfd to the calling process via `pidfd_open(getpid())`. Used
/// when a test wants `open_process_token` against itself without
/// having to thread a real pidfd through.
fn pidfd_self() -> std::io::Result<i32> {
    use libp_sys::syscall2;
    // SYS_pidfd_open on x86_64 = 434, SYS_getpid = 39.
    const SYS_PIDFD_OPEN: i64 = 434;
    const SYS_GETPID: i64 = 39;
    let pid = unsafe { libp_sys::syscall0(SYS_GETPID) };
    if pid < 0 {
        return Err(std::io::Error::from_raw_os_error(-pid as i32));
    }
    let fd = unsafe { syscall2(SYS_PIDFD_OPEN, pid as u64, 0) };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd as i32));
    }
    Ok(fd as i32)
}

#[derive(Serialize)]
struct OpenProcessResult {
    opened: bool,
    pidfd_used: i32,
    access_mask: u32,
}

fn open_process(pidfd: Option<i32>, pidfd_self_flag: bool, access: u32) -> serde_json::Value {
    let pidfd = match (pidfd, pidfd_self_flag) {
        (Some(fd), _) => fd,
        (None, true) => match pidfd_self() {
            Ok(fd) => fd,
            Err(e) => {
                return err(libp_token::Error::Syscall(libp_token::uapi::Errno::new(
                    e.raw_os_error().unwrap_or(0),
                )));
            }
        },
        (None, false) => {
            return err(libp_token::Error::WrongTokenType(
                "must pass --pidfd or --pidfd-self",
            ));
        }
    };
    match Token::open_process(pidfd, access) {
        Result::Ok(_) => ok(OpenProcessResult {
            opened: true,
            pidfd_used: pidfd,
            access_mask: access,
        }),
        Result::Err(e) => err(e),
    }
}

fn whoami_via_process() -> serde_json::Value {
    let pidfd = match pidfd_self() {
        Ok(fd) => fd,
        Err(e) => {
            return err(libp_token::Error::Syscall(libp_token::uapi::Errno::new(
                e.raw_os_error().unwrap_or(0),
            )));
        }
    };
    let tok = match Token::open_process(pidfd, KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    whoami_for(&tok)
}

fn whoami_via_thread() -> serde_json::Value {
    let pidfd = match pidfd_self() {
        Ok(fd) => fd,
        Err(e) => {
            return err(libp_token::Error::Syscall(libp_token::uapi::Errno::new(
                e.raw_os_error().unwrap_or(0),
            )));
        }
    };
    // tid = 0 means "the main thread" for kacs_open_thread_token.
    let tid = unsafe { libp_sys::syscall0(39) }; // getpid; main-thread tid == pid
    let tid = if tid < 0 { 0 } else { tid as i32 };
    let tok = match Token::open_thread(pidfd, tid, KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    whoami_for(&tok)
}

/// Shared core of the whoami subcommands. Pulled out so the open-path
/// variants can share the query+format logic.
fn whoami_for(tok: &Token) -> serde_json::Value {
    let user_sid = match tok.user_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let owner_sid = match tok.owner_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let primary_group_sid = match tok.primary_group_sid() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let il = match tok.integrity_level() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    let token_type = match tok.token_type() {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let impersonation_level = if matches!(token_type, libp_token::TokenType::Impersonation) {
        match tok.impersonation_level() {
            Result::Ok(l) => Some(format!("{:?}", l)),
            Result::Err(e) => return err(e),
        }
    } else {
        None
    };
    let elevation_type = match tok.elevation_type() {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let session_id = match tok.session_id() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };

    ok(Whoami {
        user_label: libp_wire::well_known_label(&user_sid.to_string()),
        integrity_level_label: libp_wire::well_known_label(&il.to_string()),
        user_sid: user_sid.to_string(),
        owner_sid: owner_sid.to_string(),
        primary_group_sid: primary_group_sid.to_string(),
        integrity_level_sid: il.to_string(),
        token_type: format!("{:?}", token_type),
        impersonation_level,
        elevation_type: format!("{:?}", elevation_type),
        session_id,
    })
}

#[derive(Serialize)]
struct DuplicateResult {
    requested_kind: String,
    requested_level: String,
    actual_token_type: String,
    actual_impersonation_level: Option<String>,
    actual_session_id: u32,
}

fn duplicate_self(kind: &str, level: &str, access: u32) -> serde_json::Value {
    let ttype = match kind.to_ascii_lowercase().as_str() {
        "primary" => TokenType::Primary,
        "impersonation" => TokenType::Impersonation,
        other => {
            return err(libp_token::Error::WrongTokenType(Box::leak(
                format!("unknown kind {other}").into_boxed_str(),
            )));
        }
    };
    let lvl = match level.to_ascii_lowercase().as_str() {
        "anonymous" => ImpersonationLevel::Anonymous,
        "identification" => ImpersonationLevel::Identification,
        "impersonation" => ImpersonationLevel::Impersonation,
        "delegation" => ImpersonationLevel::Delegation,
        other => {
            return err(libp_token::Error::WrongTokenType(Box::leak(
                format!("unknown level {other}").into_boxed_str(),
            )));
        }
    };
    let self_tok = match Token::open_self(
        SelfOpenFlags::default(),
        KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let dup = match self_tok.duplicate(access, ttype, lvl) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let actual_type = match dup.token_type() {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let actual_level = if matches!(actual_type, TokenType::Impersonation) {
        match dup.impersonation_level() {
            Result::Ok(l) => Some(format!("{:?}", l)),
            Result::Err(e) => return err(e),
        }
    } else {
        None
    };
    let session = match dup.session_id() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    ok(DuplicateResult {
        requested_kind: kind.to_string(),
        requested_level: level.to_string(),
        actual_token_type: format!("{:?}", actual_type),
        actual_impersonation_level: actual_level,
        actual_session_id: session,
    })
}

/// Parse a comma-separated list of privilege NAMES (per PRIVILEGES
/// table) to a `Vec<u32>` of bit indices. Empty input returns empty.
fn parse_priv_names(s: &str) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for name in s.split(',').map(|n| n.trim()).filter(|n| !n.is_empty()) {
        match PRIVILEGES.iter().find(|(_, n)| *n == name) {
            Some((bit, _)) => out.push(*bit),
            None => return Err(format!("unknown privilege name: {name}")),
        }
    }
    Ok(out)
}

#[derive(Serialize)]
struct AdjustPrivsResult {
    /// Hex string — see PrivMasks docstring for the why.
    previous_enabled_mask: HexU64,
    /// `enabled` mask after the adjust (re-queried). Hex string.
    post_enabled_mask: HexU64,
    enable_names: Vec<String>,
    disable_names: Vec<String>,
}

fn adjust_privs(enable: &str, disable: &str) -> serde_json::Value {
    let enable_bits = match parse_priv_names(enable) {
        Ok(v) => v,
        Err(msg) => {
            return err(libp_token::Error::WrongTokenType(Box::leak(
                msg.into_boxed_str(),
            )));
        }
    };
    let disable_bits = match parse_priv_names(disable) {
        Ok(v) => v,
        Err(msg) => {
            return err(libp_token::Error::WrongTokenType(Box::leak(
                msg.into_boxed_str(),
            )));
        }
    };
    let tok = match Token::open_self(
        SelfOpenFlags::default(),
        KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let mut entries: Vec<KacsPrivEntry> = Vec::new();
    for bit in &enable_bits {
        entries.push(KacsPrivEntry {
            luid: *bit,
            attributes: SE_PRIVILEGE_ENABLED,
        });
    }
    for bit in &disable_bits {
        entries.push(KacsPrivEntry {
            luid: *bit,
            attributes: 0, // 0 = disabled (not removed)
        });
    }
    let previous = match tok.adjust_privs(&entries) {
        Result::Ok(p) => p,
        Result::Err(e) => return err(e),
    };
    // Re-query privileges to confirm.
    let bytes = match tok.query(QueryClass::Privileges) {
        Result::Ok(b) => b,
        Result::Err(e) => return err(e),
    };
    let post_enabled = if bytes.len() >= 16 {
        u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    } else {
        0
    };
    let lookup_name = |bits: &[u32]| -> Vec<String> {
        bits.iter()
            .map(|b| {
                PRIVILEGES
                    .iter()
                    .find(|(bit, _)| *bit == *b)
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| format!("?{b}"))
            })
            .collect()
    };
    ok(AdjustPrivsResult {
        previous_enabled_mask: HexU64(previous),
        post_enabled_mask: HexU64(post_enabled),
        enable_names: lookup_name(&enable_bits),
        disable_names: lookup_name(&disable_bits),
    })
}

#[derive(Serialize)]
struct AdjustGroupsResult {
    previous_state_mask: HexU64,
    enable_indices: Vec<u32>,
    disable_indices: Vec<u32>,
}

fn adjust_groups(enable: &str, disable: &str) -> serde_json::Value {
    fn parse_idx_list(s: &str) -> Result<Vec<u32>, libp_token::Error> {
        s.split(',')
            .map(|n| n.trim())
            .filter(|n| !n.is_empty())
            .map(|n| {
                n.parse::<u32>().map_err(|_| {
                    libp_token::Error::WrongTokenType(Box::leak(
                        format!("not a number: {n}").into_boxed_str(),
                    ))
                })
            })
            .collect()
    }
    let enable_idx = match parse_idx_list(enable) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let disable_idx = match parse_idx_list(disable) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    let tok = match Token::open_self(
        SelfOpenFlags::default(),
        KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let mut entries: Vec<KacsGroupEntry> = Vec::new();
    for idx in &enable_idx {
        entries.push(KacsGroupEntry {
            index: *idx,
            enable: 1,
        });
    }
    for idx in &disable_idx {
        entries.push(KacsGroupEntry {
            index: *idx,
            enable: 0,
        });
    }
    let previous = match tok.adjust_groups(&entries) {
        Result::Ok(p) => p,
        Result::Err(e) => return err(e),
    };
    ok(AdjustGroupsResult {
        previous_state_mask: HexU64(previous),
        enable_indices: enable_idx,
        disable_indices: disable_idx,
    })
}

#[derive(Serialize)]
struct AdjustDefaultResult {
    requested_owner_index: u16,
    requested_group_index: u16,
}

fn adjust_default(owner_index: u16, group_index: u16) -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_ADJUST_DEFAULT) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    match tok.adjust_default(None, owner_index, group_index) {
        Result::Ok(()) => ok(AdjustDefaultResult {
            requested_owner_index: owner_index,
            requested_group_index: group_index,
        }),
        Result::Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct AdjustSessionIdResult {
    before: u32,
    requested: u32,
    after: u32,
}

fn adjust_session_id(to: u32) -> serde_json::Value {
    let tok = match Token::open_self(
        SelfOpenFlags::default(),
        KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let before = match tok.session_id() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    if let Err(e) = tok.adjust_session_id(to) {
        return err(e);
    }
    let after = match tok.session_id() {
        Result::Ok(s) => s,
        Result::Err(e) => return err(e),
    };
    ok(AdjustSessionIdResult {
        before,
        requested: to,
        after,
    })
}

#[derive(Serialize)]
struct ImpersonateRoundtripResult {
    duplicate_ok: bool,
    impersonate_ok: bool,
    revert_ok: bool,
}

fn impersonate_roundtrip() -> serde_json::Value {
    let self_tok = match Token::open_self(
        SelfOpenFlags::default(),
        KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    let dup = match self_tok.duplicate(
        KACS_TOKEN_IMPERSONATE | KACS_TOKEN_QUERY,
        TokenType::Impersonation,
        ImpersonationLevel::Impersonation,
    ) {
        Result::Ok(t) => t,
        Result::Err(e) => {
            return ok(ImpersonateRoundtripResult {
                duplicate_ok: false,
                impersonate_ok: false,
                revert_ok: false,
            })
            .as_object()
            .cloned()
            .map(|mut m| {
                m.insert("error".into(), serde_json::Value::String(e.to_string()));
                serde_json::Value::Object(m)
            })
            .unwrap_or_else(|| {
                ok(ImpersonateRoundtripResult {
                    duplicate_ok: false,
                    impersonate_ok: false,
                    revert_ok: false,
                })
            });
        }
    };
    let imp_ok = dup.impersonate().is_ok();
    let rev_ok = libp_token::revert().is_ok();
    ok(ImpersonateRoundtripResult {
        duplicate_ok: true,
        impersonate_ok: imp_ok,
        revert_ok: rev_ok,
    })
}

#[derive(Serialize)]
struct LinkedTokenResult {
    /// True if a linked token existed (kernel returned a fd). False
    /// covers both "no linked token" (ENOENT) and other errors.
    has_linked: bool,
    error: Option<String>,
}

fn linked_token() -> serde_json::Value {
    let tok = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err(e),
    };
    match tok.linked_token() {
        Result::Ok(_) => ok(LinkedTokenResult {
            has_linked: true,
            error: None,
        }),
        Result::Err(e) => ok(LinkedTokenResult {
            has_linked: false,
            error: Some(e.to_string()),
        }),
    }
}

#[derive(Serialize)]
struct CreateSessionResult {
    session_id: u64,
}

fn create_session(spec_hex: &str) -> serde_json::Value {
    let spec = match decode_hex(spec_hex) {
        Ok(v) => v,
        Err(msg) => {
            return err(libp_token::Error::WrongTokenType(Box::leak(
                msg.into_boxed_str(),
            )));
        }
    };
    match libp_token::create_session(&spec) {
        Result::Ok(id) => ok(CreateSessionResult { session_id: id }),
        Result::Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct DestroySessionResult {
    destroyed: u64,
}

fn destroy_session(id: u64) -> serde_json::Value {
    match libp_token::destroy_empty_session(id) {
        Result::Ok(()) => ok(DestroySessionResult { destroyed: id }),
        Result::Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct SetPsbResult {
    pidfd_used: i32,
    mitigations: u32,
}

fn set_psb_self(mitigations: u32) -> serde_json::Value {
    let pidfd = match pidfd_self() {
        Ok(fd) => fd,
        Err(e) => {
            return err(libp_token::Error::Syscall(libp_token::uapi::Errno::new(
                e.raw_os_error().unwrap_or(0),
            )));
        }
    };
    match libp_token::set_psb(pidfd, mitigations) {
        Result::Ok(()) => ok(SetPsbResult {
            pidfd_used: pidfd,
            mitigations,
        }),
        Result::Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct RevertResult {
    reverted: bool,
}

fn revert_cmd() -> serde_json::Value {
    match libp_token::revert() {
        Result::Ok(()) => ok(RevertResult { reverted: true }),
        Result::Err(e) => err(e),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte_str = &s[i..i + 2];
        let b = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("not hex at offset {i}: {byte_str:?}"))?;
        out.push(b);
    }
    Ok(out)
}

// Silence an unused-import warning if SE_PRIVILEGE_REMOVED isn't used
// (kept available for tests that want it).
#[allow(dead_code)]
const _UNUSED_PRIVILEGE_REMOVED: u32 = SE_PRIVILEGE_REMOVED;
