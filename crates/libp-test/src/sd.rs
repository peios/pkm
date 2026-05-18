// `libp-test sd <subcommand>` — Security Descriptor integration probes.

use clap::Subcommand;
use libp_sd::consts::{
    ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ, ACCESS_READ_CONTROL, ACCESS_WRITE_DAC,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
};
use libp_sd::{
    AccessCheckRequest, AclBuilder, ObjectTypeNode, SdBuilder, SdTarget, SecurityDescriptor,
    SecurityInfo, WellKnownSid,
};
use libp_token::{SelfOpenFlags, Token};
use peios_uapi::token::KACS_TOKEN_QUERY;
use serde::Serialize;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Build a representative SD (owner=LocalSystem, group=Administrators,
    /// a 2-ACE DACL) and emit it as hex. Pure — no kernel involved.
    BuildDemo,

    /// Parse a hex-encoded self-relative SD and dump its structure.
    Parse {
        /// Hex-encoded SECURITY_DESCRIPTOR bytes.
        #[arg(long)]
        hex: String,
    },

    /// Build the demo SD, parse it back, assert the fields survive the
    /// round-trip. Pure self-contained correctness probe.
    RoundtripBuildParse,

    /// Dump the WellKnownSid table — each variant's SID text + label.
    Wellknown,

    /// get_sd on a filesystem path. Outputs the decoded descriptor.
    Get {
        #[arg(long)]
        path: String,
    },

    /// Build an owner+DACL SD, set_sd it onto `path`, get_sd it back,
    /// and report whether the owner survived the round-trip.
    SetGet {
        #[arg(long)]
        path: String,
        /// SID text to set as owner — defaults to LocalSystem.
        #[arg(long, default_value = "LocalSystem")]
        owner: String,
    },

    /// Scalar access check. Opens the self token, builds an SD whose
    /// DACL allows Everyone `ACCESS_READ_CONTROL`, then checks the
    /// named desired access against it. Reports granted + mask.
    AccessCheck {
        /// Desired access: "read-control" (in the ACE → granted) or
        /// "write-dac" (not in the ACE → denied).
        #[arg(long, default_value = "read-control")]
        desired: String,
    },

    /// Result-list access check. Same SD as `access-check`, but run
    /// over a small object-type tree. Reports one decision per node.
    AccessCheckList {
        #[arg(long, default_value = "read-control")]
        desired: String,
        /// Number of object-tree nodes (each a distinct GUID at
        /// successive depths).
        #[arg(long, default_value_t = 2)]
        nodes: u16,
    },

    /// Access check with a `@Local` claim attached. Verifies the
    /// claims-array encoder produces a buffer the kernel accepts —
    /// the check itself uses the same Everyone/READ_CONTROL SD.
    AccessCheckWithClaim,
}

pub fn run(cmd: Cmd) {
    let out = match cmd {
        Cmd::BuildDemo => build_demo(),
        Cmd::Parse { hex } => parse(&hex),
        Cmd::RoundtripBuildParse => roundtrip_build_parse(),
        Cmd::Wellknown => wellknown(),
        Cmd::Get { path } => get(&path),
        Cmd::SetGet { path, owner } => set_get(&path, &owner),
        Cmd::AccessCheck { desired } => access_check(&desired),
        Cmd::AccessCheckList { desired, nodes } => access_check_list(&desired, nodes),
        Cmd::AccessCheckWithClaim => access_check_with_claim(),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}

// ---------------------------------------------------------------------------
// Envelope helpers.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Ok<T: Serialize> {
    ok: bool,
    #[serde(flatten)]
    data: T,
}

fn ok<T: Serialize>(data: T) -> serde_json::Value {
    serde_json::to_value(Ok { ok: true, data }).unwrap()
}

fn err_sd(e: libp_sd::Error) -> serde_json::Value {
    let errno = match &e {
        libp_sd::Error::Syscall(errno) => Some(serde_json::json!({
            "name": errno.name(),
            "raw": errno.raw(),
        })),
        _ => None,
    };
    serde_json::json!({ "ok": false, "error": e.to_string(), "errno": errno })
}

fn err_msg(msg: &str) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": msg })
}

// ---------------------------------------------------------------------------
// The demo SD — shared by build-demo and roundtrip-build-parse.
// ---------------------------------------------------------------------------

fn demo_sd_builder() -> SdBuilder {
    SdBuilder::new()
        .owner(WellKnownSid::LocalSystem)
        .group(WellKnownSid::BuiltinAdministrators)
        .dacl(
            AclBuilder::new()
                .allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL),
        )
}

// ---------------------------------------------------------------------------
// Subcommands.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BuildResult {
    byte_len: usize,
    hex: String,
}

fn build_demo() -> serde_json::Value {
    match demo_sd_builder().build() {
        Result::Ok(bytes) => ok(BuildResult {
            byte_len: bytes.len(),
            hex: to_hex(&bytes),
        }),
        Result::Err(e) => err_sd(e),
    }
}

#[derive(Serialize)]
struct ParseResult {
    revision: u8,
    control: u16,
    control_names: Vec<&'static str>,
    owner: Option<String>,
    group: Option<String>,
    dacl_present: bool,
    dacl_ace_count: u16,
    aces: Vec<AceView>,
}

#[derive(Serialize)]
struct AceView {
    ace_type: u8,
    ace_type_name: &'static str,
    flags: u8,
    mask: Option<u32>,
    sid: Option<String>,
}

fn parse(hex: &str) -> serde_json::Value {
    let bytes = match from_hex(hex) {
        Result::Ok(b) => b,
        Result::Err(m) => return err_msg(&m),
    };
    parse_bytes(&bytes)
}

fn parse_bytes(bytes: &[u8]) -> serde_json::Value {
    use peios_uapi::sd::control_bit_names;
    let sd = match SecurityDescriptor::parse(bytes) {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(libp_sd::Error::Parse(e)),
    };
    let mut aces = Vec::new();
    let mut dacl_present = false;
    let mut dacl_ace_count = 0u16;
    if let Some(dacl_result) = sd.dacl() {
        match dacl_result {
            Result::Ok(dacl) => {
                dacl_present = true;
                dacl_ace_count = dacl.ace_count;
                for ace_result in dacl.aces_iter() {
                    match ace_result {
                        Result::Ok(ace) => {
                            let (mask, sid) = match ace.as_mask_sid() {
                                Some((m, s)) => (Some(m), Some(s.to_string())),
                                None => (None, None),
                            };
                            aces.push(AceView {
                                ace_type: ace.ace_type,
                                ace_type_name: peios_uapi::sd::ace_type_name(ace.ace_type),
                                flags: ace.flags,
                                mask,
                                sid,
                            });
                        }
                        Result::Err(e) => {
                            return err_sd(libp_sd::Error::Parse(e));
                        }
                    }
                }
            }
            Result::Err(e) => return err_sd(libp_sd::Error::Parse(e)),
        }
    }
    ok(ParseResult {
        revision: sd.revision,
        control: sd.control,
        control_names: control_bit_names(sd.control),
        owner: sd.owner().map(|s| s.to_string()),
        group: sd.group().map(|s| s.to_string()),
        dacl_present,
        dacl_ace_count,
        aces,
    })
}

fn roundtrip_build_parse() -> serde_json::Value {
    // Build → parse → assert the parse matches what we put in.
    let bytes = match demo_sd_builder().build() {
        Result::Ok(b) => b,
        Result::Err(e) => return err_sd(e),
    };
    let sd = match SecurityDescriptor::parse(&bytes) {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(libp_sd::Error::Parse(e)),
    };
    let owner_ok = sd.owner() == Some(WellKnownSid::LocalSystem.to_sid());
    let group_ok = sd.group() == Some(WellKnownSid::BuiltinAdministrators.to_sid());
    let dacl_count = sd
        .dacl()
        .and_then(|r| r.ok())
        .map(|d| d.ace_count)
        .unwrap_or(0);
    serde_json::json!({
        "ok": true,
        "owner_roundtrip_ok": owner_ok,
        "group_roundtrip_ok": group_ok,
        "dacl_ace_count": dacl_count,
        "byte_len": bytes.len(),
    })
}

#[derive(Serialize)]
struct WellknownEntry {
    label: &'static str,
    sid: String,
}

fn wellknown() -> serde_json::Value {
    let variants = [
        WellKnownSid::Null,
        WellKnownSid::Everyone,
        WellKnownSid::Anonymous,
        WellKnownSid::AuthenticatedUsers,
        WellKnownSid::LocalSystem,
        WellKnownSid::LocalService,
        WellKnownSid::NetworkService,
        WellKnownSid::BuiltinAdministrators,
        WellKnownSid::BuiltinUsers,
        WellKnownSid::UntrustedIl,
        WellKnownSid::LowIl,
        WellKnownSid::MediumIl,
        WellKnownSid::MediumPlusIl,
        WellKnownSid::HighIl,
        WellKnownSid::SystemIl,
        WellKnownSid::ProtectedProcessIl,
    ];
    let entries: Vec<WellknownEntry> = variants
        .iter()
        .map(|w| WellknownEntry {
            label: w.label(),
            sid: w.to_sid().to_string(),
        })
        .collect();
    serde_json::json!({ "ok": true, "entries": entries })
}

fn get(path: &str) -> serde_json::Value {
    let target = SdTarget::path(path);
    match libp_sd::get_sd(&target, SecurityInfo::all()) {
        Result::Ok(bytes) => {
            if bytes.is_empty() {
                return serde_json::json!({
                    "ok": true, "empty": true, "byte_len": 0,
                });
            }
            parse_bytes(&bytes)
        }
        Result::Err(e) => err_sd(e),
    }
}

fn set_get(path: &str, owner: &str) -> serde_json::Value {
    let owner_sid = match resolve_owner(owner) {
        Result::Ok(s) => s,
        Result::Err(m) => return err_msg(&m),
    };
    // Build an SD with the requested owner + a permissive DACL.
    let sd_bytes = match SdBuilder::new()
        .owner(owner_sid.clone())
        .dacl(AclBuilder::new().allow(WellKnownSid::Everyone, ACCESS_GENERIC_ALL))
        .build()
    {
        Result::Ok(b) => b,
        Result::Err(e) => return err_sd(e),
    };
    let target = SdTarget::path(path);
    // Set owner + DACL.
    let info = SecurityInfo::none().with_owner().with_dacl();
    if let Result::Err(e) = libp_sd::set_sd(&target, info, &sd_bytes) {
        return err_sd(e);
    }
    // Read it back.
    let got = match libp_sd::get_sd(&target, SecurityInfo::all()) {
        Result::Ok(b) => b,
        Result::Err(e) => return err_sd(e),
    };
    let sd = match SecurityDescriptor::parse(&got) {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(libp_sd::Error::Parse(e)),
    };
    let owner_back = sd.owner().map(|s| s.to_string());
    let owner_match = sd.owner() == Some(owner_sid);
    serde_json::json!({
        "ok": true,
        "owner_set": owner,
        "owner_read_back": owner_back,
        "owner_roundtrip_ok": owner_match,
        "info_set": info.bits(),
        "_info_owner": OWNER_SECURITY_INFORMATION,
        "_info_dacl": DACL_SECURITY_INFORMATION,
    })
}

/// Resolve an owner string — either a WellKnownSid label keyword or a
/// canonical "S-1-..." SID text.
fn resolve_owner(s: &str) -> Result<libp_sd::Sid, String> {
    match s {
        "LocalSystem" => Result::Ok(WellKnownSid::LocalSystem.to_sid()),
        "Everyone" => Result::Ok(WellKnownSid::Everyone.to_sid()),
        "BuiltinAdministrators" => Result::Ok(WellKnownSid::BuiltinAdministrators.to_sid()),
        other => {
            // Try parsing "S-1-5-18"-style text.
            parse_sid_text(other)
        }
    }
}

/// Minimal "S-1-<auth>-<sub>-..." parser for the CLI.
fn parse_sid_text(s: &str) -> Result<libp_sd::Sid, String> {
    let mut parts = s.split('-');
    if parts.next() != Some("S") {
        return Result::Err(format!("not a SID: {s}"));
    }
    let revision: u8 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad SID revision in {s}"))?;
    let authority: u64 = parts
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("bad SID authority in {s}"))?;
    let mut subs = Vec::new();
    for p in parts {
        subs.push(
            p.parse::<u32>()
                .map_err(|_| format!("bad subauthority {p:?} in {s}"))?,
        );
    }
    Result::Ok(libp_sd::Sid::new(revision, authority, subs))
}

// ---------------------------------------------------------------------------
// Hex helpers.
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Result::Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at offset {i}"))?;
        out.push(b);
    }
    Result::Ok(out)
}

// ---------------------------------------------------------------------------
// Access-check subcommands.
// ---------------------------------------------------------------------------

/// The SD shared by the access-check subcommands: a DACL that allows
/// Everyone exactly `ACCESS_READ_CONTROL`.
fn access_check_sd() -> Result<Vec<u8>, libp_sd::Error> {
    SdBuilder::new()
        .owner(WellKnownSid::LocalSystem)
        .dacl(AclBuilder::new().allow(WellKnownSid::Everyone, ACCESS_READ_CONTROL))
        .build()
}

/// Map a `--desired` keyword to an access mask.
fn desired_mask(desired: &str) -> Result<u32, String> {
    match desired {
        "read-control" => Result::Ok(ACCESS_READ_CONTROL),
        "write-dac" => Result::Ok(ACCESS_WRITE_DAC),
        other => Result::Err(format!("unknown --desired {other:?}")),
    }
}

#[derive(Serialize)]
struct AccessCheckResult {
    desired: String,
    desired_mask: u32,
    granted: bool,
    granted_mask: u32,
}

fn access_check(desired: &str) -> serde_json::Value {
    let mask = match desired_mask(desired) {
        Result::Ok(m) => m,
        Result::Err(m) => return err_msg(&m),
    };
    let token = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err_msg(&format!("open self token: {e}")),
    };
    let sd = match access_check_sd() {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(e),
    };
    let req = AccessCheckRequest::new(token.as_raw_fd(), &sd, mask);
    match req.check() {
        Result::Ok(decision) => ok(AccessCheckResult {
            desired: desired.into(),
            desired_mask: mask,
            granted: decision.granted,
            granted_mask: decision.granted_mask,
        }),
        Result::Err(e) => err_sd(e),
    }
}

#[derive(Serialize)]
struct NodeDecisionView {
    granted_mask: u32,
    status: i32,
}

#[derive(Serialize)]
struct AccessCheckListResult {
    desired: String,
    node_count: usize,
    decisions: Vec<NodeDecisionView>,
}

fn access_check_list(desired: &str, nodes: u16) -> serde_json::Value {
    let mask = match desired_mask(desired) {
        Result::Ok(m) => m,
        Result::Err(m) => return err_msg(&m),
    };
    let token = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err_msg(&format!("open self token: {e}")),
    };
    let sd = match access_check_sd() {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(e),
    };
    let mut req = AccessCheckRequest::new(token.as_raw_fd(), &sd, mask);
    // Build a simple object tree: node 0 root, then descending levels.
    for i in 0..nodes {
        let mut guid = [0u8; 16];
        guid[0] = (i + 1) as u8;
        req = req.object_node(ObjectTypeNode::new(i, guid));
    }
    match req.check_list() {
        Result::Ok(decisions) => ok(AccessCheckListResult {
            desired: desired.into(),
            node_count: decisions.len(),
            decisions: decisions
                .iter()
                .map(|d| NodeDecisionView {
                    granted_mask: d.granted_mask,
                    status: d.status,
                })
                .collect(),
        }),
        Result::Err(e) => err_sd(e),
    }
}

fn access_check_with_claim() -> serde_json::Value {
    use libp_sd::{ClaimAttribute, ClaimValue};

    let token = match Token::open_self(SelfOpenFlags::default(), KACS_TOKEN_QUERY) {
        Result::Ok(t) => t,
        Result::Err(e) => return err_msg(&format!("open self token: {e}")),
    };
    let sd = match access_check_sd() {
        Result::Ok(s) => s,
        Result::Err(e) => return err_sd(e),
    };
    // A representative multi-typed claim set — exercises the claims
    // array encoder end-to-end against the kernel's parser.
    let req = AccessCheckRequest::new(token.as_raw_fd(), &sd, ACCESS_READ_CONTROL)
        .claim(ClaimAttribute::new(
            "Department",
            vec![ClaimValue::String("Engineering".into())],
        ))
        .claim(ClaimAttribute::new(
            "Level",
            vec![ClaimValue::Int64(7), ClaimValue::Int64(8)],
        ))
        .claim(ClaimAttribute::new(
            "Active",
            vec![ClaimValue::Boolean(true)],
        ));
    match req.check() {
        Result::Ok(decision) => serde_json::json!({
            "ok": true,
            "granted": decision.granted,
            "granted_mask": decision.granted_mask,
            "claims_accepted": true,
        }),
        Result::Err(e) => err_sd(e),
    }
}
