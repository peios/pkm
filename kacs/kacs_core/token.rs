// Token — per-thread identity object (§7).
//
// Every thread carries a token encoding who it is: user SID, groups,
// privileges, integrity level, claims, confinement, and metadata.
// AccessCheck takes a token + SD and produces an access decision.
//
// Token fields are organized by mutability:
//   Immutable: set at creation, never changes
//   Mutable: atomically adjustable at runtime (privileges, groups, defaults)
//
// In the kernel, the token is a refcounted object behind a pointer in
// the credential's LSM blob. Mutable fields use interior atomics.
// This userspace representation uses plain fields — the kernel wrapper
// adds the atomic/RCU layer.

use crate::compat::{self, AllocError, TryClone, Vec};
use crate::group::GroupEntry;
use crate::luid::Luid;
use crate::privilege::Privileges;
use crate::sid::Sid;

/// Token type: primary (process baseline) or impersonation (per-thread override).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenType {
    /// Process-level baseline token.
    Primary = 1,
    /// Per-thread identity override.
    Impersonation = 2,
}

/// How far an impersonation token's identity can travel (§12.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ImpersonationLevel {
    /// No identity information available.
    Anonymous = 0,
    /// Can identify but not act as the client.
    Identification = 1,
    /// Can act as the client locally.
    Impersonation = 2,
    /// Can act as the client across machine boundaries.
    Delegation = 3,
}

/// Integrity level — vertical trust hierarchy for MIC (§11.13).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum IntegrityLevel {
    /// RID 0 — sandboxed / untrusted code.
    Untrusted = 0,
    /// RID 4096 — browser tabs, low-privilege services.
    Low = 4096,
    /// RID 8192 — default for normal user processes.
    Medium = 8192,
    /// RID 12288 — elevated / admin processes.
    High = 12288,
    /// RID 16384 — kernel and core OS services.
    System = 16384,
}

impl IntegrityLevel {
    /// The RID value used in integrity label SIDs (S-1-16-{rid}).
    pub fn rid(self) -> u32 {
        self as u32
    }

    /// Parse from a mandatory label SID's sub-authority.
    pub fn from_rid(rid: u32) -> Option<Self> {
        match rid {
            0 => Some(IntegrityLevel::Untrusted),
            4096 => Some(IntegrityLevel::Low),
            8192 => Some(IntegrityLevel::Medium),
            12288 => Some(IntegrityLevel::High),
            16384 => Some(IntegrityLevel::System),
            _ => None,
        }
    }
}

/// Elevation type for linked token pairs (§7.7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElevationType {
    /// Not part of a linked pair (UAC not applicable).
    Default = 1,
    /// Full (elevated) token of a linked pair.
    Full = 2,
    /// Filtered (non-elevated) token of a linked pair.
    Limited = 3,
}

/// Mandatory integrity policy flags on the token (§7.3, §11.13).
pub mod mandatory_policy {
    /// Enforce NO_WRITE_UP integrity policy.
    pub const NO_WRITE_UP: u32 = 0x0001;
    /// New child processes inherit the minimum of parent and token integrity.
    pub const NEW_PROCESS_MIN: u32 = 0x0002;
}

/// Who minted this token (§7.3).
#[derive(Clone, Debug)]
pub struct TokenSource {
    /// 8-byte name (e.g., "PeiosKrn", "authd\0\0\0").
    pub name: [u8; 8],
    /// Source-specific identifier.
    pub source_id: Luid,
}

/// A claim attribute on a token — name-value pair for conditional ACEs (§7.3).
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct ClaimEntry {
    /// The claim attribute name (e.g., "Department").
    pub name: crate::compat::String,
    /// The value type discriminator.
    pub claim_type: ClaimType,
    /// Attribute flags (CASE_SENSITIVE, USE_FOR_DENY_ONLY, DISABLED).
    pub flags: u16,
    /// The claim's value(s).
    pub values: ClaimValues,
}

/// Claim value type (MS-DTYP §2.4.10.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimType {
    /// Signed 64-bit integer.
    Int64 = 0x0001,
    /// Unsigned 64-bit integer.
    Uint64 = 0x0002,
    /// Unicode string.
    String = 0x0003,
    /// Security identifier.
    Sid = 0x0005,
    /// Boolean (true/false).
    Boolean = 0x0006,
    /// Opaque byte sequence.
    Octet = 0x0010,
}

/// Claim values — multi-valued, type depends on ClaimType.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub enum ClaimValues {
    /// One or more signed 64-bit integers.
    Int64(Vec<i64>),
    /// One or more unsigned 64-bit integers.
    Uint64(Vec<u64>),
    /// One or more Unicode strings.
    String(Vec<crate::compat::String>),
    /// One or more SIDs.
    Sid(Vec<Sid>),
    /// One or more booleans.
    Boolean(Vec<bool>),
    /// One or more opaque byte sequences.
    Octet(Vec<Vec<u8>>),
}

/// Claim attribute flags.
pub mod claim_flags {
    /// String comparisons are case-sensitive for this claim.
    pub const CASE_SENSITIVE: u16 = 0x0002;
    /// Claim participates in deny ACEs only; invisible to allow ACEs.
    pub const USE_FOR_DENY_ONLY: u16 = 0x0004;
    /// Claim is disabled and resolves to NULL.
    pub const DISABLED: u16 = 0x0010;
}

/// The complete token structure (§7.3).
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct Token {
    // --- Identity core (immutable) ---

    /// The token's primary identity — who this thread IS.
    pub user_sid: Sid,
    /// If true, user_sid matches only deny ACEs (write-restricted token).
    pub user_deny_only: bool,
    /// Group memberships. SIDs are immutable; per-group attributes are mutable.
    pub groups: Vec<GroupEntry>,
    /// Per-authentication-event SID (S-1-5-5-x-y).
    pub logon_sid: Sid,
    /// Secondary SID list for restricted tokens. None = unrestricted.
    pub restricted_sids: Option<Vec<GroupEntry>>,
    /// If true, restricted check applies only to write bits (§11.7).
    pub write_restricted: bool,

    // --- Token type (immutable) ---

    /// Primary or impersonation.
    pub token_type: TokenType,
    /// Meaningful only for impersonation tokens.
    pub impersonation_level: ImpersonationLevel,

    // --- Integrity (immutable) ---

    /// The token's integrity level for MIC enforcement.
    pub integrity_level: IntegrityLevel,
    /// NO_WRITE_UP, NEW_PROCESS_MIN. Immutable after creation.
    pub mandatory_policy: u32,

    // --- Privileges (mutable via AdjustPrivileges) ---

    /// Privilege bitmap (enabled and available sets).
    pub privileges: Privileges,

    // --- Elevation (immutable) ---

    /// Whether this token is part of a linked elevation pair.
    pub elevation_type: ElevationType,
    // linked_token is a weak ref in the kernel — not modeled here.
    // The kernel wrapper holds the Arc.

    // --- Default object security (mutable via AdjustDefault) ---

    /// Index into [user_sid] ++ groups for the default owner of new objects.
    pub owner_sid_index: u16,
    /// Index into [user_sid] ++ groups for the default group of new objects.
    pub primary_group_index: u16,
    // default_dacl omitted for now — requires SD/ACL types (Phase 3.2/3.3)

    // --- Metadata (immutable) ---

    /// Unique identifier for this token instance.
    pub token_id: Luid,
    /// Logon session LUID.
    pub auth_id: Luid,
    /// Who minted this token.
    pub source: TokenSource,
    /// Originating logon session for derived tokens.
    pub origin: Luid,

    // --- Session (mutable, requires SeTcbPrivilege) ---

    /// Interactive session ID (desktop/console).
    pub interactive_session_id: u32,

    // --- Claims (immutable) ---

    /// User identity claims for conditional ACE evaluation.
    pub user_claims: Vec<ClaimEntry>,
    /// Device identity claims for conditional ACE evaluation.
    pub device_claims: Vec<ClaimEntry>,

    // --- Device identity (immutable) ---

    /// Device group memberships. None = no device identity.
    pub device_groups: Option<Vec<GroupEntry>>,
    /// Restricted device groups for compound identity. None = unrestricted.
    pub restricted_device_groups: Option<Vec<GroupEntry>>,

    // --- Confinement (immutable) ---

    /// Confinement SID. When set, token is in a default-deny sandbox.
    pub confinement_sid: Option<Sid>,
    /// Declared capabilities for confined processes.
    pub confinement_capabilities: Vec<GroupEntry>,
    /// Namespace filtering on top of confinement.
    pub isolation_boundary: bool,
    /// Escape hatch — confinement restrictions not evaluated.
    pub confinement_exempt: bool,

    // --- Credential projection (immutable) ---

    /// POSIX UID projected from the token's identity.
    pub projected_uid: u32,
    /// POSIX primary GID projected from the token's identity.
    pub projected_gid: u32,
    /// POSIX supplementary GIDs projected from group memberships.
    pub projected_supplementary_gids: Vec<u32>,

    // --- Audit (mutable) ---

    /// Per-token audit overrides. Additive — forces audit events.
    pub audit_policy: u64,

    // --- Mutation tracking ---

    /// Incremented on any token mutation. Cache invalidation key.
    pub modified_id: u64,
}

impl Token {
    /// Build the SYSTEM token as created at kernel boot (§7.5).
    pub fn system_token() -> Result<Self, AllocError> {
        use crate::well_known;
        use crate::group::*;
        use crate::privilege::bits::ALL_PRIVILEGES;

        let user_sid = well_known::system()?;

        let mut groups = Vec::new();
        compat::vec_push(&mut groups, GroupEntry::new(
            well_known::administrators()?,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER,
        ))?;
        compat::vec_push(&mut groups, GroupEntry::new(
            well_known::everyone()?,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        ))?;
        compat::vec_push(&mut groups, GroupEntry::new(
            well_known::authenticated_users()?,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        ))?;
        compat::vec_push(&mut groups, GroupEntry::new(
            well_known::logon_sid(0, 0)?,
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID,
        ))?;

        Ok(Token {
            user_sid: user_sid.try_clone()?,
            user_deny_only: false,
            groups,
            logon_sid: well_known::logon_sid(0, 0)?,
            restricted_sids: None,
            write_restricted: false,

            token_type: TokenType::Primary,
            impersonation_level: ImpersonationLevel::Impersonation,

            integrity_level: IntegrityLevel::System,
            mandatory_policy: mandatory_policy::NO_WRITE_UP | mandatory_policy::NEW_PROCESS_MIN,

            privileges: Privileges::new_all_enabled(ALL_PRIVILEGES),

            elevation_type: ElevationType::Default,

            owner_sid_index: 0, // user_sid
            primary_group_index: 0,

            token_id: Luid(1),
            auth_id: Luid(0), // Session 0
            source: TokenSource {
                name: *b"PeiosKrn",
                source_id: Luid(0),
            },
            origin: Luid(0),

            interactive_session_id: 0,

            user_claims: Vec::new(),
            device_claims: Vec::new(),
            device_groups: None,
            restricted_device_groups: None,

            confinement_sid: None,
            confinement_capabilities: Vec::new(),
            isolation_boundary: false,
            confinement_exempt: false,

            projected_uid: 0, // SYSTEM = UID 0
            projected_gid: 0,
            projected_supplementary_gids: Vec::new(),

            audit_policy: 0,
            modified_id: 1,
        })
    }

    /// Check if this token is confined (§11.14).
    pub fn is_confined(&self) -> bool {
        self.confinement_sid.is_some() && !self.confinement_exempt
    }

    /// Check if this token has restricting SIDs (§11.7).
    pub fn is_restricted(&self) -> bool {
        self.restricted_sids.as_ref().map_or(false, |s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_token_basics() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
        assert_eq!(token.token_type, TokenType::Primary);
        assert_eq!(token.integrity_level, IntegrityLevel::System);
        assert_eq!(token.elevation_type, ElevationType::Default);
        assert!(!token.user_deny_only);
        assert!(!token.is_confined());
        assert!(!token.is_restricted());
    }

    #[test]
    fn system_token_has_all_privileges() {
        let token = Token::system_token().unwrap();
        use crate::privilege::bits::*;
        assert!(token.privileges.check(SE_CREATE_TOKEN));
        assert!(token.privileges.check(SE_TCB));
        assert!(token.privileges.check(SE_BACKUP));
        assert!(token.privileges.check(SE_RESTORE));
        assert!(token.privileges.check(SE_IMPERSONATE));
        assert!(token.privileges.check(SE_BIND_PRIVILEGED_PORT));
        assert!(token.privileges.check(SE_CREATE_JOB));
    }

    #[test]
    fn system_token_groups() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.groups.len(), 4);
        assert_eq!(token.groups[0].sid, crate::well_known::administrators().unwrap());
        assert!(token.groups[0].is_enabled());
        assert!(token.groups[0].is_owner());
    }

    #[test]
    fn integrity_level_ordering() {
        assert!(IntegrityLevel::System > IntegrityLevel::High);
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium > IntegrityLevel::Low);
        assert!(IntegrityLevel::Low > IntegrityLevel::Untrusted);
    }

    #[test]
    fn integrity_level_round_trip() {
        for level in [
            IntegrityLevel::Untrusted,
            IntegrityLevel::Low,
            IntegrityLevel::Medium,
            IntegrityLevel::High,
            IntegrityLevel::System,
        ] {
            assert_eq!(IntegrityLevel::from_rid(level.rid()), Some(level));
        }
    }

    #[test]
    fn impersonation_level_ordering() {
        assert!(ImpersonationLevel::Delegation > ImpersonationLevel::Impersonation);
        assert!(ImpersonationLevel::Impersonation > ImpersonationLevel::Identification);
        assert!(ImpersonationLevel::Identification > ImpersonationLevel::Anonymous);
    }

    #[test]
    fn system_token_projected_uid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0); // SYSTEM = UID 0
    }
}
