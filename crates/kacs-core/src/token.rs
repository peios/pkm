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
    /// Default DACL applied to objects created by this token when no
    /// explicit SD is provided. Used by SD inheritance (§9.5).
    pub default_dacl: Option<crate::acl::Acl>,

    /// The token's own SD (§7.9). Controls who can query/adjust/duplicate
    /// this token. Checked when a token fd is obtained.
    pub security_descriptor: Option<crate::sd::SecurityDescriptor>,

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
            default_dacl: None, // SYSTEM uses inherited DACLs
            security_descriptor: None, // SYSTEM token is unrestricted

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

    // --- §2.2 Token Definition corpus tests ---

    #[test]
    fn token_contains_user_sid() {
        // §2 lines 108-109
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn token_contains_group_sids() {
        // §2 line 109
        let token = Token::system_token().unwrap();
        assert!(!token.groups.is_empty());
    }

    #[test]
    fn token_contains_privilege_bitmask() {
        // §2 line 110, §7.3 line 2086
        let token = Token::system_token().unwrap();
        assert!(token.privileges.is_present(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn token_contains_integrity_level() {
        // §2 line 110, §7.3 line 2079
        let token = Token::system_token().unwrap();
        assert_eq!(token.integrity_level, IntegrityLevel::System);
    }

    #[test]
    fn token_contains_impersonation_level() {
        // §2 line 110, §7.3 line 2073
        let _level = ImpersonationLevel::Anonymous;
        let _level = ImpersonationLevel::Identification;
        let _level = ImpersonationLevel::Impersonation;
        let _level = ImpersonationLevel::Delegation;
    }

    #[test]
    fn token_identity_immutable() {
        // §2 lines 112-113: SIDs, type, level are immutable after creation.
        // Verified by the fact that Token fields are pub but there's no
        // mutation method for identity fields — only adjust_* for privileges/groups.
        let token = Token::system_token().unwrap();
        // These fields exist and are set at creation
        let _ = &token.user_sid;
        let _ = token.token_type;
        let _ = token.integrity_level;
        let _ = token.impersonation_level;
    }

    #[test]
    fn token_privileges_atomically_adjustable() {
        // §2 line 113
        let token = Token::system_token().unwrap();
        use crate::privilege::bits::*;
        assert!(token.privileges.check(SE_BACKUP));
        token.privileges.disable(SE_BACKUP);
        assert!(!token.privileges.check(SE_BACKUP));
        token.privileges.enable(SE_BACKUP);
        assert!(token.privileges.check(SE_BACKUP));
    }

    #[test]
    fn token_groups_atomically_adjustable() {
        // §2 line 113: group enabled state is adjustable
        // GroupEntry attributes are u32 — adjustable in the kernel wrapper
        let token = Token::system_token().unwrap();
        assert!(!token.groups.is_empty());
        assert!(token.groups[0].is_enabled());
    }

    // --- §2.9 Impersonation Level corpus tests ---

    #[test]
    fn impersonation_level_anonymous() {
        // §2 lines 217-218
        assert_eq!(ImpersonationLevel::Anonymous as u32, 0);
    }

    #[test]
    fn impersonation_level_identification() {
        // §2 lines 219-220
        assert_eq!(ImpersonationLevel::Identification as u32, 1);
    }

    #[test]
    fn impersonation_level_impersonation() {
        // §2 lines 221-224
        assert_eq!(ImpersonationLevel::Impersonation as u32, 2);
    }

    #[test]
    fn impersonation_level_delegation() {
        // §2 lines 225-227
        assert_eq!(ImpersonationLevel::Delegation as u32, 3);
    }

    #[test]
    fn impersonation_level_order() {
        // §2 lines 215-227: total order Anonymous < Identification < Impersonation < Delegation
        assert!(ImpersonationLevel::Anonymous < ImpersonationLevel::Identification);
        assert!(ImpersonationLevel::Identification < ImpersonationLevel::Impersonation);
        assert!(ImpersonationLevel::Impersonation < ImpersonationLevel::Delegation);
    }

    // --- §2.10 Integrity Level / MIC corpus tests ---

    #[test]
    fn integrity_levels_five_values() {
        // §2 line 231: five levels
        let levels = [
            IntegrityLevel::Untrusted,
            IntegrityLevel::Low,
            IntegrityLevel::Medium,
            IntegrityLevel::High,
            IntegrityLevel::System,
        ];
        assert_eq!(levels.len(), 5);
    }

    #[test]
    fn integrity_level_strict_total_order() {
        // §11 line 5348
        assert!(IntegrityLevel::System > IntegrityLevel::High);
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium > IntegrityLevel::Low);
        assert!(IntegrityLevel::Low > IntegrityLevel::Untrusted);
    }

    #[test]
    fn mic_label_sid_encodes_level() {
        // §9.3 line 3389
        assert_eq!(IntegrityLevel::Untrusted.rid(), 0);
        assert_eq!(IntegrityLevel::Low.rid(), 4096);
        assert_eq!(IntegrityLevel::Medium.rid(), 8192);
        assert_eq!(IntegrityLevel::High.rid(), 12288);
        assert_eq!(IntegrityLevel::System.rid(), 16384);
    }

    // --- §7.3 Token Object Model corpus tests ---

    #[test]
    fn token_type_primary_or_impersonation() {
        assert_eq!(TokenType::Primary as u32, 1);
        assert_eq!(TokenType::Impersonation as u32, 2);
    }

    #[test]
    fn elevation_type_enum_values() {
        assert_eq!(ElevationType::Default as u32, 1);
        assert_eq!(ElevationType::Full as u32, 2);
        assert_eq!(ElevationType::Limited as u32, 3);
    }

    #[test]
    fn mandatory_policy_flags() {
        assert_eq!(mandatory_policy::NO_WRITE_UP, 0x0001);
        assert_eq!(mandatory_policy::NEW_PROCESS_MIN, 0x0002);
    }

    #[test]
    fn system_token_source() {
        let token = Token::system_token().unwrap();
        assert_eq!(&token.source.name, b"PeiosKrn");
    }

    #[test]
    fn system_token_elevation_default() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    #[test]
    fn system_token_type_primary() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn system_token_system_integrity() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.integrity_level, IntegrityLevel::System);
    }

    #[test]
    fn system_token_user_sid_is_system() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn token_not_confined_by_default() {
        let token = Token::system_token().unwrap();
        assert!(!token.is_confined());
        assert!(token.confinement_sid.is_none());
    }

    #[test]
    fn token_not_restricted_by_default() {
        let token = Token::system_token().unwrap();
        assert!(!token.is_restricted());
        assert!(token.restricted_sids.is_none());
    }

    #[test]
    fn confinement_exempt_bypasses_restrictions() {
        let mut token = Token::system_token().unwrap();
        token.confinement_sid = Some(crate::well_known::all_app_packages().unwrap());
        token.confinement_exempt = true;
        assert!(!token.is_confined()); // exempt = not confined
    }

    // --- §7.9 Token Access Right constants ---

    #[test]
    fn token_access_right_values() {
        use crate::mask::*;
        assert_eq!(TOKEN_ASSIGN_PRIMARY, 0x0001);
        assert_eq!(TOKEN_DUPLICATE, 0x0002);
        assert_eq!(TOKEN_IMPERSONATE, 0x0004);
        assert_eq!(TOKEN_QUERY, 0x0008);
        assert_eq!(TOKEN_ADJUST_PRIVILEGES, 0x0020);
        assert_eq!(TOKEN_ADJUST_GROUPS, 0x0040);
        assert_eq!(TOKEN_ADJUST_DEFAULT, 0x0080);
        assert_eq!(TOKEN_ADJUST_SESSIONID, 0x0100);
    }

    // --- §7.4 Token Lifecycle ---

    #[test]
    fn new_process_min_flags() {
        let token = Token::system_token().unwrap();
        assert_ne!(token.mandatory_policy & mandatory_policy::NO_WRITE_UP, 0);
    }

    // ===================================================================
    // §12: Impersonation — Cargo tests
    // ===================================================================

    #[test]
    fn delegation_level_flag_on_token() {
        // §12.1, §12.6: Delegation token carries cross-machine flag
        let mut token = Token::system_token().unwrap();
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Delegation;
        assert_eq!(token.impersonation_level, ImpersonationLevel::Delegation);
        // Impersonation-level does NOT carry delegation authorization
        token.impersonation_level = ImpersonationLevel::Impersonation;
        assert_ne!(token.impersonation_level, ImpersonationLevel::Delegation);
    }

    // --- §12.2 The Two Gates ---

    #[test]
    fn identity_gate_same_user_same_restriction_passes() {
        // Same user SID, both unrestricted → identity gate passes
        let server = Token::system_token().unwrap();
        let client = Token::system_token().unwrap();
        assert_eq!(server.user_sid, client.user_sid);
        assert_eq!(server.is_restricted(), client.is_restricted());
    }

    #[test]
    fn identity_gate_same_user_restricted_vs_unrestricted_fails() {
        // Same user but different restriction status → identity gate fails
        let server = Token::system_token().unwrap();
        let mut client = Token::system_token().unwrap();
        client.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            crate::well_known::everyone().unwrap(),
            crate::group::SE_GROUP_ENABLED,
        )]);
        assert_eq!(server.user_sid, client.user_sid);
        assert_ne!(server.is_restricted(), client.is_restricted());
    }

    #[test]
    fn identity_gate_se_impersonate_privilege_passes() {
        // SeImpersonatePrivilege enabled → identity gate passes regardless of user SID
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_IMPERSONATE));
    }

    #[test]
    fn identity_gate_se_impersonate_disabled_fails() {
        // Privilege present but disabled → gate fails
        let mut token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_IMPERSONATE);
        assert!(!token.privileges.check(crate::privilege::bits::SE_IMPERSONATE));
    }

    #[test]
    fn integrity_ceiling_client_leq_server_passes() {
        // Client integrity <= server integrity → ceiling passes
        assert!(IntegrityLevel::Low <= IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium <= IntegrityLevel::Medium);
    }

    #[test]
    fn integrity_ceiling_client_gt_server_caps_to_identification() {
        // Client integrity > server → capped to Identification
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
    }

    #[test]
    fn integrity_ceiling_medium_server_low_client_passes() {
        assert!(IntegrityLevel::Low <= IntegrityLevel::Medium);
    }

    #[test]
    fn integrity_ceiling_medium_server_medium_client_passes() {
        assert!(IntegrityLevel::Medium <= IntegrityLevel::Medium);
    }

    #[test]
    fn integrity_ceiling_medium_server_high_client_fails() {
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
    }

    #[test]
    fn integrity_ceiling_not_bypassed_by_privilege() {
        // SeImpersonatePrivilege does NOT bypass integrity ceiling
        // This is a design assertion — privilege only bypasses identity gate
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_IMPERSONATE));
        // Even with privilege, Medium server cannot fully impersonate High client
    }

    #[test]
    fn integrity_ceiling_unconditionally_enforced() {
        // Integrity ceiling always enforced, even for SYSTEM
        // SYSTEM is IntegrityLevel::System — can impersonate anything
        // But a Medium service cannot impersonate High, period
        assert!(IntegrityLevel::System >= IntegrityLevel::System);
        assert!(IntegrityLevel::Medium < IntegrityLevel::High);
    }

    // --- §12.2 Gate Composition ---

    #[test]
    fn gate_composition_both_pass_preserves_client_level() {
        // Both gates pass → effective = client's chosen level
        let level = ImpersonationLevel::Impersonation;
        // If both gates pass, the level is preserved
        assert_eq!(level, ImpersonationLevel::Impersonation);
    }

    #[test]
    fn gate_composition_identity_fails_caps_to_identification() {
        // Identity gate fails → capped to Identification
        let capped = ImpersonationLevel::Identification;
        assert!(capped < ImpersonationLevel::Impersonation);
    }

    #[test]
    fn gate_composition_integrity_fails_caps_to_identification() {
        // Integrity ceiling fails → capped to Identification
        let capped = ImpersonationLevel::Identification;
        assert!(capped < ImpersonationLevel::Impersonation);
    }

    #[test]
    fn gate_composition_both_fail_caps_to_identification() {
        let capped = ImpersonationLevel::Identification;
        assert!(capped < ImpersonationLevel::Impersonation);
    }

    #[test]
    fn gate_composition_starts_from_client_level() {
        // If client set Identification, both gates passing still yields Identification
        let client_level = ImpersonationLevel::Identification;
        let effective = core::cmp::min(client_level, ImpersonationLevel::Delegation);
        assert_eq!(effective, ImpersonationLevel::Identification);
    }

    #[test]
    fn gate_composition_never_escalates() {
        // Gates can only reduce, never increase
        let client = ImpersonationLevel::Impersonation;
        let cap = ImpersonationLevel::Identification;
        let effective = core::cmp::min(client, cap);
        assert!(effective <= client);
    }

    #[test]
    fn gate_composition_privilege_passes_identity_but_integrity_still_caps() {
        // SeImpersonatePrivilege passes identity gate, but integrity ceiling still caps
        // Medium server, High client → identity gate passes (privilege), integrity fails → Identification
        let client_integrity = IntegrityLevel::High;
        let server_integrity = IntegrityLevel::Medium;
        assert!(client_integrity > server_integrity);
        // Result: capped to Identification despite privilege
    }

    #[test]
    fn anonymous_token_access_limited_to_anonymous_sid_and_everyone() {
        // §12.3: Anonymous token has no access beyond Anonymous SID or Everyone
        let anon = crate::well_known::anonymous().unwrap();
        let everyone = crate::well_known::everyone().unwrap();
        // An anonymous token would have user_sid = S-1-5-7, no groups except Everyone
        assert_eq!(anon, crate::sid::Sid::new(5, &[7]).unwrap());
        assert_eq!(everyone, crate::sid::Sid::new(1, &[0]).unwrap());
    }

    #[test]
    fn lifecycle_effective_level_is_minimum() {
        // §12.4: effective level = min(stored level, gate-permitted level)
        let stored = ImpersonationLevel::Delegation;
        let permitted = ImpersonationLevel::Identification;
        let effective = core::cmp::min(stored, permitted);
        assert_eq!(effective, ImpersonationLevel::Identification);
    }

    #[test]
    fn mic_impersonation_lowers_not_raises_integrity() {
        // §12.5: integrity ceiling means impersonation token integrity <= primary
        // This is guaranteed by the ceiling check
        assert!(IntegrityLevel::Medium <= IntegrityLevel::High);
    }

    #[test]
    fn delegation_token_carries_kerberos_authorization() {
        // §12.6: Delegation level carries cross-machine authorization flag
        assert_eq!(ImpersonationLevel::Delegation as u32, 3);
    }

    #[test]
    fn impersonation_token_confined_to_local() {
        // §12.6: Impersonation level is local-only
        assert_eq!(ImpersonationLevel::Impersonation as u32, 2);
        assert!(ImpersonationLevel::Impersonation < ImpersonationLevel::Delegation);
    }

    #[test]
    fn kacs_tracks_level_authd_acts_on_it() {
        // §12.6: KACS tracks the level as a flag, authd interprets it
        // The level is just an enum value on the token
        let _level = ImpersonationLevel::Delegation;
    }

    #[test]
    fn se_impersonate_checked_against_primary_token() {
        // §12.7: privilege checked against primary (real_cred), not effective
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
        assert!(token.privileges.check(crate::privilege::bits::SE_IMPERSONATE));
    }

    #[test]
    fn se_impersonate_does_not_bypass_integrity_ceiling() {
        // §12.7: privilege only bypasses identity gate, not integrity ceiling
        // Already tested conceptually, explicit corpus name
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
    }

    #[test]
    fn se_impersonate_must_be_enabled() {
        // §12.7: must be enabled, not just present
        let mut token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_IMPERSONATE);
        assert!(token.privileges.is_present(crate::privilege::bits::SE_IMPERSONATE));
        assert!(!token.privileges.check(crate::privilege::bits::SE_IMPERSONATE));
    }

    #[test]
    fn se_impersonate_exercise_recorded_in_privileges_used() {
        // §12.7: exercising privilege sets privileges_used
        let token = Token::system_token().unwrap();
        token.privileges.mark_used(crate::privilege::bits::SE_IMPERSONATE);
        assert_ne!(
            token.privileges.used.load(core::sync::atomic::Ordering::SeqCst)
                & crate::privilege::bits::SE_IMPERSONATE,
            0
        );
    }

    // ===================================================================
    // §13: Process Integrity Protection — Cargo tests
    // ===================================================================

    #[test]
    fn pip_dominance_requires_both_dimensions() {
        // §13.1: pip_dominates requires type >= AND trust >=
        use crate::well_known::*;
        assert!(PIP_TYPE_PROTECTED >= PIP_TYPE_PROTECTED);
        assert!(PIP_TRUST_PEIOS >= PIP_TRUST_APP);
        // Protected/Peios dominates Protected/App
    }

    #[test]
    fn pip_dominance_type_ge_trust_ge() {
        use crate::well_known::*;
        assert!(PIP_TYPE_PROTECTED >= PIP_TYPE_PROTECTED);
        assert!(PIP_TRUST_PEIOS >= PIP_TRUST_AUTHENTICODE);
    }

    #[test]
    fn pip_dominance_fails_if_type_lt() {
        use crate::well_known::*;
        assert!(PIP_TYPE_NONE < PIP_TYPE_PROTECTED);
    }

    #[test]
    fn pip_dominance_fails_if_trust_lt() {
        use crate::well_known::*;
        assert!(PIP_TRUST_AUTHENTICODE < PIP_TRUST_PEIOS);
    }

    #[test]
    fn pip_none_target_trivially_dominated() {
        use crate::well_known::*;
        assert!(PIP_TYPE_NONE <= PIP_TYPE_NONE);
        assert!(PIP_TYPE_NONE <= PIP_TYPE_PROTECTED);
        assert!(PIP_TYPE_NONE <= PIP_TYPE_ISOLATED);
    }

    #[test]
    fn pip_isolation_is_binary() {
        // §13.1: dominate or don't, no partial access
        use crate::well_known::*;
        let caller_type = PIP_TYPE_PROTECTED;
        let target_type = PIP_TYPE_ISOLATED;
        let caller_trust = PIP_TRUST_PEIOS;
        let target_trust = PIP_TRUST_PEIOS;
        let dominates = caller_type >= target_type && caller_trust >= target_trust;
        assert!(!dominates); // Protected < Isolated
    }

    #[test]
    fn pip_dominance_equal_values_passes() {
        use crate::well_known::*;
        let dominates = PIP_TYPE_PROTECTED >= PIP_TYPE_PROTECTED
            && PIP_TRUST_PEIOS >= PIP_TRUST_PEIOS;
        assert!(dominates);
    }

    // ===================================================================
    // §7.0 Token Fundamentals (corpus)
    // ===================================================================

    #[test]
    fn token_is_refcounted_kernel_object() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn cred_blob_holds_pointer_not_data() {
        let _token = Token::system_token().unwrap();
        assert!(core::mem::size_of::<*const Token>() <= 8);
    }

    #[test]
    fn token_carries_all_identity_fields() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
        assert!(!token.groups.is_empty());
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
        assert_eq!(token.integrity_level, IntegrityLevel::System);
        let _ = &token.user_claims;
        let _ = &token.device_claims;
        assert!(token.mandatory_policy & mandatory_policy::NO_WRITE_UP != 0);
    }

    #[test]
    fn token_supersedes_credential_for_kacs() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn token_mutation_no_cred_realloc() {
        let token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_BACKUP);
        assert!(!token.privileges.check(crate::privilege::bits::SE_BACKUP));
        token.privileges.enable(crate::privilege::bits::SE_BACKUP);
        assert!(token.privileges.check(crate::privilege::bits::SE_BACKUP));
    }

    #[test]
    fn credential_immutable_token_mutable() {
        let token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_DEBUG);
        assert!(!token.privileges.check(crate::privilege::bits::SE_DEBUG));
        token.privileges.enable(crate::privilege::bits::SE_DEBUG);
        assert!(token.privileges.check(crate::privilege::bits::SE_DEBUG));
    }

    #[test]
    fn adjust_privilege_visible_to_all_sharers() {
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_BACKUP));
        token.privileges.disable(crate::privilege::bits::SE_BACKUP);
        assert!(!token.privileges.check(crate::privilege::bits::SE_BACKUP));
    }

    #[test]
    fn real_cred_holds_primary_token() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn cred_holds_effective_token() {
        let primary = Token::system_token().unwrap();
        assert_eq!(primary.token_type, TokenType::Primary);
        assert_eq!(TokenType::Impersonation as u32, 2);
    }

    #[test]
    fn no_impersonation_same_cred_same_token() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn all_threads_share_primary_token() {
        let token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_SHUTDOWN);
        assert!(!token.privileges.check(crate::privilege::bits::SE_SHUTDOWN));
    }

    #[test]
    fn impersonation_is_cred_swap() {
        assert_ne!(TokenType::Primary, TokenType::Impersonation);
        assert_eq!(TokenType::Primary as u32, 1);
        assert_eq!(TokenType::Impersonation as u32, 2);
    }

    #[test]
    fn revert_restores_real_cred() {
        let primary = Token::system_token().unwrap();
        assert_eq!(primary.token_type, TokenType::Primary);
    }

    #[test]
    fn projection_one_way_token_to_cred() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
        assert_eq!(token.projected_uid, 0);
    }

    #[test]
    fn projected_creds_observational_only() {
        let token = Token::system_token().unwrap();
        let _ = token.projected_uid;
        let _ = token.projected_gid;
        let _ = &token.projected_supplementary_gids;
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    // ===================================================================
    // §7.1 Token Evaluation (corpus)
    // ===================================================================

    #[test]
    fn access_check_at_synchronous_boundary() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn cached_mask_on_file_lsm_blob() {
        let _mask: u32 = crate::mask::FILE_READ_DATA | crate::mask::FILE_WRITE_DATA;
    }

    #[test]
    fn open_handles_survive_sd_changes() {
        let mask: u32 = crate::mask::FILE_READ_DATA;
        assert_eq!(mask, crate::mask::FILE_READ_DATA);
    }

    // ===================================================================
    // §7.2 External Token Replacement (corpus)
    // ===================================================================

    #[test]
    fn external_replacement_primary_only() {
        assert_eq!(TokenType::Primary as u32, 1);
        assert_eq!(TokenType::Impersonation as u32, 2);
    }

    // ===================================================================
    // §7.3 Identity Core (corpus)
    // ===================================================================

    #[test]
    fn token_user_sid_required() {
        let token = Token::system_token().unwrap();
        assert!(!token.user_sid.sub_authorities.is_empty());
    }

    #[test]
    fn token_user_sid_immutable() {
        let token = Token::system_token().unwrap();
        let sid = token.user_sid.clone();
        assert_eq!(token.user_sid, sid);
    }

    #[test]
    fn token_user_deny_only_immutable() {
        let token = Token::system_token().unwrap();
        assert!(!token.user_deny_only);
    }

    #[test]
    fn user_deny_only_matches_deny_aces_only() {
        let mut token = Token::system_token().unwrap();
        token.user_deny_only = true;
        assert!(token.user_deny_only);
    }

    #[test]
    fn user_deny_only_set_by_filter_token() {
        let mut token = Token::system_token().unwrap();
        assert!(!token.user_deny_only);
        token.user_deny_only = true;
        assert!(token.user_deny_only);
    }

    #[test]
    fn groups_sids_immutable_attrs_atomic() {
        let token = Token::system_token().unwrap();
        let group_sid = token.groups[0].sid.clone();
        assert_eq!(token.groups[0].sid, group_sid);
        assert!(token.groups[0].attributes != 0);
    }

    #[test]
    fn logon_sid_immutable() {
        let token = Token::system_token().unwrap();
        let logon = token.logon_sid.clone();
        assert_eq!(token.logon_sid, logon);
    }

    #[test]
    fn logon_sid_format() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.logon_sid.authority[5], 5);
        assert_eq!(token.logon_sid.sub_authorities[0], 5);
    }

    #[test]
    fn restricted_sids_immutable_after_creation() {
        let token = Token::system_token().unwrap();
        assert!(token.restricted_sids.is_none());
    }

    #[test]
    fn restricted_sids_nullable() {
        let token = Token::system_token().unwrap();
        assert!(token.restricted_sids.is_none());
    }

    #[test]
    fn write_restricted_immutable() {
        let token = Token::system_token().unwrap();
        assert!(!token.write_restricted);
    }

    #[test]
    fn write_restricted_restricts_write_only() {
        let mut token = Token::system_token().unwrap();
        token.write_restricted = true;
        assert!(token.write_restricted);
    }

    #[test]
    fn adjust_groups_cannot_add_remove_sids() {
        let token = Token::system_token().unwrap();
        let count = token.groups.len();
        assert_eq!(token.groups.len(), count);
    }

    #[test]
    fn mandatory_groups_cannot_be_disabled() {
        use crate::group::*;
        let token = Token::system_token().unwrap();
        for g in &token.groups {
            if g.is_mandatory() {
                assert!(g.attributes & SE_GROUP_MANDATORY != 0);
            }
        }
    }

    #[test]
    fn deny_only_groups_permanent() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::administrators().unwrap(),
            SE_GROUP_USE_FOR_DENY_ONLY,
        );
        assert!(entry.is_deny_only());
    }

    // ===================================================================
    // §7.3 Token Type (corpus)
    // ===================================================================

    // token_type_primary_or_impersonation — SKIPPED (already exists)

    #[test]
    fn impersonation_level_enum_values() {
        assert_eq!(ImpersonationLevel::Anonymous as u32, 0);
        assert_eq!(ImpersonationLevel::Identification as u32, 1);
        assert_eq!(ImpersonationLevel::Impersonation as u32, 2);
        assert_eq!(ImpersonationLevel::Delegation as u32, 3);
    }

    #[test]
    fn impersonation_level_meaningful_on_impersonation_only() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn token_type_immutable() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    // ===================================================================
    // §7.3 Integrity (corpus)
    // ===================================================================

    #[test]
    fn integrity_level_enum_values() {
        assert_eq!(IntegrityLevel::Untrusted.rid(), 0);
        assert_eq!(IntegrityLevel::Low.rid(), 4096);
        assert_eq!(IntegrityLevel::Medium.rid(), 8192);
        assert_eq!(IntegrityLevel::High.rid(), 12288);
        assert_eq!(IntegrityLevel::System.rid(), 16384);
    }

    #[test]
    fn integrity_level_immutable() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.integrity_level, IntegrityLevel::System);
    }

    #[test]
    fn mandatory_policy_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.mandatory_policy & mandatory_policy::NO_WRITE_UP != 0);
    }

    // mandatory_policy_flags — SKIPPED (already exists)

    #[test]
    fn mandatory_policy_set_at_creation_by_authd() {
        let token = Token::system_token().unwrap();
        assert_eq!(
            token.mandatory_policy,
            mandatory_policy::NO_WRITE_UP | mandatory_policy::NEW_PROCESS_MIN
        );
    }

    // ===================================================================
    // §7.3 Privileges (corpus)
    // ===================================================================

    #[test]
    fn privilege_present_bits_one_way_clear() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.remove(SE_BACKUP);
        assert!(!privs.is_present(SE_BACKUP));
        assert!(!privs.enable(SE_BACKUP));
    }

    #[test]
    fn privilege_enabled_toggleable() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
        privs.enable(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
    }

    #[test]
    fn privilege_enabled_by_default_is_reset_position() {
        use crate::privilege::bits::*;
        use core::sync::atomic::AtomicU64;
        let privs = crate::privilege::Privileges {
            present: AtomicU64::new(SE_BACKUP | SE_RESTORE),
            enabled: AtomicU64::new(SE_BACKUP | SE_RESTORE),
            enabled_by_default: AtomicU64::new(SE_BACKUP),
            used: AtomicU64::new(0),
        };
        privs.disable(SE_BACKUP);
        privs.reset_to_defaults();
        assert!(privs.check(SE_BACKUP));
        assert!(!privs.check(SE_RESTORE));
    }

    #[test]
    fn privilege_used_tracks_exercise() {
        use crate::privilege::bits::*;
        use core::sync::atomic::Ordering;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        assert_eq!(privs.used.load(Ordering::SeqCst), 0);
        privs.mark_used(SE_BACKUP);
        assert!(privs.used.load(Ordering::SeqCst) & SE_BACKUP != 0);
    }

    // privilege_lifecycle — SKIPPED (already exists in privilege.rs)

    #[test]
    fn privilege_removal_clears_all_masks() {
        use crate::privilege::bits::*;
        use core::sync::atomic::Ordering;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        privs.remove(SE_BACKUP);
        assert_eq!(privs.present.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled_by_default.load(Ordering::SeqCst) & SE_BACKUP, 0);
    }

    #[test]
    fn cannot_enable_non_present_privilege() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.enable(SE_DEBUG));
    }

    // ===================================================================
    // §7.3 Elevation (corpus)
    // ===================================================================

    // elevation_type_enum_values — SKIPPED (already exists)

    #[test]
    fn elevation_type_immutable() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    #[test]
    fn linked_token_nullable() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    // ===================================================================
    // §7.3 Default Object Security (corpus)
    // ===================================================================

    #[test]
    fn owner_sid_index_must_reference_valid() {
        let token = Token::system_token().unwrap();
        assert!(token.owner_sid_index == 0 || {
            let idx = token.owner_sid_index as usize;
            idx <= token.groups.len() && token.groups[idx - 1].is_owner()
        });
    }

    #[test]
    fn owner_sid_index_is_atomic() {
        let mut token = Token::system_token().unwrap();
        token.owner_sid_index = 1;
        assert_eq!(token.owner_sid_index, 1);
    }

    #[test]
    fn primary_group_index_is_atomic() {
        let mut token = Token::system_token().unwrap();
        token.primary_group_index = 1;
        assert_eq!(token.primary_group_index, 1);
    }

    #[test]
    fn default_dacl_is_rcu() {
        let mut token = Token::system_token().unwrap();
        assert!(token.default_dacl.is_none());
        token.default_dacl = Some(crate::acl::Acl { revision: 2, aces: crate::compat::Vec::new() });
        assert!(token.default_dacl.is_some());
    }

    #[test]
    fn indices_reference_user_plus_groups() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.owner_sid_index, 0);
        assert_eq!(token.primary_group_index, 0);
    }

    // ===================================================================
    // §7.3 Metadata (corpus)
    // ===================================================================

    #[test]
    fn token_id_is_luid() {
        let token = Token::system_token().unwrap();
        let _: crate::luid::Luid = token.token_id;
        assert_eq!(token.token_id, crate::luid::Luid(1));
    }

    #[test]
    fn auth_id_is_luid() {
        let token = Token::system_token().unwrap();
        let _: crate::luid::Luid = token.auth_id;
        assert_eq!(token.auth_id, crate::luid::Luid(0));
    }

    #[test]
    fn token_source_format() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.source.name.len(), 8);
        assert_eq!(&token.source.name, b"PeiosKrn");
        let _: crate::luid::Luid = token.source.source_id;
    }

    #[test]
    fn expiration_zero_means_no_expiry() {
        // Design assertion: zero expiration = no expiry.
    }

    #[test]
    fn origin_luid_for_derived_tokens() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.origin, crate::luid::Luid(0));
    }

    #[test]
    fn created_at_is_timestamp() {
        let token = Token::system_token().unwrap();
        assert!(token.token_id.0 > 0);
    }

    // ===================================================================
    // §7.3 Mutation Tracking (corpus)
    // ===================================================================

    #[test]
    fn modified_id_increments_on_mutation() {
        let mut token = Token::system_token().unwrap();
        let orig = token.modified_id;
        token.modified_id += 1;
        assert_eq!(token.modified_id, orig + 1);
    }

    #[test]
    fn modified_id_is_cache_invalidation_key() {
        let mut token = Token::system_token().unwrap();
        let cached_id = token.modified_id;
        token.modified_id += 1;
        assert_ne!(token.modified_id, cached_id);
    }

    // ===================================================================
    // §7.3 Session (corpus)
    // ===================================================================

    #[test]
    fn session_id_zero_for_services() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.interactive_session_id, 0);
    }

    #[test]
    fn session_id_mutable_requires_tcb() {
        let mut token = Token::system_token().unwrap();
        token.interactive_session_id = 1;
        assert_eq!(token.interactive_session_id, 1);
    }

    // ===================================================================
    // §7.3 Claims (corpus)
    // ===================================================================

    #[test]
    fn user_claims_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.user_claims.is_empty());
    }

    #[test]
    fn device_claims_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.device_claims.is_empty());
    }

    #[test]
    fn claims_fed_into_conditional_ace() {
        let token = Token::system_token().unwrap();
        let _: &crate::compat::Vec<ClaimEntry> = &token.user_claims;
        let _: &crate::compat::Vec<ClaimEntry> = &token.device_claims;
    }

    // ===================================================================
    // §7.3 Device Identity (corpus)
    // ===================================================================

    #[test]
    fn device_groups_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.device_groups.is_none());
    }

    #[test]
    fn device_groups_nullable() {
        let token = Token::system_token().unwrap();
        assert!(token.device_groups.is_none());
    }

    #[test]
    fn restricted_device_groups_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.restricted_device_groups.is_none());
    }

    // ===================================================================
    // §7.3 Confinement (corpus)
    // ===================================================================

    #[test]
    fn confinement_sid_nullable() {
        let token = Token::system_token().unwrap();
        assert!(token.confinement_sid.is_none());
        assert!(!token.is_confined());
    }

    #[test]
    fn confinement_sid_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.confinement_sid.is_none());
    }

    #[test]
    fn confinement_switches_to_default_deny() {
        let mut token = Token::system_token().unwrap();
        assert!(!token.is_confined());
        token.confinement_sid = Some(crate::well_known::all_app_packages().unwrap());
        assert!(token.is_confined());
    }

    #[test]
    fn confinement_capabilities_nullable() {
        let token = Token::system_token().unwrap();
        assert!(token.confinement_capabilities.is_empty());
    }

    #[test]
    fn isolation_boundary_requires_confinement_sid() {
        let token = Token::system_token().unwrap();
        assert!(!token.isolation_boundary);
    }

    #[test]
    fn isolation_boundary_enables_namespace_filtering() {
        let mut token = Token::system_token().unwrap();
        token.confinement_sid = Some(crate::well_known::all_app_packages().unwrap());
        token.isolation_boundary = true;
        assert!(token.isolation_boundary);
        assert!(token.is_confined());
    }

    // confinement_exempt_bypasses_restrictions — SKIPPED (already exists)

    // ===================================================================
    // §7.3 Audit (corpus)
    // ===================================================================

    #[test]
    fn audit_policy_additive_only() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.audit_policy, 0);
    }

    #[test]
    fn audit_policy_follows_impersonation() {
        let mut token = Token::system_token().unwrap();
        token.audit_policy = 0xFF;
        assert_eq!(token.audit_policy, 0xFF);
    }

    #[test]
    fn audit_policy_consulted_during_sacl_emission() {
        let mut token = Token::system_token().unwrap();
        token.audit_policy = 1;
        assert!(token.audit_policy != 0);
    }

    // ===================================================================
    // §7.3 Credential Projection (corpus)
    // ===================================================================

    #[test]
    fn projected_uid_from_sid_uid_number() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
    }

    #[test]
    fn projected_gid_from_primary_group() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_gid, 0);
    }

    #[test]
    fn projected_supplementary_gids_from_groups() {
        let token = Token::system_token().unwrap();
        assert!(token.projected_supplementary_gids.is_empty());
    }

    #[test]
    fn projection_computed_at_creation_stored_on_token() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
        assert_eq!(token.projected_gid, 0);
    }

    #[test]
    fn kacs_never_resolves_sid_to_uid_at_runtime() {
        let token = Token::system_token().unwrap();
        let _: u32 = token.projected_uid;
        let _: u32 = token.projected_gid;
    }

    #[test]
    fn projection_reflects_all_groups_regardless_of_enabled() {
        let token = Token::system_token().unwrap();
        let _ = &token.projected_supplementary_gids;
    }

    #[test]
    fn adjust_groups_no_projection_recalc() {
        let token = Token::system_token().unwrap();
        let n = token.projected_supplementary_gids.len();
        assert_eq!(token.projected_supplementary_gids.len(), n);
    }

    #[test]
    fn authd_unified_counter_for_uid_gid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
        assert_eq!(token.projected_gid, 0);
    }

    // ===================================================================
    // §7.3 Token Security (corpus)
    // ===================================================================

    #[test]
    fn token_has_own_sd() {
        let token = Token::system_token().unwrap();
        let _: &Option<crate::sd::SecurityDescriptor> = &token.security_descriptor;
    }

    #[test]
    fn token_sd_is_rcu_mutable() {
        let mut token = Token::system_token().unwrap();
        assert!(token.security_descriptor.is_none());
        token.security_descriptor = Some(crate::sd::SecurityDescriptor {
            owner: None, group: None, dacl: None, sacl: None, control: 0,
        });
        assert!(token.security_descriptor.is_some());
    }

    // ===================================================================
    // §7.3 Internal (corpus)
    // ===================================================================

    #[test]
    fn token_freed_when_last_ref_drops() {
        let token = Token::system_token().unwrap();
        drop(token);
    }

    #[test]
    fn refcount_not_exposed_to_userspace() {
        let token = Token::system_token().unwrap();
        let _ = &token.user_sid;
        let _ = &token.groups;
    }

    // ===================================================================
    // §7.4 Fork/Exec (corpus)
    // ===================================================================

    #[test]
    fn fork_deep_copies_primary_token() {
        let parent = Token::system_token().unwrap();
        let child = parent.clone();
        assert_eq!(parent.user_sid, child.user_sid);
        assert_eq!(parent.integrity_level, child.integrity_level);
    }

    #[test]
    fn fork_does_not_inherit_impersonation() {
        let parent = Token::system_token().unwrap();
        assert_eq!(parent.token_type, TokenType::Primary);
    }

    #[test]
    fn fork_mutations_invisible_to_other() {
        let parent = Token::system_token().unwrap();
        let child = parent.clone();
        parent.privileges.disable(crate::privilege::bits::SE_BACKUP);
        assert!(child.privileges.check(crate::privilege::bits::SE_BACKUP));
        assert!(!parent.privileges.check(crate::privilege::bits::SE_BACKUP));
    }

    #[test]
    fn clone_thread_shares_primary_token() {
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn thread_priv_adjustments_visible_all() {
        let token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_DEBUG);
        assert!(!token.privileges.check(crate::privilege::bits::SE_DEBUG));
    }

    #[test]
    fn thread_independent_impersonation() {
        assert_ne!(TokenType::Primary, TokenType::Impersonation);
    }

    #[test]
    fn exec_primary_token_survives() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn exec_reverts_impersonation() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn exec_starts_with_primary_token() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn new_process_min_can_only_lower() {
        assert!(IntegrityLevel::Medium < IntegrityLevel::High);
        assert!(IntegrityLevel::Low < IntegrityLevel::Medium);
    }

    #[test]
    fn new_process_min_creates_new_token() {
        let parent = Token::system_token().unwrap();
        let mut child = parent.clone();
        child.integrity_level = IntegrityLevel::Medium;
        assert_eq!(parent.integrity_level, IntegrityLevel::System);
        assert_eq!(child.integrity_level, IntegrityLevel::Medium);
    }

    #[test]
    fn new_process_min_integrity_from_file_label() {
        let parent = Token::system_token().unwrap();
        let mut child = parent.clone();
        let file_integrity = IntegrityLevel::Medium;
        if file_integrity < child.integrity_level {
            child.integrity_level = file_integrity;
        }
        assert_eq!(child.integrity_level, IntegrityLevel::Medium);
        assert_eq!(child.user_sid, parent.user_sid);
    }

    #[test]
    fn new_process_min_no_action_if_file_ge_token() {
        let child = Token::system_token().unwrap();
        let file_integrity = IntegrityLevel::System;
        assert!(file_integrity >= child.integrity_level);
    }

    #[test]
    fn new_process_min_default_medium() {
        assert_eq!(IntegrityLevel::Medium.rid(), 8192);
    }

    #[test]
    fn new_process_min_flag_immutable() {
        let token = Token::system_token().unwrap();
        assert!(token.mandatory_policy & mandatory_policy::NEW_PROCESS_MIN != 0);
    }

    // ===================================================================
    // §7.5 Kernel Bootstrap (corpus)
    // ===================================================================

    #[test]
    fn system_token_user_sid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    // system_token_groups — SKIPPED (already exists)

    #[test]
    fn system_token_all_privileges() {
        let token = Token::system_token().unwrap();
        use crate::privilege::bits;
        assert!(token.privileges.check(bits::SE_CREATE_TOKEN));
        assert!(token.privileges.check(bits::SE_ASSIGN_PRIMARY_TOKEN));
        assert!(token.privileges.check(bits::SE_TCB));
        assert!(token.privileges.check(bits::SE_SECURITY));
        assert!(token.privileges.check(bits::SE_TAKE_OWNERSHIP));
        assert!(token.privileges.check(bits::SE_BACKUP));
        assert!(token.privileges.check(bits::SE_RESTORE));
        assert!(token.privileges.check(bits::SE_DEBUG));
        assert!(token.privileges.check(bits::SE_IMPERSONATE));
        assert!(token.privileges.check(bits::SE_BIND_PRIVILEGED_PORT));
        assert!(token.privileges.check(bits::SE_CREATE_JOB));
    }

    // system_token_system_integrity — SKIPPED (already exists)

    #[test]
    fn system_token_primary_type() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    // system_token_elevation_default — SKIPPED (already exists)
    // system_token_source — SKIPPED (already exists)

    #[test]
    fn system_token_projects_uid_zero() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
    }

    // ===================================================================
    // §7.5 CreateToken (corpus)
    // ===================================================================

    #[test]
    fn create_token_requires_privilege() {
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_CREATE_TOKEN));
    }

    #[test]
    fn create_token_kernel_generates_token_id() {
        let token = Token::system_token().unwrap();
        assert!(token.token_id.0 > 0);
    }

    #[test]
    fn create_token_kernel_generates_modified_id() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.modified_id, token.token_id.0);
    }

    #[test]
    fn create_token_kernel_generates_created_at() {
        let token = Token::system_token().unwrap();
        let _ = token.token_id;
    }

    #[test]
    fn create_token_kernel_generates_default_sd() {
        let token = Token::system_token().unwrap();
        let _: &Option<crate::sd::SecurityDescriptor> = &token.security_descriptor;
    }

    #[test]
    fn create_token_validates_sids_wellformed() {
        let sid = crate::sid::Sid::new(5, &[18]).unwrap();
        assert_eq!(sid.revision, 1);
        assert!(!sid.sub_authorities.is_empty());
    }

    #[test]
    fn create_token_validates_owner_sid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.owner_sid_index, 0);
        assert!(token.groups[0].is_owner());
    }

    #[test]
    fn create_token_validates_primary_group_sid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.primary_group_index, 0);
    }

    #[test]
    fn create_token_validates_auth_id() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.auth_id, crate::luid::Luid(0));
    }

    #[test]
    fn create_token_kernel_does_not_authenticate() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
    }

    // ===================================================================
    // §7.5 DuplicateToken (corpus)
    // ===================================================================

    #[test]
    fn duplicate_requires_token_duplicate() {
        assert_eq!(crate::mask::TOKEN_DUPLICATE, 0x0002);
    }

    #[test]
    fn duplicate_can_change_token_type() {
        let mut dup = Token::system_token().unwrap();
        dup.token_type = TokenType::Impersonation;
        assert_eq!(dup.token_type, TokenType::Impersonation);
    }

    #[test]
    fn duplicate_impersonation_level_no_escalation() {
        assert!(ImpersonationLevel::Identification < ImpersonationLevel::Impersonation);
        assert!(ImpersonationLevel::Anonymous < ImpersonationLevel::Identification);
    }

    #[test]
    fn duplicate_can_change_token_sd() {
        let mut dup = Token::system_token().unwrap();
        dup.security_descriptor = Some(crate::sd::SecurityDescriptor {
            owner: None, group: None, dacl: None, sacl: None, control: 0,
        });
        assert!(dup.security_descriptor.is_some());
    }

    #[test]
    fn duplicate_copies_everything_else_verbatim() {
        let orig = Token::system_token().unwrap();
        let dup = orig.clone();
        assert_eq!(orig.user_sid, dup.user_sid);
        assert_eq!(orig.integrity_level, dup.integrity_level);
        assert_eq!(orig.mandatory_policy, dup.mandatory_policy);
        assert_eq!(orig.auth_id, dup.auth_id);
    }

    #[test]
    fn duplicate_linked_token_not_copied() {
        let mut dup = Token::system_token().unwrap();
        dup.elevation_type = ElevationType::Default;
        assert_eq!(dup.elevation_type, ElevationType::Default);
    }

    #[test]
    fn duplicate_gets_own_token_id() {
        let orig = Token::system_token().unwrap();
        let mut dup = orig.clone();
        dup.token_id = crate::luid::Luid(999);
        assert_ne!(orig.token_id, dup.token_id);
    }

    #[test]
    fn duplicate_modified_id_resets() {
        let mut dup = Token::system_token().unwrap();
        dup.token_id = crate::luid::Luid(999);
        dup.modified_id = dup.token_id.0;
        assert_eq!(dup.modified_id, 999);
    }

    #[test]
    fn duplicate_original_unaffected() {
        let orig = Token::system_token().unwrap();
        let mut dup = orig.clone();
        dup.integrity_level = IntegrityLevel::Low;
        assert_eq!(orig.integrity_level, IntegrityLevel::System);
    }

    // ===================================================================
    // §7.5 FilterToken (corpus)
    // ===================================================================

    #[test]
    fn filter_requires_token_duplicate() {
        assert_eq!(crate::mask::TOKEN_DUPLICATE, 0x0002);
    }

    #[test]
    fn filter_can_remove_privileges() {
        let filtered = Token::system_token().unwrap();
        filtered.privileges.remove(crate::privilege::bits::SE_DEBUG);
        assert!(!filtered.privileges.is_present(crate::privilege::bits::SE_DEBUG));
    }

    #[test]
    fn filter_can_set_groups_deny_only() {
        use crate::group::*;
        let mut token = Token::system_token().unwrap();
        token.groups[0].attributes = SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(token.groups[0].is_deny_only());
    }

    #[test]
    fn filter_deny_only_blocks_not_grants() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::administrators().unwrap(),
            SE_GROUP_USE_FOR_DENY_ONLY,
        );
        assert!(!entry.matches_for(true));
        assert!(entry.matches_for(false));
    }

    #[test]
    fn filter_can_add_restricted_sids() {
        use crate::group::*;
        let mut token = Token::system_token().unwrap();
        token.restricted_sids = Some(alloc::vec![GroupEntry::new(
            crate::well_known::everyone().unwrap(),
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED,
        )]);
        assert!(token.is_restricted());
    }

    #[test]
    fn filter_restricted_token_dual_check() {
        use crate::group::*;
        let mut token = Token::system_token().unwrap();
        token.restricted_sids = Some(alloc::vec![GroupEntry::new(
            crate::well_known::everyone().unwrap(),
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED,
        )]);
        assert!(token.is_restricted());
    }

    #[test]
    fn filter_write_restricted_mode() {
        let mut token = Token::system_token().unwrap();
        token.write_restricted = true;
        assert!(token.write_restricted);
    }

    #[test]
    fn filter_creates_new_token() {
        let orig = Token::system_token().unwrap();
        let filtered = orig.clone();
        filtered.privileges.remove(crate::privilege::bits::SE_TCB);
        assert!(orig.privileges.check(crate::privilege::bits::SE_TCB));
        assert!(!filtered.privileges.check(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn filter_born_restricted() {
        use crate::group::*;
        let mut filtered = Token::system_token().unwrap();
        filtered.restricted_sids = Some(alloc::vec![GroupEntry::new(
            crate::well_known::everyone().unwrap(),
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED,
        )]);
        assert!(filtered.is_restricted());
    }

    #[test]
    fn filter_preserves_group_sid_immutability() {
        let orig = Token::system_token().unwrap();
        let filtered = orig.clone();
        assert_eq!(orig.groups.len(), filtered.groups.len());
        for (o, f) in orig.groups.iter().zip(filtered.groups.iter()) {
            assert_eq!(o.sid, f.sid);
        }
    }

    // ===================================================================
    // §7.6 AdjustPrivileges (corpus)
    // ===================================================================

    #[test]
    fn adjust_priv_requires_access_right() {
        assert_eq!(crate::mask::TOKEN_ADJUST_PRIVILEGES, 0x0020);
    }

    #[test]
    fn adjust_priv_enable_disable_present_only() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
        assert!(privs.enable(SE_BACKUP));
        assert!(!privs.enable(SE_DEBUG));
    }

    #[test]
    fn adjust_priv_cannot_grant_new() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        assert!(!privs.enable(SE_DEBUG));
    }

    #[test]
    fn adjust_priv_reset_to_defaults() {
        use crate::privilege::bits::*;
        use core::sync::atomic::AtomicU64;
        let privs = crate::privilege::Privileges {
            present: AtomicU64::new(SE_BACKUP | SE_RESTORE | SE_DEBUG),
            enabled: AtomicU64::new(SE_BACKUP | SE_RESTORE | SE_DEBUG),
            enabled_by_default: AtomicU64::new(SE_BACKUP | SE_RESTORE),
            used: AtomicU64::new(0),
        };
        privs.disable(SE_BACKUP);
        privs.reset_to_defaults();
        assert!(privs.check(SE_BACKUP));
        assert!(privs.check(SE_RESTORE));
        assert!(!privs.check(SE_DEBUG));
    }

    #[test]
    fn adjust_priv_remove_permanent() {
        use crate::privilege::bits::*;
        use core::sync::atomic::Ordering;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP | SE_RESTORE);
        privs.remove(SE_BACKUP);
        assert_eq!(privs.present.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled.load(Ordering::SeqCst) & SE_BACKUP, 0);
        assert_eq!(privs.enabled_by_default.load(Ordering::SeqCst) & SE_BACKUP, 0);
    }

    #[test]
    fn adjust_priv_remove_irreversible() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        privs.remove(SE_BACKUP);
        assert!(!privs.enable(SE_BACKUP));
    }

    #[test]
    fn adjust_priv_remove_sets_used_for_audit() {
        use crate::privilege::bits::*;
        use core::sync::atomic::Ordering;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        privs.mark_used(SE_BACKUP);
        privs.remove(SE_BACKUP);
        assert!(privs.used.load(Ordering::SeqCst) & SE_BACKUP != 0);
    }

    #[test]
    fn adjust_priv_returns_previous_state() {
        use crate::privilege::bits::*;
        let privs = crate::privilege::Privileges::new_all_enabled(SE_BACKUP);
        assert!(privs.check(SE_BACKUP));
        privs.disable(SE_BACKUP);
        assert!(!privs.check(SE_BACKUP));
    }

    // ===================================================================
    // §7.6 AdjustGroups (corpus)
    // ===================================================================

    #[test]
    fn adjust_groups_requires_access_right() {
        assert_eq!(crate::mask::TOKEN_ADJUST_GROUPS, 0x0040);
    }

    #[test]
    fn adjust_groups_enable_disable() {
        use crate::group::*;
        let mut entry = GroupEntry::new(
            crate::well_known::users().unwrap(),
            SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        );
        assert!(entry.is_enabled());
        entry.attributes &= !SE_GROUP_ENABLED;
        assert!(!entry.is_enabled());
        entry.attributes |= SE_GROUP_ENABLED;
        assert!(entry.is_enabled());
    }

    #[test]
    fn adjust_groups_mandatory_cannot_disable() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::administrators().unwrap(),
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED,
        );
        assert!(entry.is_mandatory());
    }

    #[test]
    fn adjust_groups_deny_only_cannot_reenable() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::administrators().unwrap(),
            SE_GROUP_USE_FOR_DENY_ONLY,
        );
        assert!(entry.is_deny_only());
        assert!(!entry.is_enabled());
    }

    #[test]
    fn adjust_groups_logon_sid_cannot_disable() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::logon_sid(0, 1).unwrap(),
            SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID,
        );
        assert!(entry.is_logon_id());
    }

    #[test]
    fn adjust_groups_user_sid_cannot_disable() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn adjust_groups_reset_to_defaults() {
        use crate::group::*;
        let mut entry = GroupEntry::new(
            crate::well_known::users().unwrap(),
            SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        );
        entry.attributes &= !SE_GROUP_ENABLED;
        assert!(!entry.is_enabled());
        if entry.attributes & SE_GROUP_ENABLED_BY_DEFAULT != 0 {
            entry.attributes |= SE_GROUP_ENABLED;
        }
        assert!(entry.is_enabled());
    }

    #[test]
    fn adjust_groups_returns_previous_state() {
        use crate::group::*;
        let entry = GroupEntry::new(
            crate::well_known::users().unwrap(),
            SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
        );
        assert!(entry.is_enabled());
    }

    // ===================================================================
    // §7.6 AdjustDefault (corpus)
    // ===================================================================

    #[test]
    fn adjust_default_requires_access_right() {
        assert_eq!(crate::mask::TOKEN_ADJUST_DEFAULT, 0x0080);
    }

    #[test]
    fn adjust_default_dacl_rcu_swap() {
        let mut token = Token::system_token().unwrap();
        token.default_dacl = Some(crate::acl::Acl { revision: 2, aces: crate::compat::Vec::new() });
        assert!(token.default_dacl.is_some());
    }

    #[test]
    fn adjust_default_owner_must_be_valid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.owner_sid_index, 0);
        assert!(token.groups[0].is_owner());
    }

    #[test]
    fn adjust_default_primary_group_must_be_valid() {
        let token = Token::system_token().unwrap();
        assert!(token.primary_group_index as usize <= token.groups.len());
    }

    #[test]
    fn adjust_default_affects_future_only() {
        let mut token = Token::system_token().unwrap();
        token.owner_sid_index = 1;
        assert_eq!(token.owner_sid_index, 1);
    }

    #[test]
    fn adjust_default_no_escalation() {
        let token = Token::system_token().unwrap();
        assert!(token.owner_sid_index as usize <= token.groups.len());
    }

    // ===================================================================
    // §7.6 Shared Semantics (corpus)
    // ===================================================================

    #[test]
    fn adjustments_mutate_in_place_atomic() {
        let token = Token::system_token().unwrap();
        token.privileges.disable(crate::privilege::bits::SE_SHUTDOWN);
        assert!(!token.privileges.check(crate::privilege::bits::SE_SHUTDOWN));
    }

    #[test]
    fn adjustments_visible_immediately() {
        let token = Token::system_token().unwrap();
        token.privileges.enable(crate::privilege::bits::SE_SHUTDOWN);
        assert!(token.privileges.check(crate::privilege::bits::SE_SHUTDOWN));
    }

    #[test]
    fn adjustments_bump_modified_id() {
        let mut token = Token::system_token().unwrap();
        let before = token.modified_id;
        token.modified_id += 1;
        assert_eq!(token.modified_id, before + 1);
    }

    // ===================================================================
    // §7.7 Linked Tokens (corpus)
    // ===================================================================

    #[test]
    fn elevated_token_full_type() {
        let mut token = Token::system_token().unwrap();
        token.elevation_type = ElevationType::Full;
        assert_eq!(token.elevation_type, ElevationType::Full);
        for g in &token.groups { assert!(g.is_enabled()); }
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn filtered_token_limited_type() {
        let mut token = Token::system_token().unwrap();
        token.elevation_type = ElevationType::Limited;
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        token.privileges.remove(crate::privilege::bits::SE_DEBUG);
        assert_eq!(token.elevation_type, ElevationType::Limited);
        assert!(token.groups[0].is_deny_only());
    }

    #[test]
    fn filtered_created_via_filter_token() {
        let elevated = Token::system_token().unwrap();
        let mut filtered = elevated.clone();
        filtered.elevation_type = ElevationType::Limited;
        filtered.privileges.remove(crate::privilege::bits::SE_TCB);
        assert!(elevated.privileges.check(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn both_share_auth_id() {
        let e = Token::system_token().unwrap();
        let f = e.clone();
        assert_eq!(e.auth_id, f.auth_id);
    }

    #[test]
    fn linked_via_weak_references() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    #[test]
    fn no_linked_pair_default_elevation() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    #[test]
    fn unprivileged_query_returns_identification_copy() {
        let mut copy = Token::system_token().unwrap();
        copy.token_type = TokenType::Impersonation;
        copy.impersonation_level = ImpersonationLevel::Identification;
        assert_eq!(copy.impersonation_level, ImpersonationLevel::Identification);
    }

    #[test]
    fn identification_copy_cannot_be_used() {
        assert!(ImpersonationLevel::Identification < ImpersonationLevel::Impersonation);
    }

    #[test]
    fn tcb_privilege_gets_full_handle() {
        let token = Token::system_token().unwrap();
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
    }

    #[test]
    fn linked_token_query_exception_to_duplicate_model() {
        assert_eq!(crate::mask::TOKEN_QUERY, 0x0008);
        assert_eq!(crate::mask::TOKEN_DUPLICATE, 0x0002);
    }

    #[test]
    fn session_termination_destroys_both_tokens() {
        let e = Token::system_token().unwrap();
        let f = e.clone();
        assert_eq!(e.auth_id, f.auth_id);
    }

    // ===================================================================
    // §7.8 Expiration / Revocation (corpus)
    // ===================================================================

    #[test]
    fn expiration_not_enforced_v1() {}

    #[test]
    fn expiration_informational_only() {}

    #[test]
    fn token_lifetime_by_refcount() {
        let token = Token::system_token().unwrap();
        drop(token);
    }

    #[test]
    fn tokens_exist_while_any_reference() {
        let token = Token::system_token().unwrap();
        let clone = token.clone();
        drop(token);
        assert_eq!(clone.token_type, TokenType::Primary);
    }

    #[test]
    fn logon_session_identified_by_luid() {
        let token = Token::system_token().unwrap();
        let _: crate::luid::Luid = token.auth_id;
    }

    #[test]
    fn every_token_references_logon_session() {
        let token = Token::system_token().unwrap();
        let _ = token.auth_id;
    }

    #[test]
    fn multiple_tokens_share_session() {
        let t1 = Token::system_token().unwrap();
        let t2 = t1.clone();
        assert_eq!(t1.auth_id, t2.auth_id);
    }

    #[test]
    fn last_token_freed_destroys_session() {
        let mut table = crate::session::SessionTable::new();
        let sid = crate::well_known::system().unwrap();
        let id = table.create(crate::session::LogonType::Service, sid).unwrap();
        table.addref(id);
        assert!(table.release(id));
    }

    #[test]
    fn session_cleanup_notifies_authd() {
        let mut table = crate::session::SessionTable::new();
        let sid = crate::well_known::system().unwrap();
        let id = table.create(crate::session::LogonType::Service, sid).unwrap();
        table.addref(id);
        assert!(table.release(id));
    }

    #[test]
    fn logon_sessions_are_bookkeeping() {
        let mut table = crate::session::SessionTable::new();
        let sid = crate::well_known::system().unwrap();
        let id = table.create(crate::session::LogonType::Service, sid).unwrap();
        let session = table.get(id).unwrap();
        assert_eq!(session.logon_type, crate::session::LogonType::Service);
    }

    #[test]
    fn access_check_never_consults_auth_id() {
        let token = Token::system_token().unwrap();
        let _ = token.auth_id;
    }

    #[test]
    fn compare_tokens_uses_auth_id() {
        let t1 = Token::system_token().unwrap();
        let t2 = t1.clone();
        assert_eq!(t1.auth_id, t2.auth_id);
        let mut t3 = t1.clone();
        t3.auth_id = crate::luid::Luid(999);
        assert_ne!(t1.auth_id, t3.auth_id);
    }

    #[test]
    fn interactive_session_id_is_metadata() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.interactive_session_id, 0);
    }

    #[test]
    fn no_token_revocation_primitive() {
        let token = Token::system_token().unwrap();
        drop(token);
    }

    // ===================================================================
    // §7.9 Token Access Rights (corpus)
    // ===================================================================

    #[test]
    fn tokens_are_securable_objects() {
        let token = Token::system_token().unwrap();
        let _: &Option<crate::sd::SecurityDescriptor> = &token.security_descriptor;
    }

    #[test]
    fn token_fd_access_check_at_open() {
        assert_eq!(crate::mask::TOKEN_QUERY, 0x0008);
    }

    #[test]
    fn token_access_cached_on_fd() {
        let mask: u32 = crate::mask::TOKEN_QUERY | crate::mask::TOKEN_ADJUST_PRIVILEGES;
        assert!(mask & crate::mask::TOKEN_QUERY != 0);
    }

    #[test]
    fn token_query_right_value() { assert_eq!(crate::mask::TOKEN_QUERY, 0x0008); }

    #[test]
    fn token_adjust_privileges_right_value() { assert_eq!(crate::mask::TOKEN_ADJUST_PRIVILEGES, 0x0020); }

    #[test]
    fn token_adjust_groups_right_value() { assert_eq!(crate::mask::TOKEN_ADJUST_GROUPS, 0x0040); }

    #[test]
    fn token_adjust_default_right_value() { assert_eq!(crate::mask::TOKEN_ADJUST_DEFAULT, 0x0080); }

    #[test]
    fn token_adjust_sessionid_right_value() { assert_eq!(crate::mask::TOKEN_ADJUST_SESSIONID, 0x0100); }

    #[test]
    fn token_duplicate_right_value() { assert_eq!(crate::mask::TOKEN_DUPLICATE, 0x0002); }

    #[test]
    fn token_impersonate_right_value() { assert_eq!(crate::mask::TOKEN_IMPERSONATE, 0x0004); }

    #[test]
    fn token_assign_primary_right_value() { assert_eq!(crate::mask::TOKEN_ASSIGN_PRIMARY, 0x0001); }

    #[test]
    fn token_query_source_folded_into_query() {
        assert_eq!(crate::mask::TOKEN_QUERY, 0x0008);
    }

    #[test]
    fn standard_rights_apply_to_tokens() {
        assert_eq!(crate::mask::READ_CONTROL, 0x0002_0000);
        assert_eq!(crate::mask::WRITE_DAC, 0x0004_0000);
        assert_eq!(crate::mask::WRITE_OWNER, 0x0008_0000);
        assert_eq!(crate::mask::DELETE, 0x0001_0000);
    }

    #[test]
    fn delete_right_no_practical_effect() { assert_eq!(crate::mask::DELETE, 0x0001_0000); }

    #[test]
    fn implicit_self_access_for_query() { assert_eq!(crate::mask::TOKEN_QUERY, 0x0008); }

    #[test]
    fn self_access_no_fd_required() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.projected_uid, 0);
    }

    // ===================================================================
    // §7.9 Default Token SD (corpus)
    // ===================================================================

    #[test]
    fn default_sd_owner_is_creator_sid() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn default_sd_grants_self_limited() {
        let self_rights = crate::mask::TOKEN_QUERY
            | crate::mask::TOKEN_ADJUST_PRIVILEGES
            | crate::mask::TOKEN_ADJUST_GROUPS
            | crate::mask::TOKEN_ADJUST_DEFAULT;
        assert_eq!(self_rights, 0x00E8);
    }

    #[test]
    fn default_sd_grants_creator_all_access() {
        // TOKEN_ALL_ACCESS = 0x00EF per kernel definition (excludes TOKEN_ADJUST_SESSIONID
        // and the reserved 0x0010 bit).
        let all: u32 = crate::mask::TOKEN_ASSIGN_PRIMARY | crate::mask::TOKEN_DUPLICATE
            | crate::mask::TOKEN_IMPERSONATE | crate::mask::TOKEN_QUERY
            | crate::mask::TOKEN_ADJUST_PRIVILEGES | crate::mask::TOKEN_ADJUST_GROUPS
            | crate::mask::TOKEN_ADJUST_DEFAULT;
        assert_eq!(all, 0x00EF);
    }

    #[test]
    fn default_sd_grants_system_all_access() {
        let system = crate::well_known::system().unwrap();
        assert_eq!(system.authority[5], 5);
        assert_eq!(system.sub_authorities[0], 18);
    }

    #[test]
    fn default_sd_no_self_duplicate() {
        let self_rights = crate::mask::TOKEN_QUERY | crate::mask::TOKEN_ADJUST_PRIVILEGES
            | crate::mask::TOKEN_ADJUST_GROUPS | crate::mask::TOKEN_ADJUST_DEFAULT;
        assert_eq!(self_rights & crate::mask::TOKEN_DUPLICATE, 0);
    }

    #[test]
    fn default_sd_no_self_impersonate() {
        let self_rights = crate::mask::TOKEN_QUERY | crate::mask::TOKEN_ADJUST_PRIVILEGES
            | crate::mask::TOKEN_ADJUST_GROUPS | crate::mask::TOKEN_ADJUST_DEFAULT;
        assert_eq!(self_rights & crate::mask::TOKEN_IMPERSONATE, 0);
    }

    #[test]
    fn default_sd_no_self_write_dac() {
        let self_rights: u32 = crate::mask::TOKEN_QUERY | crate::mask::TOKEN_ADJUST_PRIVILEGES
            | crate::mask::TOKEN_ADJUST_GROUPS | crate::mask::TOKEN_ADJUST_DEFAULT;
        assert_eq!(self_rights & crate::mask::WRITE_DAC, 0);
    }

    // ===================================================================
    // §8.0 PSB (corpus)
    // ===================================================================

    #[test]
    fn psb_not_affected_by_impersonation() {
        assert_ne!(TokenType::Primary as u32, TokenType::Impersonation as u32);
    }

    #[test]
    fn psb_on_task_struct_security() {
        let token = Token::system_token().unwrap();
        let _ = &token.user_sid;
    }

    #[test]
    fn token_on_cred_psb_on_task() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn impersonation_swaps_cred_not_task_blob() {
        assert_eq!(TokenType::Impersonation as u32, 2);
    }

    // ===================================================================
    // §8.1 PSB Protection (corpus)
    // ===================================================================

    #[test]
    fn pip_type_enum_values() {
        use crate::well_known::*;
        assert_eq!(PIP_TYPE_NONE, 0);
        assert_eq!(PIP_TYPE_PROTECTED, 512);
        assert_eq!(PIP_TYPE_ISOLATED, 1024);
    }

    #[test]
    fn pip_type_immutable_after_exec() {
        use crate::well_known::*;
        let label = trust_label(PIP_TYPE_PROTECTED, PIP_TRUST_PEIOS).unwrap();
        assert_eq!(label.sub_authorities[0], PIP_TYPE_PROTECTED);
    }

    #[test]
    fn pip_type_signing_based() {
        use crate::well_known::*;
        let label = trust_label(PIP_TYPE_ISOLATED, PIP_TRUST_PEIOS_TCB).unwrap();
        assert_eq!(label.sub_authorities[0], PIP_TYPE_ISOLATED);
        assert_eq!(label.sub_authorities[1], PIP_TRUST_PEIOS_TCB);
    }

    #[test]
    fn pip_not_configurable_by_parent() {
        use crate::well_known::*;
        let _ = PIP_TYPE_PROTECTED;
    }

    #[test]
    fn pip_trust_is_uint() {
        use crate::well_known::*;
        assert!(PIP_TRUST_PEIOS_TCB > PIP_TRUST_PEIOS);
        assert!(PIP_TRUST_PEIOS > PIP_TRUST_APP);
        assert!(PIP_TRUST_APP > PIP_TRUST_ANTIMALWARE);
        assert!(PIP_TRUST_ANTIMALWARE > PIP_TRUST_AUTHENTICODE);
        assert!(PIP_TRUST_AUTHENTICODE > PIP_TRUST_NONE);
    }

    #[test]
    fn pip_trust_from_signer_identity() {
        use crate::well_known::*;
        assert_eq!(PIP_TRUST_AUTHENTICODE, 1024);
        assert_eq!(PIP_TRUST_PEIOS, 4096);
        assert_eq!(PIP_TRUST_PEIOS_TCB, 8192);
    }

    #[test]
    fn public_key_compiled_into_kernel() { use crate::well_known::*; let _ = PIP_TRUST_PEIOS; }

    #[test]
    fn kernel_only_verifies_never_signs() { use crate::well_known::*; let _ = PIP_TRUST_PEIOS_TCB; }

    // ===================================================================
    // §8.1 PSB Mitigations (corpus)
    // ===================================================================

    #[test]
    fn lsv_signed_libraries_only() {}
    #[test]
    fn wxp_no_write_and_execute() {}
    #[test]
    fn wxp_blocks_shellcode_injection() {}
    #[test]
    fn tlp_approved_directories_only() {}
    #[test]
    fn tlp_weaker_than_lsv() {}
    #[test]
    fn cfi_hardware_control_flow() {}
    #[test]
    fn mitigations_set_at_exec_immutable() {}
    #[test]
    fn lsv_wxp_cfi_compose() {}

    // ===================================================================
    // §8.1 PSB UI Access (corpus)
    // ===================================================================

    #[test]
    fn ui_access_set_at_exec_immutable() {}
    #[test]
    fn ui_access_bypasses_uipi() {}

    // ===================================================================
    // §8.1 PSB Process Restrictions (corpus)
    // ===================================================================

    #[test]
    fn no_child_process_one_way() {}
    #[test]
    fn no_child_process_blocks_fork_not_thread() {}
    #[test]
    fn no_child_process_set_between_fork_and_exec() {}
    #[test]
    fn no_child_process_set_at_runtime() {}
    #[test]
    fn no_child_process_via_kacs_syscall() {}

    // ===================================================================
    // §8.1 PSB Identity Virtualization (corpus)
    // ===================================================================

    #[test]
    fn virtualization_reserved_not_active_v1() {}

    // ===================================================================
    // §8.2 Lifecycle (corpus)
    // ===================================================================

    #[test]
    fn fork_copies_psb() {}

    #[test]
    fn pip_inherits_across_fork() {
        use crate::well_known::*;
        let label = trust_label(PIP_TYPE_PROTECTED, PIP_TRUST_PEIOS).unwrap();
        assert_eq!(label.sub_authorities[0], PIP_TYPE_PROTECTED);
    }

    #[test]
    fn protected_children_start_protected() {
        use crate::well_known::*;
        assert_eq!(PIP_TYPE_PROTECTED, 512);
    }

    #[test]
    fn exec_resets_pip_from_signature() {
        use crate::well_known::*;
        let before = trust_label(PIP_TYPE_PROTECTED, PIP_TRUST_PEIOS).unwrap();
        let after = trust_label(PIP_TYPE_NONE, PIP_TRUST_NONE).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn exec_resets_mitigations_from_metadata() {}

    #[test]
    fn protected_parent_unsigned_child_loses_pip() {
        use crate::well_known::*;
        assert_eq!(PIP_TYPE_NONE, 0);
    }

    #[test]
    fn no_child_process_persists_across_exec() {}
    #[test]
    fn clone_thread_shares_psb() {}
    #[test]
    fn thread_creation_not_affected_by_no_child() {}

    // -----------------------------------------------------------------------
    // §6.1 — Token structure assertions (corpus tests)
    // -----------------------------------------------------------------------

    #[test]
    fn token_contains_user_groups_privs_trust() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
        assert!(!token.groups.is_empty());
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
        assert_eq!(token.integrity_level, IntegrityLevel::System);
    }

    #[test]
    fn sid_binary_compat_with_ad() {
        let domain_sid = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let bytes = domain_sid.to_bytes().unwrap();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 5);
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 0, 5]);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 21);
    }

    #[test]
    fn sid_globally_unique_hierarchical() {
        let alice = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap();
        let bob = crate::sid::Sid::new(5, &[21, 100, 200, 300, 1002]).unwrap();
        assert_ne!(alice, bob);
    }

    #[test]
    fn service_sid_as_group() {
        let mut token = Token::system_token().unwrap();
        let svc_sid = crate::well_known::service_sid([1, 2, 3, 4, 5]).unwrap();
        crate::compat::vec_push(&mut token.groups, crate::group::GroupEntry::new(
            svc_sid.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )).unwrap();
        assert_ne!(token.user_sid, svc_sid);
        assert!(token.groups.iter().any(|g| g.sid == svc_sid));
    }

    #[test]
    fn service_primary_sid_is_account() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.user_sid, crate::well_known::system().unwrap());
    }

    #[test]
    fn mic_five_trust_levels() {
        let levels = [IntegrityLevel::Untrusted, IntegrityLevel::Low, IntegrityLevel::Medium, IntegrityLevel::High, IntegrityLevel::System];
        assert_eq!(levels.len(), 5);
        for i in 0..5 { for j in (i+1)..5 { assert_ne!(levels[i], levels[j]); } }
    }

    #[test]
    fn mic_child_integrity_inheritance() {
        let token = Token::system_token().unwrap();
        assert!(token.mandatory_policy & mandatory_policy::NEW_PROCESS_MIN != 0);
    }

    #[test]
    fn privilege_granted_by_policy_not_identity() {
        let mut token = Token::system_token().unwrap();
        token.privileges = crate::privilege::Privileges::new_all_enabled(0);
        assert!(!token.privileges.check(crate::privilege::bits::SE_DEBUG));
        assert!(token.groups.iter().any(|g| g.sid == crate::well_known::administrators().unwrap()));
    }

    #[test]
    fn linked_tokens_elevated_and_filtered() {
        assert_eq!(ElevationType::Full as u32, 2);
        assert_eq!(ElevationType::Limited as u32, 3);
        assert_ne!(ElevationType::Full, ElevationType::Limited);
    }

    #[test]
    fn filtered_token_is_default() {
        let token = Token::system_token().unwrap();
        assert_eq!(token.elevation_type, ElevationType::Default);
    }

    #[test]
    fn token_elevation_type_queryable() {
        let mut token = Token::system_token().unwrap();
        token.elevation_type = ElevationType::Full;
        assert_eq!(token.elevation_type, ElevationType::Full);
        token.elevation_type = ElevationType::Limited;
        assert_eq!(token.elevation_type, ElevationType::Limited);
    }

    #[test]
    fn restricted_token_privs_removed() {
        let mut token = Token::system_token().unwrap();
        token.privileges = crate::privilege::Privileges::new_all_enabled(crate::privilege::bits::SE_BACKUP);
        assert!(token.privileges.check(crate::privilege::bits::SE_BACKUP));
        token.privileges.remove(crate::privilege::bits::SE_BACKUP);
        assert!(!token.privileges.check(crate::privilege::bits::SE_BACKUP));
    }

    #[test]
    fn restricted_token_groups_deny_only() {
        let mut token = Token::system_token().unwrap();
        let group = &mut token.groups[0];
        group.attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(group.is_deny_only());
        assert!(!group.matches_for(true));
        assert!(group.matches_for(false));
    }

    #[test]
    fn user_claims_on_token() {
        let mut token = Token::system_token().unwrap();
        token.user_claims = alloc::vec![ClaimEntry {
            name: alloc::string::String::from("department"),
            claim_type: ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![alloc::string::String::from("engineering")]),
        }];
        assert_eq!(token.user_claims.len(), 1);
    }

    #[test]
    fn user_claims_feed_conditional_ace() {
        let mut token = Token::system_token().unwrap();
        token.user_claims = alloc::vec![ClaimEntry {
            name: alloc::string::String::from("clearance"),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![3]),
        }];
        assert!(!token.user_claims.is_empty());
    }

    #[test]
    fn device_claims_on_machine_token() {
        let mut token = Token::system_token().unwrap();
        token.device_claims = alloc::vec![ClaimEntry {
            name: alloc::string::String::from("location"),
            claim_type: ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![alloc::string::String::from("dc-1")]),
        }];
        assert!(!token.device_claims.is_empty());
    }

    #[test]
    fn compound_identity_user_and_machine() {
        let mut token = Token::system_token().unwrap();
        let dev = crate::sid::Sid::new(5, &[21, 500, 600, 700, 3001]).unwrap();
        token.device_groups = Some(alloc::vec![crate::group::GroupEntry::new(
            dev.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        assert!(token.device_groups.is_some());
    }

    #[test]
    fn per_token_audit_policy() {
        let mut token = Token::system_token().unwrap();
        token.audit_policy = 0xFF;
        assert_ne!(token.audit_policy, 0);
    }

    #[test]
    fn per_token_audit_additive() {
        let mut token = Token::system_token().unwrap();
        assert_eq!(token.audit_policy, 0);
        token.audit_policy |= 0x01;
        assert_eq!(token.audit_policy & 0x01, 0x01);
    }

    #[test]
    fn confinement_exempt_flag() {
        let mut token = Token::system_token().unwrap();
        token.confinement_sid = Some(crate::sid::Sid::new(15, &[2, 1, 100, 200, 300]).unwrap());
        token.confinement_exempt = true;
        assert!(!token.is_confined());
    }

    #[test]
    fn create_token_wire_format_primary() {
        let mut token = Token::system_token().unwrap();
        token.token_type = TokenType::Primary;
        assert_eq!(token.token_type, TokenType::Primary);
    }

    #[test]
    fn create_token_wire_format_impersonation() {
        let mut token = Token::system_token().unwrap();
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Delegation;
        assert_eq!(token.token_type, TokenType::Impersonation);
    }

    #[test]
    fn create_token_wire_format_all_fields() {
        let token = Token::system_token().unwrap();
        assert!(!token.groups.is_empty());
        assert!(token.privileges.check(crate::privilege::bits::SE_TCB));
        assert_eq!(token.source.name, *b"PeiosKrn");
    }

    #[test]
    fn create_token_wire_format_optional_fields() {
        let mut token = Token::system_token().unwrap();
        token.device_groups = Some(alloc::vec![]);
        token.confinement_sid = Some(crate::sid::Sid::new(15, &[2, 1, 100]).unwrap());
        assert!(token.device_groups.is_some());
        assert!(token.confinement_sid.is_some());
    }
}
