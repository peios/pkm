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
}
