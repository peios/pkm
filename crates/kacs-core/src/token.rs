use crate::error::{KacsError, KacsResult};
use crate::mic::IntegrityLevel;
use crate::privilege::TokenPrivileges;
use crate::sid::Sid;

/// Audit-policy flag for successful object-access events.
pub const AUDIT_POLICY_OBJECT_ACCESS_SUCCESS: u32 = 0x0001;
/// Audit-policy flag for failed object-access events.
pub const AUDIT_POLICY_OBJECT_ACCESS_FAILURE: u32 = 0x0002;
/// Audit-policy flag for successful privilege-use events.
pub const AUDIT_POLICY_PRIVILEGE_USE_SUCCESS: u32 = 0x0004;
/// Audit-policy flag for failed privilege-use events.
pub const AUDIT_POLICY_PRIVILEGE_USE_FAILURE: u32 = 0x0008;

/// A SID paired with Windows-style attribute flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SidAndAttributes<'a> {
    /// The SID value.
    pub sid: Sid<'a>,
    /// Attribute flags such as `SE_GROUP_ENABLED` or deny-only.
    pub attributes: u32,
}

/// Minimal token identity surface needed by the pure AccessCheck core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenView<'a> {
    /// Primary user SID.
    pub user: Sid<'a>,
    /// Whether the user SID should be treated as deny-only.
    pub user_deny_only: bool,
    /// Group membership list.
    pub groups: &'a [SidAndAttributes<'a>],
}

/// Token category visible to AccessCheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenType {
    /// Primary token.
    Primary,
    /// Impersonation token.
    Impersonation,
}

/// Impersonation level visible to AccessCheck gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpersonationLevel {
    /// Anonymous impersonation level.
    Anonymous,
    /// Identification impersonation level.
    Identification,
    /// Ordinary impersonation level.
    Impersonation,
    /// Delegation impersonation level.
    Delegation,
}

/// Generic identity view used by conditional expressions and synthetic passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityView<'a> {
    /// Optional user SID.
    pub user: Option<Sid<'a>>,
    /// Whether the user SID should be treated as deny-only.
    pub user_deny_only: bool,
    /// Group membership list.
    pub groups: &'a [SidAndAttributes<'a>],
}

impl<'a> TokenView<'a> {
    /// Builds the default identity view for this token.
    pub fn identity(&self) -> IdentityView<'a> {
        IdentityView {
            user: Some(self.user),
            user_deny_only: self.user_deny_only,
            groups: self.groups,
        }
    }
}

/// Full token state consumed by the pure AccessCheck core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCheckToken<'a> {
    /// Subject identity.
    pub subject: TokenView<'a>,
    /// Token kind.
    pub token_type: TokenType,
    /// Effective impersonation level.
    pub impersonation_level: ImpersonationLevel,
    /// Audit policy bitmask.
    pub audit_policy: u32,
    /// Privilege state.
    pub privileges: TokenPrivileges,
    /// Subject integrity level.
    pub integrity_level: IntegrityLevel,
    /// Subject mandatory policy bitmask.
    pub mandatory_policy: u32,
    /// Restricted-token context for the second pass.
    pub restricted: RestrictedTokenContext<'a>,
    /// Confinement-token context for sandbox narrowing.
    pub confinement: ConfinementTokenContext<'a>,
}

/// Restricted-token inputs used by the restricted AccessCheck pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictedTokenContext<'a> {
    /// Restricting SIDs for the non-device side of the second pass.
    pub restricted_sids: &'a [SidAndAttributes<'a>],
    /// Restricting device groups for the device side of the second pass.
    pub restricted_device_groups: &'a [SidAndAttributes<'a>],
    /// Whether write-restricted semantics apply.
    pub write_restricted: bool,
    /// Privilege-granted bits that must bypass restricted intersection.
    pub privilege_granted: u32,
}

impl<'a> Default for RestrictedTokenContext<'a> {
    fn default() -> Self {
        Self {
            restricted_sids: &[],
            restricted_device_groups: &[],
            write_restricted: false,
            privilege_granted: 0,
        }
    }
}

/// Confinement-token inputs used by the confinement narrowing pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfinementTokenContext<'a> {
    /// Optional confinement SID.
    pub confinement_sid: Option<Sid<'a>>,
    /// Capability SIDs participating in confinement matching.
    pub confinement_capabilities: &'a [SidAndAttributes<'a>],
    /// Whether the token is exempt from confinement narrowing.
    pub confinement_exempt: bool,
}

impl<'a> Default for ConfinementTokenContext<'a> {
    fn default() -> Self {
        Self {
            confinement_sid: None,
            confinement_capabilities: &[],
            confinement_exempt: false,
        }
    }
}

pub(crate) fn validate_access_check_token_invariants(
    token: &AccessCheckToken<'_>,
) -> KacsResult<()> {
    validate_restricted_invariants(&token.subject, &token.restricted)
}

pub(crate) fn validate_restricted_invariants(
    subject: &TokenView<'_>,
    restricted: &RestrictedTokenContext<'_>,
) -> KacsResult<()> {
    if restricted.write_restricted && !subject.user_deny_only {
        return Err(KacsError::InvalidTokenInvariant(
            "write_restricted requires user_deny_only",
        ));
    }

    Ok(())
}
