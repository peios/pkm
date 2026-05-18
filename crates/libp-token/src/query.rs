// Typed query classes and the small enums that decode out of token-info
// queries (token type, impersonation level, elevation type).

use crate::Error;
use peios_uapi::token as uapi;

/// Token-information classes that can be passed to `Token::query`.
///
/// One-to-one with `TOKEN_CLASS_*` constants in `peios-uapi`. Maintained
/// as a Rust enum so callers get typed pattern-matching and the compiler
/// catches misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QueryClass {
    User = uapi::TOKEN_CLASS_USER,
    Groups = uapi::TOKEN_CLASS_GROUPS,
    Privileges = uapi::TOKEN_CLASS_PRIVILEGES,
    Type = uapi::TOKEN_CLASS_TYPE,
    IntegrityLevel = uapi::TOKEN_CLASS_INTEGRITY_LEVEL,
    Owner = uapi::TOKEN_CLASS_OWNER,
    PrimaryGroup = uapi::TOKEN_CLASS_PRIMARY_GROUP,
    SessionId = uapi::TOKEN_CLASS_SESSION_ID,
    RestrictedSids = uapi::TOKEN_CLASS_RESTRICTED_SIDS,
    Source = uapi::TOKEN_CLASS_SOURCE,
    Statistics = uapi::TOKEN_CLASS_STATISTICS,
    Origin = uapi::TOKEN_CLASS_ORIGIN,
    ElevationType = uapi::TOKEN_CLASS_ELEVATION_TYPE,
    DeviceGroups = uapi::TOKEN_CLASS_DEVICE_GROUPS,
    AppContainerSid = uapi::TOKEN_CLASS_APPCONTAINER_SID,
    Capabilities = uapi::TOKEN_CLASS_CAPABILITIES,
    MandatoryPolicy = uapi::TOKEN_CLASS_MANDATORY_POLICY,
    LogonType = uapi::TOKEN_CLASS_LOGON_TYPE,
    LogonSid = uapi::TOKEN_CLASS_LOGON_SID,
    DefaultDacl = uapi::TOKEN_CLASS_DEFAULT_DACL,
    ImpersonationLevel = uapi::TOKEN_CLASS_IMPERSONATION_LEVEL,
    UserClaims = uapi::TOKEN_CLASS_USER_CLAIMS,
    DeviceClaims = uapi::TOKEN_CLASS_DEVICE_CLAIMS,
    ProjectedSupplementaryGids = uapi::TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS,
}

impl QueryClass {
    /// The raw `TOKEN_CLASS_*` value for this variant.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Token type — primary vs impersonation. Decoded from a
/// `QueryClass::Type` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TokenType {
    Primary = uapi::KACS_TOKEN_TYPE_PRIMARY,
    Impersonation = uapi::KACS_TOKEN_TYPE_IMPERSONATION,
}

impl TokenType {
    pub fn try_from_u32(v: u32) -> Result<Self, Error> {
        match v {
            uapi::KACS_TOKEN_TYPE_PRIMARY => Ok(TokenType::Primary),
            uapi::KACS_TOKEN_TYPE_IMPERSONATION => Ok(TokenType::Impersonation),
            other => Err(Error::UnknownDiscriminant {
                kind: "TokenType",
                value: other,
            }),
        }
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Impersonation level. Decoded from `QueryClass::ImpersonationLevel`
/// or passed to `Token::duplicate` / `set_impersonation_level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ImpersonationLevel {
    Anonymous = uapi::KACS_LEVEL_ANONYMOUS,
    Identification = uapi::KACS_LEVEL_IDENTIFICATION,
    Impersonation = uapi::KACS_LEVEL_IMPERSONATION,
    Delegation = uapi::KACS_LEVEL_DELEGATION,
}

impl ImpersonationLevel {
    pub fn try_from_u32(v: u32) -> Result<Self, Error> {
        match v {
            uapi::KACS_LEVEL_ANONYMOUS => Ok(ImpersonationLevel::Anonymous),
            uapi::KACS_LEVEL_IDENTIFICATION => Ok(ImpersonationLevel::Identification),
            uapi::KACS_LEVEL_IMPERSONATION => Ok(ImpersonationLevel::Impersonation),
            uapi::KACS_LEVEL_DELEGATION => Ok(ImpersonationLevel::Delegation),
            other => Err(Error::UnknownDiscriminant {
                kind: "ImpersonationLevel",
                value: other,
            }),
        }
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Elevation type. Decoded from `QueryClass::ElevationType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ElevationType {
    Default = uapi::KACS_ELEVATION_DEFAULT,
    Full = uapi::KACS_ELEVATION_FULL,
    Limited = uapi::KACS_ELEVATION_LIMITED,
}

impl ElevationType {
    pub fn try_from_u32(v: u32) -> Result<Self, Error> {
        match v {
            uapi::KACS_ELEVATION_DEFAULT => Ok(ElevationType::Default),
            uapi::KACS_ELEVATION_FULL => Ok(ElevationType::Full),
            uapi::KACS_ELEVATION_LIMITED => Ok(ElevationType::Limited),
            other => Err(Error::UnknownDiscriminant {
                kind: "ElevationType",
                value: other,
            }),
        }
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_type_roundtrip() {
        assert_eq!(
            TokenType::try_from_u32(TokenType::Primary.as_u32()).unwrap(),
            TokenType::Primary
        );
        assert!(TokenType::try_from_u32(99).is_err());
    }

    #[test]
    fn query_class_values_match_uapi() {
        // Spot-check that the enum discriminants didn't drift from the
        // raw constants.
        assert_eq!(QueryClass::User.as_u32(), uapi::TOKEN_CLASS_USER);
        assert_eq!(
            QueryClass::IntegrityLevel.as_u32(),
            uapi::TOKEN_CLASS_INTEGRITY_LEVEL
        );
        assert_eq!(
            QueryClass::ProjectedSupplementaryGids.as_u32(),
            uapi::TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS
        );
    }
}
