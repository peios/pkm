// Group attributes (§7.3).
//
// Each group entry on a token carries the group SID plus attribute
// flags that control how the group participates in AccessCheck.

use crate::sid::Sid;

// --- Group attribute flags (§7.3) ---

/// Group is mandatory — cannot be disabled via AdjustGroups.
pub const SE_GROUP_MANDATORY: u32 = 0x0000_0001;

/// Group is enabled by default when the token is created.
pub const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x0000_0002;

/// Group is currently enabled for access checks.
pub const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// Group SID identifies the token owner for default object creation.
pub const SE_GROUP_OWNER: u32 = 0x0000_0008;

/// Group is deny-only: matches deny ACEs but not allow ACEs.
/// Set permanently by FilterToken. Cannot be reverted.
pub const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

/// Group is the logon SID for this token's authentication session.
pub const SE_GROUP_LOGON_ID: u32 = 0x0000_0040;

/// Group carries the integrity SID for this token (MS-DTYP §2.4.4.1).
pub const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// Group's integrity SID is enabled (MS-DTYP §2.4.4.1).
pub const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x0000_0040;

/// Group was added by a resource attribute (not from directory).
pub const SE_GROUP_RESOURCE: u32 = 0x2000_0000;

/// A SID with its associated group attributes.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct GroupEntry {
    /// The security identifier for this group.
    pub sid: Sid,
    /// Bitfield of `SE_GROUP_*` attribute flags.
    pub attributes: u32,
}

impl GroupEntry {
    /// Create a group entry with the given SID and attribute flags.
    pub fn new(sid: Sid, attributes: u32) -> Self {
        GroupEntry { sid, attributes }
    }

    /// Is this group enabled for allow-ACE matching?
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.attributes & SE_GROUP_ENABLED != 0
    }

    /// Is this group deny-only (matches deny ACEs, not allow)?
    #[inline]
    pub fn is_deny_only(&self) -> bool {
        self.attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0
    }

    /// Is this group mandatory (cannot be disabled)?
    #[inline]
    pub fn is_mandatory(&self) -> bool {
        self.attributes & SE_GROUP_MANDATORY != 0
    }

    /// Can this group be used as an owner for new objects?
    #[inline]
    pub fn is_owner(&self) -> bool {
        self.attributes & SE_GROUP_OWNER != 0
    }

    /// Is this the logon SID?
    #[inline]
    pub fn is_logon_id(&self) -> bool {
        self.attributes & SE_GROUP_LOGON_ID != 0
    }

    /// Does this group participate in SID matching for the given polarity?
    ///
    /// For allow ACEs (for_allow=true): must be enabled and NOT deny-only.
    /// For deny ACEs (for_allow=false): must be enabled OR deny-only.
    /// A group with neither enabled nor deny-only set does not participate.
    #[inline]
    pub fn matches_for(&self, for_allow: bool) -> bool {
        if for_allow {
            self.is_enabled() && !self.is_deny_only()
        } else {
            self.is_enabled() || self.is_deny_only()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_group(attributes: u32) -> GroupEntry {
        GroupEntry::new(
            Sid::new(5, &[32, 544]).unwrap(), // Administrators
            attributes,
        )
    }

    #[test]
    fn enabled_group_matches_allow_and_deny() {
        let g = test_group(SE_GROUP_MANDATORY | SE_GROUP_ENABLED);
        assert!(g.matches_for(true));  // allow
        assert!(g.matches_for(false)); // deny
    }

    #[test]
    fn deny_only_group_matches_deny_not_allow() {
        let g = test_group(SE_GROUP_USE_FOR_DENY_ONLY);
        assert!(!g.matches_for(true));  // NOT allow
        assert!(g.matches_for(false));  // deny
    }

    #[test]
    fn disabled_group_matches_nothing() {
        let g = test_group(0); // neither enabled nor deny-only
        assert!(!g.matches_for(true));
        assert!(!g.matches_for(false));
    }

    #[test]
    fn deny_only_and_enabled_matches_deny_not_allow() {
        // Deny-only takes precedence over enabled for allow matching
        let g = test_group(SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY);
        assert!(!g.matches_for(true));  // deny-only blocks allow
        assert!(g.matches_for(false));  // deny still works
    }

    #[test]
    fn mandatory_cannot_be_disabled() {
        let g = test_group(SE_GROUP_MANDATORY | SE_GROUP_ENABLED);
        assert!(g.is_mandatory());
    }

    // --- §7.3 Group attribute flag constants ---

    #[test]
    fn group_attribute_flag_values() {
        assert_eq!(SE_GROUP_MANDATORY, 0x0000_0001);
        assert_eq!(SE_GROUP_ENABLED_BY_DEFAULT, 0x0000_0002);
        assert_eq!(SE_GROUP_ENABLED, 0x0000_0004);
        assert_eq!(SE_GROUP_OWNER, 0x0000_0008);
        assert_eq!(SE_GROUP_USE_FOR_DENY_ONLY, 0x0000_0010);
        assert_eq!(SE_GROUP_LOGON_ID, 0x0000_0040);
        assert_eq!(SE_GROUP_RESOURCE, 0x2000_0000);
    }

    #[test]
    fn owner_flag_identifies_potential_owner() {
        let g = test_group(SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_OWNER);
        assert!(g.is_owner());
        assert!(g.is_enabled());
    }

    #[test]
    fn logon_id_flag() {
        let g = test_group(SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID);
        assert!(g.is_logon_id());
    }

    #[test]
    fn deny_only_permanent_from_filter_token() {
        // §7.3 line 2065: deny-only set by FilterToken, cannot be reverted
        let g = test_group(SE_GROUP_USE_FOR_DENY_ONLY);
        assert!(g.is_deny_only());
        assert!(!g.is_enabled());
        // deny-only matches deny ACEs but not allow
        assert!(!g.matches_for(true));
        assert!(g.matches_for(false));
    }

    // --- §11.3 / §2.15 SID Matching in DACL Walk corpus tests ---

    fn make_token(user: &Sid, groups: &[(Sid, u32)]) -> crate::token::Token {
        let mut token = crate::token::Token::system_token().unwrap();
        token.user_sid = user.clone();
        token.user_deny_only = false;
        token.groups = groups.iter().map(|(s, a)| GroupEntry::new(s.clone(), *a)).collect();
        token.privileges = crate::privilege::Privileges::new_all_enabled(0);
        token.integrity_level = crate::token::IntegrityLevel::Medium;
        token
    }

    fn alice() -> Sid { Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap() }
    fn eng() -> Sid { Sid::new(5, &[21, 100, 200, 300, 2001]).unwrap() }

    #[test]
    fn sid_match_user_sid() {
        // §11.3 lines 4425-4426: ACE SID matches if it equals token's user SID
        let token = make_token(&alice(), &[]);
        assert!(crate::access_check::sid_matches_token(&alice(), &token, true));
        assert!(crate::access_check::sid_matches_token(&alice(), &token, false));
    }

    #[test]
    fn sid_match_group_sid() {
        // §11.3 line 4426: ACE SID matches if it equals a group SID on the token
        let token = make_token(&alice(), &[
            (eng(), SE_GROUP_MANDATORY | SE_GROUP_ENABLED),
        ]);
        assert!(crate::access_check::sid_matches_token(&eng(), &token, true));
    }

    #[test]
    fn sid_match_allow_requires_enabled() {
        // §11.3 lines 4427-4428: for allow ACEs, only enabled and NOT deny-only groups match
        let token = make_token(&alice(), &[
            (eng(), SE_GROUP_MANDATORY | SE_GROUP_ENABLED),
        ]);
        assert!(crate::access_check::sid_matches_token(&eng(), &token, true));

        // Disabled group does not match for allow
        let token2 = make_token(&alice(), &[
            (eng(), SE_GROUP_MANDATORY), // not enabled
        ]);
        assert!(!crate::access_check::sid_matches_token(&eng(), &token2, true));
    }

    #[test]
    fn sid_match_deny_includes_deny_only() {
        // §11.3 lines 4428-4430: for deny ACEs, both enabled and deny-only groups match
        let token = make_token(&alice(), &[
            (eng(), SE_GROUP_USE_FOR_DENY_ONLY),
        ]);
        assert!(crate::access_check::sid_matches_token(&eng(), &token, false));
    }

    #[test]
    fn sid_match_deny_only_overrides_enabled() {
        // §11.3 lines 4430-4432: deny-only overrides enabled for allow matching
        let token = make_token(&alice(), &[
            (eng(), SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY),
        ]);
        // Deny-only blocks allow matching even if enabled
        assert!(!crate::access_check::sid_matches_token(&eng(), &token, true));
        // But still matches for deny
        assert!(crate::access_check::sid_matches_token(&eng(), &token, false));
    }

    #[test]
    fn sid_match_neither_flag_no_match() {
        // §11.3 lines 4432-4433: group with neither enabled nor deny-only doesn't match
        let token = make_token(&alice(), &[
            (eng(), 0), // neither enabled nor deny-only
        ]);
        assert!(!crate::access_check::sid_matches_token(&eng(), &token, true));
        assert!(!crate::access_check::sid_matches_token(&eng(), &token, false));
    }

    #[test]
    fn sid_match_user_deny_only() {
        // §11.3 lines 4438-4441: when user SID is deny-only, matches deny not allow
        let mut token = make_token(&alice(), &[]);
        token.user_deny_only = true;
        assert!(!crate::access_check::sid_matches_token(&alice(), &token, true));
        assert!(crate::access_check::sid_matches_token(&alice(), &token, false));
    }

    #[test]
    fn sid_match_mandatory_group_cannot_be_disabled() {
        // §7.3 line 2064, 2435: mandatory groups cannot be disabled
        let g = test_group(SE_GROUP_MANDATORY | SE_GROUP_ENABLED);
        assert!(g.is_mandatory());
        assert!(g.is_enabled());
        // The mandatory flag prevents AdjustGroups from disabling this group
    }

    #[test]
    fn sid_match_deny_only_cannot_be_reverted() {
        // §7.3 lines 2065-2066: deny-only permanently set via FilterToken
        let g = test_group(SE_GROUP_USE_FOR_DENY_ONLY);
        assert!(g.is_deny_only());
        // Cannot be reverted: the flag is permanently set
        assert!(!g.is_enabled());
        assert!(!g.matches_for(true));
        assert!(g.matches_for(false));
    }

    #[test]
    fn se_group_integrity_value_is_0x20() {
        assert_eq!(SE_GROUP_INTEGRITY, 0x0000_0020);
    }

    #[test]
    fn se_group_integrity_enabled_value_is_0x40() {
        assert_eq!(SE_GROUP_INTEGRITY_ENABLED, 0x0000_0040);
    }
}
