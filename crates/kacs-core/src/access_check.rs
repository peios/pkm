// AccessCheck — the complete authorization pipeline (§11).
//
// Given a token (who), an SD (what are the rules), and a desired access
// mask (what do they want), AccessCheck returns which rights are granted
// and whether the request succeeds.
//
// This module implements the §11.17 pseudocode exactly. Each function
// maps to a named function in the proposal. Comments reference the
// specific proposal steps.

use crate::ace;
use crate::group::GroupEntry;
use crate::mask::{self, GenericMapping};
use crate::sd::{SecurityDescriptor, SE_DACL_PRESENT};
use crate::sid::Sid;
use crate::token::{Token, TokenType, ImpersonationLevel};
use crate::well_known;

/// Result of an AccessCheck evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct AccessCheckResult {
    /// The access rights granted by the pipeline.
    pub granted: u32,
    /// Whether the request as a whole succeeded.
    pub allowed: bool,
    /// Continuous audit mask for the opened handle (from alarm ACEs).
    pub continuous_audit_mask: u32,
}

/// Per-node result for AccessCheckResultList.
#[derive(Clone, Debug)]
pub struct NodeResult {
    pub granted: u32,
    pub allowed: bool,
}

/// Internal state for per-property object type tree nodes (§11.8).
#[derive(Clone, Debug)]
pub struct ObjectTypeNode {
    pub level: u16,
    pub guid: crate::guid::Guid,
    pub decided: u32,
    pub granted: u32,
}

// ---------------------------------------------------------------------------
// SID matching (§11.3)
// ---------------------------------------------------------------------------

/// Does a SID match the token for allow-polarity or deny-polarity?
///
/// §11.3: For allow ACEs, only groups that are enabled and NOT deny-only
/// match. For deny ACEs, both enabled groups and deny-only groups match.
/// The user SID matches unless it is deny-only (for allow).
pub fn sid_matches_token(sid: &Sid, token: &Token, for_allow: bool) -> bool {
    // Check user SID
    if *sid == token.user_sid {
        if for_allow && token.user_deny_only {
            return false;
        }
        return true;
    }
    // Check groups
    for group in &token.groups {
        if group.sid == *sid && group.matches_for(for_allow) {
            return true;
        }
    }
    false
}

/// Does a SID appear in a restricting SID list? (§11.7)
fn sid_in_restricting_sids(sid: &Sid, restricting_sids: &[GroupEntry]) -> bool {
    restricting_sids.iter().any(|rs| rs.sid == *sid)
}

/// Does a SID appear in a plain SID list? (for confinement)
fn sid_in_list(sid: &Sid, sids: &[Sid]) -> bool {
    sids.iter().any(|s| s == sid)
}

// ---------------------------------------------------------------------------
// MapGenericBits (§11.2) — re-export from mask module
// ---------------------------------------------------------------------------

pub use crate::mask::map_generic_bits;

// ---------------------------------------------------------------------------
// EnrichToken — virtual group injection (§11.17 step 5)
// ---------------------------------------------------------------------------

/// Enriched token view with virtual groups injected.
/// The original token is not modified.
#[derive(Clone, Debug)]
pub struct EnrichedToken<'a> {
    pub token: &'a Token,
    /// S-1-3-4 (OWNER RIGHTS) — present if caller is the owner.
    pub has_owner_rights: bool,
    /// S-1-5-10 (PRINCIPAL SELF) — present if caller matches self_sid.
    pub has_principal_self: bool,
    /// If true, PRINCIPAL_SELF is deny-only on this token.
    pub principal_self_deny_only: bool,
}

/// §11.17 EnrichToken: inject virtual groups S-1-3-4 and S-1-5-10.
fn enrich_token<'a>(token: &'a Token, owner: &Sid, self_sid: Option<&Sid>) -> EnrichedToken<'a> {
    let caller_is_owner = sid_matches_token(owner, token, true);
    let (has_principal_self, principal_self_deny_only) = if let Some(ss) = self_sid {
        if sid_matches_token(ss, token, true) {
            (true, false)
        } else if sid_matches_token(ss, token, false) {
            // Matches for deny but not allow — deny-only
            (true, true)
        } else {
            (false, false)
        }
    } else {
        (false, false)
    };

    EnrichedToken {
        token,
        has_owner_rights: caller_is_owner,
        has_principal_self,
        principal_self_deny_only,
    }
}

/// Extended SID matching that includes virtual groups.
fn enriched_sid_matches(
    sid: &Sid,
    enriched: &EnrichedToken,
    for_allow: bool,
) -> bool {
    // Check virtual groups first
    if *sid == well_known::owner_rights() && enriched.has_owner_rights {
        return true;
    }
    if *sid == well_known::principal_self() && enriched.has_principal_self {
        if for_allow && enriched.principal_self_deny_only {
            return false;
        }
        return true;
    }
    // Fall through to normal token matching
    sid_matches_token(sid, enriched.token, for_allow)
}

// ---------------------------------------------------------------------------
// EvaluateDACL (§11.17)
// ---------------------------------------------------------------------------

/// §11.17 EvaluateDACL: unified DACL evaluation.
///
/// Called for the normal pass, restricted pass, and confinement pass —
/// parameterized by the SID matching closure.
fn evaluate_dacl<F>(
    sd: &SecurityDescriptor,
    mapping: &GenericMapping,
    mut object_tree: Option<&mut [ObjectTypeNode]>,
    sid_match: &F,
    desired: u32,
    max_allowed_mode: bool,
    skip_owner_implicit: bool,
    decided: &mut u32,
    granted: &mut u32,
) where
    F: Fn(&Sid, bool) -> bool,
{
    // --- Owner implicit rights (§11.4) ---
    if !skip_owner_implicit {
        if let Some(ref owner) = sd.owner {
            if sid_match(owner, true) {
                // Pre-scan for OWNER RIGHTS ACE (S-1-3-4) in the DACL
                let owner_rights_present = if sd.control & SE_DACL_PRESENT != 0 {
                    if let Some(ref dacl) = sd.dacl {
                        dacl.aces.iter().any(|a| {
                            if a.flags & ace::INHERIT_ONLY_ACE != 0 {
                                return false;
                            }
                            if !ace::is_access_type(a.ace_type) {
                                return false;
                            }
                            a.sid == well_known::owner_rights()
                        })
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !owner_rights_present {
                    let implicit = (mask::READ_CONTROL | mask::WRITE_DAC) & !*decided;
                    *decided |= implicit;
                    *granted |= implicit;
                    if let Some(ref mut tree) = object_tree {
                        for node in tree.iter_mut() {
                            let node_new = (mask::READ_CONTROL | mask::WRITE_DAC) & !node.decided;
                            node.decided |= node_new;
                            node.granted |= node_new;
                        }
                    }
                }
            }
        }
    }

    // --- NULL DACL (§11.3) — grant all valid remaining bits ---
    if sd.control & SE_DACL_PRESENT == 0 {
        let all_bits = map_generic_bits(mask::GENERIC_ALL, mapping);
        let new_bits = all_bits & !*decided;
        *decided |= new_bits;
        *granted |= new_bits;
        if let Some(ref mut tree) = object_tree {
            for node in tree.iter_mut() {
                let node_new = all_bits & !node.decided;
                node.decided |= node_new;
                node.granted |= node_new;
            }
        }
        return;
    }

    let dacl = match sd.dacl {
        Some(ref d) => d,
        None => return, // SE_DACL_PRESENT set but no DACL — empty, grant nothing
    };

    // --- DACL walk (§11.3) ---
    for a in &dacl.aces {
        // Skip inherit-only ACEs
        if a.flags & ace::INHERIT_ONLY_ACE != 0 {
            continue;
        }

        // Map generic bits in ACE mask (§11.3, Peios divergence)
        let ace_mask = map_generic_bits(a.mask, mapping);

        match a.ace_type {
            // --- Basic allow ---
            ace::ACCESS_ALLOWED_ACE_TYPE => {
                if sid_match(&a.sid, true) {
                    let new_bits = ace_mask & !*decided;
                    *decided |= new_bits;
                    *granted |= new_bits;
                    if let Some(ref mut tree) = object_tree {
                        for node in tree.iter_mut() {
                            let n = ace_mask & !node.decided;
                            node.decided |= n;
                            node.granted |= n;
                        }
                    }
                }
            }

            // --- Basic deny ---
            ace::ACCESS_DENIED_ACE_TYPE => {
                if sid_match(&a.sid, false) {
                    let new_bits = ace_mask & !*decided;
                    *decided |= new_bits;
                    // NOT added to granted — decided but denied
                    if let Some(ref mut tree) = object_tree {
                        for node in tree.iter_mut() {
                            let n = ace_mask & !node.decided;
                            node.decided |= n;
                        }
                    }
                }
            }

            // --- Callback allow (conditional) ---
            ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                if sid_match(&a.sid, true) {
                    // TODO: conditional expression evaluation (Phase 3.11)
                    // For now, skip callback ACEs — they require the
                    // expression evaluator. A callback ACE with no condition
                    // evaluates as UNKNOWN → skip for allow.
                    // This is safe: skipping an allow ACE never grants access.
                }
            }

            // --- Callback deny (conditional) ---
            ace::ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                if sid_match(&a.sid, false) {
                    // TODO: conditional expression evaluation (Phase 3.11)
                    // A callback deny with no condition evaluates as UNKNOWN
                    // → deny fires (fail-safe). But without the evaluator
                    // we can't distinguish "no condition" from "condition
                    // present but unevaluated". Skip for now — this is
                    // temporarily unsafe for conditional deny ACEs.
                    // Will be fixed when the expression evaluator lands.
                }
            }

            // Object ACEs, callback object ACEs — deferred to Phase 3.12
            // Audit/alarm ACEs — handled separately in the SACL walk
            _ => {}
        }

        // Short-circuit (non-tree, non-MAXIMUM_ALLOWED only)
        if object_tree.is_none()
            && !max_allowed_mode
            && desired != 0
            && (*decided & desired) == desired
        {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// AccessCheck — single-result wrapper (§11.17)
// ---------------------------------------------------------------------------

/// The main AccessCheck entry point (§11.17 AccessCheck wrapper).
///
/// This is the initial implementation covering:
/// - Generic mapping (§11.2)
/// - MAXIMUM_ALLOWED (§11.5)
/// - Impersonation level gate (§11.17 step 0)
/// - Privilege grants: SeSecurityPrivilege, SeBackupPrivilege,
///   SeRestorePrivilege (§11.6)
/// - Owner implicit rights with OWNER RIGHTS pre-scan (§11.4)
/// - DACL walk with basic allow/deny ACEs (§11.3)
/// - Post-DACL SeTakeOwnershipPrivilege (§11.6)
/// - NULL DACL / empty DACL semantics (§11.3)
///
/// NOT YET IMPLEMENTED (will be added incrementally):
/// - MIC (§11.13)
/// - PIP (§11.15)
/// - Restricted tokens (§11.7)
/// - Confinement (§11.14)
/// - Conditional ACEs (§11.12)
/// - Object ACEs (§11.8)
/// - Central Access Policy (§11.16)
/// - Auditing (§11.10)
pub fn access_check(
    sd: &SecurityDescriptor,
    token: &Token,
    desired: u32,
    mapping: &GenericMapping,
    self_sid: Option<&Sid>,
    privilege_intent: u32,
) -> Result<AccessCheckResult, AccessCheckError> {
    // Step 0: Impersonation level gate (§12.1)
    if token.token_type == TokenType::Impersonation
        && token.impersonation_level == ImpersonationLevel::Identification
    {
        return Err(AccessCheckError::IdentificationLevel);
    }

    // Step 1: Input validation
    if sd.owner.is_none() || sd.group.is_none() {
        return Err(AccessCheckError::InvalidSecurityDescriptor);
    }

    // Step 2: Generic mapping (§11.2)
    let mut mapped_desired = map_generic_bits(desired, mapping);

    // Step 2a: Strip MAXIMUM_ALLOWED (§11.5)
    let max_allowed_mode = mapped_desired & mask::MAXIMUM_ALLOWED != 0;
    mapped_desired &= !mask::MAXIMUM_ALLOWED;

    // Step 2b: Effective privileges (§11.6)
    // Intent-gated: backup/restore only active with corresponding flag.
    let mut effective_privs = token.privileges.enabled;
    if privilege_intent & BACKUP_INTENT == 0 {
        effective_privs &= !crate::privilege::bits::SE_BACKUP;
    }
    if privilege_intent & RESTORE_INTENT == 0 {
        effective_privs &= !crate::privilege::bits::SE_RESTORE;
    }

    // Step 3: Privilege-based grants (§11.6)
    let mut decided: u32 = 0;
    let mut granted: u32 = 0;
    let mut privilege_granted: u32 = 0;

    // ACCESS_SYSTEM_SECURITY: always decided, no DACL ACE can grant it.
    decided |= mask::ACCESS_SYSTEM_SECURITY;
    if effective_privs & crate::privilege::bits::SE_SECURITY != 0 {
        granted |= mask::ACCESS_SYSTEM_SECURITY;
        privilege_granted |= mask::ACCESS_SYSTEM_SECURITY;
    }

    // Backup: all read-mapped bits
    if effective_privs & crate::privilege::bits::SE_BACKUP != 0 {
        let backup_bits = map_generic_bits(mask::GENERIC_READ, mapping);
        decided |= backup_bits;
        granted |= backup_bits;
        privilege_granted |= backup_bits;
    }

    // Restore: all write-mapped bits + WRITE_DAC + WRITE_OWNER + DELETE + ASS
    if effective_privs & crate::privilege::bits::SE_RESTORE != 0 {
        let restore_bits = map_generic_bits(mask::GENERIC_WRITE, mapping)
            | mask::WRITE_DAC
            | mask::WRITE_OWNER
            | mask::DELETE
            | mask::ACCESS_SYSTEM_SECURITY;
        decided |= restore_bits;
        granted |= restore_bits;
        privilege_granted |= restore_bits;
    }

    // WRITE_OWNER is NOT decided here — deferred to step 7a

    // Step 4: Pre-SACL walk — MIC, PIP, resource attributes, policy SIDs
    // TODO: MIC (Phase 3.7), PIP (Phase 3.8)
    // For now, no mandatory constraints are applied.

    // Step 5: Virtual group injection
    let owner = sd.owner.as_ref().unwrap();
    let enriched = enrich_token(token, owner, self_sid);

    // Step 6: Tree initialization — deferred (Phase 3.12)

    // Step 7: Normal DACL evaluation (§11.3, §11.4)
    let sid_match = |sid: &Sid, for_allow: bool| -> bool {
        enriched_sid_matches(sid, &enriched, for_allow)
    };
    evaluate_dacl(
        sd,
        mapping,
        None, // no object tree yet
        &sid_match,
        mapped_desired,
        max_allowed_mode,
        false, // don't skip owner implicit
        &mut decided,
        &mut granted,
    );

    // Step 7a: Post-DACL WRITE_OWNER override (§11.6)
    // SeTakeOwnershipPrivilege grants WRITE_OWNER if the DACL did not.
    // Deny-proof: overrides DACL deny ACEs for WRITE_OWNER.
    // BUT: respects mandatory decisions (MIC/PIP) via mandatory_decided.
    // (mandatory_decided is 0 until MIC/PIP are implemented)
    let mandatory_decided: u32 = 0; // TODO: populated by PreSACLWalk
    if mapped_desired & mask::WRITE_OWNER != 0 || max_allowed_mode {
        if effective_privs & crate::privilege::bits::SE_TAKE_OWNERSHIP != 0 {
            if mandatory_decided & mask::WRITE_OWNER == 0
                && granted & mask::WRITE_OWNER == 0
            {
                decided |= mask::WRITE_OWNER;
                granted |= mask::WRITE_OWNER;
                privilege_granted |= mask::WRITE_OWNER;
            }
        }
    }

    // Step 8: Restricted token pass — TODO (Phase 3.9)
    // Step 8a: Confinement — TODO (Phase 3.10)
    // Step 9: Central Access Policy — TODO (Phase 3.13)
    // Step 9b: Privilege-use auditing — TODO
    // Step 10: Audit emission — TODO

    // Step 15: Result computation
    let allowed = if mapped_desired == 0 {
        true
    } else {
        (granted & mapped_desired) == mapped_desired
    };

    Ok(AccessCheckResult {
        granted,
        allowed,
        continuous_audit_mask: 0, // TODO: audit
    })
}

/// Privilege intent flags for AccessCheck.
pub const BACKUP_INTENT: u32 = 0x01;
pub const RESTORE_INTENT: u32 = 0x02;

/// Errors from AccessCheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessCheckError {
    /// The token is at Identification impersonation level (§12.1).
    IdentificationLevel,
    /// The SD is structurally invalid (missing owner or group).
    InvalidSecurityDescriptor,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::ace::*;
    use crate::acl::*;
    use crate::mask::*;
    use crate::privilege;
    use crate::sd::*;
    use crate::token::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Build a simple token for a given user SID with specified groups.
    fn test_token(user: &Sid, groups: &[&Sid], privs: u64) -> Token {
        let mut token = Token::system_token();
        token.user_sid = user.clone();
        token.groups = groups
            .iter()
            .map(|s| crate::group::GroupEntry::new(
                (*s).clone(),
                crate::group::SE_GROUP_MANDATORY
                    | crate::group::SE_GROUP_ENABLED_BY_DEFAULT
                    | crate::group::SE_GROUP_ENABLED,
            ))
            .collect();
        token.privileges = privilege::Privileges::new_all_enabled(privs);
        token.token_type = TokenType::Primary;
        token.integrity_level = IntegrityLevel::Medium;
        token
    }

    fn alice() -> Sid { Sid::new(5, &[21, 100, 200, 300, 1001]) }
    fn bob() -> Sid { Sid::new(5, &[21, 100, 200, 300, 1002]) }
    fn engineers() -> Sid { Sid::new(5, &[21, 100, 200, 300, 2001]) }
    fn managers() -> Sid { Sid::new(5, &[21, 100, 200, 300, 2002]) }

    fn allow(sid: &Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    fn deny(sid: &Sid, mask: u32) -> Ace {
        Ace {
            ace_type: ACCESS_DENIED_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    fn sd_with_dacl(owner: &Sid, aces: Vec<Ace>) -> SecurityDescriptor {
        SecurityDescriptor::new(
            owner.clone(),
            well_known::users(),
            Acl { revision: ACL_REVISION, aces },
        )
    }

    fn check(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, 0).unwrap()
    }

    fn check_with_intent(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
        intent: u32,
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, intent).unwrap()
    }

    // -----------------------------------------------------------------------
    // Basic DACL walk (§11.3)
    // -----------------------------------------------------------------------

    #[test]
    fn allow_ace_grants_access() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
    }

    #[test]
    fn deny_ace_blocks_access() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn first_writer_wins_deny_before_allow() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);

        // READ should succeed (denied bit doesn't cover it)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);

        // WRITE should fail (denied first)
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn first_writer_wins_allow_before_deny() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA), // too late
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // allow won — it was first
    }

    #[test]
    fn no_matching_ace_denies() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&bob(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn group_membership_grants_access() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn multiple_aces_accumulate_bits() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn partial_grant_fails_strict() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Request both read and write, only read is granted
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA == 0);
    }

    #[test]
    fn deny_on_group_blocks_user() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn deny_on_user_allow_on_group_first_writer() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&engineers(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed); // deny came first
    }

    #[test]
    fn inherit_only_ace_skipped() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            Ace {
                ace_type: ACCESS_DENIED_ACE_TYPE,
                flags: INHERIT_ONLY_ACE,
                mask: GENERIC_ALL,
                sid: alice(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // inherit-only deny was skipped
    }

    #[test]
    fn generic_bits_in_ace_mapped() {
        // ACE uses GENERIC_READ, request uses specific bits
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_READ),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // GENERIC_READ mapped to include FILE_READ_DATA
    }

    #[test]
    fn generic_bits_in_request_mapped() {
        // Request uses GENERIC_READ, ACE uses specific bits
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA
                | READ_CONTROL | SYNCHRONIZE),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, GENERIC_READ);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // Empty DACL vs NULL DACL (§11.3, §9.8)
    // -----------------------------------------------------------------------

    #[test]
    fn null_dacl_grants_all() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE, // no SE_DACL_PRESENT
            owner: Some(alice()),
            group: Some(well_known::users()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn empty_dacl_denies_all_except_owner_implicit() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users(),
            Acl::new(ACL_REVISION), // zero ACEs
        );
        let token = test_token(&alice(), &[], 0);

        // Owner implicit rights (READ_CONTROL + WRITE_DAC) should be granted
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);

        // Data access should be denied
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn empty_dacl_non_owner_gets_nothing() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Owner implicit rights (§11.4)
    // -----------------------------------------------------------------------

    #[test]
    fn owner_gets_implicit_read_control_write_dac() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL | WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn non_owner_does_not_get_implicit_rights() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&bob(), FILE_READ_DATA),
        ]);
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL);
        assert!(!result.allowed);
    }

    #[test]
    fn owner_implicit_rights_survive_deny() {
        // Deny ACE for owner's READ_CONTROL comes after implicit grant
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Owner implicit rights are granted BEFORE the DACL walk,
        // so the deny ACE cannot override them (first-writer-wins)
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    #[test]
    fn owner_rights_ace_suppresses_implicit() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            // OWNER RIGHTS ACE with only READ_CONTROL (no WRITE_DAC)
            allow(&well_known::owner_rights(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);

        // READ_CONTROL should be granted (from OWNER RIGHTS ACE)
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);

        // WRITE_DAC should be denied (implicit suppressed, ACE doesn't grant it)
        let result = check(&sd, &token, WRITE_DAC);
        assert!(!result.allowed);
    }

    #[test]
    fn owner_rights_deny_suppresses_and_denies() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&well_known::owner_rights(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        // OWNER RIGHTS ACE present → implicit suppressed
        // Deny ACE denies both → no access
        let result = check(&sd, &token, READ_CONTROL);
        assert!(!result.allowed);
    }

    #[test]
    fn owner_rights_inherit_only_does_not_suppress() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            // OWNER RIGHTS ACE is inherit-only — should NOT suppress implicit
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: INHERIT_ONLY_ACE,
                mask: READ_CONTROL,
                sid: well_known::owner_rights(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);
        let token = test_token(&alice(), &[], 0);
        // Inherit-only OWNER RIGHTS doesn't suppress → implicit applies
        let result = check(&sd, &token, READ_CONTROL | WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn owner_via_group_gets_implicit() {
        // Owner SID matches via a group on the token
        let sd = sd_with_dacl(&engineers(), alloc::vec![]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // MAXIMUM_ALLOWED (§11.5)
    // -----------------------------------------------------------------------

    #[test]
    fn maximum_allowed_returns_full_grant() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_EXECUTE),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed); // pure MAXIMUM_ALLOWED always succeeds
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA != 0);
        assert!(result.granted & FILE_EXECUTE != 0);
        // Owner implicit rights too
        assert!(result.granted & READ_CONTROL != 0);
        assert!(result.granted & WRITE_DAC != 0);
    }

    #[test]
    fn maximum_allowed_with_specific_rights() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Request MAXIMUM_ALLOWED | FILE_WRITE_DATA
        // Should fail (FILE_WRITE_DATA not granted) but granted shows what IS available
        let result = check(&sd, &token, MAXIMUM_ALLOWED | FILE_WRITE_DATA);
        assert!(!result.allowed); // FILE_WRITE_DATA was requested but not granted
        assert!(result.granted & FILE_READ_DATA != 0); // but read IS in granted
    }

    #[test]
    fn maximum_allowed_empty_dacl() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
        // Only owner implicit rights
        assert!(result.granted & READ_CONTROL != 0);
        assert!(result.granted & WRITE_DAC != 0);
        assert!(result.granted & FILE_READ_DATA == 0);
    }

    #[test]
    fn maximum_allowed_null_dacl() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
        // Should have everything except ACCESS_SYSTEM_SECURITY (no privilege)
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA != 0);
        assert!(result.granted & DELETE != 0);
    }

    #[test]
    fn zero_desired_always_succeeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, 0);
        assert!(result.allowed); // asked for nothing, got nothing
    }

    // -----------------------------------------------------------------------
    // Privilege grants (§11.6)
    // -----------------------------------------------------------------------

    #[test]
    fn se_security_grants_access_system_security() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(result.allowed);
    }

    #[test]
    fn no_se_security_denies_access_system_security() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), // DACL can't grant ASS
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
    }

    #[test]
    fn se_backup_grants_read_with_intent() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL), // deny everything via DACL
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed); // backup privilege overrides
    }

    #[test]
    fn se_backup_without_intent_does_nothing() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        let result = check(&sd, &token, FILE_READ_DATA); // no intent flag
        assert!(!result.allowed);
    }

    #[test]
    fn se_restore_grants_write_with_intent() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[],
            privilege::bits::SE_RESTORE);
        let result = check_with_intent(&sd, &token, FILE_WRITE_DATA, RESTORE_INTENT);
        assert!(result.allowed);
    }

    #[test]
    fn se_restore_without_intent_does_nothing() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn se_restore_grants_write_dac_write_owner_delete() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]); // empty DACL, bob owns
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        let result = check_with_intent(
            &sd, &token,
            WRITE_DAC | WRITE_OWNER | DELETE,
            RESTORE_INTENT,
        );
        assert!(result.allowed);
    }

    #[test]
    fn se_take_ownership_grants_write_owner() {
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER), // explicit deny
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        // SeTakeOwnership is deny-proof per §11.6
        assert!(result.allowed);
    }

    #[test]
    fn se_take_ownership_not_needed_if_dacl_grants() {
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed);
        // The privilege should NOT be recorded as used because
        // DACL independently granted WRITE_OWNER. (Audit accuracy.)
        // We don't track this yet but the granted mask is correct.
    }

    // -----------------------------------------------------------------------
    // Impersonation level gate (§12.1)
    // -----------------------------------------------------------------------

    #[test]
    fn identification_level_denied() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        let mut token = test_token(&alice(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Identification;
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, 0,
        );
        assert_eq!(result, Err(AccessCheckError::IdentificationLevel));
    }

    #[test]
    fn anonymous_level_proceeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::anonymous(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&well_known::anonymous(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Anonymous;
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn impersonation_level_proceeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&alice(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Impersonation;
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn delegation_level_proceeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&alice(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Delegation;
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn primary_token_not_affected_by_level_gate() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0); // Primary token
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // Input validation
    // -----------------------------------------------------------------------

    #[test]
    fn missing_owner_rejected() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: None,
            group: Some(well_known::users()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, 0,
        );
        assert_eq!(result, Err(AccessCheckError::InvalidSecurityDescriptor));
    }

    #[test]
    fn missing_group_rejected() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: None,
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, 0,
        );
        assert_eq!(result, Err(AccessCheckError::InvalidSecurityDescriptor));
    }

    // -----------------------------------------------------------------------
    // Deny-only groups (§11.3)
    // -----------------------------------------------------------------------

    #[test]
    fn deny_only_group_matches_deny_not_allow() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&engineers(), FILE_READ_DATA),
            deny(&engineers(), FILE_WRITE_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        // Set engineers group to deny-only
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;

        // Allow ACE should NOT match (deny-only group)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);

        // Deny ACE SHOULD match
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Complex scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_dacl_order() {
        // Standard enterprise DACL: explicit deny, explicit allow,
        // inherited deny, inherited allow
        let sd = sd_with_dacl(&alice(), alloc::vec![
            // Explicit deny: guests can't do anything
            deny(&well_known::guests(), GENERIC_ALL),
            // Explicit allow: admins get everything
            allow(&well_known::administrators(), GENERIC_ALL),
            // Explicit allow: engineers get read
            allow(&engineers(), FILE_READ_DATA | READ_CONTROL),
            // Inherited allow: everyone gets read
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: INHERITED_ACE,
                mask: FILE_READ_DATA | READ_CONTROL,
                sid: well_known::everyone(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            },
        ]);

        // Alice (engineer) should get read
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);

        // Alice should NOT get write
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn multiple_groups_accumulate() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&engineers(), FILE_READ_DATA),
            allow(&managers(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers(), &managers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn different_mapping_table() {
        // Use registry generic mapping instead of file
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_READ),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, KEY_QUERY_VALUE, &KEY_GENERIC_MAPPING, None, 0,
        ).unwrap();
        assert!(result.allowed); // GENERIC_READ maps to KEY_QUERY_VALUE for registry
    }

    #[test]
    fn process_sd_default_pattern() {
        // The default process SD from §8.4
        let user = alice();
        let sd = sd_with_dacl(&user, alloc::vec![
            allow(&user, GENERIC_ALL),
            allow(&well_known::administrators(), GENERIC_ALL),
            allow(&well_known::system(), GENERIC_ALL),
            allow(&well_known::everyone(), PROCESS_QUERY_LIMITED),
        ]);

        // Owner (alice) gets everything
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, 0,
        ).unwrap();
        assert!(result.allowed);

        // Random user gets only PROCESS_QUERY_LIMITED
        let token = test_token(&bob(), &[&well_known::everyone()], 0);
        let result = access_check(
            &sd, &token, PROCESS_QUERY_LIMITED, &PROCESS_GENERIC_MAPPING, None, 0,
        ).unwrap();
        assert!(result.allowed);

        let result = access_check(
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn system_token_with_backup_reads_anything() {
        // SYSTEM with backup intent can read a file owned by bob
        // even with an empty DACL (no explicit grants)
        let sd = SecurityDescriptor::new(
            bob(),
            well_known::users(),
            Acl::new(ACL_REVISION),
        );
        let token = Token::system_token();
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed);
    }
}
