// Audit evaluation (§11.10).
//
// Evaluates SACL audit and alarm ACEs after the access decision is final.
// Produces audit events and continuous audit masks for open handles.
// Purely observational — does not affect grant/deny decisions.

use crate::compat::{self, AllocError, TryClone, Vec};
use crate::ace;
use crate::mask::GenericMapping;
use crate::sd::SecurityDescriptor;
use crate::sid::Sid;
use crate::access_check::EnrichedToken;
use crate::token::Token;

/// An audit event produced during AccessCheck evaluation.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct AuditEvent {
    /// Which ACE triggered this event.
    pub ace_type: u8,
    /// The SID on the triggering ACE.
    pub ace_sid: Sid,
    /// The access mask on the triggering ACE (mapped).
    pub ace_mask: u32,
    /// Was the access attempt successful?
    pub success: bool,
    /// The access mask that was requested.
    pub desired: u32,
    /// The access mask that was granted.
    pub granted: u32,
}

/// A privilege-use audit event.
#[derive(Clone, Debug)]
pub struct PrivilegeUseEvent {
    /// Which privilege was exercised (bit position).
    pub privilege: u64,
    /// Which access bits the privilege contributed.
    pub granted_bits: u32,
}

/// Results of SACL audit evaluation.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Default)]
pub struct AuditResult {
    /// Access audit events to emit.
    pub events: Vec<AuditEvent>,
    /// Continuous audit mask for the opened handle (from alarm ACEs).
    pub continuous_audit_mask: u32,
}

/// Evaluate the SACL for audit and alarm ACEs (§11.17 step 10).
///
/// Called after the access decision is final. `granted` and `desired`
/// are the mapped values from the pipeline. `access_success` is the
/// final allowed/denied verdict.
///
/// `sid_match` uses deny polarity (§11.10: "the broadest identity view").
pub fn evaluate_sacl(
    sd: &SecurityDescriptor,
    token: &Token,
    mapping: &GenericMapping,
    desired: u32,
    granted: u32,
    access_success: bool,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
) -> Result<AuditResult, AllocError> {
    let mut result = AuditResult::default();

    // Audit uses a bare enriched token (no virtual groups — audit is
    // observational and uses deny-polarity SID matching directly).
    let bare_enriched = EnrichedToken {
        token,
        has_owner_rights: false,
        has_principal_self: false,
        principal_self_deny_only: false,
    };

    if sd.control & crate::sd::SE_SACL_PRESENT == 0 {
        return Ok(result);
    }
    let sacl = match &sd.sacl {
        Some(s) => s,
        None => return Ok(result),
    };

    for a in &sacl.aces {
        if a.flags & ace::INHERIT_ONLY_ACE != 0 {
            continue;
        }

        let ace_mask = crate::mask::map_generic_bits(a.mask, mapping);

        match a.ace_type {
            // --- Access Auditing (§11.10) ---
            ace::SYSTEM_AUDIT_ACE_TYPE
            | ace::SYSTEM_AUDIT_CALLBACK_ACE_TYPE => {
                let audit_on_success = a.flags & ace::SUCCESSFUL_ACCESS_ACE_FLAG != 0;
                let audit_on_failure = a.flags & ace::FAILED_ACCESS_ACE_FLAG != 0;

                if !audit_on_success && !audit_on_failure {
                    continue;
                }
                if access_success && !audit_on_success {
                    continue;
                }
                if !access_success && !audit_on_failure {
                    continue;
                }

                // SID matching with deny polarity (broadest view)
                if !crate::access_check::sid_matches_token(&a.sid, token, false) {
                    continue;
                }

                // Condition gate for callback types
                if a.ace_type == ace::SYSTEM_AUDIT_CALLBACK_ACE_TYPE {
                    if let Some(ref cond) = a.condition {
                        let cond_result = crate::conditional::evaluate(
                            cond, &bare_enriched, resource_attributes, local_claims, false,
                        )?;
                        if cond_result == crate::conditional::TriValue::False {
                            continue;
                        }
                    }
                }

                // Mask overlap check
                if access_success {
                    if granted & ace_mask == 0 {
                        continue;
                    }
                } else {
                    // For failure audit: ACE mask must overlap with denied bits
                    if ace_mask & desired & !granted == 0 {
                        continue;
                    }
                }

                compat::vec_push(&mut result.events, AuditEvent {
                    ace_type: a.ace_type,
                    ace_sid: a.sid.try_clone()?,
                    ace_mask,
                    success: access_success,
                    desired,
                    granted,
                })?;
            }

            // --- Continuous Auditing (§11.10, alarm ACEs) ---
            ace::SYSTEM_ALARM_ACE_TYPE
            | ace::SYSTEM_ALARM_CALLBACK_ACE_TYPE => {
                // Only on successful access — handle must be opened
                if !access_success {
                    continue;
                }

                if !crate::access_check::sid_matches_token(&a.sid, token, false) {
                    continue;
                }

                // Condition gate for callback types
                if a.ace_type == ace::SYSTEM_ALARM_CALLBACK_ACE_TYPE {
                    if let Some(ref cond) = a.condition {
                        let cond_result = crate::conditional::evaluate(
                            cond, &bare_enriched, resource_attributes, local_claims, false,
                        )?;
                        if cond_result == crate::conditional::TriValue::False {
                            continue;
                        }
                    }
                }

                // Intersect with granted — only audit operations the
                // handle actually has rights for
                result.continuous_audit_mask |= ace_mask & granted;
            }

            // Other SACL ACE types (mandatory label, resource attribute,
            // scoped policy, trust label) handled in PreSACLWalk
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ace::*;
    use crate::acl::*;
    use crate::mask::*;
    use crate::sd::*;
    use crate::well_known;

    fn audit_ace(sid: &Sid, mask: u32, success: bool, failure: bool) -> crate::ace::Ace {
        let mut flags = 0u8;
        if success { flags |= SUCCESSFUL_ACCESS_ACE_FLAG; }
        if failure { flags |= FAILED_ACCESS_ACE_FLAG; }
        crate::ace::Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags,
            mask,
            sid: sid.clone(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    fn alarm_ace(sid: &Sid, mask: u32) -> crate::ace::Ace {
        crate::ace::Ace {
            ace_type: SYSTEM_ALARM_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG,
            mask,
            sid: sid.clone(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    fn sd_with_sacl_aces(sacl_aces: Vec<crate::ace::Ace>) -> SecurityDescriptor {
        SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::system().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: Some(Acl { revision: ACL_REVISION, aces: sacl_aces }),
        }
    }

    fn system_token() -> Token {
        crate::token::Token::system_token().unwrap()
    }

    // -----------------------------------------------------------------------
    // Access auditing
    // -----------------------------------------------------------------------

    #[test]
    fn audit_success_fires_on_success() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, true, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1);
        assert!(result.events[0].success);
    }

    #[test]
    fn audit_success_does_not_fire_on_failure() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, true, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, 0, false, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0);
    }

    #[test]
    fn audit_failure_fires_on_failure() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, false, true),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, 0, false, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1);
        assert!(!result.events[0].success);
    }

    #[test]
    fn audit_both_flags_fires_always() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, true, true),
        ]);
        let token = system_token();

        // Success
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1);

        // Failure
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, 0, false, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1);
    }

    #[test]
    fn audit_no_flags_never_fires() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, false, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0);
    }

    #[test]
    fn audit_sid_must_match() {
        let random_sid = Sid::new(5, &[21, 999, 999, 999, 9999]).unwrap();
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&random_sid, FILE_READ_DATA, true, true),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0); // SID doesn't match
    }

    #[test]
    fn audit_mask_must_overlap_granted() {
        // Audit ACE for WRITE, but only READ was granted
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_WRITE_DATA, true, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0); // no overlap
    }

    #[test]
    fn audit_failure_mask_overlaps_denied() {
        // Audit ACE for WRITE. WRITE was requested but denied.
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_WRITE_DATA, false, true),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_WRITE_DATA, 0, false, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1); // write was denied, matches
    }

    #[test]
    fn audit_inherit_only_skipped() {
        let sd = sd_with_sacl_aces(alloc::vec![crate::ace::Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags: SUCCESSFUL_ACCESS_ACE_FLAG | INHERIT_ONLY_ACE,
            mask: FILE_READ_DATA,
            sid: well_known::everyone().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0);
    }

    #[test]
    fn audit_multiple_aces_multiple_events() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, true, false),
            audit_ace(&well_known::system().unwrap(), FILE_READ_DATA, true, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        // Both match (SYSTEM is in token, Everyone is in token groups)
        assert_eq!(result.events.len(), 2);
    }

    #[test]
    fn audit_generic_bits_mapped() {
        // Audit ACE uses GENERIC_READ
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), GENERIC_READ, true, false),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1); // GENERIC_READ maps to include FILE_READ_DATA
    }

    #[test]
    fn no_sacl_no_events() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(well_known::system().unwrap()),
            group: Some(well_known::system().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 0);
        assert_eq!(result.continuous_audit_mask, 0);
    }

    // -----------------------------------------------------------------------
    // Continuous auditing (alarm ACEs)
    // -----------------------------------------------------------------------

    #[test]
    fn alarm_sets_continuous_mask() {
        let sd = sd_with_sacl_aces(alloc::vec![
            alarm_ace(&well_known::everyone().unwrap(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = system_token();
        // Granted read+write
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_READ_DATA | FILE_WRITE_DATA,
            true, &[], &[],
        ).unwrap();
        assert!(result.continuous_audit_mask & FILE_READ_DATA != 0);
        assert!(result.continuous_audit_mask & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn alarm_intersects_with_granted() {
        // Alarm for read+write, but only read was granted
        let sd = sd_with_sacl_aces(alloc::vec![
            alarm_ace(&well_known::everyone().unwrap(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert!(result.continuous_audit_mask & FILE_READ_DATA != 0);
        assert!(result.continuous_audit_mask & FILE_WRITE_DATA == 0); // not granted
    }

    #[test]
    fn alarm_only_on_success() {
        let sd = sd_with_sacl_aces(alloc::vec![
            alarm_ace(&well_known::everyone().unwrap(), FILE_READ_DATA),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, 0, false, &[], &[],
        ).unwrap();
        assert_eq!(result.continuous_audit_mask, 0); // access failed
    }

    #[test]
    fn alarm_sid_must_match() {
        let random_sid = Sid::new(5, &[21, 999, 999, 999, 9999]).unwrap();
        let sd = sd_with_sacl_aces(alloc::vec![
            alarm_ace(&random_sid, FILE_READ_DATA),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA, FILE_READ_DATA, true, &[], &[],
        ).unwrap();
        assert_eq!(result.continuous_audit_mask, 0);
    }

    #[test]
    fn alarm_multiple_accumulate() {
        let sd = sd_with_sacl_aces(alloc::vec![
            alarm_ace(&well_known::everyone().unwrap(), FILE_READ_DATA),
            alarm_ace(&well_known::system().unwrap(), FILE_WRITE_DATA),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_READ_DATA | FILE_WRITE_DATA,
            true, &[], &[],
        ).unwrap();
        assert!(result.continuous_audit_mask & FILE_READ_DATA != 0);
        assert!(result.continuous_audit_mask & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn mixed_audit_and_alarm() {
        let sd = sd_with_sacl_aces(alloc::vec![
            audit_ace(&well_known::everyone().unwrap(), FILE_READ_DATA, true, false),
            alarm_ace(&well_known::everyone().unwrap(), FILE_WRITE_DATA),
        ]);
        let token = system_token();
        let result = evaluate_sacl(
            &sd, &token, &FILE_GENERIC_MAPPING,
            FILE_READ_DATA | FILE_WRITE_DATA,
            FILE_READ_DATA | FILE_WRITE_DATA,
            true, &[], &[],
        ).unwrap();
        assert_eq!(result.events.len(), 1); // audit event for read
        assert!(result.continuous_audit_mask & FILE_WRITE_DATA != 0); // alarm for write
    }
}
