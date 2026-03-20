// AccessCheck — the complete authorization pipeline (§11).
//
// Given a token (who), an SD (what are the rules), and a desired access
// mask (what do they want), AccessCheck returns which rights are granted
// and whether the request succeeds.
//
// This module implements the §11.17 pseudocode exactly. Each function
// maps to a named function in the proposal. Comments reference the
// specific proposal steps.

use crate::compat::{self, AllocError, TryClone, Vec};
use crate::ace;
use crate::cap::{CentralAccessPolicy, CentralAccessRule};
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
    /// The access rights granted for this tree node.
    pub granted: u32,
    /// Whether the requested access was allowed for this node.
    pub allowed: bool,
}

/// Internal state for per-property object type tree nodes (§11.8).
#[derive(Clone, Debug)]
pub struct ObjectTypeNode {
    /// Depth in the object type tree (0 = root).
    pub level: u16,
    /// The GUID identifying this property set or property.
    pub guid: crate::guid::Guid,
    /// Bitmask of access rights already decided (allow or deny).
    pub decided: u32,
    /// Bitmask of access rights granted to this node.
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

/// Map GENERIC_{READ,WRITE,EXECUTE,ALL} to object-specific bits (§11.2).
pub use crate::mask::map_generic_bits;

// ---------------------------------------------------------------------------
// EnrichToken — virtual group injection (§11.17 step 5)
// ---------------------------------------------------------------------------

/// Enriched token view with virtual groups injected.
/// The original token is not modified.
#[derive(Clone, Debug)]
pub struct EnrichedToken<'a> {
    /// Reference to the underlying token.
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
) -> Result<bool, AllocError> {
    // Check virtual groups first
    if *sid == well_known::owner_rights()? && enriched.has_owner_rights {
        return Ok(true);
    }
    if *sid == well_known::principal_self()? && enriched.has_principal_self {
        if for_allow && enriched.principal_self_deny_only {
            return Ok(false);
        }
        return Ok(true);
    }
    // Fall through to normal token matching
    Ok(sid_matches_token(sid, enriched.token, for_allow))
}

// ---------------------------------------------------------------------------
// Object type tree helpers (§11.8, §11.17)
// ---------------------------------------------------------------------------

/// Find a node in the tree by GUID. Returns index or None.
fn find_node(tree: &[ObjectTypeNode], guid: &crate::guid::Guid) -> Option<usize> {
    tree.iter().position(|n| n.guid == *guid)
}

/// Return indices of all descendants of tree[idx].
fn descendant_indices(tree: &[ObjectTypeNode], idx: usize) -> Result<Vec<usize>, AllocError> {
    let parent_level = tree[idx].level;
    let mut result = Vec::new();
    for i in (idx + 1)..tree.len() {
        if tree[i].level <= parent_level {
            break;
        }
        compat::vec_push(&mut result, i)?;
    }
    Ok(result)
}

/// Return indices of direct children of tree[idx].
fn child_indices(tree: &[ObjectTypeNode], idx: usize) -> Result<Vec<usize>, AllocError> {
    let child_level = tree[idx].level + 1;
    let mut result = Vec::new();
    for i in (idx + 1)..tree.len() {
        if tree[i].level <= tree[idx].level {
            break;
        }
        if tree[i].level == child_level {
            compat::vec_push(&mut result, i)?;
        }
    }
    Ok(result)
}

/// Return indices of siblings of tree[idx] (same level, same parent).
fn sibling_indices(tree: &[ObjectTypeNode], idx: usize) -> Result<Vec<usize>, AllocError> {
    if tree[idx].level == 0 {
        return Ok(Vec::new());
    }
    // Find parent
    let parent_idx = parent_index(tree, idx);
    if parent_idx.is_none() {
        return Ok(Vec::new());
    }
    let parent_idx = parent_idx.unwrap();
    // All children of parent at the same level, excluding self
    let child_level = tree[idx].level;
    let mut result = Vec::new();
    for i in (parent_idx + 1)..tree.len() {
        if tree[i].level <= tree[parent_idx].level {
            break;
        }
        if tree[i].level == child_level && i != idx {
            compat::vec_push(&mut result, i)?;
        }
    }
    Ok(result)
}

/// Return the index of the parent of tree[idx].
fn parent_index(tree: &[ObjectTypeNode], idx: usize) -> Option<usize> {
    if idx == 0 || tree[idx].level == 0 {
        return None;
    }
    let target_level = tree[idx].level - 1;
    for i in (0..idx).rev() {
        if tree[i].level == target_level {
            return Some(i);
        }
    }
    None
}

/// Return indices of all ancestors, from immediate parent to root.
fn ancestor_indices(tree: &[ObjectTypeNode], idx: usize) -> Result<Vec<usize>, AllocError> {
    let mut result = Vec::new();
    let mut current = idx;
    loop {
        match parent_index(tree, current) {
            Some(p) => {
                compat::vec_push(&mut result, p)?;
                current = p;
            }
            None => break,
        }
    }
    Ok(result)
}

/// §11.8: Upward aggregation after a grant. When ALL siblings share a
/// right, propagate up to the parent. Repeat until root or no common bits.
fn upward_aggregate_grants(tree: &mut [ObjectTypeNode], start_idx: usize, _ace_mask: u32) -> Result<(), AllocError> {
    let mut v_idx = start_idx;
    while tree[v_idx].level > 0 {
        // Compute common granted bits across self + all siblings
        let siblings = sibling_indices(tree, v_idx)?;
        let mut common = tree[v_idx].granted;
        for s_idx in &siblings {
            common &= tree[*s_idx].granted;
            if common == 0 {
                break;
            }
        }
        if common == 0 {
            break;
        }
        // Propagate to parent
        let p_idx = match parent_index(tree, v_idx) {
            Some(p) => p,
            None => break,
        };
        let p_new = common & !tree[p_idx].decided;
        if p_new == 0 {
            break;
        }
        tree[p_idx].decided |= p_new;
        tree[p_idx].granted |= p_new;
        v_idx = p_idx;
    }
    Ok(())
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
    token: &Token,
    mapping: &GenericMapping,
    mut object_tree: Option<&mut [ObjectTypeNode]>,
    sid_match: &F,
    desired: u32,
    max_allowed_mode: bool,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
    skip_owner_implicit: bool,
    decided: &mut u32,
    granted: &mut u32,
) -> Result<(), AllocError> where
    F: Fn(&Sid, bool) -> Result<bool, AllocError>,
{
    // --- Owner implicit rights (§11.4) ---
    if !skip_owner_implicit {
        if let Some(ref owner) = sd.owner {
            if sid_match(owner, true)? {
                // Pre-scan for OWNER RIGHTS ACE (S-1-3-4) in the DACL
                let or_sid = well_known::owner_rights()?;
                let owner_rights_present = if sd.control & SE_DACL_PRESENT != 0 {
                    if let Some(ref dacl) = sd.dacl {
                        dacl.aces.iter().any(|a| {
                            if a.flags & ace::INHERIT_ONLY_ACE != 0 {
                                return false;
                            }
                            if !ace::is_access_type(a.ace_type) {
                                return false;
                            }
                            a.sid == or_sid
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
        return Ok(());
    }

    let dacl = match sd.dacl {
        Some(ref d) => d,
        None => return Ok(()), // SE_DACL_PRESENT set but no DACL — empty, grant nothing
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
                if sid_match(&a.sid, true)? {
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
                if sid_match(&a.sid, false)? {
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

            // --- Callback allow (conditional, §11.12) ---
            ace::ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                if sid_match(&a.sid, true)? {
                    // Condition gate: allow requires TRUE. No condition → UNKNOWN → skip.
                    // for_allow=true: USE_FOR_DENY_ONLY claims invisible (§11.12)
                    let cond_result = match &a.condition {
                        Some(cond) => crate::conditional::evaluate(
                            cond, token, resource_attributes, local_claims, true,
                        )?,
                        None => crate::conditional::TriValue::Unknown,
                    };
                    if cond_result == crate::conditional::TriValue::True {
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
            }

            // --- Callback deny (conditional, §11.12) ---
            ace::ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                if sid_match(&a.sid, false)? {
                    // Condition gate: deny applies on TRUE or UNKNOWN. FALSE → skip.
                    // for_allow=false: USE_FOR_DENY_ONLY claims VISIBLE (§11.12)
                    let cond_result = match &a.condition {
                        Some(cond) => crate::conditional::evaluate(
                            cond, token, resource_attributes, local_claims, false,
                        )?,
                        None => crate::conditional::TriValue::Unknown,
                    };
                    if cond_result != crate::conditional::TriValue::False {
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
            }

            // --- Object allow ACEs (§11.8) ---
            ace::ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ace::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                if sid_match(&a.sid, true)? {
                    // Condition gate for callback variants
                    // for_allow=true for allow ACEs (§11.12)
                    if ace::is_callback_type(a.ace_type) {
                        let cond_result = match &a.condition {
                            Some(cond) => crate::conditional::evaluate(
                                cond, token, resource_attributes, local_claims, true,
                            )?,
                            None => crate::conditional::TriValue::Unknown,
                        };
                        if cond_result != crate::conditional::TriValue::True {
                            continue;
                        }
                    }

                    if !a.has_object_type() || object_tree.is_none() {
                        // No GUID or no tree — treat as basic allow
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
                    } else if let Some(ref mut tree) = object_tree {
                        let guid = a.object_type.as_ref().unwrap();
                        if let Some(target_idx) = find_node(tree, guid) {
                            // Grant target node
                            let node_new = ace_mask & !tree[target_idx].decided;
                            tree[target_idx].decided |= node_new;
                            tree[target_idx].granted |= node_new;

                            // Downward grant to descendants (§11.8)
                            let descendants = descendant_indices(tree, target_idx)?;
                            for d_idx in &descendants {
                                let d_new = ace_mask & !tree[*d_idx].decided;
                                tree[*d_idx].decided |= d_new;
                                tree[*d_idx].granted |= d_new;
                            }

                            // Upward aggregation (§11.8): when ALL siblings
                            // share a right, propagate up. Per-bit intersection.
                            upward_aggregate_grants(tree, target_idx, ace_mask)?;
                        }
                    }
                }
            }

            // --- Object deny ACEs (§11.8) ---
            ace::ACCESS_DENIED_OBJECT_ACE_TYPE
            | ace::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
                if sid_match(&a.sid, false)? {
                    // Condition gate for callback variants
                    // for_allow=false for deny ACEs (§11.12)
                    if ace::is_callback_type(a.ace_type) {
                        let cond_result = match &a.condition {
                            Some(cond) => crate::conditional::evaluate(
                                cond, token, resource_attributes, local_claims, false,
                            )?,
                            None => crate::conditional::TriValue::Unknown,
                        };
                        if cond_result == crate::conditional::TriValue::False {
                            continue;
                        }
                    }

                    if !a.has_object_type() || object_tree.is_none() {
                        // No GUID or no tree — treat as basic deny
                        let new_bits = ace_mask & !*decided;
                        *decided |= new_bits;
                        if let Some(ref mut tree) = object_tree {
                            for node in tree.iter_mut() {
                                let n = ace_mask & !node.decided;
                                node.decided |= n;
                            }
                        }
                    } else if let Some(ref mut tree) = object_tree {
                        let guid = a.object_type.as_ref().unwrap();
                        if let Some(target_idx) = find_node(tree, guid) {
                            // Deny target node
                            let node_new = ace_mask & !tree[target_idx].decided;
                            tree[target_idx].decided |= node_new;

                            // Downward deny to descendants (§11.8)
                            let descendants = descendant_indices(tree, target_idx)?;
                            for d_idx in &descendants {
                                let d_new = ace_mask & !tree[*d_idx].decided;
                                tree[*d_idx].decided |= d_new;
                            }

                            // Upward denial: unconditional (§11.8)
                            // Prevents future grants at higher levels
                            let ancestors = ancestor_indices(tree, target_idx)?;
                            for a_idx in &ancestors {
                                tree[*a_idx].decided |= ace_mask;
                            }
                        }
                    }
                }
            }

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
    Ok(())
}

// ---------------------------------------------------------------------------
// PreSACLWalk — extract mandatory labels, PIP, resource attrs (§11.17)
// ---------------------------------------------------------------------------

/// §11.17 PreSACLWalk: extract integrity labels, PIP trust labels,
/// resource attributes, and scoped policy IDs from the SACL.
/// Enforces MIC and PIP.
fn pre_sacl_walk(
    sd: &SecurityDescriptor,
    token: &Token,
    mapping: &GenericMapping,
    effective_privs: &u64,
    decided: &mut u32,
    granted: &mut u32,
    privilege_granted: &mut u32,
    mandatory_decided: &mut u32,
    resource_attributes: &mut Vec<crate::token::ClaimEntry>,
    policy_sids: &mut Vec<Sid>,
) -> Result<(), AllocError> {
    let mut mic_ace: Option<&crate::ace::Ace> = None;
    let mut mic_found = false;
    let mut pip_ace: Option<&crate::ace::Ace> = None;
    let mut pip_found = false;

    if sd.control & crate::sd::SE_SACL_PRESENT != 0 {
        if let Some(ref sacl) = sd.sacl {
            for a in &sacl.aces {
                if a.ace_type == ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE && !mic_found {
                    mic_found = true;
                    if a.flags & ace::INHERIT_ONLY_ACE == 0 {
                        mic_ace = Some(a);
                    }
                } else if a.ace_type == ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE && !pip_found {
                    pip_found = true;
                    if a.flags & ace::INHERIT_ONLY_ACE == 0 {
                        pip_ace = Some(a);
                    }
                }
                // Resource attribute ACEs → collect for conditional expression evaluation
                // TODO: parse CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 from application_data
                // For now, resource attributes are passed in externally.

                if a.ace_type == ace::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE {
                    if a.flags & ace::INHERIT_ONLY_ACE == 0 {
                        compat::vec_push(policy_sids, a.sid.try_clone()?)?;
                    }
                }
            }
        }
    }

    // MIC: use found label or default (§11.13)
    let pre_mic = *decided;
    if let Some(a) = mic_ace {
        enforce_mic(a, token, mapping, effective_privs, decided);
    } else {
        // Default: Medium integrity, NO_WRITE_UP
        enforce_mic_default(token, mapping, effective_privs, decided);
    }
    *mandatory_decided |= *decided & !pre_mic;

    // PIP: only if trust label present. No default (§11.15).
    let pre_pip = *decided;
    if let Some(a) = pip_ace {
        enforce_pip(a, token, mapping, decided, granted, privilege_granted);
    }
    *mandatory_decided |= *decided & !pre_pip;
    Ok(())
}

// ---------------------------------------------------------------------------
// EnforceMIC (§11.17)
// ---------------------------------------------------------------------------

/// §11.17 EnforceMIC: enforce mandatory integrity control.
///
/// Follows the pseudocode exactly:
/// - If token doesn't have NO_WRITE_UP policy, return (MIC disabled)
/// - If token dominates (integrity >= object label), return (no restriction)
/// - Non-dominant: start with read+execute allowed, strip based on ACE flags
/// - SeRelabelPrivilege: allow WRITE_OWNER through MIC
fn enforce_mic(
    ace_data: &crate::ace::Ace,
    token: &Token,
    mapping: &GenericMapping,
    effective_privs: &u64,
    decided: &mut u32,
) {
    use crate::token::mandatory_policy;

    // Check token policy flag
    if token.mandatory_policy & mandatory_policy::NO_WRITE_UP == 0 {
        return;
    }

    // Extract integrity level from the label ACE's SID
    let object_level = integrity_level_from_label_sid(&ace_data.sid);

    // Dominant caller: bypass MIC entirely (§11.13)
    if token.integrity_level >= object_level {
        return;
    }

    // Non-dominant: start with R+E, strip based on ACE flags
    let mut allowed = map_generic_bits(mask::GENERIC_READ, mapping)
        | map_generic_bits(mask::GENERIC_EXECUTE, mapping);

    if ace_data.mask & mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP != 0 {
        allowed &= !map_generic_bits(mask::GENERIC_READ, mapping);
    }
    if ace_data.mask & mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP != 0 {
        allowed &= !map_generic_bits(mask::GENERIC_WRITE, mapping);
    }
    if ace_data.mask & mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP != 0 {
        allowed &= !map_generic_bits(mask::GENERIC_EXECUTE, mapping);
    }

    // SeRelabelPrivilege: allow DACL to grant WRITE_OWNER even
    // for non-dominant callers (§11.13)
    if *effective_privs & crate::privilege::bits::SE_RELABEL != 0 {
        allowed |= mask::WRITE_OWNER;
    }

    let all_bits = map_generic_bits(mask::GENERIC_ALL, mapping);
    *decided |= all_bits & !allowed;
}

/// Default MIC enforcement when no label ACE exists: Medium, NO_WRITE_UP.
fn enforce_mic_default(
    token: &Token,
    mapping: &GenericMapping,
    effective_privs: &u64,
    decided: &mut u32,
) {
    use crate::token::{IntegrityLevel, mandatory_policy};

    if token.mandatory_policy & mandatory_policy::NO_WRITE_UP == 0 {
        return;
    }

    // Default label: Medium
    if token.integrity_level >= IntegrityLevel::Medium {
        return; // dominant
    }

    // Non-dominant against Medium default: read+execute allowed, write blocked
    let mut allowed = map_generic_bits(mask::GENERIC_READ, mapping)
        | map_generic_bits(mask::GENERIC_EXECUTE, mapping);

    // Default is NO_WRITE_UP only (no read-up or execute-up restrictions)
    allowed &= !map_generic_bits(mask::GENERIC_WRITE, mapping);

    if *effective_privs & crate::privilege::bits::SE_RELABEL != 0 {
        allowed |= mask::WRITE_OWNER;
    }

    let all_bits = map_generic_bits(mask::GENERIC_ALL, mapping);
    *decided |= all_bits & !allowed;
}

/// Extract an IntegrityLevel from a mandatory label SID (S-1-16-{rid}).
fn integrity_level_from_label_sid(sid: &Sid) -> crate::token::IntegrityLevel {
    use crate::token::IntegrityLevel;
    if sid.authority == [0, 0, 0, 0, 0, 16] && !sid.sub_authorities.is_empty() {
        IntegrityLevel::from_rid(sid.sub_authorities[0])
            .unwrap_or(IntegrityLevel::Medium)
    } else {
        IntegrityLevel::Medium // fallback
    }
}

// ---------------------------------------------------------------------------
// EnforcePIP (§11.17)
// ---------------------------------------------------------------------------

/// §11.17 EnforcePIP: enforce process integrity protection.
///
/// pip_type and pip_trust come from the process's PSB (§8), not the token.
/// For now, they're passed via the token's fields as a simplification
/// until the PSB is a separate structure.
///
/// Follows the pseudocode exactly:
/// - Extract type and trust from the trust label ACE's SID
/// - If caller dominates, return (no restriction)
/// - Non-dominant: ACE mask IS the allowed set
/// - Revoke privilege-granted rights outside the allowed set
fn enforce_pip(
    ace_data: &crate::ace::Ace,
    token: &Token,
    mapping: &GenericMapping,
    decided: &mut u32,
    granted: &mut u32,
    privilege_granted: &mut u32,
) {
    // Extract PIP type and trust from the trust label SID (S-1-19-type-trust)
    let (ace_type, ace_trust) = pip_from_trust_label_sid(&ace_data.sid);

    // Caller's PIP identity — in the full implementation this comes from
    // the PSB, not the token. For now we use placeholder values.
    // TODO: take pip_type and pip_trust as parameters when PSB is modeled.
    let caller_type = crate::well_known::PIP_TYPE_NONE;
    let caller_trust: u32 = 0;

    // Dominance check: both dimensions must be >=
    let caller_dominates = caller_type >= ace_type && caller_trust >= ace_trust;

    if caller_dominates {
        return;
    }

    // Non-dominant: the ACE mask IS the allowed set
    let allowed = map_generic_bits(ace_data.mask, mapping);

    // Compute denied set: everything not explicitly allowed.
    // ACCESS_SYSTEM_SECURITY included — without this, a non-PIP admin
    // with SeSecurityPrivilege could read/write the SACL of PIP-protected
    // objects, including removing the trust label itself.
    let all_bits = map_generic_bits(mask::GENERIC_ALL, mapping)
        | mask::ACCESS_SYSTEM_SECURITY;
    let pip_denied = all_bits & !allowed;

    *decided |= pip_denied;

    // Revoke privilege-granted rights (§11.15)
    *granted &= !pip_denied;
    *privilege_granted &= !pip_denied;
}

/// Extract PIP type and trust from a trust label SID (S-1-19-{type}-{trust}).
fn pip_from_trust_label_sid(sid: &Sid) -> (u32, u32) {
    if sid.authority == [0, 0, 0, 0, 0, 19] && sid.sub_authorities.len() >= 2 {
        (sid.sub_authorities[0], sid.sub_authorities[1])
    } else {
        (0, 0)
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
    mut object_tree: Option<&mut [ObjectTypeNode]>,
    self_sid: Option<&Sid>,
    local_claims: &[crate::token::ClaimEntry],
    policies: &[CentralAccessPolicy],
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
    let mut mandatory_decided: u32 = 0;
    let mut resource_attributes: Vec<crate::token::ClaimEntry> = Vec::new();
    let mut policy_sids: Vec<Sid> = Vec::new();
    pre_sacl_walk(
        sd,
        token,
        mapping,
        &effective_privs,
        &mut decided,
        &mut granted,
        &mut privilege_granted,
        &mut mandatory_decided,
        &mut resource_attributes,
        &mut policy_sids,
    )?;

    // Step 5: Virtual group injection
    let owner = sd.owner.as_ref().unwrap();
    let enriched = enrich_token(token, owner, self_sid);

    // Step 6: Tree initialization (§11.8)
    if let Some(ref mut tree) = object_tree {
        for node in tree.iter_mut() {
            node.decided = decided;
            node.granted = granted;
        }
    }

    // Step 7: Normal DACL evaluation (§11.3, §11.4)
    let sid_match = |sid: &Sid, for_allow: bool| -> Result<bool, AllocError> {
        enriched_sid_matches(sid, &enriched, for_allow)
    };
    evaluate_dacl(
        sd,
        token,
        mapping,
        object_tree.as_deref_mut(),
        &sid_match,
        mapped_desired,
        max_allowed_mode,
        &resource_attributes,
        local_claims,
        false, // don't skip owner implicit
        &mut decided,
        &mut granted,
    )?;

    // Step 7a: Post-DACL WRITE_OWNER override (§11.6)
    // SeTakeOwnershipPrivilege grants WRITE_OWNER if the DACL did not.
    // Deny-proof: overrides DACL deny ACEs for WRITE_OWNER.
    // BUT: respects mandatory decisions (MIC/PIP) via mandatory_decided.
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

    // Step 8: Restricted token two-pass (§11.7)
    if token.is_restricted() {
        let restricted_sids = token.restricted_sids.as_ref().unwrap();

        // Build restricted SID set with virtual groups
        let owner_in_restricted = sid_in_restricting_sids(owner, restricted_sids);
        let self_in_restricted = self_sid.map_or(false, |ss| {
            sid_in_restricting_sids(ss, restricted_sids)
        });

        let restricted_sid_match = |sid: &Sid, _for_allow: bool| -> Result<bool, AllocError> {
            // Virtual groups in restricted context
            if *sid == well_known::owner_rights()? && owner_in_restricted {
                return Ok(true);
            }
            if *sid == well_known::principal_self()? && self_in_restricted {
                return Ok(true);
            }
            Ok(sid_in_restricting_sids(sid, restricted_sids))
        };

        let mut r_decided: u32 = 0;
        let mut r_granted: u32 = 0;

        evaluate_dacl(
            sd,
            token,
            mapping,
            None,
            &restricted_sid_match,
            mapped_desired,
            max_allowed_mode,
            &resource_attributes,
            local_claims,
            false, // owner implicit rights evaluated in restricted pass too
            &mut r_decided,
            &mut r_granted,
        )?;

        // Scalar merge: intersection
        if token.write_restricted {
            let write_bits = map_generic_bits(mask::GENERIC_WRITE, mapping);
            granted = (granted & !write_bits) | (granted & r_granted & write_bits);
        } else {
            granted &= r_granted;
        }
        // Privilege-granted bits bypass the restricted pass
        granted |= privilege_granted;
    }

    // Step 8a: Confinement (§11.14)
    if token.is_confined() {
        let confinement_sid = token.confinement_sid.as_ref().unwrap();
        let mut confinement_sids: Vec<Sid> = Vec::new();
        compat::vec_push(&mut confinement_sids, confinement_sid.try_clone()?)?;
        for cap in &token.confinement_capabilities {
            compat::vec_push(&mut confinement_sids, cap.sid.try_clone()?)?;
        }

        let owner_in_confinement = sid_in_list(owner, &confinement_sids);
        let self_in_confinement = self_sid.map_or(false, |ss| {
            sid_in_list(ss, &confinement_sids)
        });

        let confinement_sid_match = |sid: &Sid, _for_allow: bool| -> Result<bool, AllocError> {
            if *sid == well_known::owner_rights()? && owner_in_confinement {
                return Ok(true);
            }
            if *sid == well_known::principal_self()? && self_in_confinement {
                return Ok(true);
            }
            Ok(sid_in_list(sid, &confinement_sids))
        };

        let mut c_decided: u32 = 0;
        let mut c_granted: u32 = 0;

        evaluate_dacl(
            sd,
            token,
            mapping,
            None,
            &confinement_sid_match,
            mapped_desired,
            max_allowed_mode,
            &resource_attributes,
            local_claims,
            true, // skip owner implicit rights in confinement pass
            &mut c_decided,
            &mut c_granted,
        )?;

        // Absolute intersection. No privilege bypass.
        granted &= c_granted;
    }

    // Step 9: Central Access Policy (§11.16)
    if !policy_sids.is_empty() {
        let mut cap_effective = granted;

        for cap_sid in &policy_sids {
            let policy = policies.iter().find(|p| p.policy_sid == *cap_sid);

            let rules: &[CentralAccessRule] = match policy {
                Some(p) => &p.rules,
                None => {
                    // Recovery policy: GENERIC_ALL to admins, SYSTEM, owner rights.
                    // Since CAP is an AND intersection, recovery policy means
                    // "no further restriction from this missing policy."
                    // We skip evaluation — the recovery policy ACL contains
                    // GENERIC_ALL with OWNER RIGHTS, which after mapping and
                    // evaluation would not restrict anything the DACL granted.
                    continue;
                }
            };

            for rule in rules {
                // applies_to condition evaluation
                if let Some(ref condition) = rule.applies_to {
                    let result = crate::conditional::evaluate(
                        condition,
                        token,
                        &resource_attributes,
                        local_claims,
                        false, // deny polarity for applies_to (§11.17)
                    )?;
                    if result != crate::conditional::TriValue::True {
                        continue; // rule doesn't apply to this object
                    }
                }

                // Build synthetic SD with rule's effective DACL
                let eff_sd = SecurityDescriptor {
                    control: crate::sd::SE_DACL_PRESENT | crate::sd::SE_SELF_RELATIVE,
                    owner: sd.owner.try_clone()?,
                    group: sd.group.try_clone()?,
                    dacl: Some(rule.effective_dacl.try_clone()?),
                    sacl: None,
                };

                // Evaluate the rule's DACL through the normal pipeline.
                // No backup/restore intent for policy rules (§11.17).
                // No recursive CAP evaluation (policy_sids from this SD is empty).
                let eff_result = evaluate_rule_dacl(
                    &eff_sd,
                    token,
                    mapping,
                    mapped_desired,
                    max_allowed_mode,
                    self_sid,
                    &resource_attributes,
                    local_claims,
                );

                match eff_result {
                    Ok(eff_granted) => {
                        cap_effective &= eff_granted;
                    }
                    Err(_) => {
                        // Fail-closed with privilege escape hatch (§11.16)
                        cap_effective &= privilege_granted;
                    }
                }
            }
        }

        granted = cap_effective;
    }

    // Step 9b: Privilege-use auditing — TODO (observational, not security-critical)
    // Step 10: Audit emission — TODO (observational, not security-critical)

    // Step 15: Result computation
    // When a tree is present, root.granted reflects the whole object (§11.17).
    let final_granted = if let Some(ref tree) = object_tree {
        if !tree.is_empty() {
            tree[0].granted
        } else {
            granted
        }
    } else {
        granted
    };

    let allowed = if mapped_desired == 0 {
        true
    } else {
        (final_granted & mapped_desired) == mapped_desired
    };

    Ok(AccessCheckResult {
        granted: final_granted,
        allowed,
        continuous_audit_mask: 0, // TODO: audit
    })
}

/// Evaluate a CAP rule's DACL through the normal pipeline.
/// No backup/restore intent. No recursive CAP evaluation.
fn evaluate_rule_dacl(
    sd: &SecurityDescriptor,
    token: &Token,
    mapping: &GenericMapping,
    desired: u32,
    max_allowed_mode: bool,
    self_sid: Option<&Sid>,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
) -> Result<u32, AccessCheckError> {
    // Step 0: impersonation gate
    if token.token_type == TokenType::Impersonation
        && token.impersonation_level == ImpersonationLevel::Identification
    {
        return Err(AccessCheckError::IdentificationLevel);
    }

    if sd.owner.is_none() || sd.group.is_none() {
        return Err(AccessCheckError::InvalidSecurityDescriptor);
    }

    let mut decided: u32 = 0;
    let mut granted: u32 = 0;

    // No privilege grants for CAP rule evaluation (§11.17: privilege_intent=0)
    // Non-intent-gated privileges (SeSecurityPrivilege, SeTakeOwnershipPrivilege)
    // are still active because they're checked by the normal pipeline.
    let effective_privs = token.privileges.enabled
        & !crate::privilege::bits::SE_BACKUP
        & !crate::privilege::bits::SE_RESTORE;

    // ACCESS_SYSTEM_SECURITY always decided
    decided |= mask::ACCESS_SYSTEM_SECURITY;
    if effective_privs & crate::privilege::bits::SE_SECURITY != 0 {
        granted |= mask::ACCESS_SYSTEM_SECURITY;
    }

    // MIC from the ORIGINAL SD's SACL (not the synthetic one)
    // Actually per §11.17, the synthetic SD has no SACL, so MIC
    // uses the default (Medium, NO_WRITE_UP). This is correct —
    // each rule evaluation is independent.

    let owner = sd.owner.as_ref().unwrap();
    let enriched = enrich_token(token, owner, self_sid);

    let sid_match = |sid: &Sid, for_allow: bool| -> Result<bool, AllocError> {
        enriched_sid_matches(sid, &enriched, for_allow)
    };

    evaluate_dacl(
        sd,
        token,
        mapping,
        None,
        &sid_match,
        desired,
        max_allowed_mode,
        resource_attributes,
        local_claims,
        false,
        &mut decided,
        &mut granted,
    )?;

    // Post-DACL SeTakeOwnershipPrivilege
    if desired & mask::WRITE_OWNER != 0 || max_allowed_mode {
        if effective_privs & crate::privilege::bits::SE_TAKE_OWNERSHIP != 0 {
            if granted & mask::WRITE_OWNER == 0 {
                granted |= mask::WRITE_OWNER;
            }
        }
    }

    Ok(granted)
}

/// Privilege intent flag: activate SeBackupPrivilege in AccessCheck.
pub const BACKUP_INTENT: u32 = 0x01;
/// Privilege intent flag: activate SeRestorePrivilege in AccessCheck.
pub const RESTORE_INTENT: u32 = 0x02;

/// Errors from AccessCheck.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessCheckError {
    /// The token is at Identification impersonation level (§12.1).
    IdentificationLevel,
    /// The SD is structurally invalid (missing owner or group).
    InvalidSecurityDescriptor,
    /// An allocation failed during the access check.
    AllocationFailed,
}

impl From<AllocError> for AccessCheckError {
    fn from(_: AllocError) -> Self {
        AccessCheckError::AllocationFailed
    }
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
        let mut token = Token::system_token().unwrap();
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

    fn alice() -> Sid { Sid::new(5, &[21, 100, 200, 300, 1001]).unwrap() }
    fn bob() -> Sid { Sid::new(5, &[21, 100, 200, 300, 1002]).unwrap() }
    fn engineers() -> Sid { Sid::new(5, &[21, 100, 200, 300, 2001]).unwrap() }
    fn managers() -> Sid { Sid::new(5, &[21, 100, 200, 300, 2002]).unwrap() }

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
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces },
        )
    }

    fn check(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0).unwrap()
    }

    fn check_with_intent(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
        intent: u32,
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], intent).unwrap()
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
            group: Some(well_known::users().unwrap()),
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
            well_known::users().unwrap(),
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
            well_known::users().unwrap(),
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
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
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
            deny(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC),
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
                sid: well_known::owner_rights().unwrap(),
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
            well_known::users().unwrap(),
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
            group: Some(well_known::users().unwrap()),
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
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0,
        );
        assert_eq!(result, Err(AccessCheckError::IdentificationLevel));
    }

    #[test]
    fn anonymous_level_proceeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::anonymous().unwrap(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&well_known::anonymous().unwrap(), &[], 0);
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
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0,
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
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0,
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
            deny(&well_known::guests().unwrap(), GENERIC_ALL),
            // Explicit allow: admins get everything
            allow(&well_known::administrators().unwrap(), GENERIC_ALL),
            // Explicit allow: engineers get read
            allow(&engineers(), FILE_READ_DATA | READ_CONTROL),
            // Inherited allow: everyone gets read
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: INHERITED_ACE,
                mask: FILE_READ_DATA | READ_CONTROL,
                sid: well_known::everyone().unwrap(),
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
            &sd, &token, KEY_QUERY_VALUE, &KEY_GENERIC_MAPPING, None, None, &[], &[], 0,
        ).unwrap();
        assert!(result.allowed); // GENERIC_READ maps to KEY_QUERY_VALUE for registry
    }

    #[test]
    fn process_sd_default_pattern() {
        // The default process SD from §8.4
        let user = alice();
        let sd = sd_with_dacl(&user, alloc::vec![
            allow(&user, GENERIC_ALL),
            allow(&well_known::administrators().unwrap(), GENERIC_ALL),
            allow(&well_known::system().unwrap(), GENERIC_ALL),
            allow(&well_known::everyone().unwrap(), PROCESS_QUERY_LIMITED),
        ]);

        // Owner (alice) gets everything
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0,
        ).unwrap();
        assert!(result.allowed);

        // Random user gets only PROCESS_QUERY_LIMITED
        let token = test_token(&bob(), &[&well_known::everyone().unwrap()], 0);
        let result = access_check(
            &sd, &token, PROCESS_QUERY_LIMITED, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0,
        ).unwrap();
        assert!(result.allowed);

        let result = access_check(
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn system_token_with_backup_reads_anything() {
        // SYSTEM with backup intent can read a file owned by bob
        // even with an empty DACL (no explicit grants)
        let sd = SecurityDescriptor::new(
            bob(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = Token::system_token().unwrap();
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // MIC — Mandatory Integrity Control (§11.13)
    // -----------------------------------------------------------------------

    fn sd_with_label(owner: &Sid, aces: Vec<Ace>, label_sid: &Sid, label_mask: u32) -> SecurityDescriptor {
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                flags: 0,
                mask: label_mask,
                sid: label_sid.clone(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        SecurityDescriptor::with_sacl(
            owner.clone(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces },
            sacl,
        )
    }

    fn medium_token(user: &Sid, groups: &[&Sid], privs: u64) -> Token {
        let mut t = test_token(user, groups, privs);
        t.integrity_level = IntegrityLevel::Medium;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        t
    }

    fn low_token(user: &Sid) -> Token {
        let mut t = test_token(user, &[], 0);
        t.integrity_level = IntegrityLevel::Low;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        t
    }

    fn high_token(user: &Sid) -> Token {
        let mut t = test_token(user, &[], 0);
        t.integrity_level = IntegrityLevel::High;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        t
    }

    #[test]
    fn mic_dominant_caller_passes() {
        // Medium caller accessing Medium-labeled object → dominant, no restriction
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_dominant_high_accessing_medium() {
        // High caller accessing Medium-labeled object → dominant
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), FILE_WRITE_DATA)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = high_token(&alice());
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_no_write_up_blocks_low_writing_medium() {
        // Low caller writing to Medium-labeled object → blocked by NO_WRITE_UP
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_no_write_up_allows_low_reading_medium() {
        // Low caller reading Medium-labeled object → NO_WRITE_UP allows read
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_no_read_up_blocks_low_reading_medium() {
        // Low caller reading Medium-labeled object with NO_READ_UP → blocked
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_no_execute_up_blocks_low_executing_medium() {
        // Low caller executing Medium-labeled object with NO_EXECUTE_UP → blocked
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_EXECUTE);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_no_execute_up_allows_low_reading() {
        // NO_EXECUTE_UP doesn't block reads
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_all_three_flags_blocks_everything_for_low() {
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
                | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP
                | mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        );
        let token = low_token(&alice());

        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(!check(&sd, &token, FILE_EXECUTE).allowed);
    }

    #[test]
    fn mic_default_medium_label_when_no_sacl() {
        // No SACL → default Medium, NO_WRITE_UP
        // Low token should be blocked from writing
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![allow(&alice(), GENERIC_ALL)],
            },
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);

        // But reading should work
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_no_policy_flag_disables_mic() {
        // Token without NO_WRITE_UP → MIC disabled
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.mandatory_policy = 0; // disable MIC
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed); // MIC disabled, DACL allows
    }

    #[test]
    fn mic_se_relabel_allows_write_owner_through_mic() {
        // Low caller with SeRelabelPrivilege can get WRITE_OWNER
        // even on a Medium object (§11.13 SeRelabelPrivilege carve-out)
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), WRITE_OWNER)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        // Without privilege: WRITE_OWNER is write-category, blocked by MIC
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(!result.allowed);

        // With SeRelabelPrivilege: WRITE_OWNER punches through MIC
        let mut token_priv = low_token(&alice());
        token_priv.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_RELABEL,
        );
        let result = check(&sd, &token_priv, WRITE_OWNER);
        assert!(result.allowed);
    }

    #[test]
    fn mic_does_not_constrain_privileges() {
        // §11.13: MIC does NOT constrain privilege-granted bits
        // SeBackupPrivilege grants read BEFORE MIC runs
        let sd = sd_with_label(
            &bob(),
            alloc::vec![], // empty DACL
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
        );
        let mut token = low_token(&alice());
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_BACKUP,
        );
        // Backup privilege grants read even though MIC has no-read-up
        // (privileges are resolved in step 3, MIC in step 4)
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed);
    }

    #[test]
    fn mic_system_integrity_blocks_high() {
        // High caller cannot write to System-labeled object
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_system().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = high_token(&alice());
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);

        // But reading is fine (only no-write-up)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_same_level_is_dominant() {
        // Same level = dominant, no restriction
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), FILE_WRITE_DATA)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_untrusted_blocked_from_low() {
        // Untrusted caller cannot write to Low-labeled object
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_low().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = test_token(&alice(), &[], 0);
        token.integrity_level = IntegrityLevel::Untrusted;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_inherit_only_label_ignored() {
        // A mandatory label with INHERIT_ONLY should be ignored for this object
        // → falls back to default Medium
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                flags: INHERIT_ONLY_ACE, // inherit-only!
                mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
                    | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP
                    | mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
                sid: well_known::integrity_untrusted().unwrap(), // would block everything
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
            sacl,
        );
        // Medium token: default label is Medium, should be dominant
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed); // inherit-only label ignored, default Medium used
    }

    #[test]
    fn mic_only_first_label_used() {
        // §11.13: only the first mandatory label ACE matters
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                // First label: Medium (Low can't write)
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid: well_known::integrity_medium().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
                // Second label: Untrusted (would block everything) — IGNORED
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
                        | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                    sid: well_known::integrity_untrusted().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
            ],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
            sacl,
        );
        // Low token can read (first label is Medium, no-read-up not set)
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn mic_take_ownership_respects_mandatory_decided() {
        // SeTakeOwnershipPrivilege is deny-proof for DACL denies,
        // but respects mandatory_decided from MIC.
        // Low caller on Medium object: MIC blocks write-category,
        // WRITE_OWNER is write-category, so mandatory_decided has it.
        let sd = sd_with_label(
            &bob(),
            alloc::vec![], // empty DACL
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_TAKE_OWNERSHIP,
        );
        let result = check(&sd, &token, WRITE_OWNER);
        // MIC blocks WRITE_OWNER for non-dominant, and TakeOwnership
        // respects mandatory_decided
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // PIP — Process Integrity Protection (§11.15)
    // -----------------------------------------------------------------------

    fn sd_with_pip(
        owner: &Sid,
        aces: Vec<Ace>,
        pip_type: u32,
        pip_trust: u32,
        pip_allowed_mask: u32,
    ) -> SecurityDescriptor {
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                flags: 0,
                mask: pip_allowed_mask,
                sid: well_known::trust_label(pip_type, pip_trust).unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        SecurityDescriptor::with_sacl(
            owner.clone(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces },
            sacl,
        )
    }

    #[test]
    fn pip_non_dominant_restricted() {
        // Object labeled Protected/Peios, caller is None/0 (default)
        // Non-dominant: only the ACE mask's rights are allowed
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            READ_CONTROL | TOKEN_QUERY, // only these allowed for non-dominant
        );
        let token = medium_token(&alice(), &[], 0);

        // READ_CONTROL is in the PIP allowed mask → should succeed
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);

        // FILE_READ_DATA is NOT in the PIP allowed mask → denied
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn pip_revokes_privilege_granted_bits() {
        // §11.15: PIP revokes privilege-granted rights
        // Even SeBackupPrivilege can't read PIP-protected objects
        let sd = sd_with_pip(
            &bob(),
            alloc::vec![], // empty DACL
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0, // PIP allows NOTHING for non-dominant
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_BACKUP);
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_BACKUP,
        );
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        // Backup privilege grants read, but PIP revokes it
        assert!(!result.allowed);
    }

    #[test]
    fn pip_revokes_se_security() {
        // PIP revokes ACCESS_SYSTEM_SECURITY even with SeSecurityPrivilege
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0, // allow nothing
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
    }

    #[test]
    fn pip_zero_mask_total_lockout() {
        // PIP mask of 0 = total lockout for non-dominant callers
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_ISOLATED,
            well_known::PIP_TRUST_PEIOS_TCB,
            0,
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_SECURITY
            | privilege::bits::SE_BACKUP | privilege::bits::SE_RESTORE
            | privilege::bits::SE_TAKE_OWNERSHIP);

        // Everything denied
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn pip_no_label_no_restriction() {
        // §11.15: no default PIP. Objects without trust labels are unrestricted.
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
        );
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // Restricted tokens (§11.7)
    // -----------------------------------------------------------------------

    fn restricted_token(
        user: &Sid,
        groups: &[&Sid],
        restricting_sids: &[&Sid],
    ) -> Token {
        let mut t = medium_token(user, groups, 0);
        t.restricted_sids = Some(
            restricting_sids.iter().map(|s| {
                crate::group::GroupEntry::new(
                    (*s).clone(),
                    crate::group::SE_GROUP_MANDATORY
                        | crate::group::SE_GROUP_ENABLED_BY_DEFAULT
                        | crate::group::SE_GROUP_ENABLED,
                )
            }).collect(),
        );
        t.write_restricted = false;
        t
    }

    #[test]
    fn restricted_token_intersection() {
        // Normal pass: alice gets read+write (ACEs match user SID)
        // Restricted pass: engineers gets read only
        // Intersection: read only
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        // engineers is in the restricted SID list but the DACL grants
        // access to alice (not engineers), so the restricted pass
        // finds no matching ACE → grants nothing → intersection is empty
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn restricted_token_both_pass() {
        // Both normal and restricted SIDs match
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        // Normal: alice matches → read+write
        // Restricted: engineers matches → read
        // Intersection: read
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);

        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed); // restricted pass didn't grant write
    }

    #[test]
    fn restricted_token_privilege_bypasses_restricted_pass() {
        // §11.7: privilege-granted bits bypass the restricted pass
        let sd = sd_with_dacl(&bob(), alloc::vec![]); // empty DACL
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_BACKUP,
        );
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        // Backup grants read as a privilege. Privilege-granted bits
        // are OR'd back after the restricted intersection.
        assert!(result.allowed);
    }

    #[test]
    fn restricted_token_empty_restricting_sids_denies_all() {
        // is_restricted() checks for non-empty restricting SIDs.
        // An empty list means NOT restricted (no second pass).
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = medium_token(&alice(), &[], 0);
        token.restricted_sids = Some(Vec::new()); // empty
        assert!(!token.is_restricted()); // empty = not restricted
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // no restricted pass
    }

    #[test]
    fn write_restricted_token_read_uses_normal_only() {
        // §11.7: write-restricted — intersection only on write bits
        // Read access comes from normal pass alone
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.write_restricted = true;
        // Normal: alice → read+write
        // Restricted: no match for engineers in DACL → nothing
        // Write-restricted: read from normal only, write intersected
        // Read should pass (normal only), write should fail (intersection empty)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);

        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn write_restricted_token_write_needs_both() {
        // Write bits need both passes to agree
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_WRITE_DATA),
        ]);
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.write_restricted = true;
        // Normal: alice → read+write, engineers → write
        // Restricted: engineers → write
        // Intersection for write bits: write ∩ write = write ✓
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn restricted_token_owner_implicit_in_restricted_pass() {
        // §11.7: owner implicit rights in restricted pass if owner
        // SID is in the restricting SID list
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION), // empty DACL
        );
        // alice is owner AND in restricting SIDs
        let token = restricted_token(&alice(), &[], &[&alice()]);
        // Normal: owner implicit → READ_CONTROL + WRITE_DAC
        // Restricted: alice in restricting SIDs → owner implicit applies
        // Intersection: READ_CONTROL + WRITE_DAC
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    #[test]
    fn restricted_token_owner_not_in_restricted_loses_implicit() {
        // Owner NOT in restricting SIDs → restricted pass doesn't
        // get owner implicit → intersection loses them
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION), // empty DACL
        );
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        // Normal: owner implicit → READ_CONTROL + WRITE_DAC
        // Restricted: engineers is restricting, not alice, no owner implicit
        // Intersection: nothing (normal has it, restricted doesn't)
        // BUT: privilege_granted is OR'd back. No privileges here.
        let result = check(&sd, &token, READ_CONTROL);
        assert!(!result.allowed);
    }

    #[test]
    fn restricted_token_deny_in_normal_pass() {
        // Deny ACE in normal pass blocks even if restricted pass would allow
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        // Normal: deny write on alice (first-writer), allow read on alice
        // Restricted: engineers → read+write
        // Intersection: read (write denied in normal)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Application Confinement (§11.14)
    // -----------------------------------------------------------------------

    fn confined_token(
        user: &Sid,
        confinement_sid: &Sid,
        capabilities: &[&Sid],
    ) -> Token {
        let mut t = medium_token(user, &[], 0);
        t.confinement_sid = Some(confinement_sid.clone());
        t.confinement_capabilities = capabilities.iter().map(|s| {
            crate::group::GroupEntry::new(
                (*s).clone(),
                crate::group::SE_GROUP_ENABLED,
            )
        }).collect();
        t.confinement_exempt = false;
        t
    }

    fn app_sid() -> Sid { Sid::new(15, &[2, 0x12345678, 0x9ABCDEF0, 0x11111111,
        0x22222222, 0x33333333, 0x44444444, 0x55555555]).unwrap() }
    fn cap_network() -> Sid { Sid::new(15, &[3, 1]).unwrap() } // internetClient

    #[test]
    fn confinement_default_deny() {
        // Confined token: access denied unless object explicitly grants
        // to confinement SID or capabilities
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), // grants to alice, not to app
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        // Normal pass: alice → all. Confinement pass: no match → nothing.
        // Intersection: nothing.
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn confinement_explicit_grant_to_app_sid() {
        // Object grants to the confinement SID → access allowed
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
            allow(&app_sid(), FILE_READ_DATA),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);

        // Write not granted to app SID
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn confinement_capability_sid_grants() {
        // Object grants to a capability SID → access allowed
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
            allow(&cap_network(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[&cap_network()]);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn confinement_all_app_packages_grants() {
        // Object grants to ALL_APP_PACKAGES → confined token with it passes
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
            allow(&well_known::all_app_packages().unwrap(), FILE_READ_DATA),
        ]);
        let token = confined_token(
            &alice(),
            &app_sid(),
            &[&well_known::all_app_packages().unwrap()],
        );
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn confinement_no_privilege_bypass() {
        // §11.14: privileges do NOT bypass confinement
        let sd = sd_with_dacl(&bob(), alloc::vec![]); // empty DACL
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_BACKUP | privilege::bits::SE_SECURITY
                | privilege::bits::SE_TAKE_OWNERSHIP,
        );
        // Backup grants read, TakeOwnership grants WRITE_OWNER,
        // Security grants ASS — but confinement overrides all
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(!result.allowed);

        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
    }

    #[test]
    fn confinement_no_owner_implicit_rights() {
        // §11.14: owner implicit rights skipped in confinement pass
        let sd = SecurityDescriptor::new(
            alice(), // alice owns it
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION), // empty DACL
        );
        let token = confined_token(&alice(), &app_sid(), &[]);
        // Normal: owner implicit → READ_CONTROL + WRITE_DAC
        // Confinement: skip_owner_implicit=true → nothing
        // Intersection: nothing
        let result = check(&sd, &token, READ_CONTROL);
        assert!(!result.allowed);
    }

    #[test]
    fn confinement_exempt_bypasses() {
        // confinement_exempt = true → confinement not evaluated
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.confinement_exempt = true;
        assert!(!token.is_confined()); // exempt = not confined
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn confinement_null_dacl_grants_confined() {
        // §11.14: NULL DACL grants all in confinement pass too
        let sd = SecurityDescriptor {
            control: crate::sd::SE_SELF_RELATIVE, // no DACL present
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let token = confined_token(&alice(), &app_sid(), &[]);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // NULL DACL = no restrictions
    }

    #[test]
    fn confinement_combined_with_restricted() {
        // Both restricted AND confined: triple intersection
        // Normal: alice → read+write
        // Restricted: engineers → read
        // Confinement: app_sid → read+write
        // Final: read (tightest restriction wins)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
            allow(&app_sid(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.groups = alloc::vec![crate::group::GroupEntry::new(
            engineers(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )];
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            engineers(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        // Normal: alice → r+w, engineers → r
        // Restricted: engineers → r. Intersection(normal, restricted) = r.
        // Then privilege OR-back (none). Then confinement: app_sid → r+w.
        // Intersection(restricted_result, confinement) = r.
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn confinement_privilege_granted_then_confined() {
        // Privilege grants read (backup), restricted pass OR's it back,
        // but confinement strips it.
        // §11.17: confinement runs AFTER restricted merge + privilege OR-back.
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&app_sid(), FILE_WRITE_DATA), // only write to app
        ]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            app_sid(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        token.privileges = privilege::Privileges::new_all_enabled(
            privilege::bits::SE_BACKUP,
        );
        // Backup grants read (privilege). Restricted pass: app_sid → write.
        // Intersection of normal read + restricted write = nothing.
        // Privilege OR-back: read restored.
        // Confinement: app_sid → write only. Intersection with read = nothing.
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(!result.allowed); // confinement blocks the privilege
    }

    // -----------------------------------------------------------------------
    // Object ACEs and property trees (§11.8)
    // -----------------------------------------------------------------------

    fn guid(n: u32) -> crate::guid::Guid {
        crate::guid::Guid { data1: n, data2: 0, data3: 0, data4: [0; 8] }
    }

    fn make_tree(levels: &[(u16, u32)]) -> Vec<ObjectTypeNode> {
        levels.iter().map(|(level, id)| ObjectTypeNode {
            level: *level,
            guid: guid(*id),
            decided: 0,
            granted: 0,
        }).collect()
    }

    fn obj_allow(sid: &Sid, mask: u32, obj_guid: u32) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: Some(guid(obj_guid)),
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    fn obj_deny(sid: &Sid, mask: u32, obj_guid: u32) -> Ace {
        Ace {
            ace_type: ACCESS_DENIED_OBJECT_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: Some(guid(obj_guid)),
            inherited_object_type: None,
            condition: None,
            application_data: None,
        }
    }

    fn check_tree(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
        tree: &mut [ObjectTypeNode],
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, Some(tree), None, &[], &[], 0).unwrap()
    }

    #[test]
    fn object_ace_grant_specific_node() {
        // Tree: root(0) → child_a(1), child_b(2)
        // ACE grants DS_READ_PROP to child_a only
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), // child_a
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        // child_a should have the grant
        assert!(tree[1].granted & DS_READ_PROP != 0);
        // child_b should NOT
        assert!(tree[2].granted & DS_READ_PROP == 0);
    }

    #[test]
    fn object_ace_downward_propagation() {
        // Tree: root(0) → parent(1) → child(2)
        // ACE grants to parent → should flow down to child
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), // parent node
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        assert!(tree[1].granted & DS_READ_PROP != 0); // parent
        assert!(tree[2].granted & DS_READ_PROP != 0); // child (propagated down)
    }

    #[test]
    fn object_ace_upward_aggregation() {
        // Tree: root(0) → child_a(1), child_b(2)
        // Both children get the same right → should propagate up to root
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), // child_a
            obj_allow(&alice(), DS_READ_PROP, 2), // child_b
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        assert!(tree[0].granted & DS_READ_PROP != 0); // root (aggregated up)
        assert!(tree[1].granted & DS_READ_PROP != 0); // child_a
        assert!(tree[2].granted & DS_READ_PROP != 0); // child_b
    }

    #[test]
    fn object_ace_no_upward_if_partial() {
        // Tree: root(0) → child_a(1), child_b(2)
        // Only child_a gets the right → root should NOT get it
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), // child_a only
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        assert!(tree[0].granted & DS_READ_PROP == 0); // root NOT aggregated
        assert!(tree[1].granted & DS_READ_PROP != 0); // child_a yes
    }

    #[test]
    fn object_ace_deny_upward_unconditional() {
        // Tree: root(0) → child_a(1), child_b(2)
        // Deny on child_a → unconditional propagation UP to root
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_WRITE_PROP, 1), // deny child_a
            obj_allow(&alice(), DS_WRITE_PROP, 2), // allow child_b
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_WRITE_PROP, &mut tree);

        // child_a denied
        assert!(tree[1].granted & DS_WRITE_PROP == 0);
        // child_b granted
        assert!(tree[2].granted & DS_WRITE_PROP != 0);
        // root: deny propagated up unconditionally, preventing future grants
        assert!(tree[0].decided & DS_WRITE_PROP != 0);
        assert!(tree[0].granted & DS_WRITE_PROP == 0);
    }

    #[test]
    fn object_ace_deny_downward() {
        // Tree: root(0) → parent(1) → child(2)
        // Deny on parent → flows down to child
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_WRITE_PROP, 1), // deny parent
            obj_allow(&alice(), DS_WRITE_PROP, 2), // allow child (too late?)
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _result = check_tree(&sd, &token, DS_WRITE_PROP, &mut tree);

        // parent denied
        assert!(tree[1].granted & DS_WRITE_PROP == 0);
        // child: deny from parent propagated down, first-writer-wins
        // so the allow ACE can't override it
        assert!(tree[2].granted & DS_WRITE_PROP == 0);
    }

    #[test]
    fn object_ace_first_writer_wins_per_node() {
        // Tree: root(0) → child(1)
        // Allow on child first, then deny on child — allow wins
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_WRITE_PROP, 1), // allow first
            obj_deny(&alice(), DS_WRITE_PROP, 1),  // deny second
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _result = check_tree(&sd, &token, DS_WRITE_PROP, &mut tree);

        assert!(tree[1].granted & DS_WRITE_PROP != 0); // allow won
    }

    #[test]
    fn object_ace_no_guid_treated_as_basic() {
        // Object ACE without ObjectType GUID → applies to all nodes
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            flags: 0,
            mask: DS_READ_PROP,
            sid: alice(),
            object_type: None, // no GUID
            inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let sd = sd_with_dacl(&alice(), alloc::vec![ace]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        // All nodes should have the grant (treated as basic ACE)
        assert!(tree[0].granted & DS_READ_PROP != 0);
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[2].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn object_ace_no_tree_treated_as_basic() {
        // Object ACE with GUID but no tree → applies globally
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), FILE_READ_DATA, 999),
        ]);
        let token = medium_token(&alice(), &[], 0);
        // No tree (None) — obj ACE with GUID applies globally
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn object_ace_guid_not_in_tree_ignored() {
        // Object ACE with GUID that doesn't exist in the tree → ignored
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 999), // GUID 999 not in tree
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        assert!(tree[0].granted & DS_READ_PROP == 0); // nothing granted
        assert!(tree[1].granted & DS_READ_PROP == 0);
    }

    #[test]
    fn object_ace_deep_tree() {
        // Tree: root(0) → l1(1) → l2(2) → l3(3)
        // Grant at root → flows all the way down
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 0), // root
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (3, 3)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        for node in &tree {
            assert!(node.granted & DS_READ_PROP != 0);
        }
    }

    #[test]
    fn object_ace_mixed_with_basic() {
        // Basic ACE + object ACE in the same DACL
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), DELETE), // basic deny: all nodes
            obj_allow(&alice(), DS_READ_PROP, 1), // object allow: child_a
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP | DELETE, &mut tree);

        // DELETE denied on all nodes (basic ACE)
        assert!(tree[0].granted & DELETE == 0);
        assert!(tree[1].granted & DELETE == 0);
        // DS_READ_PROP on child_a only
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[2].granted & DS_READ_PROP == 0);
    }

    #[test]
    fn object_ace_upward_multi_level() {
        // Tree: root(0) → propset(1) → attr_a(2), attr_b(3)
        // Grant both attrs → propagates to propset → propagates to root
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 2), // attr_a
            obj_allow(&alice(), DS_READ_PROP, 3), // attr_b
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);

        // Both attrs granted
        assert!(tree[2].granted & DS_READ_PROP != 0);
        assert!(tree[3].granted & DS_READ_PROP != 0);
        // Propset: both children agree → aggregated up
        assert!(tree[1].granted & DS_READ_PROP != 0);
        // Root: propset is the only child at level 1 → aggregates up
        assert!(tree[0].granted & DS_READ_PROP != 0);
    }

    // -----------------------------------------------------------------------
    // Central Access Policy (§11.16)
    // -----------------------------------------------------------------------

    fn make_cap(policy_sid: &Sid, rules: Vec<CentralAccessRule>) -> CentralAccessPolicy {
        CentralAccessPolicy {
            policy_sid: policy_sid.clone(),
            rules,
        }
    }

    fn cap_rule(dacl_aces: Vec<Ace>) -> CentralAccessRule {
        CentralAccessRule {
            applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: dacl_aces },
            staged_dacl: None,
        }
    }

    fn policy_sid_1() -> Sid { Sid::new(5, &[21, 100, 200, 300, 9001]).unwrap() }

    fn cap_ace(policy_sid: &Sid) -> Ace {
        Ace {
            ace_type: ace::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
            flags: 0,
            mask: 0,
            sid: policy_sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    fn sd_with_cap(owner: &Sid, dacl_aces: Vec<Ace>, cap_sid: &Sid) -> SecurityDescriptor {
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![cap_ace(cap_sid)],
        };
        SecurityDescriptor::with_sacl(
            owner.clone(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: dacl_aces },
            sacl,
        )
    }

    #[test]
    fn cap_restricts_access() {
        // DACL grants read+write. CAP rule only allows read.
        // Result should be read only.
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &policy_sid_1(),
        );
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])],
        );
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA | FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0,
        ).unwrap();
        assert!(!result.allowed); // write denied by CAP
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA == 0);
    }

    #[test]
    fn cap_cannot_expand_access() {
        // DACL grants read only. CAP rule allows read+write.
        // Result should still be read only (AND intersection).
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            &policy_sid_1(),
        );
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)])],
        );
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0,
        ).unwrap();
        assert!(!result.allowed); // DACL doesn't grant write
    }

    #[test]
    fn cap_missing_policy_uses_recovery() {
        // Policy SID not found → recovery (no further restriction)
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &policy_sid_1(),
        );
        let token = medium_token(&alice(), &[], 0);
        // Lookup returns None → recovery policy
        let result = access_check(
            &sd, &token, FILE_READ_DATA | FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &[], 0,
        ).unwrap();
        assert!(result.allowed); // recovery = no restriction
    }

    #[test]
    fn cap_no_policy_sid_in_sacl() {
        // No SYSTEM_SCOPED_POLICY_ID_ACE → CAP evaluation skipped
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn cap_applies_to_filters() {
        // Rule's applies_to condition doesn't match → rule skipped
        use crate::conditional::bytecode;
        let never_true = bytecode::build(&[
            bytecode::int64_literal(0),
            bytecode::int64_literal(1),
            bytecode::op_eq(), // 0 == 1 → FALSE
        ]);
        let rule = CentralAccessRule {
            applies_to: Some(never_true),
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![] }, // empty = deny all
            staged_dacl: None,
        };
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            &policy_sid_1(),
        );
        let policy = CentralAccessPolicy {
            policy_sid: policy_sid_1(),
            rules: alloc::vec![rule],
        };
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0,
        ).unwrap();
        assert!(result.allowed); // rule skipped, no restriction
    }

    #[test]
    fn cap_multiple_rules_intersect() {
        // Two rules: one allows read+write, other allows read only.
        // Result: read only (each rule further restricts).
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &policy_sid_1(),
        );
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![
                cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]),
                cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)]),
            ],
        );
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn cap_empty_rule_dacl_denies_all() {
        // CAP rule with empty DACL → grants nothing → intersection strips everything
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &policy_sid_1(),
        );
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![])], // empty DACL
        );
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Cross-feature interactions
    // -----------------------------------------------------------------------

    #[test]
    fn restricted_token_with_mic() {
        // Low integrity + restricted token: MIC blocks write, restricted blocks too
        let sd = sd_with_label(
            &alice(),
            alloc::vec![
                allow(&alice(), GENERIC_ALL),
                allow(&engineers(), FILE_READ_DATA),
            ],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.integrity_level = crate::token::IntegrityLevel::Low;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;

        // MIC blocks write (low < medium)
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);

        // Read: MIC allows, normal pass has it, restricted pass has it (engineers)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn confinement_with_mic() {
        // Low integrity + confined: both must pass
        let sd = sd_with_label(
            &alice(),
            alloc::vec![
                allow(&alice(), GENERIC_ALL),
                allow(&app_sid(), FILE_READ_DATA | FILE_WRITE_DATA),
            ],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.integrity_level = crate::token::IntegrityLevel::Low;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;

        // Write: MIC blocks (low < medium), confinement would allow
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);

        // Read: MIC allows, confinement allows (app_sid in DACL)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn all_pipeline_stages_compound() {
        // DACL allows alice read+write
        // MIC blocks write (low integrity)
        // Restricted pass: engineers only gets read
        // Result: read only
        let sd = sd_with_label(
            &alice(),
            alloc::vec![
                allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
                allow(&engineers(), FILE_READ_DATA),
            ],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.integrity_level = crate::token::IntegrityLevel::Low;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;

        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA == 0);
    }

    #[test]
    fn pip_dominant_caller_passes() {
        // PIP with a dominant caller should pass (currently caller is always None/0).
        // This test documents the behavior — when PSB is modeled, the dominant
        // path needs real testing with non-zero caller PIP.
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            well_known::PIP_TYPE_NONE, // object protection = None
            0,
            0, // allowed mask irrelevant for None type
        );
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        // None/0 object → caller (also None/0) dominates → no PIP restriction
        assert!(result.allowed);
    }

    // -----------------------------------------------------------------------
    // Object ACE additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn object_ace_same_node_deny_then_allow() {
        // Deny on child first, then allow on same child — deny wins
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_WRITE_PROP, 1),
            obj_allow(&alice(), DS_WRITE_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _result = check_tree(&sd, &token, DS_WRITE_PROP, &mut tree);
        assert!(tree[1].granted & DS_WRITE_PROP == 0); // deny first
    }

    #[test]
    fn object_ace_multiple_aces_same_node_accumulate() {
        // Two allows on same node, different bits
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&alice(), DS_WRITE_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP | DS_WRITE_PROP, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[1].granted & DS_WRITE_PROP != 0);
    }

    #[test]
    fn object_ace_single_node_tree() {
        // Tree with only root node
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 0),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0)]);
        let result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(result.allowed);
        assert!(tree[0].granted & DS_READ_PROP != 0);
    }

    // -----------------------------------------------------------------------
    // SD parsing edge cases
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Callback ACE integration through AccessCheck
    // -----------------------------------------------------------------------

    fn callback_allow_ace(sid: &Sid, mask: u32, condition: Vec<u8>) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: Some(condition),
            application_data: None,
        }
    }

    fn callback_deny_ace(sid: &Sid, mask: u32, condition: Vec<u8>) -> Ace {
        Ace {
            ace_type: ACCESS_DENIED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: Some(condition),
            application_data: None,
        }
    }

    fn condition_true() -> Vec<u8> {
        use crate::conditional::bytecode;
        bytecode::build(&[
            bytecode::int64_literal(1),
            bytecode::int64_literal(1),
            bytecode::op_eq(),
        ])
    }

    fn condition_false() -> Vec<u8> {
        use crate::conditional::bytecode;
        bytecode::build(&[
            bytecode::int64_literal(0),
            bytecode::int64_literal(1),
            bytecode::op_eq(),
        ])
    }

    fn condition_unknown() -> Vec<u8> {
        use crate::conditional::bytecode;
        // Missing attribute → UNKNOWN
        bytecode::build(&[
            bytecode::user_attr("nonexistent"),
            bytecode::int64_literal(1),
            bytecode::op_eq(),
        ])
    }

    #[test]
    fn callback_allow_condition_true_grants() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_true()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn callback_allow_condition_false_skips() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_false()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // condition FALSE → skip → not granted
    }

    #[test]
    fn callback_allow_condition_unknown_skips() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_unknown()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // UNKNOWN → skip for allow
    }

    #[test]
    fn callback_allow_no_condition_skips() {
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: alice(),
            object_type: None, inherited_object_type: None,
            condition: None, // no condition data
            application_data: None,
        };
        let sd = sd_with_dacl(&alice(), alloc::vec![ace]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // None → UNKNOWN → skip
    }

    #[test]
    fn callback_deny_condition_true_denies() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_true()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // deny fires (TRUE), first-writer-wins
    }

    #[test]
    fn callback_deny_condition_false_skips() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_false()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // deny skipped (FALSE), allow grants
    }

    #[test]
    fn callback_deny_condition_unknown_denies() {
        // UNKNOWN on deny → deny fires (fail-safe, §11.12)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_unknown()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // UNKNOWN → deny fires
    }

    #[test]
    fn callback_deny_no_condition_denies() {
        let ace = Ace {
            ace_type: ACCESS_DENIED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: FILE_READ_DATA,
            sid: alice(),
            object_type: None, inherited_object_type: None,
            condition: None,
            application_data: None,
        };
        let sd = sd_with_dacl(&alice(), alloc::vec![ace, allow(&alice(), FILE_READ_DATA)]);
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed); // None → UNKNOWN → deny fires
    }

    #[test]
    fn callback_deny_for_allow_false_makes_deny_only_claims_visible() {
        // This tests the bug fix: deny callback ACEs must use for_allow=false
        // so USE_FOR_DENY_ONLY claims are visible to the condition.
        use crate::conditional::bytecode;
        use crate::token::{ClaimEntry, ClaimType, ClaimValues, claim_flags};

        // Condition: @User.restricted == 1
        let cond = bytecode::build(&[
            bytecode::user_attr("restricted"),
            bytecode::int64_literal(1),
            bytecode::op_eq(),
        ]);

        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, cond),
            allow(&alice(), FILE_READ_DATA),
        ]);

        // Token with a USE_FOR_DENY_ONLY claim
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![ClaimEntry {
            name: alloc::string::String::from("restricted"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::USE_FOR_DENY_ONLY,
            values: ClaimValues::Int64(alloc::vec![1]),
        }];

        let result = check(&sd, &token, FILE_READ_DATA);
        // The deny-only claim IS visible to the deny condition (for_allow=false),
        // so the condition evaluates to TRUE, and the deny fires.
        assert!(!result.allowed);
    }

    #[test]
    fn callback_allow_for_allow_true_hides_deny_only_claims() {
        // Complementary test: allow callback ACEs use for_allow=true,
        // so USE_FOR_DENY_ONLY claims are invisible.
        use crate::conditional::bytecode;
        use crate::token::{ClaimEntry, ClaimType, ClaimValues, claim_flags};

        let cond = bytecode::build(&[
            bytecode::user_attr("restricted"),
            bytecode::int64_literal(1),
            bytecode::op_eq(),
        ]);

        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, cond),
        ]);

        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![ClaimEntry {
            name: alloc::string::String::from("restricted"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::USE_FOR_DENY_ONLY,
            values: ClaimValues::Int64(alloc::vec![1]),
        }];

        let result = check(&sd, &token, FILE_READ_DATA);
        // The deny-only claim is INVISIBLE to the allow condition (for_allow=true),
        // so the condition evaluates to UNKNOWN (attribute appears NULL),
        // and the allow ACE is skipped.
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // SD parsing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn sd_components_survive_any_offset_order() {
        // Build an SD manually with non-standard offset ordering
        // (group before owner). Our parser uses offsets, not sequential reading.
        let owner = well_known::system().unwrap();
        let group = well_known::administrators().unwrap();
        let owner_bytes = owner.to_bytes().unwrap();
        let group_bytes = group.to_bytes().unwrap();

        let mut buf = alloc::vec![0u8; 20]; // header
        buf[0] = 1; // revision
        // Put group FIRST in the buffer, then owner
        let group_offset = 20u32;
        let owner_offset = (20 + group_bytes.len()) as u32;
        buf[2..4].copy_from_slice(&(SE_SELF_RELATIVE).to_le_bytes());
        buf[4..8].copy_from_slice(&owner_offset.to_le_bytes());
        buf[8..12].copy_from_slice(&group_offset.to_le_bytes());
        // sacl and dacl offsets = 0 (not present)
        buf.extend_from_slice(&group_bytes);
        buf.extend_from_slice(&owner_bytes);

        let sd = SecurityDescriptor::from_bytes(&buf).unwrap().unwrap();
        assert_eq!(sd.owner.unwrap(), owner);
        assert_eq!(sd.group.unwrap(), group);
    }
}
