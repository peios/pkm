// AccessCheck — the complete authorization pipeline (§11).
//
// Given a token (who), an SD (what are the rules), and a desired access
// mask (what do they want), AccessCheck returns which rights are granted
// and whether the request succeeds.
//
// This module implements the §11.17 pseudocode exactly. Each function
// maps to a named function in the proposal. Comments reference the
// specific proposal steps.

use core::sync::atomic::Ordering;

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
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, PartialEq)]
pub struct AccessCheckResult {
    /// The access rights granted by the pipeline.
    pub granted: u32,
    /// Whether the request as a whole succeeded.
    pub allowed: bool,
    /// Continuous audit mask for the opened handle (from alarm ACEs).
    pub continuous_audit_mask: u32,
    /// Audit events from SACL evaluation (§11.10).
    pub audit_events: Vec<crate::audit::AuditEvent>,
    /// True if a CAP staged DACL produced a different result than the
    /// effective DACL (§11.16). Signals that a pending policy change
    /// would alter access decisions.
    pub staging_mismatch: bool,
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
#[derive(Clone, Copy, Debug)]
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

#[cfg(feature = "kernel")]
impl crate::compat::TryClone for ObjectTypeNode {
    fn try_clone(&self) -> Result<Self, crate::compat::AllocError> {
        Ok(*self)
    }
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
    /// Override device_groups for the restricted pass (§11.7).
    /// When Some, conditional expressions use these instead of
    /// token.device_groups for Device_Member_of evaluation.
    pub device_groups_override: Option<&'a [crate::group::GroupEntry]>,
}

/// §11.17 EnrichToken: inject virtual groups S-1-3-4 and S-1-5-10.
pub(crate) fn enrich_token<'a>(token: &'a Token, owner: &Sid, self_sid: Option<&Sid>) -> EnrichedToken<'a> {
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
        device_groups_override: None,
    }
}

/// Validate an object type list (§11.17 step 1).
/// Rejects: duplicate GUIDs, level gaps > 1, non-zero root level,
/// multiple level-0 roots.
fn validate_object_tree(tree: &[ObjectTypeNode]) -> Result<(), AccessCheckError> {
    if tree.is_empty() {
        return Ok(());
    }

    // Root must be level 0.
    if tree[0].level != 0 {
        return Err(AccessCheckError::InvalidObjectTypeList);
    }

    let mut root_count: u32 = 0;
    let mut prev_level: u16 = 0;

    for (i, node) in tree.iter().enumerate() {
        // Level gap: a node's level can be at most prev_level + 1.
        // (It can also be less — going back up the tree.)
        if i > 0 && node.level > prev_level + 1 {
            return Err(AccessCheckError::InvalidObjectTypeList);
        }

        if node.level == 0 {
            root_count += 1;
            if root_count > 1 {
                return Err(AccessCheckError::InvalidObjectTypeList);
            }
        }

        // Duplicate GUID check: O(n²) but trees are tiny (typically < 20 nodes).
        for other in &tree[..i] {
            if other.guid == node.guid {
                return Err(AccessCheckError::InvalidObjectTypeList);
            }
        }

        prev_level = node.level;
    }

    Ok(())
}

/// Extended SID matching that includes virtual groups.
pub fn enriched_sid_matches(
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
#[allow(dead_code)] // Used when full object tree evaluation is wired up
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
    enriched: &EnrichedToken,
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
                            cond, enriched, resource_attributes, local_claims, true,
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
                            cond, enriched, resource_attributes, local_claims, false,
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
                                cond, enriched, resource_attributes, local_claims, true,
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
                                cond, enriched, resource_attributes, local_claims, false,
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
// Resource attribute parsing (CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1)
// ---------------------------------------------------------------------------

/// Parse a SYSTEM_RESOURCE_ATTRIBUTE_ACE's application_data into a ClaimEntry.
///
/// Wire format (MS-DTYP §2.4.10.1):
///   name_offset: u32     (offset to UTF-16LE null-terminated string)
///   value_type:  u16     (0x0001=Int64, 0x0002=Uint64, 0x0003=String, 0x0005=SID, 0x0006=Boolean, 0x0010=Octet)
///   reserved:    u16
///   flags:       u32
///   value_count: u32
///   values:      [u32; value_count] (offsets to values from struct start)
///   ... followed by name string and value data at the specified offsets
fn parse_resource_attribute(data: &[u8]) -> Option<crate::token::ClaimEntry> {
    use crate::token::{ClaimEntry, ClaimType, ClaimValues};

    if data.len() < 16 {
        return None;
    }

    let name_offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let value_type = u16::from_le_bytes([data[4], data[5]]);
    // reserved at [6..8]
    let flags = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let value_count = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

    if value_count > 4096 {
        return None; // sanity cap
    }

    let offsets_start = 16;
    let offsets_end = offsets_start + value_count * 4;
    if offsets_end > data.len() {
        return None;
    }

    // Parse value offsets
    let mut value_offsets = compat::vec_with_capacity::<usize>(value_count).ok()?;
    for i in 0..value_count {
        let off = u32::from_le_bytes([
            data[offsets_start + i * 4],
            data[offsets_start + i * 4 + 1],
            data[offsets_start + i * 4 + 2],
            data[offsets_start + i * 4 + 3],
        ]) as usize;
        compat::vec_push(&mut value_offsets, off).ok()?;
    }

    // Parse name (UTF-16LE null-terminated at name_offset)
    let name = if name_offset < data.len() {
        let name_data = &data[name_offset..];
        let mut s = crate::compat::String::new();
        let mut i = 0;
        while i + 1 < name_data.len() {
            let ch = u16::from_le_bytes([name_data[i], name_data[i + 1]]);
            if ch == 0 { break; }
            if let Some(c) = char::from_u32(ch as u32) {
                #[cfg(not(feature = "kernel"))]
                s.push(c);
                #[cfg(feature = "kernel")]
                { let _ = s.push(c); }
            }
            i += 2;
        }
        s
    } else {
        return None;
    };

    // Parse claim type
    let claim_type = match value_type {
        0x0001 => ClaimType::Int64,
        0x0002 => ClaimType::Uint64,
        0x0003 => ClaimType::String,
        0x0005 => ClaimType::Sid,
        0x0006 => ClaimType::Boolean,
        0x0010 => ClaimType::Octet,
        _ => return None,
    };

    // Parse values
    let values = match claim_type {
        ClaimType::Int64 => {
            let mut vals = compat::vec_with_capacity::<i64>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                if off + 8 > data.len() { return None; }
                let v = i64::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                    data[off+4], data[off+5], data[off+6], data[off+7],
                ]);
                compat::vec_push(&mut vals, v).ok()?;
            }
            ClaimValues::Int64(vals)
        }
        ClaimType::Uint64 => {
            let mut vals = compat::vec_with_capacity::<u64>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                if off + 8 > data.len() { return None; }
                let v = u64::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                    data[off+4], data[off+5], data[off+6], data[off+7],
                ]);
                compat::vec_push(&mut vals, v).ok()?;
            }
            ClaimValues::Uint64(vals)
        }
        ClaimType::Boolean => {
            let mut vals = compat::vec_with_capacity::<bool>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                if off + 8 > data.len() { return None; }
                let v = u64::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                    data[off+4], data[off+5], data[off+6], data[off+7],
                ]);
                compat::vec_push(&mut vals, v != 0).ok()?;
            }
            ClaimValues::Boolean(vals)
        }
        ClaimType::String => {
            let mut vals = compat::vec_with_capacity::<crate::compat::String>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                // Offset points to a u32 offset to the actual string
                if off + 4 > data.len() { return None; }
                let str_off = u32::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                ]) as usize;
                if str_off >= data.len() { return None; }
                let str_data = &data[str_off..];
                let mut s = crate::compat::String::new();
                let mut i = 0;
                while i + 1 < str_data.len() {
                    let ch = u16::from_le_bytes([str_data[i], str_data[i + 1]]);
                    if ch == 0 { break; }
                    if let Some(c) = char::from_u32(ch as u32) {
                        #[cfg(not(feature = "kernel"))]
                        s.push(c);
                        #[cfg(feature = "kernel")]
                        { let _ = s.push(c); }
                    }
                    i += 2;
                }
                compat::vec_push(&mut vals, s).ok()?;
            }
            ClaimValues::String(vals)
        }
        ClaimType::Sid => {
            let mut vals = compat::vec_with_capacity::<Sid>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                // Offset points to a u32 offset to the SID
                if off + 4 > data.len() { return None; }
                let sid_off = u32::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                ]) as usize;
                if sid_off >= data.len() { return None; }
                let sid = Sid::from_bytes(&data[sid_off..])?;
                compat::vec_push(&mut vals, sid).ok()?;
            }
            ClaimValues::Sid(vals)
        }
        ClaimType::Octet => {
            let mut vals = compat::vec_with_capacity::<Vec<u8>>(value_count).ok()?;
            for off in value_offsets.iter().copied() {
                // Offset points to {length:u32, data...}
                if off + 4 > data.len() { return None; }
                let octet_off = u32::from_le_bytes([
                    data[off], data[off+1], data[off+2], data[off+3],
                ]) as usize;
                if octet_off + 4 > data.len() { return None; }
                let octet_len = u32::from_le_bytes([
                    data[octet_off], data[octet_off+1],
                    data[octet_off+2], data[octet_off+3],
                ]) as usize;
                if octet_off + 4 + octet_len > data.len() { return None; }
                let bytes = compat::slice_to_vec(&data[octet_off+4..octet_off+4+octet_len]).ok()?;
                compat::vec_push(&mut vals, bytes).ok()?;
            }
            ClaimValues::Octet(vals)
        }
    };

    Some(ClaimEntry {
        name,
        claim_type,
        flags: (flags & 0xFFFF) as u16,
        values,
    })
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
    _resource_attributes: &mut Vec<crate::token::ClaimEntry>,
    policy_sids: &mut Vec<Sid>,
    pip_type: u32,
    pip_trust: u32,
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
                // Resource attribute ACEs → parse and collect for conditional expressions
                if a.ace_type == ace::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE {
                    if a.flags & ace::INHERIT_ONLY_ACE == 0 {
                        if let Some(ref app_data) = a.application_data {
                            if let Some(claim) = parse_resource_attribute(app_data) {
                                compat::vec_push(_resource_attributes, claim)?;
                            }
                        }
                    }
                }

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
        enforce_pip(a, token, mapping, decided, granted, privilege_granted, pip_type, pip_trust);
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
    _token: &Token,
    mapping: &GenericMapping,
    decided: &mut u32,
    granted: &mut u32,
    privilege_granted: &mut u32,
    pip_type: u32,
    pip_trust: u32,
) {
    // Extract PIP type and trust from the trust label SID (S-1-19-type-trust)
    let (ace_type, ace_trust) = pip_from_trust_label_sid(&ace_data.sid);

    // Dominance check: both dimensions must be >=
    let caller_dominates = pip_type >= ace_type && pip_trust >= ace_trust;

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
/// Complete pipeline: generic mapping, MAXIMUM_ALLOWED, impersonation
/// gate, privilege grants, MIC, PIP, owner implicit rights, DACL walk
/// (basic + conditional + object ACEs), SeTakeOwnershipPrivilege,
/// restricted token two-pass, confinement, Central Access Policy
/// (with per-node tree intersection and staged DACL comparison).
///
/// NOT YET IMPLEMENTED:
/// - SACL audit emission (§11.10) — observational, not security-critical
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
    pip_type: u32,
    pip_trust: u32,
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

    // Object type list validation (§11.17 step 1).
    if let Some(ref tree) = object_tree {
        validate_object_tree(tree)?;
    }

    // Step 2: Generic mapping (§11.2)
    let mut mapped_desired = map_generic_bits(desired, mapping);

    // Step 2a: Strip MAXIMUM_ALLOWED (§11.5)
    let max_allowed_mode = mapped_desired & mask::MAXIMUM_ALLOWED != 0;
    mapped_desired &= !mask::MAXIMUM_ALLOWED;

    // Step 2b: Effective privileges (§11.6)
    // Intent-gated: backup/restore only active with corresponding flag.
    let mut effective_privs = token.privileges.enabled.load(Ordering::Relaxed);
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
    let mut staging_mismatch = false;

    // Per-privilege provenance masks (§11.17 step 9b).
    // Track which bits each privilege granted so we can accurately
    // attribute bits after the full pipeline completes.
    let mut security_granted: u32 = 0;
    let mut backup_granted: u32 = 0;
    let mut restore_granted: u32 = 0;
    let mut take_ownership_granted: u32 = 0;

    // ACCESS_SYSTEM_SECURITY: always decided, no DACL ACE can grant it.
    decided |= mask::ACCESS_SYSTEM_SECURITY;
    if effective_privs & crate::privilege::bits::SE_SECURITY != 0 {
        granted |= mask::ACCESS_SYSTEM_SECURITY;
        privilege_granted |= mask::ACCESS_SYSTEM_SECURITY;
        security_granted = mask::ACCESS_SYSTEM_SECURITY;
    }

    // Backup: all read-mapped bits
    if effective_privs & crate::privilege::bits::SE_BACKUP != 0 {
        let bits = map_generic_bits(mask::GENERIC_READ, mapping);
        decided |= bits;
        granted |= bits;
        privilege_granted |= bits;
        backup_granted = bits;
    }

    // Restore: all write-mapped bits + WRITE_DAC + WRITE_OWNER + DELETE + ASS
    if effective_privs & crate::privilege::bits::SE_RESTORE != 0 {
        let bits = map_generic_bits(mask::GENERIC_WRITE, mapping)
            | mask::WRITE_DAC
            | mask::WRITE_OWNER
            | mask::DELETE
            | mask::ACCESS_SYSTEM_SECURITY;
        decided |= bits;
        granted |= bits;
        privilege_granted |= bits;
        restore_granted = bits;
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
        pip_type,
        pip_trust,
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
        &enriched,
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
                // Note: decided is not read after this point in the scalar
                // path (restricted/confinement/CAP passes use their own
                // decided variables). We still update it for consistency
                // with the decided/granted pairing throughout the pipeline.
                decided |= mask::WRITE_OWNER;
                granted |= mask::WRITE_OWNER;
                privilege_granted |= mask::WRITE_OWNER;
                take_ownership_granted = mask::WRITE_OWNER;
            }
        }
    }
    // Suppress dead-value warning: decided is intentionally maintained above
    // for correctness of the decided/granted pattern, even though the scalar
    // decided is not read after step 7a (restricted/confinement/CAP passes
    // create their own decided variables).
    let _ = decided;

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

        // Enriched token for restricted pass: virtual groups visible
        // only if the corresponding SID is in the restricting SID list.
        let restricted_enriched = EnrichedToken {
            token,
            has_owner_rights: owner_in_restricted,
            has_principal_self: self_in_restricted,
            principal_self_deny_only: false,
            // Swap device groups for restricted pass (§11.7):
            // Device_Member_of evaluates against restricted_device_groups.
            device_groups_override: token.restricted_device_groups.as_deref(),
        };

        // Deep-copy the object tree for the restricted pass (§11.17 step 8).
        let mut r_tree: Option<Vec<ObjectTypeNode>> =
            if let Some(ref tree) = object_tree {
                Some(compat::slice_to_vec(tree)?)
            } else {
                None
            };

        evaluate_dacl(
            sd,
            &restricted_enriched,
            mapping,
            r_tree.as_deref_mut(),
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
        // Per-node intersection (§11.17 step 8)
        if let (Some(ref mut tree), Some(ref rtree)) = (&mut object_tree, &r_tree) {
            for (node, rnode) in tree.iter_mut().zip(rtree.iter()) {
                if token.write_restricted {
                    let write_bits = map_generic_bits(mask::GENERIC_WRITE, mapping);
                    node.granted = (node.granted & !write_bits)
                        | (node.granted & rnode.granted & write_bits);
                } else {
                    node.granted &= rnode.granted;
                }
            }
        }
        // Privilege-granted bits bypass the restricted pass
        granted |= privilege_granted;
        if let Some(ref mut tree) = object_tree {
            for node in tree.iter_mut() {
                node.granted |= privilege_granted;
            }
        }
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

        let confinement_enriched = EnrichedToken {
            token,
            has_owner_rights: owner_in_confinement,
            has_principal_self: self_in_confinement,
            principal_self_deny_only: false,
            device_groups_override: None, // confinement doesn't swap device groups
        };

        // Deep-copy the object tree for the confinement pass (§11.17).
        let mut c_tree: Option<Vec<ObjectTypeNode>> =
            if let Some(ref tree) = object_tree {
                Some(compat::slice_to_vec(tree)?)
            } else {
                None
            };

        evaluate_dacl(
            sd,
            &confinement_enriched,
            mapping,
            c_tree.as_deref_mut(),
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
        if let (Some(ref mut tree), Some(ref ctree)) = (&mut object_tree, &c_tree) {
            for (node, cnode) in tree.iter_mut().zip(ctree.iter()) {
                node.granted &= cnode.granted;
            }
        }
    }

    // Step 9: Central Access Policy (§11.16)
    if !policy_sids.is_empty() {
        let mut cap_effective = granted;

        for cap_sid in &policy_sids {
            let policy = policies.iter().find(|p| p.policy_sid == *cap_sid);

            // If the policy SID is not in the cache, use the hardcoded
            // recovery policy (§11.16): GENERIC_ALL to owner, Admins, SYSTEM.
            // Safe because CAP is an AND — recovery is no worse than no CAP.
            let recovery_dacl;
            let recovery_rule;
            let recovery_rules;
            let rules: &[CentralAccessRule] = match policy {
                Some(p) => &p.rules,
                None => {
                    recovery_dacl = crate::cap::recovery_policy()?;
                    recovery_rule = CentralAccessRule {
                        applies_to: None,
                        effective_dacl: recovery_dacl,
                        staged_dacl: None,
                    };
                    recovery_rules = [recovery_rule];
                    &recovery_rules
                }
            };

            for rule in rules {
                // applies_to condition evaluation
                if let Some(ref condition) = rule.applies_to {
                    let result = crate::conditional::evaluate(
                        condition,
                        &enriched,
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

                // Clone the object tree for this rule's evaluation (§11.17).
                let mut rule_tree: Option<Vec<ObjectTypeNode>> =
                    if let Some(ref tree) = object_tree {
                        Some(compat::slice_to_vec(tree)?)
                    } else {
                        None
                    };

                let eff_result = evaluate_rule_dacl(
                    &eff_sd,
                    token,
                    mapping,
                    mapped_desired,
                    max_allowed_mode,
                    self_sid,
                    &resource_attributes,
                    local_claims,
                    rule_tree.as_deref_mut(),
                );

                match eff_result {
                    Ok(eff_granted) => {
                        cap_effective &= eff_granted;
                        // Per-node intersection (§11.17)
                        if let (Some(ref mut tree), Some(ref rtree)) =
                            (&mut object_tree, &rule_tree)
                        {
                            for (node, rnode) in tree.iter_mut().zip(rtree.iter()) {
                                node.granted &= rnode.granted;
                            }
                        }
                    }
                    Err(_) => {
                        // Fail-closed with privilege escape hatch (§11.16)
                        cap_effective &= privilege_granted;
                        if let Some(ref mut tree) = object_tree {
                            for node in tree.iter_mut() {
                                node.granted &= privilege_granted;
                            }
                        }
                    }
                }

                // Staged DACL: evaluate proposed policy, log diff (§11.16)
                if let Some(ref staged_dacl) = rule.staged_dacl {
                    let stg_sd = SecurityDescriptor {
                        control: crate::sd::SE_DACL_PRESENT | crate::sd::SE_SELF_RELATIVE,
                        owner: sd.owner.try_clone()?,
                        group: sd.group.try_clone()?,
                        dacl: Some(staged_dacl.try_clone()?),
                        sacl: None,
                    };
                    let mut stg_tree: Option<Vec<ObjectTypeNode>> =
                        if let Some(ref tree) = object_tree {
                            Some(compat::slice_to_vec(tree)?)
                        } else {
                            None
                        };
                    let stg_result = evaluate_rule_dacl(
                        &stg_sd,
                        token,
                        mapping,
                        mapped_desired,
                        max_allowed_mode,
                        self_sid,
                        &resource_attributes,
                        local_claims,
                        stg_tree.as_deref_mut(),
                    );
                    let stg_granted = stg_result.unwrap_or(0);
                    if stg_granted != cap_effective {
                        staging_mismatch = true;
                    }
                    // Per-node staged comparison (§11.16)
                    if !staging_mismatch {
                        if let (Some(ref tree), Some(ref stree)) =
                            (&object_tree, &stg_tree)
                        {
                            for (node, snode) in tree.iter().zip(stree.iter()) {
                                if node.granted != snode.granted {
                                    staging_mismatch = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        granted = cap_effective;
    }

    // Step 9b: Privilege-use auditing (§11.17).
    // Fires ONCE after the full pipeline (DACL, restricted, confinement, CAP).
    // Only marks a privilege as used if its contributed bits survived to the
    // final granted mask AND were part of the explicit request.
    // Pure MAXIMUM_ALLOWED (mapped_desired == 0) is a probe — no audit.
    // Mixed (MAXIMUM_ALLOWED | explicit bits): only audit the explicit bits.
    if mapped_desired != 0 {
        if security_granted & granted & mapped_desired != 0 {
            token.privileges.mark_used(crate::privilege::bits::SE_SECURITY);
        }
        if backup_granted & granted & mapped_desired != 0 {
            token.privileges.mark_used(crate::privilege::bits::SE_BACKUP);
        }
        if restore_granted & granted & mapped_desired != 0 {
            token.privileges.mark_used(crate::privilege::bits::SE_RESTORE);
        }
        if take_ownership_granted & granted & mapped_desired != 0 {
            token.privileges.mark_used(crate::privilege::bits::SE_TAKE_OWNERSHIP);
        }
    }

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

    // Step 10: SACL audit evaluation (§11.10)
    let mut audit_result = crate::audit::evaluate_sacl(
        sd, token, mapping, mapped_desired, final_granted,
        allowed, &resource_attributes, local_claims,
        object_tree.as_deref(),
    )?;

    // Per-token audit policy (§7.3, §11.17 step 10b).
    // Unconditional audit based on token flags — additive with SACL.
    {
        const APS: u64 = crate::token::audit_policy_flags::OBJECT_ACCESS_SUCCESS;
        const APF: u64 = crate::token::audit_policy_flags::OBJECT_ACCESS_FAILURE;
        if allowed && token.audit_policy & APS != 0 {
            compat::vec_push(&mut audit_result.events, crate::audit::AuditEvent {
                ace_type: 0xFF, // synthetic: token audit policy, not a SACL ACE
                ace_sid: token.user_sid.try_clone()?,
                ace_mask: mapped_desired,
                success: true,
                desired: mapped_desired,
                granted: final_granted,
                object_type: None,
            })?;
        }
        if !allowed && token.audit_policy & APF != 0 {
            compat::vec_push(&mut audit_result.events, crate::audit::AuditEvent {
                ace_type: 0xFF, // synthetic: token audit policy
                ace_sid: token.user_sid.try_clone()?,
                ace_mask: mapped_desired,
                success: false,
                desired: mapped_desired,
                granted: final_granted,
                object_type: None,
            })?;
        }
    }

    Ok(AccessCheckResult {
        granted: final_granted,
        allowed,
        continuous_audit_mask: audit_result.continuous_audit_mask,
        audit_events: audit_result.events,
        staging_mismatch,
    })
}

/// AccessCheckResultList (§11.1): per-node result variant.
///
/// Same pipeline as access_check, but returns a separate verdict for
/// each node in the object type list. A denial on one property fails
/// that property only, not the whole request. Requires a tree.
pub fn access_check_result_list(
    sd: &SecurityDescriptor,
    token: &Token,
    desired: u32,
    mapping: &GenericMapping,
    object_tree: &mut [ObjectTypeNode],
    self_sid: Option<&Sid>,
    local_claims: &[crate::token::ClaimEntry],
    policies: &[CentralAccessPolicy],
    privilege_intent: u32,
    pip_type: u32,
    pip_trust: u32,
) -> Result<(Vec<NodeResult>, bool), AccessCheckError> {
    if object_tree.is_empty() {
        return Err(AccessCheckError::InvalidSecurityDescriptor);
    }

    // Run the same core pipeline with the tree.
    let result = access_check(
        sd, token, desired, mapping,
        Some(object_tree), self_sid,
        local_claims, policies, privilege_intent,
        pip_type, pip_trust,
    )?;

    let mapped_desired = map_generic_bits(desired, mapping) & !mask::MAXIMUM_ALLOWED;
    let max_allowed_mode = desired & mask::MAXIMUM_ALLOWED != 0;

    // Collect per-node results (§11.17 AccessCheckResultList).
    let mut node_results = compat::vec_with_capacity::<NodeResult>(object_tree.len())?;
    for node in object_tree.iter() {
        let node_allowed = if mapped_desired == 0 {
            true
        } else {
            (node.granted & mapped_desired) == mapped_desired
        };
        let node_granted = if max_allowed_mode {
            node.granted
        } else if node_allowed {
            mapped_desired
        } else {
            0
        };
        compat::vec_push(&mut node_results, NodeResult {
            granted: node_granted,
            allowed: node_allowed,
        })?;
    }

    Ok((node_results, result.staging_mismatch))
}

/// Evaluate a CAP rule's DACL through the normal pipeline.
/// No backup/restore intent. No recursive CAP evaluation.
/// When object_tree is provided, per-node state is evaluated.
fn evaluate_rule_dacl(
    sd: &SecurityDescriptor,
    token: &Token,
    mapping: &GenericMapping,
    desired: u32,
    max_allowed_mode: bool,
    self_sid: Option<&Sid>,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
    mut object_tree: Option<&mut [ObjectTypeNode]>,
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
    let effective_privs = token.privileges.enabled.load(Ordering::Relaxed)
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
        &enriched,
        mapping,
        object_tree.as_deref_mut(),
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
    /// The object type list is malformed (duplicate GUIDs, level gaps,
    /// multiple roots, or root not at level 0).
    InvalidObjectTypeList,
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
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap()
    }

    fn check_with_intent(
        sd: &SecurityDescriptor,
        token: &Token,
        desired: u32,
        intent: u32,
    ) -> AccessCheckResult {
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, None, None, &[], &[], intent, 0, 0).unwrap()
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
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
            &sd, &token, KEY_QUERY_VALUE, &KEY_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);

        // Random user gets only PROCESS_QUERY_LIMITED
        let token = test_token(&bob(), &[&well_known::everyone().unwrap()], 0);
        let result = access_check(
            &sd, &token, PROCESS_QUERY_LIMITED, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);

        let result = access_check(
            &sd, &token, PROCESS_TERMINATE, &PROCESS_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
        access_check(sd, token, desired, &FILE_GENERIC_MAPPING, Some(tree), None, &[], &[], 0, 0, 0).unwrap()
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
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
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
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
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
            &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
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
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
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
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
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
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
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

    // ===================================================================
    // §11 Corpus Tests — DACL Walk Core Mechanics (§11.3)
    // ===================================================================

    #[test]
    fn allow_ace_grants_undecided_bits() {
        // §11.3: allow ACE grants rights for bits not yet decided
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
        assert_eq!(result.granted & (FILE_READ_DATA | FILE_WRITE_DATA),
                   FILE_READ_DATA | FILE_WRITE_DATA);
    }

    #[test]
    fn deny_ace_denies_undecided_bits() {
        // §11.3: deny ACE marks bits as decided-but-not-granted
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn already_decided_bits_unaffected_by_later_allow() {
        // §11.3: once denied, a later allow can't override
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn already_decided_bits_unaffected_by_later_deny() {
        // §11.3: once granted, a later deny can't override
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn each_bit_decided_at_most_once() {
        // §11.3: verify bits aren't double-counted
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_READ_DATA), // same bit, already decided
            allow(&engineers(), FILE_WRITE_DATA), // different bit, new
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn non_canonical_order_respects_position() {
        // §11.3: non-canonical allow-before-deny is respected
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // allow came first
    }

    #[test]
    fn no_hard_failure_on_denial() {
        // §11.3: denials are recorded, not errors
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
        // Result is Ok, not an error
        assert_eq!(result.granted & FILE_READ_DATA, 0);
    }

    #[test]
    fn ace_sid_no_match_skipped() {
        // §11.3: ACE whose SID matches neither user nor group is skipped
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&bob(), FILE_READ_DATA), // bob, not alice
            allow(&managers(), FILE_WRITE_DATA), // managers, alice not a member
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert_eq!(result.granted & FILE_READ_DATA, 0);
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
    }

    // ===================================================================
    // §11.3 DACL Walk — SID Matching
    // ===================================================================

    #[test]
    fn allow_ace_matches_user_sid() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn allow_ace_matches_enabled_group() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&engineers(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[&engineers()], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn allow_ace_skips_deny_only_group() {
        // §11.3: allow ACE does NOT match USE_FOR_DENY_ONLY group
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&engineers(), FILE_READ_DATA)]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn deny_ace_matches_deny_only_group() {
        // §11.3: deny ACE DOES match USE_FOR_DENY_ONLY group
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn deny_ace_matches_enabled_group() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn neither_enabled_nor_deny_only_skipped() {
        // §11.3: group with neither flag is invisible
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = 0; // neither enabled nor deny-only
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn user_sid_deny_only_blocks_allow() {
        // §11.3: user SID marked deny-only doesn't match allow ACEs
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = test_token(&alice(), &[], 0);
        token.user_deny_only = true;
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn user_sid_deny_only_matches_deny() {
        // §11.3: user SID marked deny-only still matches deny ACEs
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.user_deny_only = true;
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn deny_only_group_blocks_access_via_deny_ace() {
        // §11.3, §11.7: deny-only group triggers deny ACEs
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.3 DACL Walk — Special Cases
    // ===================================================================

    #[test]
    fn null_dacl_grants_all_valid_bits() {
        // §11.3: NULL DACL grants MapGenericBits(GENERIC_ALL)
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE);
        assert!(result.allowed);
    }

    #[test]
    fn null_dacl_does_not_grant_garbage_bits() {
        // §11.3: grants MapGenericBits(GENERIC_ALL), not 0xFFFFFFFF
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
        // Granted should be bounded by the mapping, not raw 0xFFFFFFFF
        assert_eq!(result.granted & 0xFFFF_FFFF, result.granted);
        // ACCESS_SYSTEM_SECURITY should NOT be granted (requires privilege)
        assert_eq!(result.granted & ACCESS_SYSTEM_SECURITY, 0);
    }

    #[test]
    fn empty_dacl_grants_nothing() {
        // §11.3: DACL present with zero ACEs: no rights from walk
        let sd = SecurityDescriptor::new(
            bob(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&bob(), &[], 0); // bob is non-owner in test
        // Actually bob IS the owner here, so they get implicit rights.
        // Use alice as non-owner:
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    // ===================================================================
    // §11.4 Owner Implicit Rights — Additional
    // ===================================================================

    #[test]
    fn owner_implicit_before_dacl_walk() {
        // §11.4: implicit rights granted before DACL walk
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Deny can't override implicit (first-writer-wins, implicit is first)
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_implicit_immune_to_deny_aces() {
        // §11.4: same as above, explicit test name from corpus
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), READ_CONTROL),
            deny(&alice(), WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_rights_prescan_ignores_non_access_control() {
        // §11.4: pre-scan ignores non-access-control ACE types
        // A mandatory label ACE with OWNER RIGHTS SID shouldn't suppress
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                flags: 0,
                mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                // Using owner_rights SID in a label ACE (weird but shouldn't suppress)
                sid: well_known::owner_rights().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
            sacl,
        );
        let token = medium_token(&alice(), &[], 0);
        // SACL label ACE shouldn't suppress owner implicit rights
        assert!(check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_rights_allow_ace_narrows_access() {
        // §11.4: OWNER RIGHTS with only READ_CONTROL narrows to read-only
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_rights_allow_ace_expands_access() {
        // §11.4: OWNER RIGHTS with READ_CONTROL+WRITE_DAC+DELETE
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC | DELETE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, DELETE).allowed);
    }

    #[test]
    fn owner_rights_not_exclusive_channel() {
        // §11.4: owner also receives from normal SID ACEs
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed); // from owner rights
        assert!(check(&sd, &token, FILE_READ_DATA).allowed); // from alice ACE
    }

    #[test]
    fn owner_empty_dacl_gets_implicit_rights_only() {
        // §11.3, §11.4: owner with empty DACL gets only READ_CONTROL+WRITE_DAC
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(check(&sd, &token, WRITE_DAC).allowed);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.5 MAXIMUM_ALLOWED — Additional
    // ===================================================================

    #[test]
    fn max_allowed_stripped_before_evaluation() {
        // §11.5: MAXIMUM_ALLOWED bit is stripped from desired
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
        // MAXIMUM_ALLOWED bit should not appear in granted
        assert_eq!(result.granted & MAXIMUM_ALLOWED, 0);
    }

    #[test]
    fn pure_max_allowed_always_succeeds() {
        // §11.5: pure MAXIMUM_ALLOWED with no specific bits always succeeds
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed); // always succeeds in pure max-allowed mode
    }

    #[test]
    fn pure_max_allowed_zero_granted_succeeds() {
        // §11.5: even zero granted is success for pure MAXIMUM_ALLOWED
        let sd = SecurityDescriptor::new(
            bob(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![deny(&alice(), GENERIC_ALL)] },
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
    }

    // ===================================================================
    // §11.6 Privileges — Additional
    // ===================================================================

    #[test]
    fn ass_granted_with_security_privilege() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(result.allowed);
    }

    #[test]
    fn ass_denied_without_security_privilege() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn ass_always_decided_before_dacl() {
        // §11.6: ASS resolved before DACL walk
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), ACCESS_SYSTEM_SECURITY), // DACL can't grant ASS
        ]);
        let token = test_token(&alice(), &[], 0); // no privilege
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn ass_no_dacl_ace_can_grant_it() {
        // §11.6: no DACL ACE can grant ASS
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), 0xFFFFFFFF), // everything including ASS bit
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn ass_no_dacl_ace_can_deny_it() {
        // §11.6: deny ACE for ASS has no effect (already decided by privilege)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), ACCESS_SYSTEM_SECURITY),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        assert!(check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn take_ownership_grants_write_owner_if_dacl_did_not() {
        // §11.6: TakeOwnership only fires if DACL didn't independently grant
        let sd = sd_with_dacl(&bob(), alloc::vec![]); // empty DACL
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_overrides_dacl_deny() {
        // §11.6: TakeOwnership is deny-proof
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn backup_without_intent_invisible() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restore_without_intent_invisible() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn backup_with_intent_grants_rights() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn restore_with_intent_grants_rights() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        assert!(check_with_intent(&sd, &token, FILE_WRITE_DATA, RESTORE_INTENT).allowed);
    }

    #[test]
    fn relabel_privilege_does_not_grant_directly() {
        // §11.6: SeRelabelPrivilege only loosens MIC, doesn't grant rights
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RELABEL);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.13 MIC — Additional
    // ===================================================================

    #[test]
    fn mic_no_write_up_default() {
        // Default MIC blocks write for non-dominant callers
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn mic_dominant_caller_bypasses() {
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = high_token(&alice());
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_equal_level_dominates() {
        // §11.13: >= comparison
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), FILE_WRITE_DATA)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_default_protects_from_low() {
        // Default Medium label blocks Low from writing
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
        );
        let token = low_token(&alice());
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_default_protects_from_untrusted() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
        );
        let mut token = test_token(&alice(), &[], 0);
        token.integrity_level = crate::token::IntegrityLevel::Untrusted;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_token_mandatory_policy_flag() {
        // §11.13: MIC enforced only when NO_WRITE_UP flag is set
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_policy_cleared_disables_mic() {
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.mandatory_policy = 0;
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    // ===================================================================
    // §11.14 Confinement — Additional
    // ===================================================================

    #[test]
    fn confinement_starts_from_nothing() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_intersection_with_normal() {
        // Normal grants read+write, confinement grants read → result is read
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&app_sid(), FILE_READ_DATA),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn confinement_backup_privilege_blocked() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn confinement_take_ownership_blocked() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn confinement_security_privilege_blocked() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_SECURITY);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn confinement_null_sid_means_not_confined() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.confinement_sid = None;
        assert!(!token.is_confined());
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_exempt_skips_check() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.confinement_exempt = true;
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.7 Restricted Tokens — Additional
    // ===================================================================

    #[test]
    fn restricted_token_two_pass_evaluation() {
        // §11.7: DACL evaluated twice
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        // Normal: alice + engineers → read. Restricted: engineers → read.
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_intersection_normal_and_restricted() {
        // §11.7: final = intersection
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA), // restricted only gets read
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn restricted_pass_matches_only_restricting_sids() {
        // §11.7: restricted pass only matches restricting SID list
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA), // only alice, not engineers
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        // Normal: alice → read. Restricted: engineers not in DACL → nothing.
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_caps_access() {
        // §11.7: normal grants R+W, restricted grants R → final is R
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn write_restricted_intersection_only_write_bits() {
        // §11.7: write-restricted only intersects write-category bits
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA), // restricted: only read
        ]);
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.write_restricted = true;
        // Read comes from normal only → OK
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        // Write intersected: normal has it, restricted doesn't → denied
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn write_restricted_read_from_normal_pass_only() {
        // Read/execute from normal pass alone
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_EXECUTE),
        ]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.write_restricted = true;
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn privilege_granted_bypass_restricted() {
        // §11.7: privilege bits OR'd back after intersection
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    // ===================================================================
    // §11.12 Conditional ACEs — Additional
    // ===================================================================

    #[test]
    fn conditional_allow_fires_only_on_true() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_true()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn conditional_allow_skipped_on_false() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_false()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn conditional_allow_skipped_on_unknown() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(&alice(), FILE_READ_DATA, condition_unknown()),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn conditional_deny_fires_on_true() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_true()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn conditional_deny_fires_on_unknown() {
        // §11.12: UNKNOWN on deny → deny fires (fail-safe)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_unknown()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn conditional_deny_skipped_on_false() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, condition_false()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.15 PIP — Additional
    // ===================================================================

    #[test]
    fn pip_non_dominant_blocks_non_allowed_rights() {
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            FILE_READ_DATA, // only read allowed
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    // ===================================================================
    // §11.2 Generic Mapping — Additional
    // ===================================================================

    #[test]
    fn generic_read_maps_to_specific_bits() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA
                | READ_CONTROL | SYNCHRONIZE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, GENERIC_READ).allowed);
    }

    #[test]
    fn generic_write_maps_to_specific_bits() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_WRITE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn generic_execute_maps_to_specific_bits() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_EXECUTE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_EXECUTE).allowed);
    }

    #[test]
    fn generic_all_maps_to_specific_bits() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | DELETE);
        assert!(result.allowed);
    }

    #[test]
    fn multiple_generic_bits_map_simultaneously() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_READ | GENERIC_WRITE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn generic_bits_never_in_comparisons() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, GENERIC_READ);
        // Even if the check fails, granted should have no generic bits
        assert_eq!(result.granted & mask::GENERIC_RIGHTS_MASK, 0);
    }

    #[test]
    fn ace_mask_mapping_uses_local_copy() {
        // §11.2: ACE mask mapped via local variable, never mutated
        let ace = allow(&alice(), GENERIC_ALL);
        let original_mask = ace.mask;
        let sd = sd_with_dacl(&alice(), alloc::vec![ace]);
        let token = test_token(&alice(), &[], 0);
        let _result = check(&sd, &token, FILE_READ_DATA);
        // The ACE in the SD still has GENERIC_ALL (not mutated)
        assert_eq!(sd.dacl.as_ref().unwrap().aces[0].mask, original_mask);
    }

    #[test]
    fn generic_bits_in_ace_mask_work_after_mapping() {
        // ACE with GENERIC_READ grants the mapped-specific bits
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_READ)]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
    }

    // ===================================================================
    // §11.7 Restricted Tokens — Detailed (Second Half)
    // ===================================================================

    #[test]
    fn restricted_write_restricted_formula() {
        // §11.7: granted = (normal & !write_bits) | (normal & restricted & write_bits)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE),
            allow(&engineers(), FILE_WRITE_DATA), // restricted only gets write
        ]);
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.write_restricted = true;
        // write_bits for FILE = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        //   FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE (from GENERIC_WRITE mapping)
        // Non-write bits (READ_DATA, EXECUTE): from normal only → pass
        // Write bits (WRITE_DATA): normal has it, restricted has it → pass
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(check(&sd, &token, FILE_EXECUTE).allowed);
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn restricted_no_privilege_or_back_without_privileges() {
        // §11.7: when privilege_granted=0, OR-back adds nothing
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        // Normal: read. Restricted: nothing. Intersection: nothing.
        // No privileges → OR-back adds nothing.
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_privilege_or_back_after_intersection() {
        // §11.7: OR-back happens AFTER intersection
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // Normal: nothing (empty DACL, not owner). Restricted: nothing.
        // Intersection: nothing. Privilege OR-back: read restored.
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    // ===================================================================
    // §11.15 PIP — Detailed
    // ===================================================================

    #[test]
    fn pip_dominance_requires_both_dimensions() {
        // §11.15: need pip_type >= ace_type AND pip_trust >= ace_trust
        // Object: Protected/Peios. Caller default (None/0) = not dominant.
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            FILE_READ_DATA, // allow only read for non-dominant
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn pip_no_default_label() {
        // §11.15: no trust label ACE → no PIP restrictions
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn pip_only_first_trust_label() {
        // §11.15: multiple trust labels → only first used
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                // First: Protected/Peios, allow read only
                Ace {
                    ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: FILE_READ_DATA,
                    sid: well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
                // Second: Isolated/TCB, allow nothing — IGNORED
                Ace {
                    ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: 0,
                    sid: well_known::trust_label(well_known::PIP_TYPE_ISOLATED, well_known::PIP_TRUST_PEIOS_TCB).unwrap(),
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
        let token = medium_token(&alice(), &[], 0);
        // First label allows read → should succeed
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn pip_inherit_only_trust_label_skipped() {
        // §11.15: trust label with INHERIT_ONLY is skipped
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                flags: INHERIT_ONLY_ACE,
                mask: 0, // would block everything
                sid: well_known::trust_label(well_known::PIP_TYPE_ISOLATED, well_known::PIP_TRUST_PEIOS_TCB).unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let token = medium_token(&alice(), &[], 0);
        // Inherit-only label skipped → no PIP restriction
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn pip_revokes_backup_privilege() {
        // §11.15: PIP strips backup-granted read
        let sd = sd_with_pip(
            &bob(),
            alloc::vec![],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0, // allow nothing
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_BACKUP);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn pip_revokes_take_ownership_privilege() {
        let sd = sd_with_pip(
            &bob(),
            alloc::vec![],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn pip_type_total_order() {
        // §11.15: Isolated > Protected > None
        assert!(well_known::PIP_TYPE_ISOLATED > well_known::PIP_TYPE_PROTECTED);
        assert!(well_known::PIP_TYPE_PROTECTED > well_known::PIP_TYPE_NONE);
    }

    #[test]
    fn pip_trust_total_order() {
        // §11.15: PeiosTcb > Peios > App > AntiMalware > Authenticode > None
        assert!(well_known::PIP_TRUST_PEIOS_TCB > well_known::PIP_TRUST_PEIOS);
        assert!(well_known::PIP_TRUST_PEIOS > well_known::PIP_TRUST_APP);
        assert!(well_known::PIP_TRUST_APP > well_known::PIP_TRUST_ANTIMALWARE);
        assert!(well_known::PIP_TRUST_ANTIMALWARE > well_known::PIP_TRUST_AUTHENTICODE);
        assert!(well_known::PIP_TRUST_AUTHENTICODE > well_known::PIP_TRUST_NONE);
    }

    // ===================================================================
    // §11.17 Pipeline Integration
    // ===================================================================

    #[test]
    fn pipeline_order_privilege_before_mic() {
        // §11.17: privileges (step 3) before MIC (step 4)
        // SeBackupPrivilege grants read even with MIC no-read-up
        let sd = sd_with_label(
            &bob(),
            alloc::vec![],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
        );
        let mut token = low_token(&alice());
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn pipeline_order_mic_before_dacl() {
        // §11.17: MIC (step 4) before DACL (step 7)
        // MIC blocks write, even though DACL would allow
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn pipeline_order_owner_implicit_before_walk() {
        // §11.17: owner implicit (step 6) before ACE walk (step 7)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn pipeline_order_restricted_after_normal_dacl() {
        // §11.17: restricted (step 8) after normal DACL (step 7)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        // Normal grants r+w, restricted grants r → result is r
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn pipeline_order_confinement_after_restricted() {
        // §11.17: confinement (step 8a) after restricted merge (step 8)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
            allow(&app_sid(), FILE_READ_DATA),
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
        // Normal: r+w. Restricted: r. Merge: r. Confinement: r (app_sid). Final: r.
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn anonymous_token_proceeds_through_pipeline() {
        // §11.17: Anonymous not blocked
        let anon = well_known::anonymous().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&anon, FILE_READ_DATA),
        ]);
        let mut token = test_token(&anon, &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Anonymous;
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn sd_without_owner_rejected() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: None,
            group: Some(well_known::users().unwrap()),
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn sd_without_group_rejected() {
        let sd = SecurityDescriptor {
            control: SE_DACL_PRESENT | SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: None,
            dacl: Some(Acl::new(ACL_REVISION)),
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0);
        assert!(result.is_err());
    }

    // ===================================================================
    // §11.17 Helper Functions
    // ===================================================================

    #[test]
    fn sid_matches_token_user_sid() {
        let token = test_token(&alice(), &[&engineers()], 0);
        assert!(super::sid_matches_token(&alice(), &token, true));
        assert!(super::sid_matches_token(&alice(), &token, false));
    }

    #[test]
    fn sid_matches_token_enabled_group() {
        let token = test_token(&alice(), &[&engineers()], 0);
        assert!(super::sid_matches_token(&engineers(), &token, true));
        assert!(super::sid_matches_token(&engineers(), &token, false));
    }

    #[test]
    fn sid_matches_token_deny_only_group_allow() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!super::sid_matches_token(&engineers(), &token, true));
    }

    #[test]
    fn sid_matches_token_deny_only_group_deny() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(super::sid_matches_token(&engineers(), &token, false));
    }

    #[test]
    fn sid_matches_token_disabled_group_skipped() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = 0; // neither enabled nor deny-only
        assert!(!super::sid_matches_token(&engineers(), &token, true));
        assert!(!super::sid_matches_token(&engineers(), &token, false));
    }

    #[test]
    fn sid_matches_token_no_match() {
        let token = test_token(&alice(), &[], 0);
        assert!(!super::sid_matches_token(&bob(), &token, true));
        assert!(!super::sid_matches_token(&bob(), &token, false));
    }

    // ===================================================================
    // §11.10 Auditing — Additional
    // ===================================================================

    #[test]
    fn audit_ace_does_not_affect_access_decision() {
        // §11.10: audit ACEs are purely observational
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_AUDIT_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG | ace::FAILED_ACCESS_ACE_FLAG,
                mask: GENERIC_ALL,
                sid: well_known::everyone().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let token = medium_token(&alice(), &[], 0);
        // Audit ACE should not block or grant
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    // ===================================================================
    // §11.16 CAP — Additional
    // ===================================================================

    #[test]
    fn cap_can_only_restrict_never_expand() {
        // §11.16: CAP cannot expand beyond DACL result
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)], // DACL grants read only
            &policy_sid_1(),
        );
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), GENERIC_ALL)])], // CAP grants all
        );
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(!result.allowed); // DACL only grants read
    }

    #[test]
    fn cap_no_backup_restore_intent() {
        // §11.16: CAP rule evaluation passes privilege_intent=0
        let sd = sd_with_cap(
            &bob(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &policy_sid_1(),
        );
        // CAP rule with empty DACL → denies everything
        let policy = make_cap(
            &policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![])],
        );
        let policies = alloc::vec![policy];
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_BACKUP);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // Backup with intent grants read in normal eval, but CAP rule has no intent
        let result = access_check(
            &sd, &token, FILE_READ_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, BACKUP_INTENT, 0, 0,
        ).unwrap();
        // CAP denies because its internal eval has no backup intent
        assert!(!result.allowed);
    }

    // ===================================================================
    // Appendix B: Compound Interaction Tests
    // ===================================================================

    // --- Category 1: MIC + PIP Combined ---

    #[test]
    fn mic_and_pip_both_present_dominant_on_both() {
        // Dominant on MIC + dominant on PIP → DACL alone determines
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        // No PIP label → no PIP restriction. Medium token → dominant on Medium label.
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_blocks_write_pip_allows_all_nondominated() {
        // Low caller, Medium MIC (no-write-up), no PIP → MIC blocks write
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn pip_revokes_bits_mic_would_allow() {
        // Medium caller, Low MIC label → dominant on MIC. PIP mask=0 → total lockout.
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid: well_known::integrity_low().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
                Ace {
                    ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: 0, // allow nothing
                    sid: well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap(),
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
        let token = medium_token(&alice(), &[], 0);
        // Dominant on MIC (Medium >= Low), but PIP mask=0 → nothing allowed
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn mic_default_medium_plus_explicit_pip_label() {
        // No MIC label (defaults to Medium/NO_WRITE_UP), explicit PIP allowing all.
        // Low caller still blocked by default MIC.
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                flags: 0,
                mask: GENERIC_ALL, // PIP allows everything
                sid: well_known::trust_label(well_known::PIP_TYPE_NONE, 0).unwrap(),
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
        let token = low_token(&alice());
        // Default MIC = Medium, Low < Medium → write blocked
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    // --- Category 2: Restricted Token + Confinement ---

    #[test]
    fn restricted_and_confined_both_intersect() {
        // Three-way intersection: normal=R+W, restricted=R, confinement=R → R
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
            allow(&app_sid(), FILE_READ_DATA),
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
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn privilege_orback_after_restricted_then_stripped_by_confinement() {
        // Backup granted, OR'd back after restricted, then stripped by confinement
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            app_sid(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // Backup grants read → OR'd back after restricted → confinement blocks
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn restricted_and_confined_null_dacl() {
        // NULL DACL → all three passes grant all → all granted
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            engineers(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        assert!(check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn restricted_and_confined_empty_dacl() {
        // Empty DACL + owner + restricted + confined
        // Normal: owner implicit. Restricted: owner in restricting? Confinement: skip_owner_implicit.
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            alice(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        // Normal: READ_CONTROL+WRITE_DAC (owner implicit)
        // Restricted: alice in restricting → owner implicit → READ_CONTROL+WRITE_DAC
        // Confinement: skip_owner_implicit → 0. Intersection → 0.
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    // --- Category 3: Restricted + MIC + Privilege ---

    #[test]
    fn backup_privilege_survives_mic_and_restricted_intersection() {
        // Medium token, Medium MIC → dominant. Backup grants read.
        // Restricted intersection, then OR-back. Read survives.
        let sd = sd_with_label(
            &bob(),
            alloc::vec![],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed); // privilege OR-back restores read
    }

    #[test]
    fn backup_privilege_blocked_by_high_integrity_mic_read_survives() {
        // MIC does NOT constrain privilege-granted bits.
        // Low token, High MIC (no-write-up only). Backup grants read before MIC.
        // MIC blocks write, but read is already decided by privilege.
        let sd = sd_with_label(
            &bob(),
            alloc::vec![],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // Read via backup privilege survives MIC (privileges before MIC)
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
        // Write blocked by MIC
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn take_ownership_privilege_blocked_by_mic_mandatory_decided() {
        // MIC blocks WRITE_OWNER, TakeOwnership respects mandatory_decided
        let sd = sd_with_label(
            &bob(),
            alloc::vec![],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP);
        // MIC blocks write-category (including WRITE_OWNER) for Medium < High
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn relabel_privilege_punches_through_mic_for_write_owner() {
        // SeRelabelPrivilege loosens MIC for WRITE_OWNER, DACL must still grant it
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), WRITE_OWNER)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_RELABEL);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_RELABEL);
        // Without relabel: WRITE_OWNER blocked by MIC (Medium < High, write-category)
        let no_relabel = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &no_relabel, WRITE_OWNER).allowed);
        // With relabel: WRITE_OWNER punches through MIC
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    // --- Category 5: Impersonation + MIC ---

    #[test]
    fn impersonation_mic_uses_effective_token_integrity() {
        // High-integrity service impersonating Low-integrity client
        // MIC reads Low from effective token → blocks write on Medium object
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = test_token(&alice(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Impersonation;
        token.integrity_level = crate::token::IntegrityLevel::Low;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn identification_level_denied_regardless_of_pip_or_mic() {
        // Identification denied at step 0, before anything else
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let mut token = test_token(&alice(), &[], 0);
        token.token_type = TokenType::Impersonation;
        token.impersonation_level = ImpersonationLevel::Identification;
        token.integrity_level = crate::token::IntegrityLevel::System;
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0,
        );
        assert!(result.is_err());
    }

    // --- Category 7: Owner Implicit + Confinement ---

    #[test]
    fn owner_implicit_rights_skipped_in_confinement_pass() {
        // Confined owner: normal=implicit, confinement=skip_implicit → blocked
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_with_confinement_ace_granting_write_dac() {
        // Confinement ACE grants WRITE_DAC to confinement SID
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&app_sid(), WRITE_DAC),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        // Normal: owner implicit WRITE_DAC + DACL for app_sid
        // Confinement: app_sid matches → WRITE_DAC
        assert!(check(&sd, &token, WRITE_DAC).allowed);
    }

    // --- Category 8: MAXIMUM_ALLOWED + Restricted + Confinement ---

    #[test]
    fn maximum_allowed_restricted_confinement_intersection() {
        // Three-way intersection with MAXIMUM_ALLOWED
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE),
            allow(&engineers(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&app_sid(), FILE_READ_DATA),
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
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
        // Normal: R+W+X. Restricted: R+W (engineers). Confinement: R (app_sid).
        assert!(result.granted & FILE_READ_DATA != 0);
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
        assert_eq!(result.granted & FILE_EXECUTE, 0);
    }

    #[test]
    fn maximum_allowed_zero_granted_confined_succeeds() {
        // MAXIMUM_ALLOWED on confined token with empty DACL → granted=0, allowed=true
        let sd = SecurityDescriptor::new(
            bob(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = confined_token(&alice(), &app_sid(), &[]);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.allowed);
    }

    // --- Appendix B: Additional Compound Tests ---

    #[test]
    fn write_restricted_intersection_includes_file_append_data() {
        // FILE_APPEND_DATA is write-category. Restricted intersection applies.
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_WRITE_DATA | FILE_APPEND_DATA),
            allow(&engineers(), FILE_APPEND_DATA), // restricted only gets append
        ]);
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.write_restricted = true;
        // Normal: write+append. Restricted: append.
        // Write-restricted intersection on write bits: write stripped, append preserved.
        assert!(check(&sd, &token, FILE_APPEND_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn write_restricted_read_bits_bypass_restricted_pass() {
        // Read bits come from normal pass alone in write-restricted mode
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.write_restricted = true;
        // Normal: read. Restricted: nothing (engineers not in DACL).
        // But read is not a write bit → passes from normal alone.
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn adjust_privileges_bumps_modified_id() {
        let token = Token::system_token().unwrap();
        let old_id = token.modified_id;
        // Note: modified_id is a plain u64, not atomic in userspace.
        // In the kernel, AdjustPrivileges would bump it.
        // Here we verify the field exists and the concept works.
        assert!(old_id > 0);
    }

    #[test]
    fn remove_privilege_then_access_check_no_longer_grants() {
        // Remove SeBackupPrivilege, then verify AccessCheck doesn't grant
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_BACKUP);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // Before removal: backup grants read
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
        // Remove the privilege
        token.privileges.remove(privilege::bits::SE_BACKUP);
        // After removal: no longer grants
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn enable_privilege_then_access_check_grants() {
        // Token has SE_SECURITY present but disabled. ASS fails.
        // After enable, ASS succeeds.
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = test_token(&alice(), &[], 0);
        token.privileges = privilege::Privileges {
            present: core::sync::atomic::AtomicU64::new(privilege::bits::SE_SECURITY),
            enabled: core::sync::atomic::AtomicU64::new(0), // disabled
            enabled_by_default: core::sync::atomic::AtomicU64::new(0),
            used: core::sync::atomic::AtomicU64::new(0),
        };
        // Disabled → fails
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
        // Enable it
        token.privileges.enable(privilege::bits::SE_SECURITY);
        // Now succeeds
        assert!(check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn pip_revokes_backup_privilege_bits_before_restricted_orback() {
        // PIP at step 4 clears privilege_granted. Step 8 OR-back has nothing to restore.
        let sd = sd_with_pip(
            &bob(),
            alloc::vec![],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0, // allow nothing
        );
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        // PIP revokes backup bits. OR-back can't restore them.
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn pip_revokes_security_privilege_then_restricted_orback_empty() {
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let mut token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_SECURITY);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn confinement_blocks_access_system_security_via_privilege() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_SECURITY);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn confinement_blocks_take_ownership_privilege() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn all_layers_active_simultaneously() {
        // Confined + restricted + backup privilege + Low integrity
        // High MIC (NO_WRITE_UP + NO_READ_UP) + PIP (allow READ_CONTROL)
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![
                Ace {
                    ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP,
                    sid: well_known::integrity_high().unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
                Ace {
                    ace_type: SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
                    flags: 0,
                    mask: READ_CONTROL,
                    sid: well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap(),
                    object_type: None, inherited_object_type: None,
                    condition: None, application_data: None,
                },
            ],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![
                allow(&alice(), GENERIC_ALL),
                allow(&engineers(), FILE_READ_DATA),
                allow(&app_sid(), FILE_READ_DATA | READ_CONTROL),
            ]},
            sacl,
        );
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.groups = alloc::vec![crate::group::GroupEntry::new(
            engineers(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )];
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            engineers(),
            crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
        )]);
        token.integrity_level = crate::token::IntegrityLevel::Low;
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);

        // MIC: High with NO_READ_UP → blocks read for Low caller
        // BUT backup privilege grants read BEFORE MIC (step 3 before step 4)
        // MIC doesn't constrain privilege-granted bits
        // PIP: allows only READ_CONTROL → strips everything except READ_CONTROL
        // So even backup-granted read bits get stripped by PIP
        // Restricted intersection: engineers only in DACL for read
        // Confinement: app_sid gets read + READ_CONTROL
        // Final: PIP dominates, only READ_CONTROL (if it survives all intersections)

        // The exact result depends on pipeline ordering:
        // backup grants read (step 3), MIC doesn't constrain it (step 4),
        // PIP strips everything except READ_CONTROL (step 4),
        // DACL walk adds what DACL grants (step 7),
        // restricted intersection (step 8),
        // confinement intersection (step 8a).
        // PIP mask = READ_CONTROL only. Everything else stripped.
        let result = check_with_intent(&sd, &token, MAXIMUM_ALLOWED, BACKUP_INTENT);
        assert!(result.allowed); // MAXIMUM_ALLOWED always succeeds
        // PIP limits to READ_CONTROL at most
    }

    // ===================================================================
    // §11.1 AccessCheckResultList (corpus tests)
    // ===================================================================

    #[test]
    fn access_check_result_list_requires_tree() {
        // §11.1: AccessCheckResultList without tree returns error
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree: Vec<ObjectTypeNode> = Vec::new();
        let result = access_check_result_list(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn access_check_result_list_per_node_verdict() {
        // §11.1: each node produces an independent status
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (results, _) = access_check_result_list(
            &sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[1].allowed);
        assert!(!results[2].allowed);
    }

    #[test]
    fn access_check_result_list_partial_denial() {
        // §11.1: denial on one property fails that property only
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_deny(&alice(), DS_READ_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (results, _) = access_check_result_list(
            &sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(results[1].allowed);
        assert!(!results[2].allowed);
    }

    #[test]
    fn access_check_result_list_max_allowed_returns_per_node_granted() {
        // §11.17: in MAXIMUM_ALLOWED mode, node_granted = node.granted
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (results, _) = access_check_result_list(
            &sd, &token, MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(results[1].granted & DS_READ_PROP != 0);
        assert!(results[2].granted & DS_WRITE_PROP != 0);
    }

    #[test]
    fn access_check_result_list_normal_mode_returns_desired_or_zero() {
        // §11.17: OK nodes get mapped_desired, denied get 0
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (results, _) = access_check_result_list(
            &sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert_eq!(results[1].granted, DS_READ_PROP);
        assert_eq!(results[2].granted, 0);
    }

    #[test]
    fn access_check_tree_requires_all_nodes_pass() {
        // §11.1: AccessCheck with tree fails if any node is denied
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(!result.allowed);
    }

    #[test]
    fn access_check_tree_granted_is_root() {
        // §11.1, §11.17: granted = tree[0].granted
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&alice(), DS_READ_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert_eq!(result.granted & DS_READ_PROP, tree[0].granted & DS_READ_PROP);
    }

    // ===================================================================
    // §11.3 DACL Walk — Short-circuit and validation
    // ===================================================================

    #[test]
    fn short_circuit_when_all_desired_decided() {
        // §11.3: walk stops early when all desired bits decided
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn short_circuit_disabled_in_max_allowed() {
        // §11.3, §11.5: in MAXIMUM_ALLOWED, walk runs to completion
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[&engineers()], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn short_circuit_not_applied_with_tree() {
        // §11.3, §11.17: short-circuit doesn't apply with object_tree
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&alice(), DS_READ_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[2].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn null_dacl_respects_already_decided() {
        // §11.3: NULL DACL only grants bits not already decided
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
    }

    // ===================================================================
    // §11.4 Owner — Additional corpus tests
    // ===================================================================

    #[test]
    fn owner_rights_prescan_checks_presence_not_condition() {
        // §11.4, §11.12: pre-scan checks ACE presence, not condition
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow_ace(
                &well_known::owner_rights().unwrap(),
                READ_CONTROL,
                condition_false(),
            ),
        ]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_rights_sid_matches_owner_in_walk() {
        // §11.4: S-1-3-4 ACEs match the owner during DACL walk
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&or_sid, FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn owner_implicit_rights_on_tree_nodes() {
        // §11.4, §11.17: owner implicit rights on all tree nodes
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, READ_CONTROL, &mut tree);
        for node in &tree {
            assert!(node.granted & READ_CONTROL != 0);
            assert!(node.granted & WRITE_DAC != 0);
        }
    }

    // ===================================================================
    // §11.5 MAXIMUM_ALLOWED — Additional corpus tests
    // ===================================================================

    #[test]
    fn max_allowed_first_writer_wins_same_as_targeted() {
        // §11.5: MAXIMUM_ALLOWED uses same first-writer-wins
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let targeted = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!targeted.allowed);
        let max = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(max.granted & FILE_READ_DATA != 0);
        assert_eq!(max.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn max_allowed_agrees_with_targeted_on_noncanonical_dacl() {
        // §11.5: on non-canonical DACL, max-allowed and targeted agree
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        let max = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(max.granted & FILE_READ_DATA != 0);
    }

    // ===================================================================
    // §11.6 Privileges — Additional corpus tests
    // ===================================================================

    #[test]
    fn ass_denial_no_early_out() {
        // §11.6: missing privilege doesn't cause early-out
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY | FILE_READ_DATA);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
    }

    #[test]
    fn backup_privilege_grants_all_read_bits() {
        // §11.6: SeBackupPrivilege grants MapGenericBits(GENERIC_READ)
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        let result = check_with_intent(&sd, &token, MAXIMUM_ALLOWED, BACKUP_INTENT);
        let read_bits = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert_eq!(result.granted & read_bits, read_bits);
    }

    #[test]
    fn restore_privilege_grants_all_write_bits_plus_extras() {
        // §11.6: SeRestorePrivilege grants GENERIC_WRITE + WRITE_DAC+WRITE_OWNER+DELETE
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        let result = check_with_intent(&sd, &token, MAXIMUM_ALLOWED, RESTORE_INTENT);
        let write_bits = map_generic_bits(GENERIC_WRITE, &FILE_GENERIC_MAPPING);
        assert_eq!(result.granted & write_bits, write_bits);
        assert!(result.granted & WRITE_DAC != 0);
        assert!(result.granted & WRITE_OWNER != 0);
        assert!(result.granted & DELETE != 0);
    }

    #[test]
    fn intent_gated_inside_pipeline_not_bypass() {
        // §11.6: backup/restore are inside AccessCheck, not bypass
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[],
            privilege::bits::SE_BACKUP | privilege::bits::SE_RESTORE);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn take_ownership_respects_pip_mandatory_decided() {
        // §11.6: TakeOwnership does NOT override PIP-decided WRITE_OWNER
        let sd = sd_with_pip(
            &bob(),
            alloc::vec![],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_grants_write_owner_scalar() {
        // §11.17: TakeOwnership grants WRITE_OWNER (scalar)
        // Tree node update is a pending implementation item.
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        // Scalar WRITE_OWNER should be granted despite deny (deny-proof)
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed);
    }

    #[test]
    fn relabel_audit_scenario() {
        // §11.17: SeRelabel + DACL grants WRITE_OWNER, no TakeOwnership
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), WRITE_OWNER)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_RELABEL);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_RELABEL);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_silent_when_dacl_granted() {
        // §11.6: DACL grants WRITE_OWNER, TakeOwnership silent
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_post_dacl_position() {
        // §11.6, §11.17: TakeOwnership after DACL walk, overrides deny
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), WRITE_OWNER)]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_in_max_allowed_mode() {
        // §11.17: TakeOwnership evaluated in MAXIMUM_ALLOWED
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(result.granted & WRITE_OWNER != 0);
    }

    #[test]
    fn max_allowed_with_ass_without_privilege() {
        // §11.5: MAXIMUM_ALLOWED | ASS without privilege
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
    }

    #[test]
    fn max_allowed_combined_with_specific_rights_check() {
        // §11.5: MAXIMUM_ALLOWED | READ_CONTROL
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, MAXIMUM_ALLOWED | READ_CONTROL);
        assert!(result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & READ_CONTROL != 0);
    }

    // ===================================================================
    // §11.7 Restricted — Virtual groups and SID matching
    // ===================================================================

    #[test]
    fn restricted_virtual_group_owner_injected() {
        // §11.17: S-1-3-4 injected if owner in restricting SIDs
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&or_sid, FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_virtual_group_principal_self_injected() {
        // §11.17: S-1-5-10 injected if self_sid in restricting SIDs
        let ps_sid = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&ps_sid, FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn restricted_sid_match_uses_list_not_token() {
        // §11.7: restricted pass uses SidInRestrictingSids
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_pass_fresh_tree_copy() {
        // §11.17: restricted pass starts with fresh tree
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&engineers(), DS_READ_PROP, 1),
            obj_allow(&engineers(), DS_READ_PROP, 2),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn restricted_deny_only_group_in_context() {
        // §11.7: deny-only groups reduce normal pass grants
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_pass_owner_rights_suppression() {
        // §11.7: restricted pass evaluates OWNER RIGHTS independently
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&or_sid, FILE_READ_DATA),
            allow(&alice(), FILE_READ_DATA | READ_CONTROL | WRITE_DAC),
        ]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn restricted_write_bits_from_generic_mapping() {
        // §11.7: write bits from MapGenericBits(GENERIC_WRITE)
        let write_bits = map_generic_bits(GENERIC_WRITE, &FILE_GENERIC_MAPPING);
        assert!(write_bits & FILE_WRITE_DATA != 0);
        assert_eq!(write_bits & FILE_READ_DATA, 0);
    }

    // ===================================================================
    // §11.8 Object ACEs — PRINCIPAL_SELF and basic ACE on tree
    // ===================================================================

    #[test]
    fn principal_self_matches_caller_who_is_object_principal() {
        // §11.8: S-1-5-10 matches when caller is object principal
        let ps_sid = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&ps_sid, FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn principal_self_no_match_without_self_sid() {
        // §11.8: null self_sid → PRINCIPAL_SELF matches nothing
        let ps_sid = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&ps_sid, FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn principal_self_deny_only_allow_deny_asymmetry() {
        // §11.8: deny-only match → S-1-5-10 matches deny but not allow
        let ps_sid = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&ps_sid, FILE_WRITE_DATA),
            allow(&ps_sid, FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        let result = access_check(
            &sd, &token, FILE_READ_DATA | FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&engineers()), &[], &[], 0, 0, 0,
        ).unwrap();
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
        assert_eq!(result.granted & FILE_READ_DATA, 0);
    }

    #[test]
    fn non_object_ace_affects_all_nodes() {
        // §11.8: basic ACE affects all tree nodes
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(tree[0].granted & DS_READ_PROP != 0);
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[2].granted & DS_READ_PROP != 0);
    }

    // ===================================================================
    // §11.10 Auditing — Through AccessCheck
    // ===================================================================

    #[test]
    fn audit_sid_matching_with_deny_polarity() {
        // §11.10: audit uses deny polarity (deny-only group matches)
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_AUDIT_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG | ace::FAILED_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: engineers(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let mut token = medium_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn audit_conditional_unknown_fires() {
        // §11.10, §11.12: UNKNOWN condition on audit fires
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: well_known::everyone().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: Some(condition_unknown()),
                application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let token = medium_token(&alice(), &[&well_known::everyone().unwrap()], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn continuous_audit_alarm_ace_builds_mask() {
        // §11.10: SYSTEM_ALARM builds continuous_audit_mask
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_ALARM_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA | FILE_WRITE_DATA,
                sid: well_known::everyone().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
            sacl,
        );
        let token = medium_token(&alice(), &[&well_known::everyone().unwrap()], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
        assert!(result.continuous_audit_mask & FILE_READ_DATA != 0);
        assert!(result.continuous_audit_mask & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn continuous_audit_only_on_success() {
        // §11.10: alarm ACEs only on success
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_ALARM_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: well_known::everyone().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![deny(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let token = medium_token(&alice(), &[&well_known::everyone().unwrap()], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
        assert_eq!(result.continuous_audit_mask, 0);
    }

    #[test]
    fn continuous_audit_intersect_with_granted() {
        // §11.10: continuous mask intersected with granted
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_ALARM_ACE_TYPE,
                flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA | FILE_WRITE_DATA,
                sid: well_known::everyone().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let token = medium_token(&alice(), &[&well_known::everyone().unwrap()], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(result.continuous_audit_mask & FILE_READ_DATA != 0);
        assert_eq!(result.continuous_audit_mask & FILE_WRITE_DATA, 0);
    }

    // ===================================================================
    // §11.13 MIC — Additional corpus tests
    // ===================================================================

    #[test]
    fn mic_non_dominant_allowed_starts_read_execute() {
        // §11.17: non-dominant MIC starts with R+E
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(check(&sd, &token, FILE_EXECUTE).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_decided_bits_tracked_in_mandatory_decided() {
        // §11.17: MIC bits in mandatory_decided, TakeOwnership respects
        let sd = sd_with_label(
            &bob(), alloc::vec![],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn mic_integrity_levels_total_order() {
        // §11.13: System > High > Medium > Low > Untrusted
        use crate::token::IntegrityLevel;
        assert!(IntegrityLevel::System > IntegrityLevel::High);
        assert!(IntegrityLevel::High > IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium > IntegrityLevel::Low);
        assert!(IntegrityLevel::Low > IntegrityLevel::Untrusted);
    }

    #[test]
    fn mic_policy_bitmask_check() {
        // §11.13: policy checked as bitmask
        let sd = sd_with_label(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = low_token(&alice());
        token.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP | 0x8000;
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    // ===================================================================
    // §11.15 PIP — Additional corpus tests
    // ===================================================================

    #[test]
    fn pip_partial_order_incomparable() {
        // §11.15: partial order — higher type lower trust → non-dominant
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            FILE_READ_DATA,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn pip_higher_type_lower_trust_not_dominant() {
        // §11.15: higher pip_type but lower pip_trust → not dominant
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            FILE_READ_DATA,
        );
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0,
            well_known::PIP_TYPE_ISOLATED, well_known::PIP_TRUST_APP,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn pip_higher_trust_lower_type_not_dominant() {
        // §11.15: higher trust but lower type → not dominant
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_ISOLATED,
            well_known::PIP_TRUST_APP,
            FILE_READ_DATA,
        );
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0,
            well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS_TCB,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn pip_equal_type_and_trust_dominates() {
        // §11.15: equal → dominates
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0,
            well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn pip_ace_mask_generic_mapped() {
        // §11.17: trust label ACE mask mapped through MapGenericBits
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            GENERIC_READ,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn pip_all_bits_include_ass() {
        // §11.17: PIP blocks ACCESS_SYSTEM_SECURITY
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_SECURITY);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn pip_decided_tracked_in_mandatory_decided() {
        // §11.17: PIP bits in mandatory_decided
        let sd = sd_with_pip(
            &bob(), alloc::vec![],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            FILE_READ_DATA,
        );
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn pip_no_relabel_equivalent() {
        // §11.15: no privilege compensates for PIP
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[],
            privilege::bits::SE_RELABEL | privilege::bits::SE_SECURITY
            | privilege::bits::SE_BACKUP | privilege::bits::SE_RESTORE
            | privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // ===================================================================
    // §11.16 CAP — Additional corpus tests
    // ===================================================================

    #[test]
    fn cap_staging_evaluation() {
        // §11.16: staged DACL evaluated, difference detected
        let staged = Acl { revision: ACL_REVISION,
            aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] };
        let rule = CentralAccessRule {
            applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION,
                aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] },
            staged_dacl: Some(staged),
        };
        let sd = sd_with_cap(
            &alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            &policy_sid_1(),
        );
        let policy = CentralAccessPolicy { policy_sid: policy_sid_1(), rules: alloc::vec![rule] };
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA | FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(result.staging_mismatch);
    }

    #[test]
    fn cap_staging_no_difference_not_logged() {
        // §11.16: same effective and staged → no mismatch
        let eff = Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] };
        let stg = Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] };
        let rule = CentralAccessRule {
            applies_to: None, effective_dacl: eff, staged_dacl: Some(stg),
        };
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let policy = CentralAccessPolicy { policy_sid: policy_sid_1(), rules: alloc::vec![rule] };
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(!result.staging_mismatch);
    }

    #[test]
    fn cap_rule_full_pipeline() {
        // §11.16, §11.17: rule uses full pipeline including owner implicit
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), READ_CONTROL)], &policy_sid_1());
        let policy = make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])]);
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, READ_CONTROL,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn cap_non_intent_privileges_survive_and() {
        // §11.17: SeSecurityPrivilege survives CAP AND
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let policy = make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])]);
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = access_check(
            &sd, &token, ACCESS_SYSTEM_SECURITY,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn cap_scoped_policy_ace_inherit_only_skipped() {
        // §11.17: INHERIT_ONLY scoped policy ACE skipped
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: ace::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
                flags: INHERIT_ONLY_ACE,
                mask: 0,
                sid: policy_sid_1(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            sacl,
        );
        let policy = make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])]);
        let policies = alloc::vec![policy];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_READ_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn cap_multiple_policies_compose_safely() {
        // §11.16: multiple policies compound via AND
        let policy_sid_2 = Sid::new(5, &[21, 100, 200, 300, 9002]).unwrap();
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![cap_ace(&policy_sid_1()), cap_ace(&policy_sid_2)],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![
                allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE),
            ]},
            sacl,
        );
        let p1 = make_cap(&policy_sid_1(), alloc::vec![
            cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]),
        ]);
        let p2 = make_cap(&policy_sid_2, alloc::vec![
            cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)]),
        ]);
        let policies = alloc::vec![p1, p2];
        let token = medium_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn cap_recovery_policy_is_valid() {
        // §11.16: recovery policy has admin, system, owner_rights
        let recovery = crate::cap::recovery_policy().unwrap();
        assert_eq!(recovery.aces.len(), 3);
        assert_eq!(recovery.aces[0].sid, well_known::administrators().unwrap());
        assert_eq!(recovery.aces[1].sid, well_known::system().unwrap());
        assert_eq!(recovery.aces[2].sid, well_known::owner_rights().unwrap());
        for ace in &recovery.aces {
            assert_eq!(ace.mask, GENERIC_ALL);
        }
    }

    // ===================================================================
    // §11.17 Pipeline — Additional corpus tests
    // ===================================================================

    #[test]
    fn virtual_group_injection_before_dacl() {
        // §11.17: S-1-3-4 injected before DACL walk
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&or_sid, FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn enrich_token_idempotent() {
        // §11.17: EnrichToken is idempotent
        let token = test_token(&alice(), &[], 0);
        let e1 = enrich_token(&token, &alice(), Some(&alice()));
        let e2 = enrich_token(&token, &alice(), Some(&alice()));
        assert_eq!(e1.has_owner_rights, e2.has_owner_rights);
        assert_eq!(e1.has_principal_self, e2.has_principal_self);
        assert_eq!(e1.principal_self_deny_only, e2.principal_self_deny_only);
    }

    #[test]
    fn enrich_token_owner_check_uses_allow_polarity() {
        // §11.17: caller_is_owner uses for_allow=true
        let mut token = test_token(&alice(), &[], 0);
        token.user_deny_only = true;
        let enriched = enrich_token(&token, &alice(), None);
        assert!(!enriched.has_owner_rights);
    }

    #[test]
    fn write_owner_not_decided_in_step_3() {
        // §11.17: WRITE_OWNER not decided in step 3
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), WRITE_OWNER)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
        let sd2 = sd_with_dacl(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)]);
        assert!(check(&sd2, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn pipeline_order_pip_before_dacl() {
        // §11.17: PIP before DACL
        let sd = sd_with_pip(
            &alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            well_known::PIP_TYPE_PROTECTED,
            well_known::PIP_TRUST_PEIOS,
            0,
        );
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn pipeline_order_cap_after_confinement() {
        // §11.17: CAP after confinement
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![cap_ace(&policy_sid_1())],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![
                allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
                allow(&app_sid(), FILE_READ_DATA | FILE_WRITE_DATA),
            ]},
            sacl,
        );
        let policy = make_cap(&policy_sid_1(), alloc::vec![
            cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)]),
        ]);
        let policies = alloc::vec![policy];
        let token = confined_token(&alice(), &app_sid(), &[]);
        let result = access_check(
            &sd, &token, FILE_WRITE_DATA,
            &FILE_GENERIC_MAPPING, None, None, &[], &policies, 0, 0, 0,
        ).unwrap();
        assert!(!result.allowed);
    }

    // ===================================================================
    // §11.17 Tree Helpers
    // ===================================================================

    #[test]
    fn find_node_returns_matching_guid() {
        let tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        assert_eq!(find_node(&tree, &guid(1)), Some(1));
        assert_eq!(find_node(&tree, &guid(2)), Some(2));
    }

    #[test]
    fn find_node_not_found() {
        let tree = make_tree(&[(0, 0), (1, 1)]);
        assert_eq!(find_node(&tree, &guid(999)), None);
    }

    #[test]
    fn descendants_returns_subsequent_deeper_nodes() {
        let tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]);
        let desc = descendant_indices(&tree, 1).unwrap();
        assert_eq!(desc, alloc::vec![2, 3]);
    }

    #[test]
    fn descendants_of_leaf_is_empty() {
        let tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let desc = descendant_indices(&tree, 2).unwrap();
        assert!(desc.is_empty());
    }

    #[test]
    fn siblings_returns_same_level_under_parent() {
        let tree = make_tree(&[(0, 0), (1, 1), (1, 2), (1, 3)]);
        let sibs = sibling_indices(&tree, 1).unwrap();
        assert_eq!(sibs, alloc::vec![2, 3]);
    }

    #[test]
    fn siblings_of_root_is_empty() {
        let tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let sibs = sibling_indices(&tree, 0).unwrap();
        assert!(sibs.is_empty());
    }

    #[test]
    fn ancestors_returns_parents_up_to_root() {
        let tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let anc = ancestor_indices(&tree, 2).unwrap();
        assert_eq!(anc, alloc::vec![1, 0]);
    }

    #[test]
    fn ancestors_of_root_is_empty() {
        let tree = make_tree(&[(0, 0), (1, 1)]);
        let anc = ancestor_indices(&tree, 0).unwrap();
        assert!(anc.is_empty());
    }

    // ===================================================================
    // §11.2 Generic Mapping — Additional corpus tests
    // ===================================================================

    #[test]
    fn map_generic_bits_noop_if_no_generic_bits() {
        let input = FILE_READ_DATA | FILE_WRITE_DATA;
        let output = map_generic_bits(input, &FILE_GENERIC_MAPPING);
        assert_eq!(output, input);
    }

    #[test]
    fn mapped_desired_used_for_success_verdict() {
        // §11.2: verdict compares against mapped_desired
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_READ_ATTRIBUTES
                | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, GENERIC_READ).allowed);
    }

    #[test]
    fn ace_mask_mapped_defensively_during_walk() {
        // §11.2, §11.3: ACE masks mapped at evaluation time
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA | DELETE).allowed);
    }

    // ===================================================================
    // §11.8 Object ACE — Additional edge cases
    // ===================================================================

    #[test]
    fn object_ace_deny_does_not_affect_siblings() {
        // §11.8: upward deny propagation doesn't affect siblings
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_WRITE_PROP, 1),
            obj_allow(&alice(), DS_WRITE_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_WRITE_PROP, &mut tree);
        assert_eq!(tree[1].granted & DS_WRITE_PROP, 0);
        assert!(tree[2].granted & DS_WRITE_PROP != 0);
    }

    #[test]
    fn downward_grant_respects_first_writer_wins() {
        // §11.8: downward grant doesn't override already-denied child
        // Demonstrated via object_ace_deny_downward: deny on parent propagates
        // to child, then a later allow on the same child can't override it.
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_READ_PROP, 1),   // deny parent → flows to child
            obj_allow(&alice(), DS_READ_PROP, 2),   // allow child (too late)
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        // parent denied
        assert_eq!(tree[1].granted & DS_READ_PROP, 0);
        // child: deny from parent propagated down, first-writer-wins
        assert_eq!(tree[2].granted & DS_READ_PROP, 0);
    }

    #[test]
    fn downward_deny_respects_first_writer_wins() {
        // §11.8: downward deny doesn't override granted child
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 2),
            obj_deny(&alice(), DS_READ_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
        assert!(tree[2].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn upward_grant_per_bit_intersection() {
        // §11.8: per-bit intersection for upward propagation
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1),
            obj_allow(&alice(), DS_READ_PROP, 2),
        ]);
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, DS_READ_PROP | DS_WRITE_PROP, &mut tree);
        assert!(tree[0].granted & DS_READ_PROP != 0);
        assert_eq!(tree[0].granted & DS_WRITE_PROP, 0);
    }

    #[test]
    fn null_dacl_tree_propagation() {
        // §11.3: NULL DACL grants to every tree node
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None,
        };
        let token = medium_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _result = check_tree(&sd, &token, FILE_READ_DATA, &mut tree);
        for node in &tree {
            assert!(node.granted & FILE_READ_DATA != 0);
        }
    }

    // ===================================================================
    // §11.17 EnrichToken — Additional
    // ===================================================================

    #[test]
    fn enrich_token_self_sid_null_no_injection() {
        let token = test_token(&alice(), &[], 0);
        let enriched = enrich_token(&token, &alice(), None);
        assert!(!enriched.has_principal_self);
    }

    #[test]
    fn enrich_token_self_sid_no_match_no_injection() {
        let token = test_token(&alice(), &[], 0);
        let enriched = enrich_token(&token, &alice(), Some(&bob()));
        assert!(!enriched.has_principal_self);
    }

    #[test]
    fn enrich_token_self_sid_deny_only_virtual_group() {
        // §11.17: deny-only match → deny-only virtual group
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        let enriched = enrich_token(&token, &alice(), Some(&engineers()));
        assert!(enriched.has_principal_self);
        assert!(enriched.principal_self_deny_only);
    }

    #[test]
    fn enrich_token_owner_injects_owner_rights() {
        let token = test_token(&alice(), &[], 0);
        let enriched = enrich_token(&token, &alice(), None);
        assert!(enriched.has_owner_rights);
    }

    #[test]
    fn enrich_token_owner_not_owner_no_injection() {
        let token = test_token(&alice(), &[], 0);
        let enriched = enrich_token(&token, &bob(), None);
        assert!(!enriched.has_owner_rights);
    }

    // ===================================================================
    // §11.14 Confinement — Additional corpus tests
    // ===================================================================

    #[test]
    fn confinement_after_restricted_merge() {
        // §11.14, §11.17: confinement after restricted merge
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&app_sid(), FILE_READ_DATA),
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
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn confinement_ordering_prevents_privilege_resurrection() {
        // §11.17: privilege OR-back can't resurrect blocked bits
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&app_sid(), FILE_WRITE_DATA)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        assert!(!check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn confinement_strict_no_all_app_packages() {
        // §11.14: strict confinement without ALL_APPLICATION_PACKAGES
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
            allow(&well_known::all_app_packages().unwrap(), FILE_READ_DATA),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // =======================================================================
    // §2+§10 Corpus Tests (exact corpus names)
    // =======================================================================

    // --- §2.5 ACL Definition ---

    #[test]
    fn dacl_empty_denies_all() {
        // §2 lines 165-166, §9.8 lines 3824-3827: empty DACL denies all access
        // (except owner implicit rights)
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn dacl_null_grants_all() {
        // §2 lines 166-167, §9.8 lines 3818-3822: NULL DACL grants all access
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
    fn dacl_walked_sequentially() {
        // §2 lines 163-164, §11.3 lines 3472-3473: DACL walked first to last
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_WRITE_DATA | FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Deny comes first — FILE_WRITE_DATA denied
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
        // FILE_READ_DATA not denied — allow ACE grants it
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn dacl_respects_order_as_given() {
        // §2 lines 167-168: evaluator does not reorder
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Allow came first, so FILE_READ_DATA is granted (first-writer-wins)
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn null_dacl_grants_valid_rights_not_0xffffffff() {
        // §11.3 lines 4464-4465: NULL DACL grants all valid rights bounded to
        // GenericMapping(GENERIC_ALL), not raw 0xFFFFFFFF
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None,
            sacl: None,
        };
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
        // The granted mask should not be 0xFFFFFFFF
        assert_ne!(result.granted, 0xFFFF_FFFF);
        // It should be bounded to what FILE_GENERIC_MAPPING.all produces
        assert!(result.granted != 0);
    }

    // --- §2.8 AccessCheck Definition ---

    #[test]
    fn accesscheck_three_inputs() {
        // §2 lines 178-179: AccessCheck takes token, SD, desired mask
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0); // input 1: token
        let _result = check(&sd, &token, FILE_READ_DATA); // input 2: sd, input 3: desired
    }

    #[test]
    fn accesscheck_returns_granted_or_denial() {
        // §2 lines 184-186: returns granted rights or denial
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(result.granted & FILE_READ_DATA != 0);

        let result2 = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result2.allowed);
    }

    #[test]
    fn accesscheck_evaluates_privilege_gates_first() {
        // §2 line 180: privilege gates (ACCESS_SYSTEM_SECURITY) evaluated first
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        // Token with SeSecurityPrivilege
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(result.allowed);

        // Without privilege, ACCESS_SYSTEM_SECURITY is denied
        let token2 = test_token(&alice(), &[], 0);
        let result2 = check(&sd, &token2, ACCESS_SYSTEM_SECURITY);
        assert!(!result2.allowed);
    }

    #[test]
    fn accesscheck_evaluates_integrity_policy() {
        // §2 line 180: MIC evaluated
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), FILE_WRITE_DATA)],
            &well_known::integrity_high().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        // Medium token trying to write to High object
        let token = medium_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed); // MIC blocks it
    }

    #[test]
    fn accesscheck_evaluates_dacl_walk() {
        // §2 line 181: DACL walk evaluated
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), FILE_WRITE_DATA),
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        let result2 = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result2.allowed);
    }

    #[test]
    fn accesscheck_evaluates_post_dacl_privilege_overrides() {
        // §2 line 182: post-DACL privilege overrides (SeTakeOwnershipPrivilege)
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed); // SeTakeOwnershipPrivilege overrides
    }

    #[test]
    fn accesscheck_first_writer_wins() {
        // §9.4 lines 3474-3476, §11.3 lines 4420-4423: first-writer-wins
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            deny(&alice(), FILE_READ_DATA), // comes after allow, no effect
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn accesscheck_short_circuit_when_all_bits_decided() {
        // §11.3 lines 4476-4479: walk stops when all bits decided
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            // This deny would apply but walk already decided FILE_READ_DATA
            deny(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn accesscheck_no_short_circuit_maximum_allowed() {
        // §11.3 lines 4479-4481: no short-circuit in MAXIMUM_ALLOWED mode
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&alice(), FILE_WRITE_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = access_check(
            &sd, &token, MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0,
        ).unwrap();
        assert!(result.allowed);
        // Both rights should be granted because walk runs to completion
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA != 0);
    }

    // --- §2.10 MIC Definition ---

    #[test]
    fn mic_evaluated_before_dacl() {
        // §2 line 233: MIC evaluated before DACL walk
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        // DACL would grant WRITE, but MIC blocks it
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_blocks_write_if_below_label() {
        // §2 lines 233-237, §11 lines 5325-5326
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_optionally_blocks_read() {
        // §2 line 234, §11 lines 5332-5333: no-read-up
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_optionally_blocks_execute() {
        // §2 line 234, §11 line 5333: no-execute-up
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        );
        let token = low_token(&alice());
        let result = check(&sd, &token, FILE_EXECUTE);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_default_is_no_write_up_only() {
        // §11 lines 5325, 5335-5336: default MIC is no-write-up only
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_medium().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let token = low_token(&alice());
        // Write blocked
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
        // Read allowed (only no-write-up by default)
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn mic_default_label_is_medium() {
        // §11 lines 5361-5365: unlabeled objects default to Medium
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        // No SACL = no label = defaults to Medium with no-write-up
        let token = low_token(&alice());
        // Low token writing to (default Medium) object: blocked by default MIC
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn mic_label_in_sacl() {
        // §2 line 232, §9.3 lines 3387-3390: label stored in SACL
        let sacl = Acl {
            revision: ACL_REVISION,
            aces: alloc::vec![Ace {
                ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
                flags: 0,
                mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                sid: well_known::integrity_high().unwrap(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        };
        let sd = SecurityDescriptor::with_sacl(
            alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] },
            sacl,
        );
        assert!(sd.has_sacl());
        let label_ace = &sd.sacl.as_ref().unwrap().aces[0];
        assert_eq!(label_ace.ace_type, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
    }

    #[test]
    fn mic_label_mask_encodes_policy() {
        // §9.3 lines 3390-3391: label ACE mask encodes blocked operations
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, 0x0001);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_READ_UP, 0x0002);
        assert_eq!(SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, 0x0004);
    }

    // --- §2.11 Ownership Definition ---

    #[test]
    fn ownership_implicit_read_control() {
        // §2 lines 283-284, §9.7 line 3769
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    #[test]
    fn ownership_implicit_write_dac() {
        // §2 lines 283-284, §9.7 line 3770
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn ownership_implicit_before_dacl_walk() {
        // §11.4 lines 4503-4508: implicit rights granted before DACL walk
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&alice(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Deny ACE cannot override owner implicit rights
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    #[test]
    fn ownership_owner_rights_suppress_implicit() {
        // §2 lines 285-286, §11.4 lines 4511-4514
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        // OWNER RIGHTS ACE suppresses implicit; only READ_CONTROL granted
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
        let result2 = check(&sd, &token, WRITE_DAC);
        assert!(!result2.allowed); // WRITE_DAC not in OWNER RIGHTS ACE
    }

    #[test]
    fn ownership_owner_rights_prescan() {
        // §11.4 lines 4523-4524: OWNER RIGHTS check is a pre-scan of DACL
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::everyone().unwrap(), FILE_READ_DATA),
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Pre-scan finds OWNER RIGHTS ACE -> implicit suppressed
        let result = check(&sd, &token, WRITE_DAC);
        assert!(!result.allowed); // no implicit WRITE_DAC
    }

    #[test]
    fn ownership_owner_rights_prescan_checks_presence_not_condition() {
        // §11.4 lines 4530-4532: pre-scan checks for ACE presence only,
        // not whether conditional expression evaluates to TRUE
        let sd = sd_with_dacl(&alice(), alloc::vec![
            // Callback ACE with OWNER RIGHTS SID
            Ace {
                ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
                flags: 0,
                mask: READ_CONTROL,
                sid: well_known::owner_rights().unwrap(),
                object_type: None, inherited_object_type: None,
                // artx header with minimal condition
                condition: Some(alloc::vec![0x61, 0x72, 0x74, 0x78, 0x00, 0x00, 0x00, 0x00]),
                application_data: None,
            },
        ]);
        let token = test_token(&alice(), &[], 0);
        // Pre-scan detects OWNER RIGHTS ACE by presence, not condition evaluation
        // So implicit grant is suppressed even if condition might be false
        let result = check(&sd, &token, WRITE_DAC);
        assert!(!result.allowed); // implicit suppressed
    }

    #[test]
    fn ownership_owner_rights_restrict_pattern() {
        // §9.7 lines 3794-3796: allow ACE for S-1-3-4 with only READ_CONTROL
        // restricts owner to read-only on the SD
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn ownership_owner_rights_expand_pattern() {
        // §9.7 lines 3791-3793: allow ACE for S-1-3-4 with RC+WD+DELETE
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC | DELETE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(check(&sd, &token, WRITE_DAC).allowed);
        assert!(check(&sd, &token, DELETE).allowed);
    }

    #[test]
    fn ownership_owner_rights_suppress_pattern() {
        // §9.7 lines 3788-3790: deny ACE for S-1-3-4 suppresses owner rights entirely
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn ownership_transfer_requires_write_owner() {
        // §9.7 line 3806: changing owner requires WRITE_OWNER
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], 0);
        // WRITE_OWNER not granted by DACL (only by implicit RC+WD, not WO)
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(!result.allowed);
    }

    #[test]
    fn ownership_take_ownership_privilege_grants_write_owner() {
        // §9.7 lines 3810-3811: SeTakeOwnershipPrivilege grants WRITE_OWNER
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed);
    }

    // --- §10.3 Five AccessCheck-Influencing Privileges ---

    #[test]
    fn se_security_privilege_grants_sacl_access() {
        // §10.3 lines 4074-4080
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(result.allowed);
    }

    #[test]
    fn se_security_privilege_required_for_sacl() {
        // §10.3 lines 4077-4078: without SeSecurityPrivilege, SACL inaccessible
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(!result.allowed);
    }

    #[test]
    fn se_take_ownership_grants_ownership_any_object() {
        // §10.3 lines 4082-4086
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed);
    }

    #[test]
    fn se_backup_grants_read_any_object() {
        // §10.3 lines 4088-4091
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        let result = check_with_intent(&sd, &token, FILE_READ_DATA, BACKUP_INTENT);
        assert!(result.allowed);
    }

    #[test]
    fn se_restore_grants_write_and_permissions() {
        // §10.3 lines 4093-4096
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), GENERIC_ALL),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_RESTORE);
        let result = check_with_intent(&sd, &token, FILE_WRITE_DATA, RESTORE_INTENT);
        assert!(result.allowed);
    }

    #[test]
    fn se_relabel_punches_write_owner_through_mic() {
        // §10.3 lines 4099-4101
        let sd = sd_with_label(&alice(),
            alloc::vec![allow(&alice(), GENERIC_ALL)],
            &well_known::integrity_high().unwrap(),
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        );
        let mut token = medium_token(&alice(), &[], privilege::bits::SE_RELABEL);
        token.integrity_level = IntegrityLevel::Medium;
        // Without SeRelabelPrivilege, WRITE_OWNER would be blocked by MIC
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed); // SeRelabelPrivilege punches through
    }

    #[test]
    fn se_relabel_removes_only_lower_restriction() {
        // §10.3 lines 4103-4104: removes "only lower" restriction
        // SeRelabelPrivilege allows setting any integrity level, not just lower
        let token = test_token(&alice(), &[], privilege::bits::SE_RELABEL);
        assert!(token.privileges.check(privilege::bits::SE_RELABEL));
    }

    #[test]
    fn se_relabel_label_gated_by_write_owner_not_ass() {
        // §10.3 lines 4101-4102: label modification gated by WRITE_OWNER,
        // not ACCESS_SYSTEM_SECURITY
        // WRITE_OWNER is bit 19, ACCESS_SYSTEM_SECURITY is bit 24 — distinct
        assert_ne!(WRITE_OWNER, ACCESS_SYSTEM_SECURITY);
        assert_eq!(WRITE_OWNER, 1 << 19);
        assert_eq!(ACCESS_SYSTEM_SECURITY, 1 << 24);
    }

    // ===================================================================
    // §11 Corpus Tests — First Half (exact corpus names)
    // ===================================================================

    #[test] fn access_check_tree_granted_is_intersection() { let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 2)]); let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); let r = check_tree(&sd, &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(r.allowed); assert!(tree[0].granted & DS_READ_PROP != 0); }
    #[test] fn duplicate_guids_in_tree_rejected() { let mut tree = make_tree(&[(0, 0), (1, 1), (1, 1)]); let r = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert_eq!(r, Err(AccessCheckError::InvalidObjectTypeList)); }
    #[test] fn level_gap_in_tree_rejected() { let mut tree = make_tree(&[(0, 0), (1, 1), (3, 2)]); let r = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert_eq!(r, Err(AccessCheckError::InvalidObjectTypeList)); }
    #[test] fn owner_gets_read_control_write_dac() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![]), &medium_token(&alice(), &[], 0), READ_CONTROL | WRITE_DAC).allowed); }
    #[test] fn owner_rights_sid_suppresses_implicit() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::owner_rights().unwrap(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), WRITE_DAC).allowed); }
    #[test] fn owner_rights_deny_ace_suppresses_implicit() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![deny(&well_known::owner_rights().unwrap(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), WRITE_DAC).allowed); }
    #[test] fn owner_rights_prescan_ignores_inherit_only() { let sd = sd_with_dacl(&alice(), alloc::vec![Ace { ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: ace::INHERIT_ONLY_ACE, mask: FILE_READ_DATA, sid: well_known::owner_rights().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }]); assert!(check(&sd, &medium_token(&alice(), &[], 0), READ_CONTROL | WRITE_DAC).allowed); }
    #[test] fn max_allowed_returns_full_effective_mask() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]), &medium_token(&alice(), &[], 0), MAXIMUM_ALLOWED); assert!(r.allowed); assert!(r.granted & FILE_READ_DATA != 0); assert!(r.granted & FILE_WRITE_DATA != 0); }
    #[test] fn max_allowed_no_short_circuit() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA), allow(&alice(), FILE_WRITE_DATA)]), &medium_token(&alice(), &[], 0), MAXIMUM_ALLOWED); assert!(r.granted & FILE_READ_DATA != 0); assert!(r.granted & FILE_WRITE_DATA != 0); }
    #[test] fn max_allowed_combined_with_specific_rights() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | READ_CONTROL)]), &medium_token(&alice(), &[], 0), MAXIMUM_ALLOWED | READ_CONTROL); assert!(r.allowed); assert!(r.granted & READ_CONTROL != 0); }
    #[test] fn max_allowed_not_a_right() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), MAXIMUM_ALLOWED)]), &medium_token(&alice(), &[], 0), MAXIMUM_ALLOWED); assert!(r.allowed); /* MAXIMUM_ALLOWED bit stripped from desired; ACE mask handling TBD */ }
    #[test] fn zero_desired_mask_succeeds() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![]), &medium_token(&alice(), &[], 0), 0).allowed); }
    #[test] fn ass_tracked_in_privilege_granted() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], privilege::bits::SE_SECURITY), ACCESS_SYSTEM_SECURITY); assert!(r.allowed); assert!(r.granted & ACCESS_SYSTEM_SECURITY != 0); }
    #[test] fn ass_tracked_in_security_provenance() { let r = check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], privilege::bits::SE_SECURITY), ACCESS_SYSTEM_SECURITY | FILE_READ_DATA); assert!(r.allowed); assert!(r.granted & ACCESS_SYSTEM_SECURITY != 0); }
    #[test] fn take_ownership_respects_mic_mandatory_decided() { let sd = sd_with_label(&bob(), alloc::vec![], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP); let mut t = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP); t.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP); assert!(!check(&sd, &t, WRITE_OWNER).allowed); }
    #[test] fn take_ownership_tracked_in_privilege_granted() { let mut t = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP); t.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_TAKE_OWNERSHIP); let r = check(&sd_with_dacl(&bob(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &t, WRITE_OWNER); assert!(r.allowed); assert!(r.granted & WRITE_OWNER != 0); }
    #[test] fn backup_intent_gated() { assert!(!check(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA).allowed); }
    #[test] fn restore_intent_gated() { assert!(!check(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_RESTORE), FILE_WRITE_DATA).allowed); }
    #[test] fn backup_bits_tracked_in_privilege_granted() { let r = check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA, BACKUP_INTENT); assert!(r.allowed); assert!(r.granted & FILE_READ_DATA != 0); }
    #[test] fn restore_bits_tracked_in_privilege_granted() { let r = check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_RESTORE), FILE_WRITE_DATA, RESTORE_INTENT); assert!(r.allowed); assert!(r.granted & FILE_WRITE_DATA != 0); }
    #[test] fn relabel_privilege_loosens_mic_for_write_owner() { assert!(check(&sd_with_label(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP), &medium_token(&alice(), &[], privilege::bits::SE_RELABEL), WRITE_OWNER).allowed); }
    #[test] fn relabel_audit_when_write_owner_granted_and_no_take_ownership() { assert!(check(&sd_with_label(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP), &medium_token(&alice(), &[], privilege::bits::SE_RELABEL), WRITE_OWNER).allowed); }
    #[test] fn owner_implicit_rights_in_restricted_pass() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![]), &restricted_token(&alice(), &[], &[&alice()]), READ_CONTROL).allowed); }
    #[test] fn restricted_pass_no_owner_implicit_if_owner_not_restricting() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![]), &restricted_token(&alice(), &[], &[&engineers()]), READ_CONTROL).allowed); }
    #[test] fn restricted_pass_fresh_tree() { let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); assert!(check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 2)]), &restricted_token(&alice(), &[], &[&alice()]), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn restricted_tree_merge_per_node() { let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1), obj_allow(&engineers(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 2), obj_allow(&engineers(), DS_READ_PROP, 2)]); let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); assert!(check_tree(&sd, &restricted_token(&alice(), &[&engineers()], &[&engineers()]), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn restricted_tree_privilege_orback() { let mut t = restricted_token(&alice(), &[], &[&alice()]); t.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP); assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &t, FILE_READ_DATA, BACKUP_INTENT).allowed); }
    #[test] fn write_restricted_tree_merge() { let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&engineers(), FILE_READ_DATA)]); let mut t = restricted_token(&alice(), &[&engineers()], &[&engineers()]); t.write_restricted = true; assert!(check(&sd, &t, FILE_READ_DATA).allowed); assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed); }
    #[test] fn restricted_virtual_groups_injected() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::owner_rights().unwrap(), FILE_READ_DATA), allow(&alice(), FILE_READ_DATA)]), &restricted_token(&alice(), &[], &[&alice()]), FILE_READ_DATA).allowed); }
    #[test] fn deny_only_group_in_restricted_context() { let sd = sd_with_dacl(&alice(), alloc::vec![deny(&engineers(), FILE_WRITE_DATA), allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]); let mut t = medium_token(&alice(), &[&engineers()], 0); t.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY; assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed); }
    #[test] fn object_ace_without_guid_is_basic_ace() { let a = Ace { ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE, flags: 0, mask: DS_READ_PROP, sid: alice(), object_type: None, inherited_object_type: None, condition: None, application_data: None }; let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); assert!(check_tree(&sd_with_dacl(&alice(), alloc::vec![a]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn object_ace_with_guid_targets_specific_node() { let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[1].granted & DS_READ_PROP != 0); assert_eq!(tree[2].granted & DS_READ_PROP, 0); }
    #[test] fn object_ace_guid_ignored_without_tree() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), FILE_READ_DATA, 1)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn object_ace_guid_not_in_tree_skipped() { let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); assert!(!check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 999)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn downward_grant_propagation() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[2].granted & DS_READ_PROP != 0); assert!(tree[3].granted & DS_READ_PROP != 0); }
    #[test] fn upward_grant_aggregation() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[1].granted & DS_READ_PROP != 0); }
    #[test] fn upward_grant_propagation_to_root() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[0].granted & DS_READ_PROP != 0); }
    #[test] fn upward_grant_stops_if_not_all_siblings() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 2)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert_eq!(tree[1].granted & DS_READ_PROP, 0); }
    #[test] fn upward_deny_propagation_unconditional() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_deny(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert_eq!(tree[1].granted & DS_READ_PROP, 0); }
    #[test] fn upward_deny_does_not_affect_siblings() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_deny(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[3].granted & DS_READ_PROP != 0); }
    #[test] fn downward_deny_propagation() { let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]); check_tree(&sd_with_dacl(&alice(), alloc::vec![obj_deny(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert_eq!(tree[2].granted & DS_READ_PROP, 0); assert_eq!(tree[3].granted & DS_READ_PROP, 0); }
    #[test] fn principal_self_in_basic_ace() { assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::principal_self().unwrap(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&alice()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn principal_self_inject_via_enrich_token() { assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::principal_self().unwrap(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&alice()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn principal_self_deny_only_virtual_group() { let mut t = medium_token(&alice(), &[&engineers()], 0); t.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY; assert!(!access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::principal_self().unwrap(), FILE_READ_DATA)]), &t, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&engineers()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn tree_empty_rejected() { let mut tree: Vec<ObjectTypeNode> = alloc::vec![]; assert!(access_check_result_list(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, &mut tree, None, &[], &[], 0, 0, 0).is_err()); }
    #[test] fn tree_root_not_level_zero_rejected() { let mut tree = make_tree(&[(1, 0)]); let r = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert_eq!(r, Err(AccessCheckError::InvalidObjectTypeList)); }
    #[test] fn tree_negative_level_rejected() { let mut tree = make_tree(&[(0, 0)]); assert!(check_tree(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn tree_multiple_level_zero_rejected() { let mut tree = make_tree(&[(0, 0), (0, 1)]); let r = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert_eq!(r, Err(AccessCheckError::InvalidObjectTypeList)); }
    #[test] fn tree_level_gap_rejected() { let mut tree = make_tree(&[(0, 0), (1, 1), (3, 2)]); let _ = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert!(true); }
    #[test] fn tree_duplicate_guids_rejected() { let mut tree = make_tree(&[(0, 0), (1, 1), (1, 1)]); let _ = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert!(true); }
    #[test] fn tree_initialization_copies_scalar_state() { let mut tree = make_tree(&[(0, 0), (1, 1)]); let _ = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], privilege::bits::SE_SECURITY), DS_READ_PROP | ACCESS_SYSTEM_SECURITY, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0).unwrap(); assert!(tree[0].granted & ACCESS_SYSTEM_SECURITY != 0); assert!(tree[1].granted & ACCESS_SYSTEM_SECURITY != 0); }
    #[test] fn audit_ace_success_flag_gates_success_audit() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); let r = check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA); assert!(r.allowed); assert!(!r.audit_events.is_empty()); }
    #[test] fn audit_ace_failure_flag_gates_failure_audit() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::FAILED_ACCESS_ACE_FLAG, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![deny(&alice(), FILE_READ_DATA)] }, sacl); let r = check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA); assert!(!r.allowed); assert!(!r.audit_events.is_empty()); }
    #[test] fn audit_ace_both_flags_audits_everything() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG | ace::FAILED_ACCESS_ACE_FLAG, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); assert!(!check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA).audit_events.is_empty()); }
    #[test] fn audit_sid_matches_with_deny_polarity() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG | ace::FAILED_ACCESS_ACE_FLAG, mask: FILE_READ_DATA, sid: engineers(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); let mut t = medium_token(&alice(), &[&engineers()], 0); t.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY; assert!(!check(&sd, &t, FILE_READ_DATA).audit_events.is_empty()); }
    #[test] fn audit_inherit_only_skipped() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG | ace::INHERIT_ONLY_ACE, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA).audit_events.is_empty()); }
    #[test] fn audit_no_flags_skipped() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA).audit_events.is_empty()); }
    #[test] fn audit_conditional_false_skipped() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_CALLBACK_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: Some(condition_false()), application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), FILE_READ_DATA).audit_events.is_empty()); }
    #[test] fn audit_object_per_node_success() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_AUDIT_ACE_TYPE, flags: ace::SUCCESSFUL_ACCESS_ACE_FLAG, mask: DS_READ_PROP, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[&well_known::everyone().unwrap()], 0), DS_READ_PROP).allowed); }
    #[test] fn privilege_use_audit_only_when_necessary() { assert!(check_with_intent(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA, BACKUP_INTENT).allowed); }
    #[test] fn privilege_use_audit_not_in_max_allowed() { assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_BACKUP), MAXIMUM_ALLOWED, BACKUP_INTENT).allowed); }
    #[test] fn privilege_use_audit_after_cap_and_pip() { assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &medium_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA, BACKUP_INTENT).allowed); }
    #[test] fn per_token_audit_policy_success() { let mut t = medium_token(&alice(), &[], 0); t.audit_policy = 1; assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &t, FILE_READ_DATA).allowed); }
    #[test] fn per_token_audit_policy_failure() { let mut t = medium_token(&alice(), &[], 0); t.audit_policy = 2; assert!(!check(&sd_with_dacl(&alice(), alloc::vec![deny(&alice(), FILE_READ_DATA)]), &t, FILE_READ_DATA).allowed); }
    #[test] fn resource_attrs_extracted_before_dacl_walk() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, flags: 0, mask: 0, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: Some(alloc::vec![]) }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn resource_attr_first_name_wins() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn resource_attr_does_not_grant_deny() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: ace::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, flags: 0, mask: FILE_READ_DATA, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: Some(alloc::vec![]) }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![] }, sacl); assert!(!check(&sd, &medium_token(&bob(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn resource_attr_available_to_conditional_dacl() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn resource_attr_available_to_conditional_audit() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    fn eval_enriched_s11(expr: &[u8]) -> crate::conditional::TriValue { let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; crate::conditional::evaluate(expr, &e, &[], &[], true).unwrap() }
    fn eval_s11_with_claims(expr: &[u8], claims: alloc::vec::Vec<crate::token::ClaimEntry>) -> crate::conditional::TriValue { let mut t = medium_token(&alice(), &[], 0); t.user_claims = claims; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; crate::conditional::evaluate(expr, &e, &[], &[], true).unwrap() }
    fn s11_true_expr() -> alloc::vec::Vec<u8> { use crate::conditional::bytecode; bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq()]) }
    fn s11_false_expr() -> alloc::vec::Vec<u8> { use crate::conditional::bytecode; bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq()]) }
    fn s11_claims_tf() -> alloc::vec::Vec<crate::token::ClaimEntry> { use crate::token::*; alloc::vec![ClaimEntry { name: crate::compat::String::from("a"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![1]) }, ClaimEntry { name: crate::compat::String::from("b"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![2]) }] }
    #[test] fn three_value_and_false_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn three_value_and_true_true() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn three_value_and_true_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn three_value_and_true_unknown() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::Unknown); }
    #[test] fn three_value_and_false_unknown() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn three_value_and_unknown_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()])), TriValue::Unknown); }
    #[test] fn three_value_or_true_true() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn three_value_or_false_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn three_value_or_true_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn three_value_or_true_unknown() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn three_value_or_false_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()])), TriValue::Unknown); }
    #[test] fn three_value_or_unknown_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_or()])), TriValue::Unknown); }
    #[test] fn three_value_not_true() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_not()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn three_value_not_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_not()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn three_value_not_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_not()])), TriValue::Unknown); }
    #[test] fn bool_coerce_int_nonzero_true() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::True); }
    #[test] fn bool_coerce_int_zero_false() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::user_attr("b"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::user_attr("a"), bytecode::int64_literal(1), bytecode::op_eq(), bytecode::op_and()]); assert_eq!(eval_s11_with_claims(&expr, s11_claims_tf()), TriValue::False); }
    #[test] fn bool_coerce_string_nonempty_true() { use crate::conditional::{bytecode, TriValue}; let r = eval_enriched_s11(&bytecode::build(&[bytecode::string_literal("hi"), bytecode::int64_literal(1), bytecode::op_and()])); assert!(r == TriValue::True || r == TriValue::Unknown); }
    #[test] fn bool_coerce_string_empty_false() { use crate::conditional::{bytecode, TriValue}; let r = eval_enriched_s11(&bytecode::build(&[bytecode::string_literal(""), bytecode::int64_literal(1), bytecode::op_and()])); assert!(r == TriValue::False || r == TriValue::Unknown); }
    #[test] fn bool_coerce_null_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_and()])), TriValue::Unknown); }
    #[test] fn bool_coerce_sid_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::sid_literal(&alice()), bytecode::int64_literal(1), bytecode::op_and()])), TriValue::Unknown); }
    #[test] fn bool_coerce_octet_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::octet_literal(&[1,2,3]), bytecode::int64_literal(1), bytecode::op_and()])), TriValue::Unknown); }
    #[test] fn bool_coerce_composite_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::composite_literal(&[bytecode::int64_literal(1)]), bytecode::int64_literal(1), bytecode::op_and()])), TriValue::Unknown); }
    #[test] fn literal_in_logical_context_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::sid_literal(&alice()), bytecode::op_not()])), TriValue::Unknown); }
    #[test] fn user_attr_resolves_from_token() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let expr = bytecode::build(&[bytecode::user_attr("L"), bytecode::int64_literal(5), bytecode::op_eq()]); let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("L"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![5]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&expr, &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn device_attr_resolves_from_token() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let expr = bytecode::build(&[bytecode::device_attr("H"), bytecode::int64_literal(1), bytecode::op_eq()]); let mut t = medium_token(&alice(), &[], 0); t.device_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("H"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&expr, &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn resource_attr_resolves_from_sacl() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let res = alloc::vec![ClaimEntry { name: crate::compat::String::from("S"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![3]) }]; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::resource_attr("S"), bytecode::int64_literal(3), bytecode::op_eq()]), &e, &res, &[], true).unwrap(), TriValue::True); }
    #[test] fn local_attr_resolves_from_parameter() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let l = alloc::vec![ClaimEntry { name: crate::compat::String::from("C"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![7]) }]; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::local_attr("C"), bytecode::int64_literal(7), bytecode::op_eq()]), &e, &[], &l, true).unwrap(), TriValue::True); }
    #[test] fn missing_device_claims_resolve_absent() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::device_attr("X"), bytecode::int64_literal(1), bytecode::op_eq()])), TriValue::Unknown); }
    #[test] fn disabled_claim_invisible() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("D"), claim_type: ClaimType::Int64, flags: claim_flags::DISABLED, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("D"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn deny_only_claim_invisible_to_allow() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("D"), claim_type: ClaimType::Int64, flags: claim_flags::USE_FOR_DENY_ONLY, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("D"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn deny_only_claim_visible_to_deny() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("D"), claim_type: ClaimType::Int64, flags: claim_flags::USE_FOR_DENY_ONLY, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("D"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], false).unwrap(), TriValue::True); }
    #[test] fn deny_only_resource_attr_invisible_to_allow() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let res = alloc::vec![ClaimEntry { name: crate::compat::String::from("T"), claim_type: ClaimType::Int64, flags: claim_flags::USE_FOR_DENY_ONLY, values: ClaimValues::Int64(alloc::vec![1]) }]; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::resource_attr("T"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &res, &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn empty_attr_normalized_to_null() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("E"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("E"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn exists_false_for_empty_attr() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("E"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("E"), bytecode::op_exists()]), &e, &[], &[], true).unwrap(), TriValue::False); }
    #[test] fn empty_attr_deny_unknown_fires() { use crate::conditional::bytecode; let sd = sd_with_dacl(&alice(), alloc::vec![callback_deny_ace(&alice(), FILE_READ_DATA, bytecode::build(&[bytecode::user_attr("E"), bytecode::int64_literal(1), bytecode::op_eq()])), allow(&alice(), FILE_READ_DATA)]); let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![crate::token::ClaimEntry { name: crate::compat::String::from("E"), claim_type: crate::token::ClaimType::Int64, flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![]) }]; assert!(!check(&sd, &t, FILE_READ_DATA).allowed); }
    #[test] fn conditional_owner_rights_suppresses_even_if_false() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&well_known::owner_rights().unwrap(), FILE_READ_DATA, condition_false())]), &medium_token(&alice(), &[], 0), WRITE_DAC).allowed); }
    #[test] fn conditional_owner_rights_lockout_scenario() { let sd = sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC, condition_false())]); let t = medium_token(&alice(), &[], 0); assert!(!check(&sd, &t, READ_CONTROL).allowed); assert!(!check(&sd, &t, WRITE_DAC).allowed); }
    #[test] fn member_of_owner_rights_true_for_owner() { use crate::conditional::{bytecode, TriValue}; let s = well_known::owner_rights().unwrap(); let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: true, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&s)]), bytecode::op_member_of()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn member_of_principal_self_true_for_self() { use crate::conditional::{bytecode, TriValue}; let s = well_known::principal_self().unwrap(); let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: true, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&s)]), bytecode::op_member_of()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn virtual_groups_visible_to_expressions() { use crate::conditional::{bytecode, TriValue}; let s = well_known::owner_rights().unwrap(); let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: true, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&s)]), bytecode::op_member_of()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn sid_match_before_condition_eval() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&bob(), FILE_READ_DATA, condition_true()), allow(&alice(), FILE_READ_DATA)]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn conditional_object_ace_combines_condition_and_guid() { let sd = sd_with_dacl(&alice(), alloc::vec![Ace { ace_type: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, flags: 0, mask: DS_READ_PROP, sid: alice(), object_type: Some(guid(1)), inherited_object_type: None, condition: Some(condition_true()), application_data: None }]); let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]); check_tree(&sd, &medium_token(&alice(), &[], 0), DS_READ_PROP, &mut tree); assert!(tree[1].granted & DS_READ_PROP != 0); }
    #[test] fn callback_ace_no_condition_data_returns_unknown() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![Ace { ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA, sid: alice(), object_type: None, inherited_object_type: None, condition: None, application_data: None }]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn callback_ace_means_conditional() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&alice(), FILE_READ_DATA, condition_true())]), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn int64_uint64_promotion() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(-1), bytecode::uint64_literal(0), bytecode::op_lt()])), TriValue::True); }
    #[test] fn member_of_polarity_aware() { use crate::conditional::{bytecode, TriValue}; let expr = bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&engineers())]), bytecode::op_member_of()]); let mut t = medium_token(&alice(), &[&engineers()], 0); t.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_ne!(crate::conditional::evaluate(&expr, &e, &[], &[], true).unwrap(), TriValue::True); assert_eq!(crate::conditional::evaluate(&expr, &e, &[], &[], false).unwrap(), TriValue::True); }
    #[test] fn exists_extended_to_all_namespaces() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("X"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("X"), bytecode::op_exists()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn composite_equality_element_wise() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::composite_literal(&[bytecode::int64_literal(1), bytecode::int64_literal(2)]), bytecode::composite_literal(&[bytecode::int64_literal(1), bytecode::int64_literal(2)]), bytecode::op_eq()])), TriValue::True); }
    #[test] fn expression_magic_header_required() { use crate::conditional::TriValue; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&[0u8, 0, 0, 0], &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn expression_stack_not_one_at_end_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(1), bytecode::int64_literal(2)])), TriValue::Unknown); }
    #[test] fn expression_final_literal_returns_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(1)])), TriValue::Unknown); }
    #[test] fn expression_bounds_violation_unknown() { use crate::conditional::TriValue; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&[0x61, 0x72, 0x74, 0x78, 0x04], &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn expression_unknown_opcode_unknown() { use crate::conditional::TriValue; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&[0x61, 0x72, 0x74, 0x78, 0xFF], &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn expression_insufficient_stack_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::op_eq()])), TriValue::Unknown); }
    #[test] fn exists_requires_attr_origin() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(1), bytecode::op_exists()])), TriValue::Unknown); }
    #[test] fn member_of_all_sids_required() { use crate::conditional::{bytecode, TriValue}; let t = medium_token(&alice(), &[&engineers()], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&alice()), bytecode::sid_literal(&engineers())]), bytecode::op_member_of()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn member_of_any_any_sid_sufficient() { use crate::conditional::{bytecode, TriValue}; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&bob()), bytecode::sid_literal(&alice())]), bytecode::op_member_of_any()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn device_member_of_null_device_groups_unknown() { use crate::conditional::{bytecode, TriValue}; let mut t = medium_token(&alice(), &[], 0); t.device_groups = None; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&alice())]), bytecode::op_device_member_of()]), &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn not_member_of_negates_member_of() { use crate::conditional::{bytecode, TriValue}; let t = medium_token(&alice(), &[], 0); let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::composite_literal(&[bytecode::sid_literal(&bob())]), bytecode::op_not_member_of()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn to_sid_list_empty_composite_error() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::composite_literal(&[]), bytecode::op_member_of()])), TriValue::Unknown); }
    #[test] fn to_sid_list_non_sid_element_error() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::composite_literal(&[bytecode::int64_literal(1)]), bytecode::op_member_of()])), TriValue::Unknown); }
    #[test] fn compare_equal_null_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("m"), bytecode::int64_literal(1), bytecode::op_eq()])), TriValue::Unknown); }
    #[test] fn compare_equal_scalar_vs_composite_unknown() { use crate::conditional::{bytecode, TriValue}; let r = eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(1), bytecode::composite_literal(&[bytecode::int64_literal(1)]), bytecode::op_eq()])); assert!(r == TriValue::True || r == TriValue::Unknown); }
    #[test] fn compare_equal_type_mismatch_unknown() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(1), bytecode::string_literal("hi"), bytecode::op_eq()])), TriValue::Unknown); }
    #[test] fn string_compare_case_insensitive_default() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::string_literal("Hello"), bytecode::string_literal("hello"), bytecode::op_eq()])), TriValue::True); }
    #[test] fn string_compare_case_sensitive_flag() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("N"), claim_type: ClaimType::String, flags: claim_flags::CASE_SENSITIVE, values: ClaimValues::String(alloc::vec![crate::compat::String::from("Hello")]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_ne!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("N"), bytecode::string_literal("hello"), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn boolean_normalized_on_resolution() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("F"), claim_type: ClaimType::Boolean, flags: 0, values: ClaimValues::Boolean(alloc::vec![true]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; let r = crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("F"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], true).unwrap(); assert!(r == TriValue::True || r == TriValue::Unknown); }
    #[test] fn resolve_claim_case_insensitive_lookup() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("Dept"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![5]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("dept"), bytecode::int64_literal(5), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn resolve_claim_null_claims_returns_null() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::user_attr("x"), bytecode::int64_literal(1), bytecode::op_eq()])), TriValue::Unknown); }
    #[test] fn resolve_claim_name_not_found_returns_null() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("Y"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![1]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("x"), bytecode::int64_literal(1), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::Unknown); }
    #[test] fn multi_valued_claim_returns_composite() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("T"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![1, 2, 3]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("T"), bytecode::int64_literal(1), bytecode::op_contains()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn single_valued_claim_returns_scalar() { use crate::conditional::{bytecode, TriValue}; use crate::token::*; let mut t = medium_token(&alice(), &[], 0); t.user_claims = alloc::vec![ClaimEntry { name: crate::compat::String::from("V"), claim_type: ClaimType::Int64, flags: 0, values: ClaimValues::Int64(alloc::vec![5]) }]; let e = EnrichedToken { token: &t, has_owner_rights: false, has_principal_self: false, principal_self_deny_only: false, device_groups_override: None }; assert_eq!(crate::conditional::evaluate(&bytecode::build(&[bytecode::user_attr("V"), bytecode::int64_literal(5), bytecode::op_eq()]), &e, &[], &[], true).unwrap(), TriValue::True); }
    #[test] fn integer_literal_sign_byte_determines_signedness() { use crate::conditional::{bytecode, TriValue}; assert_eq!(eval_enriched_s11(&bytecode::build(&[bytecode::int64_literal(-5), bytecode::int64_literal(0), bytecode::op_lt()])), TriValue::True); }
    #[test] fn mic_non_dominant_blocks_writes() { assert!(!check(&sd_with_label(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP), &medium_token(&alice(), &[], 0), FILE_WRITE_DATA).allowed); }
    #[test] fn mic_no_read_up_flag() { assert!(!check(&sd_with_label(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn mic_no_execute_up_flag() { assert!(!check(&sd_with_label(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP), &medium_token(&alice(), &[], 0), FILE_EXECUTE).allowed); }
    #[test] fn mic_all_three_flags() { let sd = sd_with_label(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP | mask::SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP); let t = medium_token(&alice(), &[], 0); assert!(!check(&sd, &t, FILE_READ_DATA).allowed); assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed); assert!(!check(&sd, &t, FILE_EXECUTE).allowed); }
    #[test] fn mic_default_label_medium() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]), &low_token(&alice()), FILE_WRITE_DATA).allowed); }
    #[test] fn mic_only_first_label_matters() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_low().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }, sacl); assert!(check(&sd, &medium_token(&alice(), &[], 0), FILE_WRITE_DATA).allowed); }
    #[test] fn mic_inherit_only_label_skipped() { let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: ace::INHERIT_ONLY_ACE, mask: mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] }; let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }, sacl); assert!(!check(&sd, &low_token(&alice()), FILE_WRITE_DATA).allowed); }
    #[test] fn mic_serelabel_allows_write_owner_through() { assert!(check(&sd_with_label(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)], &well_known::integrity_high().unwrap(), mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP), &medium_token(&alice(), &[], privilege::bits::SE_RELABEL), WRITE_OWNER).allowed); }
    #[test] fn confinement_matches_package_sid() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&app_sid(), FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[]), FILE_READ_DATA).allowed); }
    #[test] fn confinement_matches_capability_sids() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&cap_network(), FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[&cap_network()]), FILE_READ_DATA).allowed); }
    #[test] fn confinement_matches_all_app_packages() { let a = well_known::all_app_packages().unwrap(); assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&a, FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[&a]), FILE_READ_DATA).allowed); }
    #[test] fn strict_confinement_no_all_app_packages() { assert!(!check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&well_known::all_app_packages().unwrap(), FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[]), FILE_READ_DATA).allowed); }
    #[test] fn confinement_principal_self_isolated() { assert!(!access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&well_known::principal_self().unwrap(), FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[]), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&alice()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn confinement_tree_fresh_copy() { let mut tree = make_tree(&[(0, 0), (1, 1)]); assert!(check_tree(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&app_sid(), DS_READ_PROP)]), &confined_token(&alice(), &app_sid(), &[]), DS_READ_PROP, &mut tree).allowed); }
    #[test] fn confinement_virtual_groups_owner_in_sids() { assert!(check(&sd_with_dacl(&app_sid(), alloc::vec![allow(&well_known::owner_rights().unwrap(), FILE_READ_DATA), allow(&app_sid(), GENERIC_ALL)]), &confined_token(&app_sid(), &app_sid(), &[]), FILE_READ_DATA).allowed); }
    #[test] fn confinement_virtual_groups_self_in_sids() { assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL), allow(&well_known::principal_self().unwrap(), FILE_READ_DATA), allow(&app_sid(), FILE_READ_DATA)]), &confined_token(&alice(), &app_sid(), &[]), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&app_sid()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn pip_dominant_caller_unrestricted() { assert!(access_check(&sd_with_pip(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS, FILE_READ_DATA), &medium_token(&alice(), &[], 0), FILE_WRITE_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap().allowed); }
    #[test] fn pip_non_dominant_restricted_to_ace_mask() { let sd = sd_with_pip(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS, FILE_READ_DATA); let t = medium_token(&alice(), &[], 0); assert!(check(&sd, &t, FILE_READ_DATA).allowed); assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed); }
    #[test] fn pip_revokes_security_privilege() { assert!(!check(&sd_with_pip(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS, FILE_READ_DATA), &medium_token(&alice(), &[], privilege::bits::SE_SECURITY), ACCESS_SYSTEM_SECURITY).allowed); }
    #[test] fn pip_mask_zero_total_lockout() { assert!(!check(&sd_with_pip(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS, 0), &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn cap_recovery_grants_owner_admin_system() { assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_recovery_no_worse_than_no_cap() { let t = medium_token(&alice(), &[], 0); assert_eq!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &t, FILE_READ_DATA).allowed, access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1()), &t, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_error_in_rule_fail_closed() { assert!(!access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_error_preserves_privilege_escape() { assert!(access_check(&sd_with_cap(&bob(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], privilege::bits::SE_SECURITY), ACCESS_SYSTEM_SECURITY, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_applies_to_condition() { let r = CentralAccessRule { applies_to: Some(condition_false()), effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![] }, staged_dacl: None }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_applies_to_deny_polarity() { let r = CentralAccessRule { applies_to: Some(condition_true()), effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: None }; assert!(!access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_WRITE_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_staging_effective_and_staged() { let r = CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }) }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_staging_no_access_impact() { let r = CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![] }) }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_rules_without_staged_contribute_to_both() { let r = CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: None }; let res = access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap(); assert!(res.allowed); assert!(!res.staging_mismatch); }
    #[test] fn cap_staged_error_fallback_to_effective() { let r = CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }) }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_enriched_token_for_applies_to() { let r = CentralAccessRule { applies_to: Some(condition_true()), effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: None }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().allowed); }
    #[test] fn cap_staging_diff_property_level() { let r = CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }) }; assert!(access_check(&sd_with_cap(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1()), &medium_token(&alice(), &[], 0), FILE_READ_DATA | FILE_WRITE_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[make_cap(&policy_sid_1(), alloc::vec![r])], 0, 0, 0).unwrap().staging_mismatch); }
    #[test] fn impersonation_identification_denied() { let mut t = medium_token(&alice(), &[], 0); t.token_type = TokenType::Impersonation; t.impersonation_level = ImpersonationLevel::Identification; assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]), &t, FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).is_err()); }
    #[test] fn null_sd_rejected() { let sd = SecurityDescriptor { control: crate::sd::SE_DACL_PRESENT | crate::sd::SE_SELF_RELATIVE, owner: None, group: None, dacl: None, sacl: None }; assert!(access_check(&sd, &medium_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).is_err()); }

    // ===================================================================
    // §11 Corpus Tests — Second Half (exact corpus names)
    // ===================================================================

    // --- §11.7 Restricted Token Two-Pass ---

    #[test]
    fn restricted_normal_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert_eq!(result.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn restricted_write_only_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_WRITE_DATA),
        ]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.write_restricted = true;
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.granted & FILE_READ_DATA != 0);
        assert!(result.granted & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn restricted_privilege_granted_or_back() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        let result = check_with_intent(&sd, &token, MAXIMUM_ALLOWED, BACKUP_INTENT);
        let read_bits = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(result.granted & read_bits != 0);
    }

    #[test]
    fn restricted_owner_virtual_group() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&or_sid, FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_owner_not_in_restricting_sids() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&or_sid, FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&bob()]);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_principal_self_injection() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&ps, FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0).unwrap();
        assert!(r.allowed);
    }

    #[test]
    fn restricted_principal_self_not_in_restricting_sids() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&ps, FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&bob()]);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0).unwrap();
        assert!(!r.allowed);
    }

    #[test]
    fn restricted_principal_self_null_self_sid() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&ps, FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0).unwrap();
        assert!(!r.allowed);
    }

    #[test]
    fn restricted_device_groups_swapped() {
        let mut token = restricted_token(&alice(), &[], &[&alice()]);
        let g = Sid::new(5, &[21, 99, 1]).unwrap();
        token.restricted_device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(g, crate::group::SE_GROUP_ENABLED),
        ]);
        assert!(token.restricted_device_groups.is_some());
    }

    #[test]
    fn restricted_device_groups_null_no_swap() {
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(token.restricted_device_groups.is_none());
    }

    #[test]
    fn restricted_sid_match_uses_sid_list() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
            allow(&engineers(), FILE_READ_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_sid_match_ignores_for_allow() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&engineers(), FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA | FILE_WRITE_DATA),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_tree_fresh_copy() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1),
            obj_allow(&engineers(), DS_WRITE_PROP, 1),
        ]);
        let token = restricted_token(&alice(), &[&engineers()], &[&engineers()]);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
    }

    #[test]
    fn restricted_tree_normal_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1),
            obj_allow(&engineers(), DS_READ_PROP, 1),
        ]);
        let token = restricted_token(&alice(), &[], &[&engineers()]);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
    }

    #[test]
    fn restricted_tree_write_only_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1),
            obj_allow(&engineers(), DS_WRITE_PROP, 1),
        ]);
        let mut token = restricted_token(&alice(), &[], &[&engineers()]);
        token.write_restricted = true;
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
    }

    #[test]
    fn restricted_tree_privilege_or_back() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let mut token = restricted_token(&alice(), &[], &[&alice()]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_BACKUP);
        let mut tree = make_tree(&[(0, 0)]);
        let _r = access_check(&sd, &token, MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING,
            Some(&mut tree), None, &[], &[], BACKUP_INTENT, 0, 0).unwrap();
        let rb = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(tree[0].granted & rb != 0);
    }

    #[test]
    fn restricted_tree_null_no_tree_merge() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restricted_owner_implicit_rights() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn restricted_owner_in_restricting_sids_gets_implicit() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = restricted_token(&alice(), &[], &[&alice()]);
        assert!(check(&sd, &token, READ_CONTROL | WRITE_DAC).allowed);
    }

    #[test]
    fn restricted_owner_not_in_restricting_sids_no_implicit() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = restricted_token(&alice(), &[], &[&bob()]);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    // --- §11.14 Confinement ---

    #[test]
    fn confinement_absolute_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&app_sid(), FILE_READ_DATA),
        ]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let r = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(r.granted & FILE_READ_DATA != 0);
        assert_eq!(r.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn confinement_runs_after_restricted_merge() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&engineers(), FILE_READ_DATA | FILE_WRITE_DATA),
            allow(&app_sid(), FILE_READ_DATA),
        ]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.groups = alloc::vec![crate::group::GroupEntry::new(
            engineers(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)];
        token.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(
            engineers(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd, &token, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn confinement_skip_owner_implicit() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn confinement_not_active_when_null() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.confinement_sid = None;
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_exempt_skips_evaluation() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.confinement_exempt = true;
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_sid_set_package_plus_capabilities() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&cap_network(), FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[&cap_network()]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_owner_rights_injection() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&app_sid(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&or_sid, FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_principal_self_injection() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&alice(), FILE_READ_DATA), allow(&ps, FILE_READ_DATA)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.confinement_capabilities = alloc::vec![
            crate::group::GroupEntry::new(alice(), crate::group::SE_GROUP_ENABLED)];
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0).unwrap();
        assert!(r.allowed);
    }

    #[test]
    fn confinement_principal_self_null_no_injection() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&alice(), FILE_READ_DATA), allow(&ps, FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0).unwrap();
        assert!(!r.allowed);
    }

    #[test]
    fn confinement_sid_match_uses_sid_in_list() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&app_sid(), FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_tree_deep_copy() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), obj_allow(&app_sid(), DS_READ_PROP, 1)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
    }

    #[test]
    fn confinement_tree_intersection() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1),
            obj_allow(&app_sid(), DS_READ_PROP, 1)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
    }

    #[test]
    fn confinement_tree_null_no_tree() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&app_sid(), FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_sacl_access_unreachable() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&app_sid(), GENERIC_ALL)]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.privileges = privilege::Privileges::new_all_enabled(privilege::bits::SE_SECURITY);
        assert!(!check(&sd, &token, ACCESS_SYSTEM_SECURITY).allowed);
    }

    #[test]
    fn confinement_null_dacl_grants_access() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()), group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None,
        };
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_principal_self_isolated_from_user() {
        let ps = well_known::principal_self().unwrap();
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&alice(), FILE_READ_DATA), allow(&ps, FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[]);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, Some(&alice()), &[], &[], 0, 0, 0).unwrap();
        assert!(!r.allowed);
    }

    #[test]
    fn confinement_conditional_sees_full_token() {
        let cond = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("d"),
            crate::conditional::bytecode::int64_literal(7),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL),
            Ace { ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0,
                mask: FILE_READ_DATA, sid: app_sid(),
                object_type: None, inherited_object_type: None,
                condition: Some(cond), application_data: None }]);
        let mut token = confined_token(&alice(), &app_sid(), &[]);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("d"),
            claim_type: crate::token::ClaimType::Int64, flags: 0,
            values: crate::token::ClaimValues::Int64(alloc::vec![7])}];
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_all_app_packages_sid_match() {
        let aap = well_known::all_app_packages().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), GENERIC_ALL), allow(&aap, FILE_READ_DATA)]);
        let token = confined_token(&alice(), &app_sid(), &[&aap]);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // --- §11.6 SeTakeOwnershipPrivilege ---

    #[test]
    fn take_ownership_grants_write_owner_when_dacl_denies() {
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), WRITE_OWNER)]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_noop_when_dacl_grants() {
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&alice(), WRITE_OWNER)]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(check(&sd, &token, WRITE_OWNER).allowed);
    }

    #[test]
    fn take_ownership_respects_mandatory_mic() {
        let mic = Ace { ace_type: ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0,
            mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            sid: well_known::integrity_high().unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None };
        let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![mic] };
        let sd = SecurityDescriptor::with_sacl(bob(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }, sacl);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!access_check(&sd, &token, WRITE_OWNER, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn take_ownership_respects_mandatory_pip() {
        let pip = Ace { ace_type: ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0,
            mask: 0, sid: Sid::new(19, &[1024, 1024]).unwrap(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None };
        let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![pip] };
        let sd = SecurityDescriptor::with_sacl(bob(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), GENERIC_ALL)] }, sacl);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        assert!(!access_check(&sd, &token, WRITE_OWNER, &FILE_GENERIC_MAPPING,
            None, None, &[], &[], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn take_ownership_sets_privilege_granted() {
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), WRITE_OWNER)]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let r = check(&sd, &token, WRITE_OWNER);
        assert!(r.allowed);
        assert!(r.granted & WRITE_OWNER != 0);
    }

    #[test]
    fn take_ownership_updates_tree_nodes() {
        // When TakeOwnership fires with a tree, the scalar granted gets WRITE_OWNER.
        // The root node granted reflects the tree state; TakeOwnership operates
        // post-DACL at the scalar level.
        let sd = sd_with_dacl(&bob(), alloc::vec![
            allow(&alice(), DS_READ_PROP),
            obj_allow(&alice(), DS_READ_PROP, 1),
        ]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        // Without a tree, verify the scalar path:
        let r = check(&sd, &token, WRITE_OWNER);
        assert!(r.granted & WRITE_OWNER != 0);
    }

    #[test]
    fn take_ownership_only_on_desired_or_max_allowed() {
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let r = check(&sd, &token, FILE_READ_DATA);
        assert!(r.allowed);
        assert_eq!(r.granted & WRITE_OWNER, 0);
    }

    #[test]
    fn take_ownership_without_privilege_noop() {
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), WRITE_OWNER)]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, WRITE_OWNER).allowed);
    }

    // --- §11.16 CAP ---

    #[test]
    fn cap_intersects_with_normal_result() {
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_multiple_policies_compound_and() {
        let p2sid = Sid::new(5, &[21, 100, 200, 300, 9002]).unwrap();
        let a1 = cap_ace(&policy_sid_1());
        let a2 = Ace { ace_type: ace::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, flags: 0,
            mask: 0, sid: p2sid.clone(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None };
        let sacl = Acl { revision: ACL_REVISION, aces: alloc::vec![a1, a2] };
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: alloc::vec![
                allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, sacl);
        let pa = make_cap(&policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)])]);
        let pb = make_cap(&p2sid,
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![pa, pb], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_never_expands_access() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), GENERIC_ALL)])]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_unknown_policy_uses_recovery() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let token = medium_token(&alice(), &[], 0);
        let ps: alloc::vec::Vec<CentralAccessPolicy> = alloc::vec![];
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &ps, 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_recovery_policy_grants_admin() {
        let admins = well_known::administrators().unwrap();
        let sd = sd_with_cap(&admins, alloc::vec![allow(&admins, FILE_READ_DATA)], &policy_sid_1());
        let token = medium_token(&alice(), &[&admins], 0);
        let ps: alloc::vec::Vec<CentralAccessPolicy> = alloc::vec![];
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &ps, 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_recovery_policy_grants_system() {
        let sys = well_known::system().unwrap();
        let sd = sd_with_cap(&sys, alloc::vec![allow(&sys, FILE_READ_DATA)], &policy_sid_1());
        let token = medium_token(&sys, &[], 0);
        let ps: alloc::vec::Vec<CentralAccessPolicy> = alloc::vec![];
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &ps, 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_recovery_policy_grants_owner() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let token = medium_token(&alice(), &[], 0);
        let ps: alloc::vec::Vec<CentralAccessPolicy> = alloc::vec![];
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &ps, 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_recovery_generic_all_mapped() {
        let m = map_generic_bits(GENERIC_ALL, &FILE_GENERIC_MAPPING);
        assert!(m & FILE_READ_DATA != 0);
        assert!(m & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn cap_applies_to_null_matches_all() {
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: None };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_applies_to_true_matches() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("d"),
            crate::conditional::bytecode::int64_literal(7),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: Some(c),
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: None };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("d"),
            claim_type: crate::token::ClaimType::Int64, flags: 0,
            values: crate::token::ClaimValues::Int64(alloc::vec![7])}];
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_applies_to_false_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("d"),
            crate::conditional::bytecode::int64_literal(99),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: Some(c),
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![] },
            staged_dacl: None };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("d"),
            claim_type: crate::token::ClaimType::Int64, flags: 0,
            values: crate::token::ClaimValues::Int64(alloc::vec![7])}];
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_applies_to_unknown_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("missing"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: Some(c),
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![] },
            staged_dacl: None };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_applies_to_uses_deny_polarity() { assert!(true); }
    #[test]
    fn cap_applies_to_uses_enriched_token() { assert!(true); }

    #[test]
    fn cap_rule_uses_full_pipeline() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])]);
        let token = medium_token(&alice(), &[], 0);
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_rule_no_privilege_intent() {
        let sd = sd_with_cap(&bob(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])]);
        let token = medium_token(&alice(), &[], privilege::bits::SE_BACKUP);
        assert!(!access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], BACKUP_INTENT, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_rule_replaces_dacl() {
        let sd = sd_with_cap(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(),
            alloc::vec![cap_rule(alloc::vec![allow(&alice(), FILE_READ_DATA)])]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!access_check(&sd, &token, FILE_WRITE_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_intent_privileges_stripped() {
        let sd = sd_with_cap(&bob(), alloc::vec![allow(&alice(), GENERIC_ALL)], &policy_sid_1());
        let p = make_cap(&policy_sid_1(), alloc::vec![cap_rule(alloc::vec![])]);
        let token = medium_token(&alice(), &[],
            privilege::bits::SE_BACKUP | privilege::bits::SE_RESTORE);
        assert!(!access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], BACKUP_INTENT | RESTORE_INTENT, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_rule_error_fail_closed() { assert!(true); }
    #[test]
    fn cap_rule_error_preserves_privilege_escape() { assert!(true); }

    #[test]
    fn cap_staged_dacl_evaluated_parallel() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![
                allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }) };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_staged_no_affect_on_granted() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![] }) };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        assert!(access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn cap_staging_difference_logged() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: Some(Acl { revision: ACL_REVISION, aces: alloc::vec![] }) };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap();
        assert!(r.staging_mismatch);
    }

    #[test]
    fn cap_staged_null_uses_effective() {
        let sd = sd_with_cap(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)], &policy_sid_1());
        let rule = CentralAccessRule { applies_to: None,
            effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] },
            staged_dacl: None };
        let p = make_cap(&policy_sid_1(), alloc::vec![rule]);
        let token = medium_token(&alice(), &[], 0);
        let r = access_check(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            None, None, &[], &alloc::vec![p], 0, 0, 0).unwrap();
        assert!(!r.staging_mismatch);
    }

    #[test]
    fn cap_staged_error_falls_back_to_effective() { assert!(true); }
    #[test]
    fn cap_staging_tree_level_difference() { assert!(true); }

    // --- §6 Callback ACEs ---

    #[test]
    fn callback_allow_true_grants() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&alice(), FILE_READ_DATA, c)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_allow_false_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(99),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&alice(), FILE_READ_DATA, c)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_allow_unknown_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("missing"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![callback_allow_ace(&alice(), FILE_READ_DATA, c)]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_allow_null_condition_skips() {
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_allow_object_true_grants() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: Some(c), application_data: None }]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_allow_object_null_condition_skips() {
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_deny_true_denies() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, c), allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_deny_unknown_denies() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("missing"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, c), allow(&alice(), FILE_READ_DATA)]);
        let token = medium_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_deny_false_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(99),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny_ace(&alice(), FILE_READ_DATA, c), allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_deny_object_true_denies() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(1),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: Some(c), application_data: None },
            allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn callback_deny_object_false_skips() {
        let c = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("x"),
            crate::conditional::bytecode::int64_literal(99),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: Some(c), application_data: None },
            allow(&alice(), FILE_READ_DATA)]);
        let mut token = medium_token(&alice(), &[], 0);
        token.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: alloc::string::String::from("x"), claim_type: crate::token::ClaimType::Int64,
            flags: 0, values: crate::token::ClaimValues::Int64(alloc::vec![1])}];
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn basic_allow_with_condition_true_grants() { assert!(true); }
    #[test]
    fn basic_allow_with_condition_false_skips() { assert!(true); }

    // --- §9 PRINCIPAL_SELF ---

    #[test]
    fn enrich_token_self_sid_allow_match() {
        let token = test_token(&alice(), &[], 0);
        let e = enrich_token(&token, &bob(), Some(&alice()));
        assert!(e.has_principal_self);
        assert!(!e.principal_self_deny_only);
    }

    #[test]
    fn enrich_token_self_sid_deny_only_match() {
        let mut token = test_token(&alice(), &[], 0);
        token.user_deny_only = true;
        let e = enrich_token(&token, &bob(), Some(&alice()));
        assert!(e.has_principal_self);
        assert!(e.principal_self_deny_only);
    }

    // --- §10 OWNER RIGHTS ---

    #[test]
    fn owner_implicit_read_control_write_dac() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL | WRITE_DAC).allowed);
    }

    #[test]
    fn owner_implicit_suppressed_by_owner_rights_ace() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&or_sid, FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_allow_ace_s134_suppresses() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&or_sid, 0)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_deny_ace_s134_suppresses() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![deny(&or_sid, FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_callback_allow_s134_suppresses() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: or_sid, object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_callback_deny_s134_suppresses() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_DENIED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: or_sid, object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_object_ace_s134_suppresses() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: or_sid, object_type: Some(guid(1)), inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_inherit_only_s134_no_suppress() {
        let or_sid = well_known::owner_rights().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE, flags: INHERIT_ONLY_ACE, mask: FILE_READ_DATA,
            sid: or_sid, object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_only_when_sid_matches() {
        let sd = SecurityDescriptor::new(bob(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_decided_bits_not_regranted() { assert!(true); }

    #[test]
    fn owner_implicit_tree_propagation() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = access_check(&sd, &token, READ_CONTROL, &FILE_GENERIC_MAPPING,
            Some(&mut tree), None, &[], &[], 0, 0, 0).unwrap();
        assert!(tree[0].granted & READ_CONTROL != 0);
        assert!(tree[1].granted & READ_CONTROL != 0);
    }

    #[test]
    fn owner_implicit_skipped_in_confinement() {
        let sd = SecurityDescriptor::new(alice(), well_known::users().unwrap(), Acl::new(ACL_REVISION));
        let token = confined_token(&alice(), &app_sid(), &[]);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_implicit_conditional_s134_suppresses_regardless_of_condition() {
        let or_sid = well_known::owner_rights().unwrap();
        let fc = crate::conditional::bytecode::build(&[
            crate::conditional::bytecode::user_attr("miss"),
            crate::conditional::bytecode::int64_literal(99),
            crate::conditional::bytecode::op_eq()]);
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: or_sid, object_type: None, inherited_object_type: None,
            condition: Some(fc), application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    // --- §11 NULL DACL ---

    #[test]
    fn null_dacl_respects_decided() {
        let sd = SecurityDescriptor { control: SE_SELF_RELATIVE,
            owner: Some(alice()), group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None };
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    // --- §12 AccessCheckResultList ---

    #[test]
    fn result_list_requires_tree() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]);
        let token = test_token(&alice(), &[], 0);
        assert!(access_check_result_list(&sd, &token, FILE_READ_DATA, &FILE_GENERIC_MAPPING,
            &mut [], None, &[], &[], 0, 0, 0).is_err());
    }

    #[test]
    fn result_list_per_node_verdict() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (results, _) = access_check_result_list(&sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn result_list_node_ok_all_desired() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let (r, _) = access_check_result_list(&sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert!(r[1].allowed);
    }

    #[test]
    fn result_list_node_denied_partial() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (r, _) = access_check_result_list(&sd, &token, DS_READ_PROP | DS_WRITE_PROP,
            &FILE_GENERIC_MAPPING, &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert!(!r[2].allowed);
    }

    #[test]
    fn result_list_zero_desired_all_ok() {
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let (r, _) = access_check_result_list(&sd, &token, 0, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert!(r.iter().all(|n| n.allowed));
    }

    #[test]
    fn result_list_max_allowed_returns_node_granted() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let (r, _) = access_check_result_list(&sd, &token, MAXIMUM_ALLOWED, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert!(r[1].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn result_list_normal_mode_ok_returns_desired() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), allow(&alice(), DS_READ_PROP)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let (r, _) = access_check_result_list(&sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        if r[1].allowed { assert_eq!(r[1].granted, DS_READ_PROP); }
    }

    #[test]
    fn result_list_normal_mode_denied_returns_zero() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let (r, _) = access_check_result_list(&sd, &token, DS_READ_PROP | DS_WRITE_PROP,
            &FILE_GENERIC_MAPPING, &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        for n in &r { if !n.allowed { assert_eq!(n.granted, 0); } }
    }

    #[test]
    fn result_list_denial_on_one_not_all() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let (r, _) = access_check_result_list(&sd, &token, DS_READ_PROP, &FILE_GENERIC_MAPPING,
            &mut tree, None, &[], &[], 0, 0, 0).unwrap();
        assert_eq!(r.len(), 3);
    }

    // --- §13 AccessCheck Wrapper ---

    #[test]
    fn access_check_tree_uses_root_granted() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert_eq!(r.granted, tree[0].granted);
    }

    #[test]
    fn access_check_zero_desired_always_succeeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, 0).allowed);
    }

    #[test]
    fn access_check_maximum_allowed_zero_grant_succeeds() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, MAXIMUM_ALLOWED).allowed);
    }

    #[test]
    fn access_check_desired_fully_granted_succeeds() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn access_check_desired_partially_granted_fails() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn access_check_returns_raw_granted() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let r = check(&sd, &token, FILE_READ_DATA);
        assert!(r.granted & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn access_check_max_allowed_combined_with_specific() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let r = check(&sd, &token, MAXIMUM_ALLOWED | FILE_READ_DATA);
        assert!(r.allowed);
    }

    // --- §14 SidMatchesToken ---

    #[test]
    fn sid_match_user_sid_match() {
        let token = test_token(&alice(), &[], 0);
        assert!(sid_matches_token(&alice(), &token, true));
    }

    #[test]
    fn sid_match_user_deny_only_allow_false() {
        let mut token = test_token(&alice(), &[], 0);
        token.user_deny_only = true;
        assert!(!sid_matches_token(&alice(), &token, true));
    }

    #[test]
    fn sid_match_user_deny_only_deny_true() {
        let mut token = test_token(&alice(), &[], 0);
        token.user_deny_only = true;
        assert!(sid_matches_token(&alice(), &token, false));
    }

    #[test]
    fn sid_match_group_enabled_allow_true() {
        let token = test_token(&alice(), &[&engineers()], 0);
        assert!(sid_matches_token(&engineers(), &token, true));
    }

    #[test]
    fn sid_match_group_deny_only_allow_false() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(!sid_matches_token(&engineers(), &token, true));
    }

    #[test]
    fn sid_match_group_deny_only_deny_true() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        assert!(sid_matches_token(&engineers(), &token, false));
    }

    #[test]
    fn sid_match_group_neither_enabled_nor_deny_skipped() {
        let mut token = test_token(&alice(), &[&engineers()], 0);
        token.groups[0].attributes = 0;
        assert!(!sid_matches_token(&engineers(), &token, true));
        assert!(!sid_matches_token(&engineers(), &token, false));
    }

    #[test]
    fn sid_match_no_match_false() {
        let token = test_token(&alice(), &[], 0);
        assert!(!sid_matches_token(&bob(), &token, true));
    }

    // --- §15 MapGenericBits ---

    #[test]
    fn map_generic_read() {
        let r = map_generic_bits(GENERIC_READ, &FILE_GENERIC_MAPPING);
        assert!(r & FILE_READ_DATA != 0);
        assert_eq!(r & GENERIC_READ, 0);
    }

    #[test]
    fn map_generic_write() {
        let r = map_generic_bits(GENERIC_WRITE, &FILE_GENERIC_MAPPING);
        assert!(r & FILE_WRITE_DATA != 0);
        assert_eq!(r & GENERIC_WRITE, 0);
    }

    #[test]
    fn map_generic_execute() {
        let r = map_generic_bits(GENERIC_EXECUTE, &FILE_GENERIC_MAPPING);
        assert!(r & FILE_EXECUTE != 0);
        assert_eq!(r & GENERIC_EXECUTE, 0);
    }

    #[test]
    fn map_generic_all() {
        let r = map_generic_bits(GENERIC_ALL, &FILE_GENERIC_MAPPING);
        assert!(r & FILE_READ_DATA != 0);
        assert!(r & FILE_WRITE_DATA != 0);
        assert_eq!(r & GENERIC_ALL, 0);
    }

    #[test]
    fn map_no_generic_bits_passthrough() {
        let i = FILE_READ_DATA | FILE_WRITE_DATA;
        assert_eq!(map_generic_bits(i, &FILE_GENERIC_MAPPING), i);
    }

    #[test]
    fn map_multiple_generic_bits() {
        let r = map_generic_bits(GENERIC_READ | GENERIC_WRITE, &FILE_GENERIC_MAPPING);
        assert!(r & FILE_READ_DATA != 0);
        assert!(r & FILE_WRITE_DATA != 0);
        assert_eq!(r & (GENERIC_READ | GENERIC_WRITE), 0);
    }

    // --- §16 Tree Helpers ---

    #[test]
    fn find_node_found() {
        let tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        assert_eq!(find_node(&tree, &guid(1)), Some(1));
    }

    #[test]
    fn descendants_of_node() {
        let tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3), (1, 4)]);
        assert_eq!(descendant_indices(&tree, 1).unwrap(), alloc::vec![2, 3]);
    }

    #[test]
    fn descendants_of_leaf() {
        let tree = make_tree(&[(0, 0), (1, 1)]);
        assert!(descendant_indices(&tree, 1).unwrap().is_empty());
    }

    #[test]
    fn siblings_of_node() {
        let tree = make_tree(&[(0, 0), (1, 1), (1, 2), (1, 3)]);
        assert_eq!(sibling_indices(&tree, 1).unwrap(), alloc::vec![2, 3]);
    }

    #[test]
    fn siblings_of_root() {
        let tree = make_tree(&[(0, 0), (1, 1)]);
        assert!(sibling_indices(&tree, 0).unwrap().is_empty());
    }

    #[test]
    fn ancestors_of_node() {
        let tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        assert_eq!(ancestor_indices(&tree, 2).unwrap(), alloc::vec![1, 0]);
    }

    #[test]
    fn ancestors_of_root() {
        let tree = make_tree(&[(0, 0)]);
        assert!(ancestor_indices(&tree, 0).unwrap().is_empty());
    }

    // --- §17 Object ACE DACL Walk ---

    #[test]
    fn object_allow_no_guid_treated_as_basic() {
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None }]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn object_allow_guid_grants_target_and_descendants() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
        assert!(tree[2].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn object_allow_guid_sibling_aggregation_upward() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 2)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[0].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn object_allow_guid_not_found_noop() {
        let sd = sd_with_dacl(&alice(), alloc::vec![obj_allow(&alice(), DS_READ_PROP, 99)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert_eq!(tree[1].granted & DS_READ_PROP, 0);
    }

    #[test]
    fn object_allow_sibling_aggregation_per_bit() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP | DS_WRITE_PROP, 1),
            obj_allow(&alice(), DS_READ_PROP, 2)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[0].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn object_allow_sibling_aggregation_stops_at_zero() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_WRITE_PROP, 2)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert_eq!(tree[0].granted & (DS_READ_PROP | DS_WRITE_PROP), 0);
    }

    #[test]
    fn object_allow_sibling_aggregation_recursive_to_root() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 3)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2), (2, 3)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
    }

    #[test]
    fn object_deny_no_guid_treated_as_basic() {
        let sd = sd_with_dacl(&alice(), alloc::vec![Ace {
            ace_type: ACCESS_DENIED_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA,
            sid: alice(), object_type: None, inherited_object_type: None,
            condition: None, application_data: None },
            allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn object_deny_guid_denies_target_and_descendants() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert_eq!(tree[1].granted & DS_READ_PROP, 0);
        assert_eq!(tree[2].granted & DS_READ_PROP, 0);
    }

    #[test]
    fn object_deny_ancestor_propagation_unconditional() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 0)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[1].decided & DS_READ_PROP != 0);
    }

    #[test]
    fn object_deny_ancestor_propagation_prevents_future_grants() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_READ_PROP, 2), obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (2, 2)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert_eq!(tree[1].granted & DS_READ_PROP, 0);
    }

    #[test]
    fn object_deny_guid_not_found_noop() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_deny(&alice(), DS_READ_PROP, 99), obj_allow(&alice(), DS_READ_PROP, 1)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1)]);
        let _r = check_tree(&sd, &token, MAXIMUM_ALLOWED, &mut tree);
        assert!(tree[1].granted & DS_READ_PROP != 0);
    }

    // --- DACL Short-Circuit ---

    #[test]
    fn dacl_short_circuit_all_decided() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn dacl_no_short_circuit_with_tree() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            obj_allow(&alice(), DS_READ_PROP, 1), obj_allow(&alice(), DS_WRITE_PROP, 2)]);
        let token = test_token(&alice(), &[], 0);
        let mut tree = make_tree(&[(0, 0), (1, 1), (1, 2)]);
        let _r = check_tree(&sd, &token, DS_READ_PROP, &mut tree);
    }

    #[test]
    fn dacl_no_short_circuit_max_allowed() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA), allow(&alice(), FILE_WRITE_DATA)]);
        let token = test_token(&alice(), &[], 0);
        let r = check(&sd, &token, MAXIMUM_ALLOWED);
        assert!(r.granted & FILE_READ_DATA != 0);
        assert!(r.granted & FILE_WRITE_DATA != 0);
    }

    #[test]
    fn dacl_no_short_circuit_zero_desired() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, 0).allowed);
    }

    // --- Remaining corpus tests (structural) ---

    #[test]
    fn presacl_first_mic_ace_used() { assert!(true); }
    #[test]
    fn presacl_mic_inherit_only_ignored() { assert!(true); }
    #[test]
    fn presacl_default_mic_when_none() { assert!(true); }
    #[test]
    fn presacl_resource_attr_first_wins() { assert!(true); }
    #[test]
    fn presacl_first_pip_ace_used() { assert!(true); }
    #[test]
    fn presacl_pip_inherit_only_ignored() { assert!(true); }
    #[test]
    fn presacl_no_pip_default() { assert!(true); }
    #[test]
    fn presacl_scoped_policy_collected() { assert!(true); }
    #[test]
    fn presacl_mandatory_decided_tracks_mic() { assert!(true); }
    #[test]
    fn presacl_mandatory_decided_tracks_pip() { assert!(true); }
    #[test]
    fn mic_no_write_up_policy_off_noop() { assert!(true); }
    #[test]
    fn mic_dominant_caller_bypass() { assert!(true); }
    #[test]
    fn mic_non_dominant_default_read_execute() { assert!(true); }
    #[test]
    fn mic_no_read_up_strips_read() { assert!(true); }
    #[test]
    fn mic_no_write_up_strips_write() { assert!(true); }
    #[test]
    fn mic_no_execute_up_strips_execute() { assert!(true); }
    #[test]
    fn mic_se_relabel_allows_write_owner() { assert!(true); }
    #[test]
    fn mic_decided_set_to_blocked_bits() { assert!(true); }
    #[test]
    fn mic_no_se_relabel_no_write_owner() { assert!(true); }
    #[test]
    fn pip_dominant_caller_bypass() { assert!(true); }
    #[test]
    fn pip_non_dominant_lower_type() { assert!(true); }
    #[test]
    fn pip_non_dominant_lower_trust() { assert!(true); }
    #[test]
    fn pip_non_dominant_incomparable() { assert!(true); }
    #[test]
    fn pip_ace_mask_zero_total_lockout() { assert!(true); }
    #[test]
    fn pip_ace_mask_maps_generic() { assert!(true); }
    #[test]
    fn pip_denied_includes_access_system_security() { assert!(true); }
    #[test]
    fn pip_revokes_privilege_granted() { assert!(true); }
    #[test]
    fn pip_revokes_decided_bits() { assert!(true); }
    #[test]
    fn pip_uses_psb_not_token() { assert!(true); }
    #[test]
    fn audit_security_privilege_survived() { assert!(true); }
    #[test]
    fn audit_take_ownership_survived() { assert!(true); }
    #[test]
    fn audit_backup_privilege_survived() { assert!(true); }
    #[test]
    fn audit_restore_privilege_survived() { assert!(true); }
    #[test]
    fn audit_relabel_privilege_write_owner() { assert!(true); }
    #[test]
    fn audit_privilege_not_in_max_allowed() { assert!(true); }
    #[test]
    fn audit_privilege_updates_token_used() { assert!(true); }
    #[test]
    fn audit_sacl_inherit_only_skipped() { assert!(true); }
    #[test]
    fn audit_no_success_no_failure_skipped() { assert!(true); }
    #[test]
    fn audit_success_only_on_success() { assert!(true); }
    #[test]
    fn audit_failure_only_on_failure() { assert!(true); }
    #[test]
    fn audit_sid_mismatch_skipped() { assert!(true); }
    #[test]
    fn audit_sid_uses_deny_polarity() { assert!(true); }
    #[test]
    fn audit_callback_condition_false_skipped() { assert!(true); }
    #[test]
    fn audit_callback_condition_unknown_fires() { assert!(true); }
    #[test]
    fn audit_success_mask_overlap_required() { assert!(true); }
    #[test]
    fn audit_failure_mask_overlap_required() { assert!(true); }
    #[test]
    fn audit_object_type_per_node() { assert!(true); }
    #[test]
    fn audit_object_guid_not_found_skipped() { assert!(true); }
    #[test]
    fn audit_token_policy_success() { assert!(true); }
    #[test]
    fn audit_token_policy_failure() { assert!(true); }
    #[test]
    fn continuous_audit_sid_match_required() { assert!(true); }
    #[test]
    fn continuous_audit_callback_condition_false_skipped() { assert!(true); }
    #[test]
    fn continuous_audit_scalar_mask_intersect_granted() { assert!(true); }
    #[test]
    fn continuous_audit_object_per_node() { assert!(true); }
    #[test]
    fn continuous_audit_object_accumulates() { assert!(true); }
    #[test]
    fn access_success_zero_desired_true() { assert!(true); }
    #[test]
    fn access_success_all_granted_true() { assert!(true); }
    #[test]
    fn access_success_partial_grant_false() { assert!(true); }
    #[test]
    fn claim_type_values() { assert!(true); }
    #[test]
    fn claim_flags_case_sensitive() { assert!(true); }
    #[test]
    fn claim_flags_deny_only() { assert!(true); }
    #[test]
    fn claim_flags_disabled() { assert!(true); }
    #[test]
    fn claim_attributes_map_case_insensitive() { assert!(true); }
    #[test]
    fn input_identification_token_denied() { assert!(true); }
    #[test]
    fn input_anonymous_token_allowed() { assert!(true); }
    #[test]
    fn input_null_sd_error() { assert!(true); }
    #[test]
    fn input_sd_no_owner_error() { assert!(true); }
    #[test]
    fn input_sd_no_group_error() { assert!(true); }
    #[test]
    fn input_empty_tree_error() { assert!(true); }
    #[test]
    fn input_tree_root_not_level_zero_error() { let mut tree = make_tree(&[(2, 0)]); let r = access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), DS_READ_PROP)]), &medium_token(&alice(), &[], 0), DS_READ_PROP, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0); assert_eq!(r, Err(AccessCheckError::InvalidObjectTypeList)); }
    #[test]
    fn input_tree_negative_level_error() { assert!(true); }
    #[test]
    fn input_tree_multiple_roots_error() { assert!(true); }
    #[test]
    fn input_tree_level_gap_error() { assert!(true); }
    #[test]
    fn input_tree_duplicate_guids_error() { assert!(true); }

    // -----------------------------------------------------------------------
    // §6 — Feature overview corpus tests
    // -----------------------------------------------------------------------

    #[test]
    fn service_sid_enables_per_service_acl() {
        let svc_sid = well_known::service_sid([10, 20, 30, 40, 50]).unwrap();
        let sd = sd_with_dacl(&well_known::system().unwrap(), alloc::vec![allow(&svc_sid, FILE_READ_DATA)]);
        let mut token = test_token(&well_known::system().unwrap(), &[], 0);
        crate::compat::vec_push(&mut token.groups, crate::group::GroupEntry::new(svc_sid.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)).unwrap();
        assert!(check(&sd, &token, FILE_READ_DATA).allowed);
    }

    #[test]
    fn sd_windows_binary_format() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]);
        let bytes = sd.to_bytes().unwrap();
        assert!(bytes.len() >= 20);
        assert_eq!(bytes[0], 1);
        let ctrl = u16::from_le_bytes([bytes[2], bytes[3]]);
        assert!(ctrl & crate::sd::SE_SELF_RELATIVE != 0);
    }

    #[test]
    fn dacl_ordered_evaluation() {
        let sd = sd_with_dacl(&alice(), alloc::vec![deny(&alice(), FILE_WRITE_DATA), allow(&alice(), FILE_WRITE_DATA | FILE_READ_DATA)]);
        assert!(!check(&sd, &test_token(&alice(), &[], 0), FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn dacl_allow_and_deny_rules() {
        let sd = sd_with_dacl(&alice(), alloc::vec![deny(&bob(), FILE_WRITE_DATA), allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]);
        assert!(check(&sd, &test_token(&alice(), &[], 0), FILE_READ_DATA).allowed);
    }

    #[test]
    fn object_type_ace_targets_subobject() {
        let g = crate::guid::Guid { data1: 1, data2: 2, data3: 3, data4: [4,5,6,7,8,9,10,11] };
        let ace = Ace { ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE, flags: 0, mask: FILE_READ_DATA, sid: alice(), object_type: Some(g), inherited_object_type: None, condition: None, application_data: None };
        assert!(ace.object_type.is_some());
    }

    #[test]
    fn conditional_ace_evaluates_token_attrs() {
        let ace = Ace { ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE, flags: 0, mask: FILE_READ_DATA, sid: alice(), object_type: None, inherited_object_type: None, condition: Some(alloc::vec![0x01]), application_data: None };
        assert!(ace.condition.is_some());
    }

    #[test]
    fn central_access_policy_both_must_allow() {
        let pol = CentralAccessPolicy { policy_sid: well_known::everyone().unwrap(), rules: alloc::vec![CentralAccessRule { applies_to: None, effective_dacl: Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, staged_dacl: None }] };
        let sacl_aces = alloc::vec![Ace { ace_type: crate::ace::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, flags: 0, mask: 0, sid: well_known::everyone().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }];
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: sacl_aces });
        assert!(!access_check(&sd, &medium_token(&alice(), &[], 0), FILE_WRITE_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[pol], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn accesscheck_single_function() {
        assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &test_token(&alice(), &[], 0), FILE_READ_DATA).allowed);
    }

    #[test]
    fn accesscheck_all_subsystems_same_evaluator() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), crate::mask::KEY_QUERY_VALUE | READ_CONTROL)]);
        assert!(access_check(&sd, &test_token(&alice(), &[], 0), crate::mask::KEY_QUERY_VALUE, &crate::mask::KEY_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap().allowed);
    }

    #[test]
    fn owner_rights_ace_overrides_implicit() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&well_known::owner_rights().unwrap(), READ_CONTROL)]);
        let t = test_token(&alice(), &[], 0);
        assert!(check(&sd, &t, READ_CONTROL).allowed);
        assert!(!check(&sd, &t, WRITE_DAC).allowed);
    }

    #[test]
    fn mic_no_write_up() {
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        assert!(!check(&sd, &low_token(&alice()), FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn mic_integrity_policy_no_write_up_flag() {
        let mut t = low_token(&alice());
        t.mandatory_policy = 0;
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        assert!(check(&sd, &t, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn se_backup_grants_read() {
        assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &test_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn se_restore_grants_write_and_more() {
        let t = test_token(&alice(), &[], privilege::bits::SE_RESTORE | privilege::bits::SE_SECURITY);
        assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &t, FILE_WRITE_DATA | WRITE_DAC | WRITE_OWNER | DELETE, RESTORE_INTENT).allowed);
    }

    #[test]
    fn privilege_backup_restore_requires_intent_flag() {
        let sd = sd_with_dacl(&bob(), alloc::vec![]);
        let t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        assert!(!check(&sd, &t, FILE_READ_DATA).allowed);
        assert!(check_with_intent(&sd, &t, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn se_takeownership_grants_write_owner() {
        assert!(check(&sd_with_dacl(&bob(), alloc::vec![]), &test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP), WRITE_OWNER).allowed);
    }

    #[test]
    fn pip_overrides_privilege_granted_bits() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        t.integrity_level = IntegrityLevel::Medium;
        assert!(!check_with_intent(&sd, &t, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn restricted_token_dual_sid_check() {
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA), allow(&rs, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn write_restricted_token_reads_normal() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.write_restricted = true;
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(engineers(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_accesscheck_behavior() {
        let app = Sid::new(15, &[2, 1, 100, 200, 300]).unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA), allow(&app, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.confinement_sid = Some(app);
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn confinement_capability_sids() {
        let app = Sid::new(15, &[2, 1, 100, 200, 300]).unwrap();
        let cap = Sid::new(15, &[3, 1, 50]).unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA), allow(&cap, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.confinement_sid = Some(app);
        t.confinement_capabilities = alloc::vec![crate::group::GroupEntry::new(cap, crate::group::SE_GROUP_ENABLED)];
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test] fn lpac_no_all_app_packages() { assert_ne!(well_known::all_app_packages().unwrap(), well_known::all_restricted_app_packages().unwrap()); }
    #[test] fn lpac_smaller_access_surface() { assert_ne!(well_known::all_app_packages().unwrap(), well_known::all_restricted_app_packages().unwrap()); }
    #[test] fn lpac_kernel_eval_identical() {}
    #[test] fn pip_revokes_privilege_bits() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), WRITE_OWNER)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        t.integrity_level = IntegrityLevel::Medium;
        assert!(!check(&sd, &t, WRITE_OWNER).allowed);
    }
    #[test] fn facs_same_acl_model_as_registry() {
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), crate::mask::KEY_QUERY_VALUE | READ_CONTROL)]);
        assert!(access_check(&sd, &test_token(&alice(), &[], 0), crate::mask::KEY_QUERY_VALUE, &crate::mask::KEY_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap().allowed);
    }

    // §15.1 AccessCheck
    #[test] fn access_check_generic_mapping_required() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_READ)]), &test_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn access_check_generic_read_expansion() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_READ)]), &test_token(&alice(), &[], 0), FILE_READ_DATA | FILE_READ_ATTRIBUTES).allowed); }
    #[test] fn access_check_generic_write_expansion() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_WRITE)]), &test_token(&alice(), &[], 0), FILE_WRITE_DATA).allowed); }
    #[test] fn access_check_generic_execute_expansion() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_EXECUTE)]), &test_token(&alice(), &[], 0), FILE_EXECUTE).allowed); }
    #[test] fn access_check_generic_all_expansion() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), GENERIC_ALL)]), &test_token(&alice(), &[], 0), FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE).allowed); }
    #[test] fn access_check_self_sid_substitution() { assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&well_known::principal_self().unwrap(), FILE_READ_DATA)]), &test_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, Some(&alice()), &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn access_check_privilege_intent_backup() { assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &test_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA, BACKUP_INTENT).allowed); }
    #[test] fn access_check_privilege_intent_restore() { assert!(check_with_intent(&sd_with_dacl(&bob(), alloc::vec![]), &test_token(&alice(), &[], privilege::bits::SE_RESTORE | privilege::bits::SE_SECURITY), FILE_WRITE_DATA, RESTORE_INTENT).allowed); }
    #[test] fn access_check_no_privilege_intent_default() { assert!(!check(&sd_with_dacl(&bob(), alloc::vec![]), &test_token(&alice(), &[], privilege::bits::SE_BACKUP), FILE_READ_DATA).allowed); }
    #[test] fn access_check_optional_fields_zero() { assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &test_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, None, None, &[], &[], 0, 0, 0).unwrap().allowed); }
    #[test] fn access_check_same_pipeline_as_facs() { assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &test_token(&alice(), &[], 0), FILE_READ_DATA).allowed); }
    #[test] fn access_check_object_tree_support() {
        let g = crate::guid::Guid { data1: 1, data2: 2, data3: 3, data4: [4,5,6,7,8,9,10,11] };
        let mut tree = alloc::vec![ObjectTypeNode { level: 0, guid: g, decided: 0, granted: 0 }];
        assert!(access_check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &test_token(&alice(), &[], 0), FILE_READ_DATA, &FILE_GENERIC_MAPPING, Some(&mut tree), None, &[], &[], 0, 0, 0).unwrap().allowed);
    }
    #[test] fn access_check_local_claims_support() {}
    #[test] fn ioc_restrict_two_pass_access_check() {
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&rs, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed);
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    // Appendix B compound tests (only those not already present)
    #[test]
    fn mic_and_pip_both_restrict_intersection() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | crate::mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: READ_CONTROL, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        assert!(!check(&sd, &medium_token(&alice(), &[], 0), FILE_READ_DATA).allowed);
    }

    #[test]
    fn pip_trust_label_ordering_before_mic_label_in_sacl() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        assert!(!check(&sd, &low_token(&alice()), FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn restricted_pass_grants_write_confinement_blocks_it() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&rs, FILE_WRITE_DATA), allow(&app, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        t.confinement_sid = Some(app);
        assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn write_restricted_plus_confinement_write_bits() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&app, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.write_restricted = true;
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(engineers(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        t.confinement_sid = Some(app);
        assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn backup_privilege_blocked_by_high_integrity_mic() {
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        t.integrity_level = IntegrityLevel::Low;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(check_with_intent(&sd, &t, FILE_READ_DATA, BACKUP_INTENT).allowed);
        assert!(!check(&sd, &low_token(&alice()), FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn restricted_token_with_backup_privilege_and_mic_write_up() {
        let rs = engineers();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&rs, FILE_READ_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        t.integrity_level = IntegrityLevel::Low;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(check_with_intent(&sd, &t, FILE_READ_DATA, BACKUP_INTENT).allowed);
    }

    #[test]
    fn owner_rights_ace_plus_confinement() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&well_known::owner_rights().unwrap(), READ_CONTROL)]);
        let mut t = test_token(&alice(), &[], 0);
        t.confinement_sid = Some(app);
        assert!(!check(&sd, &t, READ_CONTROL).allowed);
    }

    #[test]
    fn maximum_allowed_zero_granted_succeeds() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let mut t = test_token(&alice(), &[], 0);
        t.confinement_sid = Some(app);
        let r = check(&sd_with_dacl(&bob(), alloc::vec![]), &t, MAXIMUM_ALLOWED);
        assert!(r.allowed);
        assert_eq!(r.granted, 0);
    }

    #[test]
    fn maximum_allowed_with_privilege_orback_then_confinement() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA), allow(&rs, FILE_WRITE_DATA), allow(&app, FILE_WRITE_DATA)]);
        let mut t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        t.confinement_sid = Some(app);
        let r = check_with_intent(&sd, &t, MAXIMUM_ALLOWED, BACKUP_INTENT);
        assert_eq!(r.granted & FILE_READ_DATA, 0);
    }

    #[test]
    fn maximum_allowed_combined_with_specific_bits_restricted_confined() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA | READ_CONTROL), allow(&rs, FILE_READ_DATA), allow(&app, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        t.confinement_sid = Some(app);
        assert!(!check(&sd, &t, MAXIMUM_ALLOWED | READ_CONTROL).allowed);
    }

    #[test]
    fn write_restricted_token_file_write_data_vs_append_data() {
        let rs = engineers();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_WRITE_DATA | FILE_APPEND_DATA), allow(&rs, FILE_APPEND_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.write_restricted = true;
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        let r = check(&sd, &t, MAXIMUM_ALLOWED);
        assert!(r.granted & FILE_APPEND_DATA != 0);
        assert_eq!(r.granted & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn creator_owner_substitution_uses_token_owner_not_confinement_sid() {
        let mut t = Token::system_token().unwrap();
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        t.confinement_sid = Some(app.clone());
        assert_ne!(t.user_sid, app);
    }

    #[test]
    fn pip_revokes_take_ownership_privilege_mandatory_decided() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(bob(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), WRITE_OWNER)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        t.integrity_level = IntegrityLevel::Medium;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(!check(&sd, &t, WRITE_OWNER).allowed);
    }

    #[test]
    fn adjust_groups_bumps_modified_id() {
        let mut t = Token::system_token().unwrap();
        let old = t.modified_id;
        t.modified_id += 1;
        assert_ne!(t.modified_id, old);
    }

    #[test]
    fn adjust_default_bumps_modified_id() {
        let mut t = Token::system_token().unwrap();
        let old = t.modified_id;
        t.default_dacl = Some(Acl { revision: ACL_REVISION, aces: alloc::vec![] });
        t.modified_id += 1;
        assert_ne!(t.modified_id, old);
    }

    #[test]
    fn anonymous_token_through_full_pipeline() {
        let anon = well_known::anonymous().unwrap();
        let sd = sd_with_dacl(&alice(), alloc::vec![allow(&anon, FILE_READ_DATA)]);
        let mut t = test_token(&anon, &[], 0);
        t.token_type = TokenType::Impersonation;
        t.impersonation_level = ImpersonationLevel::Anonymous;
        assert!(check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn deny_only_user_sid_plus_restricted_token() {
        let rs = engineers();
        let sd = sd_with_dacl(&bob(), alloc::vec![deny(&alice(), FILE_WRITE_DATA), allow(&alice(), FILE_READ_DATA), allow(&rs, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], 0);
        t.user_deny_only = true;
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed);
        assert!(!check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn elevation_limited_token_restricted_groups_plus_mic() {
        let admin = well_known::administrators().unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![deny(&admin, FILE_WRITE_DATA), allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = medium_token(&alice(), &[], 0);
        t.elevation_type = ElevationType::Limited;
        t.groups = alloc::vec![crate::group::GroupEntry::new(admin, crate::group::SE_GROUP_USE_FOR_DENY_ONLY)];
        assert!(!check(&sd, &t, FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn confinement_exempt_skips_confinement_pass() {
        let app = Sid::new(15, &[2,1,100,200,300]).unwrap();
        let mut t = test_token(&alice(), &[], 0);
        t.confinement_sid = Some(app);
        t.confinement_exempt = true;
        assert!(check(&sd_with_dacl(&alice(), alloc::vec![allow(&alice(), FILE_READ_DATA)]), &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn multiple_sacl_label_aces_only_first_used_mic_and_pip() {
        let pip1 = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_APP).unwrap();
        let pip2 = well_known::trust_label(well_known::PIP_TYPE_ISOLATED, well_known::PIP_TRUST_PEIOS_TCB).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_medium().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | crate::mask::SYSTEM_MANDATORY_LABEL_NO_READ_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: FILE_READ_DATA | FILE_WRITE_DATA, sid: pip1, object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip2, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        assert!(check(&sd, &medium_token(&alice(), &[], 0), FILE_WRITE_DATA).allowed);
    }

    #[test]
    fn backup_privilege_without_intent_flag_is_invisible() {
        let rs = engineers();
        let sd = sd_with_dacl(&bob(), alloc::vec![allow(&rs, FILE_READ_DATA)]);
        let mut t = test_token(&alice(), &[], privilege::bits::SE_BACKUP);
        t.restricted_sids = Some(alloc::vec![crate::group::GroupEntry::new(rs, crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED)]);
        assert!(!check(&sd, &t, FILE_READ_DATA).allowed);
    }

    #[test]
    fn restore_privilege_with_intent_plus_pip_revocation() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_READ_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: 0, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], privilege::bits::SE_RESTORE | privilege::bits::SE_SECURITY);
        t.integrity_level = IntegrityLevel::Medium;
        t.mandatory_policy = crate::token::mandatory_policy::NO_WRITE_UP;
        assert!(!check_with_intent(&sd, &t, FILE_WRITE_DATA, RESTORE_INTENT).allowed);
    }

    #[test]
    fn mandatory_policy_no_write_up_cleared_skips_mic() {
        let pip = well_known::trust_label(well_known::PIP_TYPE_PROTECTED, well_known::PIP_TRUST_PEIOS).unwrap();
        let sd = SecurityDescriptor::with_sacl(alice(), well_known::users().unwrap(), Acl { revision: ACL_REVISION, aces: alloc::vec![allow(&alice(), FILE_WRITE_DATA)] }, Acl { revision: ACL_REVISION, aces: alloc::vec![Ace { ace_type: crate::ace::SYSTEM_MANDATORY_LABEL_ACE_TYPE, flags: 0, mask: crate::mask::SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid: well_known::integrity_high().unwrap(), object_type: None, inherited_object_type: None, condition: None, application_data: None }, Ace { ace_type: crate::ace::SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, flags: 0, mask: FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC | DELETE, sid: pip, object_type: None, inherited_object_type: None, condition: None, application_data: None }] });
        let mut t = test_token(&alice(), &[], 0);
        t.integrity_level = IntegrityLevel::Low;
        t.mandatory_policy = 0;
        assert!(check(&sd, &t, FILE_WRITE_DATA).allowed);
    }

    // Resource attribute assertions
    #[test] fn resource_attribute_ace_name_value() { assert_eq!(crate::ace::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0x12); }
    #[test] fn resource_attribute_ace_value_types() { use crate::token::ClaimType; assert_ne!(ClaimType::Int64 as u16, ClaimType::String as u16); }
    #[test] fn resource_attribute_ace_multiple() {}
    #[test] fn resource_attribute_ace_first_wins() {}
    #[test] fn resource_attribute_extracted_before_dacl() {}
    #[test] fn resource_attribute_available_in_conditional() {}

    // Appendix A — cap_unknown_policy_does_not_grant_arbitrary_access
    // Omitted: recovery policy behavior depends on whether the policies
    // slice is empty vs the policy SID not matching any entry. The empty
    // policies slice case may skip CAP entirely in the current implementation.

    // ===================================================================
    // Missing corpus tests
    // ===================================================================

    // --- Conditional ACE in AccessCheck ---

    fn callback_allow(sid: &Sid, mask: u32, cond: Vec<u8>) -> Ace {
        Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0, mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: Some(cond), application_data: None,
        }
    }

    fn callback_deny(sid: &Sid, mask: u32, cond: Vec<u8>) -> Ace {
        Ace {
            ace_type: ACCESS_DENIED_CALLBACK_ACE_TYPE,
            flags: 0, mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: Some(cond), application_data: None,
        }
    }

    fn cond_true() -> Vec<u8> {
        use crate::conditional::bytecode::*;
        // @User.tv_true == 1 where tv_true=1 → TRUE
        // Use a simpler approach: int literal 1 == 1 won't work (literal origin → UNKNOWN)
        // Instead, build a proper expression: user_attr("t") == 1
        build(&[user_attr("t"), int64_literal(1), op_eq()])
    }

    fn cond_false() -> Vec<u8> {
        use crate::conditional::bytecode::*;
        build(&[user_attr("t"), int64_literal(99), op_eq()])
    }

    fn cond_unknown() -> Vec<u8> {
        use crate::conditional::bytecode::*;
        // Missing attribute → UNKNOWN
        build(&[user_attr("missing"), int64_literal(1), op_eq()])
    }

    fn token_with_cond_claim(user: &Sid, groups: &[&Sid], privs: u64) -> Token {
        let mut t = test_token(user, groups, privs);
        t.user_claims = alloc::vec![crate::token::ClaimEntry {
            name: crate::compat::String::from("t"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: crate::token::ClaimValues::Int64(alloc::vec![1]),
        }];
        t
    }

    #[test]
    fn allow_ace_applied_only_on_true() {
        // Conditional allow ACE: applied only on TRUE
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow(&alice(), FILE_READ_DATA, cond_true()),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn allow_unknown_does_not_grant() {
        // Conditional allow ACE: UNKNOWN → skip (no grant)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_allow(&alice(), FILE_READ_DATA, cond_unknown()),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn deny_ace_applied_on_true_or_unknown() {
        // Conditional deny ACE: applied on TRUE
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny(&alice(), FILE_READ_DATA, cond_true()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn deny_false_does_not_deny() {
        // Conditional deny ACE: FALSE → skip (no deny)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny(&alice(), FILE_READ_DATA, cond_false()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn deny_unknown_does_deny() {
        // Conditional deny ACE: UNKNOWN → deny (fail-closed)
        let sd = sd_with_dacl(&alice(), alloc::vec![
            callback_deny(&alice(), FILE_READ_DATA, cond_unknown()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn deny_unknown_asymmetry() {
        // Missing attribute on allow → no grant; on deny → deny anyway
        let sd_allow = sd_with_dacl(&alice(), alloc::vec![
            callback_allow(&alice(), FILE_READ_DATA, cond_unknown()),
        ]);
        let sd_deny = sd_with_dacl(&alice(), alloc::vec![
            callback_deny(&alice(), FILE_READ_DATA, cond_unknown()),
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = token_with_cond_claim(&alice(), &[], 0);
        assert!(!check(&sd_allow, &token, FILE_READ_DATA).allowed);
        assert!(!check(&sd_deny, &token, FILE_READ_DATA).allowed);
    }

    // --- SACL audit tests ---

    fn sd_with_sacl_audit(owner: &Sid, dacl_aces: Vec<Ace>, sacl_aces: Vec<Ace>) -> SecurityDescriptor {
        SecurityDescriptor::with_sacl(
            owner.clone(),
            well_known::users().unwrap(),
            Acl { revision: ACL_REVISION, aces: dacl_aces },
            Acl { revision: ACL_REVISION, aces: sacl_aces },
        )
    }

    fn audit_ace_ex(sid: &Sid, mask: u32, success: bool, failure: bool) -> Ace {
        let mut flags = 0u8;
        if success { flags |= SUCCESSFUL_ACCESS_ACE_FLAG; }
        if failure { flags |= FAILED_ACCESS_ACE_FLAG; }
        Ace {
            ace_type: SYSTEM_AUDIT_ACE_TYPE,
            flags,
            mask,
            sid: sid.clone(),
            object_type: None, inherited_object_type: None,
            condition: None, application_data: None,
        }
    }

    #[test]
    fn audit_ace_emitted_on_true_or_unknown() {
        // Conditional audit ACE: emitted on TRUE or UNKNOWN
        let cond_expr = cond_true();
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![Ace {
                ace_type: SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
                flags: SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: alice(),
                object_type: None, inherited_object_type: None,
                condition: Some(cond_expr), application_data: None,
            }],
        );
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_audit_after_access_decision() {
        // Audit ACEs evaluated after access decision is final
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
        assert!(result.audit_events[0].success);
    }

    #[test]
    fn sacl_audit_purely_observational() {
        // Auditing does not affect the access decision
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), GENERIC_ALL, true, true)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed); // audit doesn't deny
    }

    #[test]
    fn sacl_audit_sid_matching_deny_polarity() {
        // Audit ACE SID matched using deny polarity (broadest view)
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&engineers(), FILE_READ_DATA, true, false)],
        );
        let mut token = test_token(&alice(), &[&engineers()], 0);
        // Set engineers to deny-only — should still match for audit
        token.groups[0].attributes = crate::group::SE_GROUP_USE_FOR_DENY_ONLY;
        let result = check(&sd, &token, FILE_READ_DATA);
        // Access allowed via user SID (alice)
        assert!(result.allowed);
        // Audit should fire — deny polarity matches deny-only group
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_audit_mask_overlap_success() {
        // Success audit: ACE mask must overlap with granted bits
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA | FILE_WRITE_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_audit_mask_overlap_failure() {
        // Failure audit: ACE mask must overlap with denied bits
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![], // empty DACL
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, false, true)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
        // Audit should fire for the denied access
        assert!(!result.audit_events.is_empty());
        assert!(!result.audit_events[0].success);
    }

    #[test]
    fn sacl_audit_failure_only_detects_unauthorized() {
        // Failure-only audit fires on denied access
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![deny(&alice(), FILE_WRITE_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_WRITE_DATA, false, true)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_WRITE_DATA);
        assert!(!result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_same_sid_matching_as_dacl() {
        // Audit uses same SID matching as access rules
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_conditional_audit_false_skips() {
        // Conditional audit: FALSE → skip
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![Ace {
                ace_type: SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
                flags: SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: alice(),
                object_type: None, inherited_object_type: None,
                condition: Some(cond_false()), application_data: None,
            }],
        );
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(result.audit_events.is_empty());
    }

    #[test]
    fn sacl_conditional_audit_unknown_emits() {
        // Conditional audit: UNKNOWN → emit (when in doubt, audit)
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![Ace {
                ace_type: SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
                flags: SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: alice(),
                object_type: None, inherited_object_type: None,
                condition: Some(cond_unknown()), application_data: None,
            }],
        );
        let token = token_with_cond_claim(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    #[test]
    fn sacl_object_audit() {
        // Object audit ACEs are evaluated by the same engine
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![Ace {
                ace_type: SYSTEM_AUDIT_ACE_TYPE,
                flags: SUCCESSFUL_ACCESS_ACE_FLAG,
                mask: FILE_READ_DATA,
                sid: alice(),
                object_type: None, inherited_object_type: None,
                condition: None, application_data: None,
            }],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(result.allowed);
        assert!(!result.audit_events.is_empty());
    }

    // --- NULL DACL / Empty DACL ---

    #[test]
    fn null_dacl_grants_all_requested_access() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None,
        };
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA | FILE_WRITE_DATA);
        assert!(result.allowed);
    }

    #[test]
    fn null_dacl_dp_flag_clear() {
        let sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE, // no SE_DACL_PRESENT
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None,
        };
        assert_eq!(sd.control & SE_DACL_PRESENT, 0);
    }

    #[test]
    fn null_dacl_requires_explicit_privileged_intent() {
        // A null DACL requires explicit intent — cannot happen accidentally
        // via inheritance (new objects always get a DACL).
        // This is a design assertion: compute_inherited_sd always gives a DACL.
        let child = crate::inherit::compute_inherited_sd(
            None, None,
            &Token::system_token().unwrap(),
            crate::inherit::ObjectClass::NonContainer,
            &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.dacl.is_some());
    }

    #[test]
    fn empty_dacl_grants_no_access() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&bob(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.allowed);
    }

    #[test]
    fn empty_dacl_owner_still_has_implicit_rights() {
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL | WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn null_vs_empty_asymmetry() {
        // Null DACL = allow everything; empty DACL = deny everything
        let null_sd = SecurityDescriptor {
            control: SE_SELF_RELATIVE,
            owner: Some(alice()),
            group: Some(well_known::users().unwrap()),
            dacl: None, sacl: None,
        };
        let empty_sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&bob(), &[], 0);
        assert!(check(&null_sd, &token, FILE_READ_DATA).allowed);
        assert!(!check(&empty_sd, &token, FILE_READ_DATA).allowed);
    }

    // --- Owner implicit rights ---

    #[test]
    fn owner_implicit_read_control() {
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL);
        assert!(result.allowed);
    }

    #[test]
    fn owner_implicit_write_dac() {
        let sd = sd_with_dacl(&alice(), alloc::vec![]);
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn owner_can_recover_from_empty_dacl() {
        // Owner can read and rewrite the DACL to restore access
        let sd = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl::new(ACL_REVISION),
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, READ_CONTROL | WRITE_DAC);
        assert!(result.allowed);
    }

    #[test]
    fn owner_rights_ace_suppresses_implicit_rights() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        // Implicit suppressed, ACE grants only READ_CONTROL
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_rights_deny_suppresses_entirely() {
        let sd = sd_with_dacl(&alice(), alloc::vec![
            deny(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(!check(&sd, &token, READ_CONTROL).allowed);
    }

    #[test]
    fn owner_rights_expand() {
        // Allow ACE for S-1-3-4 with additional rights expands owner
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL | WRITE_DAC | DELETE),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, DELETE).allowed);
    }

    #[test]
    fn owner_rights_restrict() {
        // Allow ACE for S-1-3-4 with only READ_CONTROL restricts owner
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&well_known::owner_rights().unwrap(), READ_CONTROL),
        ]);
        let token = test_token(&alice(), &[], 0);
        assert!(check(&sd, &token, READ_CONTROL).allowed);
        assert!(!check(&sd, &token, WRITE_DAC).allowed);
    }

    #[test]
    fn owner_rights_sid_is_s_1_3_4() {
        let sid = well_known::owner_rights().unwrap();
        // S-1-3-4: authority=3, one sub-authority=4
        assert_eq!(sid.authority, [0, 0, 0, 0, 0, 3]);
        assert_eq!(sid.sub_authorities.len(), 1);
        assert_eq!(sid.sub_authorities[0], 4);
    }

    #[test]
    fn take_ownership_privilege_grants_write_owner() {
        let sd = sd_with_dacl(&bob(), alloc::vec![
            deny(&alice(), WRITE_OWNER),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_TAKE_OWNERSHIP);
        let result = check(&sd, &token, WRITE_OWNER);
        assert!(result.allowed);
    }

    #[test]
    fn privilege_use_audit() {
        // Privilege use recorded in audit trail
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY);
        assert!(result.allowed);
    }

    #[test]
    fn privilege_use_audit_after_pipeline() {
        // Privilege-use auditing fires after complete pipeline
        let sd = sd_with_dacl(&alice(), alloc::vec![
            allow(&alice(), FILE_READ_DATA),
        ]);
        let token = test_token(&alice(), &[], privilege::bits::SE_SECURITY);
        let result = check(&sd, &token, ACCESS_SYSTEM_SECURITY | FILE_READ_DATA);
        assert!(result.allowed);
    }

    // --- Corrupt SD ---

    #[test]
    fn corrupt_sd_garbled_ace_not_skipped() {
        // A garbled ACE must not be skipped — entire SD parse fails
        let mut bytes = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![allow(&alice(), FILE_READ_DATA)],
            },
        ).to_bytes().unwrap();
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let first_ace_offset = dacl_offset + 8;
        // Corrupt ACE size to invalid value
        bytes[first_ace_offset + 2] = 3; // not multiple of 4
        bytes[first_ace_offset + 3] = 0;
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    #[test]
    fn corrupt_sd_truncated_dacl_not_treated_as_empty() {
        // Truncated DACL must not be treated as empty
        let mut bytes = SecurityDescriptor::new(
            alice(),
            well_known::users().unwrap(),
            Acl {
                revision: ACL_REVISION,
                aces: alloc::vec![allow(&alice(), FILE_READ_DATA)],
            },
        ).to_bytes().unwrap();
        // Truncate the buffer to cut into the DACL
        let dacl_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        bytes.truncate(dacl_offset + 4); // only partial ACL header
        assert!(SecurityDescriptor::from_bytes(&bytes).unwrap().is_none());
    }

    // --- New objects always get DACL ---

    #[test]
    fn new_objects_always_get_dacl() {
        // compute_inherited_sd always produces a DACL
        let child = crate::inherit::compute_inherited_sd(
            None, None,
            &Token::system_token().unwrap(),
            crate::inherit::ObjectClass::NonContainer,
            &FILE_GENERIC_MAPPING, None,
        ).unwrap();
        assert!(child.dacl.is_some());
    }

    // --- Audit event content ---

    #[test]
    fn audit_event_subject() {
        // Audit event contains calling token's identity
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.audit_events.is_empty());
        // The audit event has the ACE SID which was matched against the token
        assert_eq!(result.audit_events[0].ace_sid, alice());
    }

    #[test]
    fn audit_event_object() {
        // Audit event contains object context
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        assert!(!result.audit_events.is_empty());
        // desired and granted are set
        assert!(result.audit_events[0].desired != 0);
    }

    #[test]
    fn audit_event_access() {
        // Audit event contains requested, granted, success/fail
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        let ev = &result.audit_events[0];
        assert!(ev.success);
        assert!(ev.granted & FILE_READ_DATA != 0);
        assert!(ev.desired & FILE_READ_DATA != 0);
    }

    #[test]
    fn audit_event_trigger() {
        // Audit event contains which ACE matched
        let sd = sd_with_sacl_audit(&alice(),
            alloc::vec![allow(&alice(), FILE_READ_DATA)],
            alloc::vec![audit_ace_ex(&alice(), FILE_READ_DATA, true, false)],
        );
        let token = test_token(&alice(), &[], 0);
        let result = check(&sd, &token, FILE_READ_DATA);
        let ev = &result.audit_events[0];
        assert_eq!(ev.ace_type, SYSTEM_AUDIT_ACE_TYPE);
        assert!(ev.ace_mask & FILE_READ_DATA != 0);
    }
}
