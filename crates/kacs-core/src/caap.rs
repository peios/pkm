use alloc::vec::Vec;

use crate::access_mask::GenericMapping;
use crate::condition::{evaluate_conditional_expression, ConditionalContext, ConditionalResult};
use crate::error::{KacsError, KacsResult};
use crate::evaluate_sd::{evaluate_security_descriptor, EvaluateSecurityDescriptorState};
use crate::object_tree::ObjectTypeList;
use crate::pip::PipContext;
use crate::security_descriptor::{
    SecurityDescriptor, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use crate::sid::Sid;
use crate::token::AccessCheckToken;
use crate::{ACCESS_ALLOWED_ACE_TYPE, GENERIC_ALL, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE};

const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaapRule<'a> {
    pub applies_to: Option<&'a [u8]>,
    pub effective_dacl: &'a [u8],
    pub effective_sacl: Option<&'a [u8]>,
    pub staged_dacl: Option<&'a [u8]>,
    pub staged_sacl: Option<&'a [u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaapPolicy<'a> {
    pub rules: Vec<CaapRule<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaapPolicyEntry<'a> {
    pub sid: Sid<'a>,
    pub policy: CaapPolicy<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaapEvaluationState<'a> {
    pub granted: u32,
    pub object_granted_list: Option<Vec<u32>>,
    pub staged_granted: u32,
    pub staged_object_granted_list: Option<Vec<u32>>,
    pub effective_sacls: Vec<&'a [u8]>,
    pub staged_sacls: Vec<&'a [u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuleGrantState {
    granted: u32,
    object_granted_list: Option<Vec<u32>>,
}

pub fn evaluate_caap<'a>(
    sd: &SecurityDescriptor<'a>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    base: &EvaluateSecurityDescriptorState<'a>,
    policies: &[CaapPolicyEntry<'a>],
) -> KacsResult<CaapEvaluationState<'a>> {
    let mut granted = base.granted;
    let mut object_granted_list = clone_base_object_grants(base, object_tree)?;
    let mut staged_granted = base.granted;
    let mut staged_object_granted_list = clone_base_object_grants(base, object_tree)?;
    let mut effective_sacls = Vec::new();
    let mut staged_sacls = Vec::new();

    if base.policy_sids.is_empty() {
        return Ok(CaapEvaluationState {
            granted,
            object_granted_list,
            staged_granted,
            staged_object_granted_list,
            effective_sacls,
            staged_sacls,
        });
    }

    for policy_sid in &base.policy_sids {
        if let Some(policy) = lookup_policy(policies, *policy_sid) {
            for rule in &policy.rules {
                apply_rule(
                    rule.applies_to,
                    rule.effective_dacl,
                    rule.effective_sacl,
                    rule.staged_dacl,
                    rule.staged_sacl,
                    sd,
                    token,
                    pip,
                    desired_access,
                    mapping,
                    object_tree,
                    conditional_context,
                    base,
                    &mut granted,
                    object_granted_list.as_mut(),
                    &mut staged_granted,
                    staged_object_granted_list.as_mut(),
                    &mut effective_sacls,
                    &mut staged_sacls,
                )?;
            }
        } else {
            let recovery_dacl = build_recovery_policy_dacl();
            apply_rule(
                None,
                recovery_dacl.as_slice(),
                None,
                None,
                None,
                sd,
                token,
                pip,
                desired_access,
                mapping,
                object_tree,
                conditional_context,
                base,
                &mut granted,
                object_granted_list.as_mut(),
                &mut staged_granted,
                staged_object_granted_list.as_mut(),
                &mut effective_sacls,
                &mut staged_sacls,
            )?;
        }
    }

    Ok(CaapEvaluationState {
        granted,
        object_granted_list,
        staged_granted,
        staged_object_granted_list,
        effective_sacls,
        staged_sacls,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_rule<'a>(
    applies_to: Option<&[u8]>,
    effective_dacl: &[u8],
    effective_sacl: Option<&'a [u8]>,
    staged_dacl: Option<&[u8]>,
    staged_sacl: Option<&'a [u8]>,
    sd: &SecurityDescriptor<'a>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    base: &EvaluateSecurityDescriptorState<'a>,
    granted: &mut u32,
    object_granted_list: Option<&mut Vec<u32>>,
    staged_granted: &mut u32,
    staged_object_granted_list: Option<&mut Vec<u32>>,
    effective_sacls: &mut Vec<&'a [u8]>,
    staged_sacls: &mut Vec<&'a [u8]>,
) -> KacsResult<()> {
    if !rule_applies(
        applies_to,
        token,
        conditional_context,
        &base.resource_attributes,
    ) {
        return Ok(());
    }

    let effective_rule = evaluate_rule_dacl(
        sd,
        token,
        pip,
        desired_access,
        mapping,
        object_tree,
        conditional_context,
        effective_dacl,
    );

    let effective_state = effective_rule.clone().unwrap_or_else(|| {
        deny_except_privileges(base.privilege_granted, base.privilege_granted, object_tree)
    });
    *granted &= effective_state.granted;
    intersect_object_grants(object_granted_list, &effective_state.object_granted_list)?;

    if let Some(sacl) = effective_sacl {
        effective_sacls.push(sacl);
    }

    let staged_state = if let Some(staged_dacl) = staged_dacl {
        evaluate_rule_dacl(
            sd,
            token,
            pip,
            desired_access,
            mapping,
            object_tree,
            conditional_context,
            staged_dacl,
        )
        .unwrap_or_else(|| deny_except_privileges(0, base.privilege_granted, object_tree))
    } else {
        effective_rule.clone().unwrap_or_else(|| {
            deny_except_privileges(base.privilege_granted, base.privilege_granted, object_tree)
        })
    };

    *staged_granted &= staged_state.granted;
    intersect_object_grants(
        staged_object_granted_list,
        &staged_state.object_granted_list,
    )?;

    if let Some(sacl) = staged_sacl {
        staged_sacls.push(sacl);
    } else if let Some(sacl) = effective_sacl {
        staged_sacls.push(sacl);
    }

    Ok(())
}

fn lookup_policy<'a, 'p>(
    policies: &'p [CaapPolicyEntry<'a>],
    sid: Sid<'a>,
) -> Option<&'p CaapPolicy<'a>> {
    policies
        .iter()
        .find(|entry| entry.sid == sid)
        .map(|entry| &entry.policy)
}

fn rule_applies(
    applies_to: Option<&[u8]>,
    token: &AccessCheckToken<'_>,
    conditional_context: &ConditionalContext<'_>,
    resource_attributes: &[crate::claims::ClaimAttribute],
) -> bool {
    let Some(applies_to) = applies_to else {
        return true;
    };

    let applies_context = ConditionalContext {
        self_sid: None,
        principal_self_matches: None,
        caller_is_owner: false,
        identity: None,
        identity_membership_is_presence_based: false,
        device_groups: conditional_context.device_groups,
        user_claims: conditional_context.user_claims,
        device_claims: conditional_context.device_claims,
        resource_claims: resource_attributes,
        local_claims: conditional_context.local_claims,
    };

    evaluate_conditional_expression(applies_to, &token.subject, &applies_context, false)
        == ConditionalResult::True
}

fn evaluate_rule_dacl<'a>(
    base_sd: &SecurityDescriptor<'a>,
    token: &AccessCheckToken<'a>,
    pip: PipContext,
    desired_access: u32,
    mapping: &GenericMapping,
    object_tree: Option<&ObjectTypeList>,
    conditional_context: &ConditionalContext<'a>,
    dacl_bytes: &[u8],
) -> Option<RuleGrantState> {
    let synthetic_bytes = build_synthetic_sd_bytes(base_sd, dacl_bytes).ok()?;
    let synthetic_sd = SecurityDescriptor::parse(&synthetic_bytes).ok()?;
    let result = evaluate_security_descriptor(
        Some(&synthetic_sd),
        token,
        pip,
        desired_access,
        mapping,
        object_tree,
        conditional_context,
        0,
    )
    .ok()?;

    Some(RuleGrantState {
        granted: result.granted,
        object_granted_list: result.object_granted_list,
    })
}

fn build_synthetic_sd_bytes(
    base_sd: &SecurityDescriptor<'_>,
    dacl_bytes: &[u8],
) -> KacsResult<Vec<u8>> {
    let owner = base_sd
        .owner()
        .ok_or(KacsError::MissingSecurityDescriptorOwner)?;
    let group = base_sd
        .group()
        .ok_or(KacsError::MissingSecurityDescriptorGroup)?;
    let sacl = strip_scoped_policy_aces(base_sd.sacl())?;

    let mut control = base_sd.control() | SE_SELF_RELATIVE | SE_DACL_PRESENT;
    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    } else {
        control &= !SE_SACL_PRESENT;
    }

    let mut bytes = vec![0u8; SecurityDescriptor::HEADER_SIZE];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner.as_bytes());

    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(group.as_bytes());

    if let Some(sacl) = sacl.as_deref() {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
    }

    let dacl_offset = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(dacl_bytes);

    Ok(bytes)
}

fn clone_base_object_grants(
    base: &EvaluateSecurityDescriptorState<'_>,
    object_tree: Option<&ObjectTypeList>,
) -> KacsResult<Option<Vec<u32>>> {
    let Some(object_tree) = object_tree else {
        return Ok(None);
    };

    let object_granted_list =
        base.object_granted_list
            .clone()
            .ok_or(KacsError::InvariantViolation(
                "missing base object_granted_list",
            ))?;
    if object_granted_list.len() != object_tree.len() {
        return Err(KacsError::InvariantViolation(
            "base object_granted_list length mismatch",
        ));
    }
    Ok(Some(object_granted_list))
}

fn intersect_object_grants(
    current: Option<&mut Vec<u32>>,
    next: &Option<Vec<u32>>,
) -> KacsResult<()> {
    let (Some(current), Some(next)) = (current, next.as_ref()) else {
        return Ok(());
    };
    if current.len() != next.len() {
        return Err(KacsError::InvariantViolation(
            "object_granted_list length mismatch",
        ));
    }
    for (current, next) in current.iter_mut().zip(next.iter().copied()) {
        *current &= next;
    }
    Ok(())
}

fn deny_except_privileges(
    scalar_privilege_granted: u32,
    object_privilege_granted: u32,
    object_tree: Option<&ObjectTypeList>,
) -> RuleGrantState {
    RuleGrantState {
        granted: scalar_privilege_granted,
        object_granted_list: object_tree.map(|tree| vec![object_privilege_granted; tree.len()]),
    }
}

fn strip_scoped_policy_aces(sacl: Option<crate::Acl<'_>>) -> KacsResult<Option<Vec<u8>>> {
    let Some(sacl) = sacl else {
        return Ok(None);
    };

    let mut kept = Vec::new();
    for ace in sacl.entries() {
        let ace = ace?;
        if ace.ace_type() != SYSTEM_SCOPED_POLICY_ID_ACE_TYPE {
            kept.push(ace.bytes().to_vec());
        }
    }

    let size = 8 + kept.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(sacl.revision());
    bytes.push(sacl.sbz1());
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(kept.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&sacl.sbz2().to_le_bytes());
    for ace in kept {
        bytes.extend_from_slice(&ace);
    }

    Ok(Some(bytes))
}

fn build_recovery_policy_dacl() -> Vec<u8> {
    let aces = [
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            GENERIC_ALL,
            ADMINISTRATORS_SID_BYTES,
        ),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, SYSTEM_SID_BYTES),
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            GENERIC_ALL,
            OWNER_RIGHTS_SID_BYTES,
        ),
    ];
    acl_bytes(&aces)
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(4);
    bytes.push(0);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{build_synthetic_sd_bytes, strip_scoped_policy_aces};
    use crate::{
        extract_sacl_metadata, SecurityDescriptor, ACCESS_ALLOWED_ACE_TYPE, SE_DACL_PRESENT,
        SE_SACL_PRESENT, SE_SELF_RELATIVE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
    };

    fn sid_bytes(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
        bytes.push(1);
        bytes.push(sub_authorities.len() as u8);
        bytes.extend_from_slice(&authority);
        for sub_authority in sub_authorities {
            bytes.extend_from_slice(&sub_authority.to_le_bytes());
        }
        bytes
    }

    fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let size = 8 + sid.len();
        let mut bytes = Vec::with_capacity(size);
        bytes.push(ace_type);
        bytes.push(flags);
        bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
        bytes
    }

    fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
        let mut bytes = Vec::with_capacity(size);
        bytes.push(4);
        bytes.push(0);
        bytes.extend_from_slice(&(size as u16).to_le_bytes());
        bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for ace in aces {
            bytes.extend_from_slice(ace);
        }
        bytes
    }

    fn sd_bytes(owner: &[u8], group: &[u8], sacl: &[u8], dacl: &[u8]) -> Vec<u8> {
        let control = SE_SELF_RELATIVE | SE_SACL_PRESENT | SE_DACL_PRESENT;
        let mut bytes = vec![0u8; 20];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&control.to_le_bytes());
        let owner_offset = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
        bytes.extend_from_slice(owner);
        let group_offset = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
        bytes.extend_from_slice(group);
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
        let dacl_offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        bytes.extend_from_slice(dacl);
        bytes
    }

    #[test]
    fn strip_scoped_policy_aces_removes_policy_references() {
        let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
        let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
        let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15000]);
        let policy = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15100]);
        let sacl = acl_bytes(&[
            basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &policy),
            basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x10, &user),
        ]);
        let dacl = acl_bytes(&[]);
        let base_bytes = sd_bytes(&owner, &group, &sacl, &dacl);
        let sd = SecurityDescriptor::parse(&base_bytes).expect("sd should parse");

        let stripped = strip_scoped_policy_aces(sd.sacl())
            .expect("strip should succeed")
            .expect("sacl should remain present");
        let stripped_sd_bytes = sd_bytes(&owner, &group, &stripped, &dacl);
        let stripped_sd =
            SecurityDescriptor::parse(&stripped_sd_bytes).expect("synthetic sd should parse");
        let metadata = extract_sacl_metadata(&stripped_sd).expect("metadata should parse");

        assert!(metadata.policy_sids.is_empty());
    }

    #[test]
    fn synthetic_sd_builder_strips_scoped_policy_aces() {
        let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
        let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
        let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15200]);
        let policy = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 15300]);
        let sacl = acl_bytes(&[
            basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &policy),
            basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x10, &user),
        ]);
        let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1, &user)]);
        let base_sd_bytes = sd_bytes(&owner, &group, &sacl, &dacl);
        let base_sd = SecurityDescriptor::parse(&base_sd_bytes).expect("sd should parse");

        let synthetic = build_synthetic_sd_bytes(&base_sd, &dacl).expect("builder should succeed");
        let synthetic_sd = SecurityDescriptor::parse(&synthetic).expect("synthetic sd parses");
        let metadata = extract_sacl_metadata(&synthetic_sd).expect("metadata parses");

        assert!(metadata.policy_sids.is_empty());
    }
}
