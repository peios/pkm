use crate::access_mask::GenericMapping;
use crate::condition::{
    evaluate_conditional_expression, validate_conditional_expression_structure, ConditionalContext,
    ConditionalResult,
};
use crate::error::{KacsError, KacsResult};
use crate::evaluate_sd::{evaluate_security_descriptor, EvaluateSecurityDescriptorState};
use crate::object_tree::ObjectTypeList;
use crate::pip::PipContext;
use crate::pkm_alloc::{slice_to_vec, Vec};
use crate::security_descriptor::{
    SecurityDescriptor, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use crate::sid::Sid;
use crate::token::AccessCheckToken;
use crate::{Acl, ACCESS_ALLOWED_ACE_TYPE, GENERIC_ALL, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE};

const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const SYSTEM_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS_SID_BYTES: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const CAAP_SPEC_VERSION: u8 = 0x01;
const MAX_CAAP_SPEC_LEN: usize = 256 * 1024;
const MAX_CAAP_RULE_COUNT: u32 = 256;
const MAX_CAAP_FIELD_LEN: usize = 64 * 1024;

/// Borrowed view of one CAAP rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaapRule<'a> {
    /// Optional `applies_to` conditional-expression bytecode.
    pub applies_to: Option<&'a [u8]>,
    /// Effective DACL payload for the rule.
    pub effective_dacl: &'a [u8],
    /// Optional effective SACL payload for the rule.
    pub effective_sacl: Option<&'a [u8]>,
    /// Optional staged DACL payload for the rule.
    pub staged_dacl: Option<&'a [u8]>,
    /// Optional staged SACL payload for the rule.
    pub staged_sacl: Option<&'a [u8]>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Borrowed CAAP policy view.
pub struct CaapPolicy<'a> {
    /// Rules in policy order.
    pub rules: Vec<CaapRule<'a>>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Borrowed mapping from one policy SID to one CAAP policy.
pub struct CaapPolicyEntry<'a> {
    /// Policy SID.
    pub sid: Sid<'a>,
    /// Policy payload.
    pub policy: CaapPolicy<'a>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Owned CAAP rule stored in the pure cache and ingestion layer.
pub struct OwnedCaapRule {
    /// Optional owned `applies_to` bytecode.
    pub applies_to: Option<Vec<u8>>,
    /// Owned effective DACL payload.
    pub effective_dacl: Vec<u8>,
    /// Owned effective SACL payload.
    pub effective_sacl: Option<Vec<u8>>,
    /// Owned staged DACL payload.
    pub staged_dacl: Option<Vec<u8>>,
    /// Owned staged SACL payload.
    pub staged_sacl: Option<Vec<u8>>,
}

impl OwnedCaapRule {
    /// Returns a borrowed view over this owned rule.
    pub fn borrowed(&self) -> CaapRule<'_> {
        CaapRule {
            applies_to: self.applies_to.as_deref(),
            effective_dacl: self.effective_dacl.as_slice(),
            effective_sacl: self.effective_sacl.as_deref(),
            staged_dacl: self.staged_dacl.as_deref(),
            staged_sacl: self.staged_sacl.as_deref(),
        }
    }
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Owned CAAP policy stored in the pure cache and ingestion layer.
pub struct OwnedCaapPolicy {
    /// Owned rules in policy order.
    pub rules: Vec<OwnedCaapRule>,
}

impl OwnedCaapPolicy {
    /// Returns a borrowed policy view over this owned policy.
    pub fn borrowed(&self) -> KacsResult<CaapPolicy<'_>> {
        let mut rules = Vec::with_capacity(self.rules.len())?;
        for rule in &self.rules {
            rules.push(rule.borrowed())?;
        }
        Ok(CaapPolicy { rules })
    }
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
/// Owned mapping from one policy SID to one owned CAAP policy.
pub struct OwnedCaapPolicyEntry {
    /// Raw policy SID bytes.
    pub sid: Vec<u8>,
    /// Owned policy payload.
    pub policy: OwnedCaapPolicy,
}

impl OwnedCaapPolicyEntry {
    /// Returns a borrowed policy entry view after re-validating the stored SID.
    pub fn borrowed(&self) -> KacsResult<CaapPolicyEntry<'_>> {
        Ok(CaapPolicyEntry {
            sid: Sid::parse(self.sid.as_slice()).expect("policy SID validated at ingestion"),
            policy: self.policy.borrowed()?,
        })
    }
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Default, Eq, PartialEq)]
/// Owned CAAP policy cache keyed by policy SID.
pub struct CaapPolicyCache {
    entries: Vec<OwnedCaapPolicyEntry>,
}

impl CaapPolicyCache {
    /// Returns the owned cache entries.
    pub fn entries(&self) -> &[OwnedCaapPolicyEntry] {
        self.entries.as_slice()
    }

    /// Returns borrowed cache entries suitable for evaluation.
    pub fn borrowed_entries(&self) -> KacsResult<Vec<CaapPolicyEntry<'_>>> {
        let mut entries = Vec::with_capacity(self.entries.len())?;
        for entry in &self.entries {
            entries.push(entry.borrowed()?)?;
        }
        Ok(entries)
    }

    /// Inserts or replaces one policy by SID.
    pub fn upsert_policy(&mut self, policy_sid: &[u8], policy: OwnedCaapPolicy) -> KacsResult<()> {
        validate_policy_sid(policy_sid)?;

        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.sid.as_slice() == policy_sid)
        {
            entry.policy = policy;
        } else {
            self.entries.push(OwnedCaapPolicyEntry {
                sid: slice_to_vec(policy_sid)?,
                policy,
            })?;
        }
        Ok(())
    }

    /// Removes one policy by SID if it exists.
    pub fn remove_policy(&mut self, policy_sid: &[u8]) -> KacsResult<()> {
        validate_policy_sid(policy_sid)?;
        remove_policy_entries(&mut self.entries, policy_sid)?;
        Ok(())
    }

    /// Applies the `kacs_set_caap` replace/remove semantics for one policy SID.
    pub fn set_policy_spec(&mut self, policy_sid: &[u8], spec: Option<&[u8]>) -> KacsResult<()> {
        validate_policy_sid(policy_sid)?;

        let Some(spec) = spec.filter(|spec| !spec.is_empty()) else {
            remove_policy_entries(&mut self.entries, policy_sid)?;
            return Ok(());
        };

        let policy = parse_caap_policy_spec(spec)?;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.sid.as_slice() == policy_sid)
        {
            entry.policy = policy;
        } else {
            self.entries.push(OwnedCaapPolicyEntry {
                sid: slice_to_vec(policy_sid)?,
                policy,
            })?;
        }
        Ok(())
    }
}

/// CAAP evaluation output containing effective and staged intersections.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
pub struct CaapEvaluationState<'a> {
    /// Effective scalar granted mask after CAAP.
    pub granted: u32,
    /// Effective per-node granted list after CAAP.
    pub object_granted_list: Option<Vec<u32>>,
    /// Staged scalar granted mask after CAAP.
    pub staged_granted: u32,
    /// Staged per-node granted list after CAAP.
    pub staged_object_granted_list: Option<Vec<u32>>,
    /// Effective SACL payloads contributed by matching rules.
    pub effective_sacls: Vec<&'a [u8]>,
    /// Staged SACL payloads contributed by matching rules.
    pub staged_sacls: Vec<&'a [u8]>,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
struct RuleGrantState {
    granted: u32,
    object_granted_list: Option<Vec<u32>>,
}

/// Parses one CAAP policy spec into owned cache form.
pub fn parse_caap_policy_spec(spec: &[u8]) -> KacsResult<OwnedCaapPolicy> {
    if spec.is_empty() {
        return Err(KacsError::InvalidCaapSpec("empty caap spec"));
    }
    if spec.len() > MAX_CAAP_SPEC_LEN {
        return Err(KacsError::InvalidCaapSpec("caap spec exceeds maximum size"));
    }

    let mut offset = 0usize;
    let version = read_u8(spec, &mut offset)?;
    if version != CAAP_SPEC_VERSION {
        return Err(KacsError::InvalidCaapSpec("unsupported caap version"));
    }

    let rule_count = read_u32(spec, &mut offset)?;
    if rule_count > MAX_CAAP_RULE_COUNT {
        return Err(KacsError::InvalidCaapSpec(
            "caap rule count exceeds maximum",
        ));
    }

    let mut rules = Vec::with_capacity(rule_count as usize)?;
    for _ in 0..rule_count {
        let applies_to =
            read_len_prefixed_field(spec, &mut offset, MAX_CAAP_FIELD_LEN, "caap applies_to")?;
        if !applies_to.is_empty() && !validate_conditional_expression_structure(applies_to) {
            return Err(KacsError::InvalidCaapSpec(
                "malformed caap applies_to expression",
            ));
        }

        let effective_dacl =
            read_len_prefixed_field(spec, &mut offset, MAX_CAAP_FIELD_LEN, "caap effective_dacl")?;
        if effective_dacl.is_empty() {
            return Err(KacsError::InvalidCaapSpec(
                "caap effective_dacl must not be empty",
            ));
        }
        validate_acl_payload(effective_dacl)?;

        let effective_sacl =
            read_len_prefixed_field(spec, &mut offset, MAX_CAAP_FIELD_LEN, "caap effective_sacl")?;
        if !effective_sacl.is_empty() {
            validate_acl_payload(effective_sacl)?;
        }

        let staged_dacl =
            read_len_prefixed_field(spec, &mut offset, MAX_CAAP_FIELD_LEN, "caap staged_dacl")?;
        if !staged_dacl.is_empty() {
            validate_acl_payload(staged_dacl)?;
        }

        let staged_sacl =
            read_len_prefixed_field(spec, &mut offset, MAX_CAAP_FIELD_LEN, "caap staged_sacl")?;
        if !staged_sacl.is_empty() {
            validate_acl_payload(staged_sacl)?;
        }

        rules.push(OwnedCaapRule {
            applies_to: (!applies_to.is_empty())
                .then(|| slice_to_vec(applies_to))
                .transpose()?,
            effective_dacl: slice_to_vec(effective_dacl)?,
            effective_sacl: (!effective_sacl.is_empty())
                .then(|| slice_to_vec(effective_sacl))
                .transpose()?,
            staged_dacl: (!staged_dacl.is_empty())
                .then(|| slice_to_vec(staged_dacl))
                .transpose()?,
            staged_sacl: (!staged_sacl.is_empty())
                .then(|| slice_to_vec(staged_sacl))
                .transpose()?,
        })?;
    }

    if offset != spec.len() {
        return Err(KacsError::InvalidCaapSpec("trailing bytes in caap spec"));
    }

    Ok(OwnedCaapPolicy { rules })
}

/// Evaluates all CAAP policies referenced by the base security descriptor
/// result.
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
            let recovery_dacl = build_recovery_policy_dacl()?;
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

    let effective_state = match &effective_rule {
        Some(state) => clone_rule_grants(state)?,
        None => {
            deny_except_privileges(base.privilege_granted, base.privilege_granted, object_tree)?
        }
    };
    *granted &= effective_state.granted;
    intersect_object_grants(object_granted_list, &effective_state.object_granted_list)?;

    if let Some(sacl) = effective_sacl {
        effective_sacls.push(sacl)?;
    }

    let staged_state = if let Some(staged_dacl) = staged_dacl {
        match evaluate_rule_dacl(
            sd,
            token,
            pip,
            desired_access,
            mapping,
            object_tree,
            conditional_context,
            staged_dacl,
        ) {
            Some(state) => state,
            None => deny_except_privileges(0, base.privilege_granted, object_tree)?,
        }
    } else {
        match &effective_rule {
            Some(state) => clone_rule_grants(state)?,
            None => {
                deny_except_privileges(base.privilege_granted, base.privilege_granted, object_tree)?
            }
        }
    };

    *staged_granted &= staged_state.granted;
    intersect_object_grants(
        staged_object_granted_list,
        &staged_state.object_granted_list,
    )?;

    if let Some(sacl) = staged_sacl {
        staged_sacls.push(sacl)?;
    } else if let Some(sacl) = effective_sacl {
        staged_sacls.push(sacl)?;
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
    let group = base_sd.group();
    let sacl = strip_scoped_policy_aces(base_sd.sacl())?;

    let mut control = base_sd.control() | SE_SELF_RELATIVE | SE_DACL_PRESENT;
    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    } else {
        control &= !SE_SACL_PRESENT;
    }

    let mut bytes = Vec::with_capacity(
        SecurityDescriptor::HEADER_SIZE
            + owner.as_bytes().len()
            + group.map_or(0, |sid| sid.as_bytes().len())
            + sacl.as_ref().map_or(0, Vec::len)
            + dacl_bytes.len(),
    )?;
    bytes.extend_from_slice(&[0u8; SecurityDescriptor::HEADER_SIZE])?;
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner.as_bytes())?;

    if let Some(group) = group {
        let group_offset = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
        bytes.extend_from_slice(group.as_bytes())?;
    }

    if let Some(sacl) = sacl.as_deref() {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl)?;
    }

    let dacl_offset = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(dacl_bytes)?;

    Ok(bytes)
}

fn clone_base_object_grants(
    base: &EvaluateSecurityDescriptorState<'_>,
    object_tree: Option<&ObjectTypeList>,
) -> KacsResult<Option<Vec<u32>>> {
    let Some(object_tree) = object_tree else {
        return Ok(None);
    };

    let object_granted_list = base
        .object_granted_list
        .as_ref()
        .ok_or(KacsError::InvariantViolation(
            "missing base object_granted_list",
        ))
        .and_then(|list| slice_to_vec(list.as_slice()).map_err(Into::into))?;
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
) -> KacsResult<RuleGrantState> {
    let object_granted_list = if let Some(tree) = object_tree {
        let mut grants = Vec::with_capacity(tree.len())?;
        for _ in 0..tree.len() {
            grants.push(object_privilege_granted)?;
        }
        Some(grants)
    } else {
        None
    };

    Ok(RuleGrantState {
        granted: scalar_privilege_granted,
        object_granted_list,
    })
}

fn strip_scoped_policy_aces(sacl: Option<crate::Acl<'_>>) -> KacsResult<Option<Vec<u8>>> {
    let Some(sacl) = sacl else {
        return Ok(None);
    };

    let mut kept = Vec::new();
    for ace in sacl.entries() {
        let ace = ace?;
        if ace.ace_type() != SYSTEM_SCOPED_POLICY_ID_ACE_TYPE {
            kept.push(slice_to_vec(ace.bytes())?)?;
        }
    }

    let size = 8 + kept.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size)?;
    bytes.push(sacl.revision())?;
    bytes.push(sacl.sbz1())?;
    bytes.extend_from_slice(&(size as u16).to_le_bytes())?;
    bytes.extend_from_slice(&(kept.len() as u16).to_le_bytes())?;
    bytes.extend_from_slice(&sacl.sbz2().to_le_bytes())?;
    for ace in kept {
        bytes.extend_from_slice(ace.as_slice())?;
    }

    Ok(Some(bytes))
}

fn build_recovery_policy_dacl() -> KacsResult<Vec<u8>> {
    let aces = [
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            GENERIC_ALL,
            ADMINISTRATORS_SID_BYTES,
        )?,
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, GENERIC_ALL, SYSTEM_SID_BYTES)?,
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            GENERIC_ALL,
            OWNER_RIGHTS_SID_BYTES,
        )?,
    ];
    acl_bytes(&aces)
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> KacsResult<Vec<u8>> {
    let size = 8 + sid.len();
    let mut bytes = Vec::with_capacity(size)?;
    bytes.push(ace_type)?;
    bytes.push(flags)?;
    bytes.extend_from_slice(&(size as u16).to_le_bytes())?;
    bytes.extend_from_slice(&mask.to_le_bytes())?;
    bytes.extend_from_slice(sid)?;
    Ok(bytes)
}

fn validate_policy_sid(policy_sid: &[u8]) -> KacsResult<()> {
    Sid::parse(policy_sid)?;
    Ok(())
}

fn validate_acl_payload(bytes: &[u8]) -> KacsResult<()> {
    let acl = Acl::parse(bytes)?;
    for ace in acl.entries() {
        ace?;
    }
    Ok(())
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> KacsResult<u8> {
    let value = *bytes
        .get(*offset)
        .ok_or(KacsError::Truncated("caap spec"))?;
    *offset += 1;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> KacsResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(KacsError::InvalidCaapSpec("caap length overflow"))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(KacsError::Truncated("caap spec"))?;
    *offset = end;
    Ok(u32::from_le_bytes(
        <[u8; 4]>::try_from(slice).expect("slice length checked"),
    ))
}

fn read_len_prefixed_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    max_len: usize,
    field: &'static str,
) -> KacsResult<&'a [u8]> {
    let len = read_u32(bytes, offset)? as usize;
    if len > max_len {
        return Err(KacsError::InvalidCaapSpec(field));
    }
    let end = offset
        .checked_add(len)
        .ok_or(KacsError::InvalidCaapSpec("caap length overflow"))?;
    let slice = bytes.get(*offset..end).ok_or(KacsError::Truncated(field))?;
    *offset = end;
    Ok(slice)
}

fn acl_bytes(aces: &[Vec<u8>]) -> KacsResult<Vec<u8>> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size)?;
    bytes.push(4)?;
    bytes.push(0)?;
    bytes.extend_from_slice(&(size as u16).to_le_bytes())?;
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes())?;
    bytes.extend_from_slice(&0u16.to_le_bytes())?;
    for ace in aces {
        bytes.extend_from_slice(ace.as_slice())?;
    }
    Ok(bytes)
}

fn clone_rule_grants(state: &RuleGrantState) -> KacsResult<RuleGrantState> {
    Ok(RuleGrantState {
        granted: state.granted,
        object_granted_list: state
            .object_granted_list
            .as_ref()
            .map(|list| slice_to_vec(list.as_slice()))
            .transpose()?,
    })
}

fn remove_policy_entries(
    entries: &mut Vec<OwnedCaapPolicyEntry>,
    policy_sid: &[u8],
) -> KacsResult<()> {
    let mut kept = Vec::with_capacity(entries.len())?;
    for entry in core::mem::take(entries) {
        if entry.sid.as_slice() != policy_sid {
            kept.push(entry)?;
        }
    }
    *entries = kept;
    Ok(())
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
