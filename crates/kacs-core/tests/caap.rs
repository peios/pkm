mod common;
use common::{acl_bytes, append_tokens, basic_ace, expr, parse_sid, resource_attribute_ace, sid_bytes};
use kacs_core::{
    evaluate_caap, evaluate_security_descriptor, AccessCheckToken, CaapPolicy, CaapPolicyEntry,
    CaapRule, CaapSaclPhase, ClaimAttribute, ClaimValue, ConditionalContext,
    ConfinementTokenContext, EvaluateSecurityDescriptorState, GenericMapping, ImpersonationLevel,
    IntegrityLevel, ObjectTypeList, ObjectTypeNode, PipContext, PrivilegeProvenance,
    RestrictedTokenContext, SecurityDescriptor, Sid, SidAndAttributes, TokenPrivileges, TokenType,
    TokenView, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_SYSTEM_SECURITY,
    ACE_OBJECT_TYPE_PRESENT, READ_CONTROL, SE_BACKUP_PRIVILEGE, SE_DACL_PRESENT, SE_GROUP_ENABLED,
    SE_RESTORE_PRIVILEGE, SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC,
};

const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;




fn object_ace(
    ace_type: u8,
    flags: u8,
    mask: u32,
    object_flags: u32,
    object_type: [u8; 16],
    sid: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&object_flags.to_le_bytes());
    body.extend_from_slice(&object_type);
    body.extend_from_slice(sid);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}


fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn int64_claim(name: &str, value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let values_start = 20usize;
    let name_offset = 28usize;

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(values_start as u32).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}


fn scoped_policy_ace(policy_sid: &[u8]) -> Vec<u8> {
    basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, policy_sid)
}

fn sd_bytes(
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Vec<u8> {
    let control = SE_SELF_RELATIVE
        | if sacl.is_some() { SE_SACL_PRESENT } else { 0 }
        | if dacl.is_some() { SE_DACL_PRESENT } else { 0 };
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());

    if let Some(owner) = owner {
        let owner_offset = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
        bytes.extend_from_slice(owner);
    }

    if let Some(group) = group {
        let group_offset = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
        bytes.extend_from_slice(group);
    }

    if let Some(sacl) = sacl {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
    }

    if let Some(dacl) = dacl {
        let dacl_offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        bytes.extend_from_slice(dacl);
    }

    bytes
}


fn int64_literal(value: i64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(11);
    bytes.push(0x04);
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.push(if value < 0 { 0x02 } else { 0x01 });
    bytes.push(0x02);
    bytes
}

fn string_literal(value: &str) -> Vec<u8> {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let mut bytes = Vec::new();
    bytes.push(0x10);
    bytes.extend_from_slice(&((utf16.len() * 2) as u32).to_le_bytes());
    for code_unit in utf16 {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

fn sid_literal(sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x51);
    bytes.extend_from_slice(&(sid.len() as u32).to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn attr_ref(opcode: u8, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(opcode);
    bytes.extend_from_slice(&string_literal(name)[1..]);
    bytes
}


fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0x0000_0020,
        all: READ_CONTROL | WRITE_DAC | 0x0000_0020,
    }
}

fn primary_token<'a>(user: Sid<'a>) -> AccessCheckToken<'a> {
    AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups: &[],
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        audit_policy: 0,
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        restricted: RestrictedTokenContext::default(),
        confinement: Default::default(),
    }
}

fn default_pip() -> PipContext {
    PipContext::default()
}

fn evaluate_base<'a>(
    sd: &SecurityDescriptor<'a>,
    token: &AccessCheckToken<'a>,
    desired_access: u32,
    object_tree: Option<&ObjectTypeList>,
) -> kacs_core::EvaluateSecurityDescriptorState<'a> {
    evaluate_security_descriptor(
        Some(sd),
        token,
        default_pip(),
        desired_access,
        &mapping(),
        object_tree,
        &ConditionalContext::default(),
        0,
    )
    .expect("base evaluate_security_descriptor should succeed")
}

fn caap_base<'a>(policy_sid: Sid<'a>, granted: u32) -> EvaluateSecurityDescriptorState<'a> {
    EvaluateSecurityDescriptorState {
        decided: granted,
        granted,
        privilege_granted: 0,
        max_allowed_mode: false,
        mapped_desired: granted,
        resource_attributes: Vec::new().into(),
        policy_sids: vec![policy_sid].into(),
        pip_decided: 0,
        provenance: PrivilegeProvenance::default(),
        object_granted_list: None,
    }
}

#[test]
fn missing_policy_uses_recovery_policy_and_narrows_access() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12000]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 88]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, READ_CONTROL, None);

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &[],
    )
    .expect("caap evaluation should succeed");

    assert_eq!(base.granted, READ_CONTROL);
    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
    assert!(result.effective_sacls.is_empty());
    assert!(result.staged_sacls.is_empty());
}

#[test]
fn installed_policies_compose_by_intersection() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12009]);
    let policy_read_write_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12010]);
    let policy_read_execute_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12011]);
    let desired = READ_CONTROL | WRITE_DAC | 0x0000_0020;
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, desired, &user)]);
    let sacl = acl_bytes(&[
        scoped_policy_ace(&policy_read_write_sid),
        scoped_policy_ace(&policy_read_execute_sid),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, desired, None);
    let read_write_dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let read_execute_dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | 0x0000_0020,
        &user,
    )]);
    let read_write_policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: read_write_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let read_execute_policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: read_execute_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [
        CaapPolicyEntry {
            sid: parse_sid(&policy_read_write_sid),
            policy: read_write_policy,
        },
        CaapPolicyEntry {
            sid: parse_sid(&policy_read_execute_sid),
            policy: read_execute_policy,
        },
    ];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        desired,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(base.granted, desired);
    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.staged_granted, READ_CONTROL);
}

#[test]
fn installed_and_missing_policies_compose_with_recovery() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12012]);
    let installed_policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12013]);
    let missing_policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12014]);
    let desired = READ_CONTROL | WRITE_DAC;
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, desired, &user)]);
    let sacl = acl_bytes(&[
        scoped_policy_ace(&installed_policy_sid),
        scoped_policy_ace(&missing_policy_sid),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, desired, None);
    let installed_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let installed_policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: installed_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&installed_policy_sid),
        policy: installed_policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        desired,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(base.granted, desired);
    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn rule_dacl_pipeline_applies_mic() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12015]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12016]);
    let high_il = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[
        scoped_policy_ace(&policy_sid),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &high_il,
        ),
    ]);
    let sd_bytes = sd_bytes(
        Some(&owner),
        Some(&group),
        Some(&sacl),
        Some(&acl_bytes(&[])),
    );
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = caap_base(parse_sid(&policy_sid), WRITE_DAC);
    let rule_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &user)]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: rule_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        WRITE_DAC,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn rule_dacl_pipeline_applies_pip() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12017]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12018]);
    let trust_label = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let sacl = acl_bytes(&[
        scoped_policy_ace(&policy_sid),
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, 0, &trust_label),
    ]);
    let sd_bytes = sd_bytes(
        Some(&owner),
        Some(&group),
        Some(&sacl),
        Some(&acl_bytes(&[])),
    );
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = caap_base(parse_sid(&policy_sid), READ_CONTROL);
    let rule_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: rule_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        PipContext {
            pip_type: 512,
            pip_trust: 1024,
        },
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn rule_dacl_pipeline_applies_restricted_pass() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12019]);
    let restricted_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12020]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12021]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(
        Some(&owner),
        Some(&group),
        Some(&sacl),
        Some(&acl_bytes(&[])),
    );
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted_sid),
        attributes: SE_GROUP_ENABLED,
    }];
    let mut token = primary_token(parse_sid(&user));
    token.restricted = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    let base = caap_base(parse_sid(&policy_sid), READ_CONTROL);
    let rule_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: rule_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn rule_dacl_pipeline_applies_confinement() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12022]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 12023]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12024]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(
        Some(&owner),
        Some(&group),
        Some(&sacl),
        Some(&acl_bytes(&[])),
    );
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let mut token = primary_token(parse_sid(&user));
    token.confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };
    let base = caap_base(parse_sid(&policy_sid), READ_CONTROL);
    let rule_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: rule_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn rule_dacl_pipeline_suppresses_backup_and_restore_intent() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12025]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12026]);
    let desired = READ_CONTROL | WRITE_DAC;
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(
        Some(&owner),
        Some(&group),
        Some(&sacl),
        Some(&acl_bytes(&[])),
    );
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let mut token = primary_token(parse_sid(&user));
    token.privileges = TokenPrivileges {
        present: SE_BACKUP_PRIVILEGE | SE_RESTORE_PRIVILEGE,
        enabled: SE_BACKUP_PRIVILEGE | SE_RESTORE_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    let base = caap_base(parse_sid(&policy_sid), desired);
    let empty_rule_dacl = acl_bytes(&[]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: empty_rule_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        desired,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &policies,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn applies_to_false_and_unknown_rules_are_skipped() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12001]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 89]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        scoped_policy_ace(&policy_sid),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, READ_CONTROL | WRITE_DAC, None);

    let false_expr = expr(&append_tokens(&[
        attr_ref(0xfa, "Level"),
        int64_literal(4),
        vec![0x80],
    ]));
    let false_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let unknown_expr = b"nope".to_vec();
    let unknown_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let policy = CaapPolicy {
        rules: vec![
            CaapRule {
                applies_to: Some(false_expr.as_slice()),
                effective_dacl: false_dacl.as_slice(),
                effective_sacl: None,
                staged_dacl: None,
                staged_sacl: None,
            },
            CaapRule {
                applies_to: Some(unknown_expr.as_slice()),
                effective_dacl: unknown_dacl.as_slice(),
                effective_sacl: None,
                staged_dacl: None,
                staged_sacl: None,
            },
        ]
        .into(),
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &entries,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
    assert_eq!(result.staged_granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn applies_to_sees_claim_namespaces_but_not_membership() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12002]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 94]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        scoped_policy_ace(&policy_sid),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, READ_CONTROL, None);
    let applies = expr(&append_tokens(&[
        attr_ref(0xfa, "Level"),
        int64_literal(3),
        vec![0x80],
        attr_ref(0xf9, "Clearance"),
        int64_literal(4),
        vec![0x80],
        vec![0xa0],
        attr_ref(0xfb, "TrustedDevice"),
        int64_literal(1),
        vec![0x80],
        vec![0xa0],
        attr_ref(0xf8, "LocalDecision"),
        int64_literal(7),
        vec![0x80],
        vec![0xa0],
    ]));
    let effective_dacl = acl_bytes(&[]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: Some(applies.as_slice()),
            effective_dacl: effective_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];
    let user_claims = [ClaimAttribute::new(
        "Clearance",
        0,
        vec![ClaimValue::Int64(4)],
    )];
    let device_claims = [ClaimAttribute::new(
        "TrustedDevice",
        0,
        vec![ClaimValue::Boolean(1)],
    )];
    let local_claims = [ClaimAttribute::new(
        "LocalDecision",
        0,
        vec![ClaimValue::Int64(7)],
    )];
    let context = ConditionalContext {
        user_claims: &user_claims,
        device_claims: &device_claims,
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &context,
        &base,
        &policies,
    )
    .expect("caap should evaluate");

    assert_eq!(result.granted, 0);
    assert_eq!(result.staged_granted, 0);
}

#[test]
fn applies_to_membership_expression_is_unknown_and_skipped() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12006]);
    let token_group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12007]);
    let device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12008]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 95]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token_groups = [SidAndAttributes {
        sid: parse_sid(&token_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let device_groups = [SidAndAttributes {
        sid: parse_sid(&device_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let mut token = primary_token(parse_sid(&user));
    token.subject = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &token_groups,
    };
    let base = evaluate_base(&sd, &token, READ_CONTROL, None);
    let member_applies = expr(&append_tokens(&[sid_literal(&token_group), vec![0x89]]));
    let device_member_applies = expr(&append_tokens(&[sid_literal(&device_group), vec![0x8a]]));
    let effective_dacl = acl_bytes(&[]);
    let policy = CaapPolicy {
        rules: vec![
            CaapRule {
                applies_to: Some(member_applies.as_slice()),
                effective_dacl: effective_dacl.as_slice(),
                effective_sacl: None,
                staged_dacl: None,
                staged_sacl: None,
            },
            CaapRule {
                applies_to: Some(device_member_applies.as_slice()),
                effective_dacl: effective_dacl.as_slice(),
                effective_sacl: None,
                staged_dacl: None,
                staged_sacl: None,
            },
        ]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];
    let context = ConditionalContext {
        device_groups: &device_groups,
        ..ConditionalContext::default()
    };

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &context,
        &base,
        &policies,
    )
    .expect("caap should evaluate");

    assert_eq!(base.granted, READ_CONTROL);
    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.staged_granted, READ_CONTROL);
}

#[test]
fn effective_and_staged_dacls_are_tracked_separately_and_sacls_are_collected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12002]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 90]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        scoped_policy_ace(&policy_sid),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, READ_CONTROL | WRITE_DAC, None);

    let applies_true = expr(&append_tokens(&[
        attr_ref(0xfa, "Level"),
        int64_literal(3),
        vec![0x80],
    ]));
    let effective_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let staged_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &user)]);
    let effective_sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let staged_sacl = acl_bytes(&[resource_attribute_ace(0, &int64_claim("Audit", 1))]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: Some(applies_true.as_slice()),
            effective_dacl: effective_dacl.as_slice(),
            effective_sacl: Some(effective_sacl.as_slice()),
            staged_dacl: Some(staged_dacl.as_slice()),
            staged_sacl: Some(staged_sacl.as_slice()),
        }]
        .into(),
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &entries,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.staged_granted, WRITE_DAC);
    assert_eq!(result.effective_sacls.len(), 1);
    assert_eq!(result.effective_sacls[0].policy_sid, parse_sid(&policy_sid));
    assert_eq!(result.effective_sacls[0].rule_index, 0);
    assert_eq!(result.effective_sacls[0].phase, CaapSaclPhase::Effective);
    assert_eq!(result.effective_sacls[0].sacl, effective_sacl.as_slice());
    assert_eq!(result.staged_sacls.len(), 1);
    assert_eq!(result.staged_sacls[0].policy_sid, parse_sid(&policy_sid));
    assert_eq!(result.staged_sacls[0].rule_index, 0);
    assert_eq!(result.staged_sacls[0].phase, CaapSaclPhase::Staged);
    assert_eq!(result.staged_sacls[0].sacl, staged_sacl.as_slice());
}

#[test]
fn rule_dacl_error_preserves_only_privilege_granted_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12003]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 91]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut token = primary_token(parse_sid(&user));
    token.privileges = TokenPrivileges {
        present: SE_SECURITY_PRIVILEGE,
        enabled: SE_SECURITY_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    let base = evaluate_base(&sd, &token, READ_CONTROL | ACCESS_SYSTEM_SECURITY, None);

    let malformed_dacl = [1u8, 2, 3];
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: &malformed_dacl,
            effective_sacl: None,
            staged_dacl: None,
            staged_sacl: None,
        }]
        .into(),
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL | ACCESS_SYSTEM_SECURITY,
        &mapping(),
        None,
        &ConditionalContext::default(),
        &base,
        &entries,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(base.privilege_granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(result.granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(result.staged_granted, ACCESS_SYSTEM_SECURITY);
}

#[test]
fn object_tree_tracks_effective_and_staged_per_node_results() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12004]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 92]);
    let tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: [0x10; 16],
        },
        ObjectTypeNode {
            level: 1,
            guid: [0x11; 16],
        },
        ObjectTypeNode {
            level: 1,
            guid: [0x12; 16],
        },
    ])
    .expect("tree should parse");
    let base_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&base_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let base = evaluate_base(&sd, &token, READ_CONTROL, Some(&tree));

    let effective_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let staged_dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        [0x11; 16],
        &user,
    )]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: effective_dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: Some(staged_dacl.as_slice()),
            staged_sacl: None,
        }]
        .into(),
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        Some(&tree),
        &ConditionalContext::default(),
        &base,
        &entries,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(
        result.object_granted_list,
        Some(vec![READ_CONTROL, READ_CONTROL, READ_CONTROL].into())
    );
    assert_eq!(result.staged_granted, 0);
    assert_eq!(
        result.staged_object_granted_list,
        Some(vec![0, READ_CONTROL, 0].into())
    );
}

#[test]
fn staged_object_tree_error_preserves_per_node_privilege_granted_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 12005]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 93]);
    let tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: [0x10; 16],
        },
        ObjectTypeNode {
            level: 1,
            guid: [0x11; 16],
        },
    ])
    .expect("tree should parse");
    let dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut token = primary_token(parse_sid(&user));
    token.privileges = TokenPrivileges {
        present: SE_SECURITY_PRIVILEGE,
        enabled: SE_SECURITY_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    let base = evaluate_base(&sd, &token, ACCESS_SYSTEM_SECURITY, Some(&tree));

    let malformed_dacl = [1u8, 2, 3];
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: Some(&malformed_dacl),
            staged_sacl: None,
        }]
        .into(),
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
        default_pip(),
        ACCESS_SYSTEM_SECURITY,
        &mapping(),
        Some(&tree),
        &ConditionalContext::default(),
        &base,
        &entries,
    )
    .expect("caap evaluation should succeed");

    assert_eq!(result.staged_granted, 0);
    assert_eq!(
        result.staged_object_granted_list,
        Some(vec![ACCESS_SYSTEM_SECURITY, ACCESS_SYSTEM_SECURITY].into())
    );
}
