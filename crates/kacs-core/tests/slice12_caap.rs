use kacs_core::{
    evaluate_caap, evaluate_security_descriptor, AccessCheckToken, CaapPolicy, CaapPolicyEntry,
    CaapRule, ConditionalContext, GenericMapping, ImpersonationLevel, IntegrityLevel,
    ObjectTypeList, ObjectTypeNode, RestrictedTokenContext, SecurityDescriptor, Sid,
    TokenPrivileges, TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_SYSTEM_SECURITY, ACE_OBJECT_TYPE_PRESENT, READ_CONTROL, SE_DACL_PRESENT,
    SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE, TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
    WRITE_DAC,
};

const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;

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

fn parse_sid(bytes: &[u8]) -> Sid<'_> {
    Sid::parse(bytes).expect("sid should parse")
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

fn resource_attribute_ace(flags: u8, application_data: &[u8]) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 1], &[0]);
    let unpadded_size = 8 + sid.len() + application_data.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
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

fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
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

fn attr_ref(opcode: u8, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(opcode);
    bytes.extend_from_slice(&string_literal(name)[1..]);
    bytes
}

fn append_tokens(tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for token in tokens {
        bytes.extend_from_slice(token);
    }
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
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        pip_type: 0,
        pip_trust: 0,
        restricted: RestrictedTokenContext::default(),
        confinement: Default::default(),
    }
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
        desired_access,
        &mapping(),
        object_tree,
        &ConditionalContext::default(),
        0,
    )
    .expect("base evaluate_security_descriptor should succeed")
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
        ],
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
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
        }],
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
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
    assert_eq!(result.effective_sacls, vec![effective_sacl.as_slice()]);
    assert_eq!(result.staged_sacls, vec![staged_sacl.as_slice()]);
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
        }],
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
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
        }],
    };
    let entries = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = evaluate_caap(
        &sd,
        &token,
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
        Some(vec![READ_CONTROL, READ_CONTROL, READ_CONTROL])
    );
    assert_eq!(result.staged_granted, 0);
    assert_eq!(
        result.staged_object_granted_list,
        Some(vec![0, READ_CONTROL, 0])
    );
}
