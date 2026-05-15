use kacs_core::{
    access_check, access_check_core, access_check_result_list, AccessCheckMode, AccessCheckResult,
    AccessCheckResultListState, AccessCheckToken, AccessStatus, CaapPolicy, CaapPolicyEntry,
    CaapRule, ClaimAttribute, ClaimValue, ConditionalContext, GenericMapping, ImpersonationLevel,
    IntegrityLevel, ObjectTypeList, ObjectTypeNode, PipContext, RestrictedTokenContext,
    SecurityDescriptor, Sid, SidAndAttributes, TokenPrivileges, TokenType, TokenView,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACE_OBJECT_TYPE_PRESENT, AUDIT_POLICY_OBJECT_ACCESS_FAILURE,
    AUDIT_POLICY_OBJECT_ACCESS_SUCCESS, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY, READ_CONTROL,
    SE_DACL_PRESENT, SE_GROUP_USE_FOR_DENY_ONLY, SE_SACL_PRESENT, SE_SELF_RELATIVE,
    SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC,
};

const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;

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

fn callback_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8], condition: &[u8]) -> Vec<u8> {
    let unpadded_size = 8 + sid.len() + condition.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(condition);
    bytes.resize(size, 0);
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

fn scoped_policy_ace(policy_sid: &[u8]) -> Vec<u8> {
    basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, policy_sid)
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

fn attr_ref(opcode: u8, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(opcode);
    bytes.extend_from_slice(&string_literal(name)[1..]);
    bytes
}

fn sid_literal(sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x51);
    bytes.extend_from_slice(&(sid.len() as u32).to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn append_tokens(tokens: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for token in tokens {
        bytes.extend_from_slice(token);
    }
    bytes
}

fn guid(seed: u8) -> [u8; 16] {
    [seed; 16]
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
    primary_token_with_groups(user, &[])
}

fn primary_token_with_groups<'a>(
    user: Sid<'a>,
    groups: &'a [SidAndAttributes<'a>],
) -> AccessCheckToken<'a> {
    AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups,
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        restricted: RestrictedTokenContext::default(),
        confinement: Default::default(),
        audit_policy: 0,
    }
}

fn default_pip() -> PipContext {
    PipContext::default()
}

#[test]
fn audit_aces_use_mapped_desired_overlap_and_final_success_or_failure() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13000]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_AUDIT_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
        ),
        basic_ace(
            SYSTEM_AUDIT_ACE_TYPE,
            FAILED_ACCESS_ACE_FLAG,
            WRITE_DAC,
            &user,
        ),
    ]);
    let with_sacl_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&with_sacl_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let success = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        kacs_core::GENERIC_READ,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("success audit should evaluate");
    assert_eq!(success.audit_events.len(), 1);
    assert!(success.audit_events[0].success);

    let failure = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        WRITE_DAC,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("failure audit should evaluate");
    assert_eq!(failure.audit_events.len(), 1);
    assert!(!failure.audit_events[0].success);
}

#[test]
fn callback_unknown_audits_and_alarm_masks_are_accumulated() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13001]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let unknown_condition = expr(&append_tokens(&[
        attr_ref(0xf9, "MissingClaim"),
        int64_literal(1),
        vec![0x80],
    ]));
    let sacl = acl_bytes(&[
        callback_ace(
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
            &unknown_condition,
        ),
        basic_ace(SYSTEM_ALARM_ACE_TYPE, 0, WRITE_DAC, &user),
    ]);
    let with_sacl_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&with_sacl_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("callback audit should evaluate");

    assert_eq!(result.audit_events.len(), 1);
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
}

#[test]
fn sacl_resource_attribute_feeds_dacl_callback_condition() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13011]);
    let condition = expr(&append_tokens(&[
        attr_ref(0xfa, "Level"),
        int64_literal(7),
        vec![0x80],
    ]));
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        &condition,
    )]);
    let sacl = acl_bytes(&[resource_attribute_ace(0, &int64_claim("Level", 7))]);
    let with_sacl_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&with_sacl_bytes).expect("sd should parse");
    let without_sacl_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let without_sacl =
        SecurityDescriptor::parse(&without_sacl_bytes).expect("sd without sacl should parse");
    let token = primary_token(parse_sid(&user));

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("resource-backed callback should evaluate");
    let missing_result = access_check_core(
        Some(&without_sacl),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("missing resource callback should evaluate as skipped");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(missing_result.granted, 0);
}

#[test]
fn deny_only_claims_are_visible_to_audit_and_alarm_conditions() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13009]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let audit_condition = expr(&append_tokens(&[attr_ref(0xf8, "audit_gate"), vec![0x87]]));
    let alarm_condition = expr(&append_tokens(&[attr_ref(0xf8, "alarm_gate"), vec![0x87]]));
    let sacl = acl_bytes(&[
        callback_ace(
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
            &audit_condition,
        ),
        callback_ace(
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            0,
            WRITE_DAC,
            &user,
            &alarm_condition,
        ),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let local_claims = [
        ClaimAttribute::new(
            "audit_gate",
            CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
            vec![ClaimValue::Boolean(2)],
        ),
        ClaimAttribute::new(
            "alarm_gate",
            CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
            vec![ClaimValue::Boolean(2)],
        ),
    ];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &context,
        None,
        0,
        &[],
    )
    .expect("deny-only audit conditions should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.audit_events.len(), 1);
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
}

#[test]
fn deny_only_groups_are_visible_to_audit_and_alarm_member_conditions() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13010]);
    let deny_only_group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23010]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let member_condition = expr(&append_tokens(&[sid_literal(&deny_only_group), vec![0x89]]));
    let sacl = acl_bytes(&[
        callback_ace(
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
            &member_condition,
        ),
        callback_ace(
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            0,
            WRITE_DAC,
            &user,
            &member_condition,
        ),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let groups = [SidAndAttributes {
        sid: parse_sid(&deny_only_group),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let token = primary_token_with_groups(parse_sid(&user), &groups);

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("deny-only membership audit conditions should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.audit_events.len(), 1);
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
}

#[test]
fn object_alarm_guid_scoping_requires_a_matching_node() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13002]);
    let object_tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: guid(1),
        },
        ObjectTypeNode {
            level: 1,
            guid: guid(2),
        },
    ])
    .expect("tree should build");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        guid(2),
        &user,
    )]);
    let sacl = acl_bytes(&[
        object_ace(
            SYSTEM_ALARM_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            guid(2),
            &user,
        ),
        object_ace(
            SYSTEM_ALARM_OBJECT_ACE_TYPE,
            0,
            WRITE_DAC,
            ACE_OBJECT_TYPE_PRESENT,
            guid(9),
            &user,
        ),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        Some(&object_tree),
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("object alarm should evaluate");

    assert_eq!(result.continuous_audit_mask, READ_CONTROL);
}

#[test]
fn staged_audit_delta_sets_staging_mismatch() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13003]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23003]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let effective_sacl = acl_bytes(&[basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    )]);
    let staged_sacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
            effective_sacl: Some(effective_sacl.as_slice()),
            staged_dacl: Some(dacl.as_slice()),
            staged_sacl: Some(staged_sacl.as_slice()),
        }]
        .into(),
    };
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &policies,
    )
    .expect("audit delta should evaluate");

    assert!(result.staging_mismatch);
}

#[test]
fn token_audit_policy_forces_success_and_failure_audits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13004]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut success_token = primary_token(parse_sid(&user));
    success_token.audit_policy = AUDIT_POLICY_OBJECT_ACCESS_SUCCESS;
    let success = access_check_core(
        Some(&sd),
        &success_token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        Some(b"/obj"),
        0,
        &[],
    )
    .expect("forced success should evaluate");
    assert_eq!(success.audit_events.len(), 1);
    assert!(success.audit_events[0].policy_forced);
    assert_eq!(
        success.audit_events[0].object_audit_context,
        Some(b"/obj".to_vec().into())
    );

    let mut failure_token = primary_token(parse_sid(&user));
    failure_token.audit_policy = AUDIT_POLICY_OBJECT_ACCESS_FAILURE;
    let failure = access_check_core(
        Some(&sd),
        &failure_token,
        default_pip(),
        WRITE_DAC,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("forced failure should evaluate");
    assert_eq!(failure.audit_events.len(), 1);
    assert!(failure.audit_events[0].policy_forced);
    assert!(!failure.audit_events[0].success);
}

#[test]
fn scalar_access_check_wrapper_returns_public_outputs() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13005]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[basic_ace(SYSTEM_ALARM_ACE_TYPE, 0, WRITE_DAC, &user)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let result: AccessCheckResult = access_check(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("access_check should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert!(result.allowed);
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
    assert!(!result.staging_mismatch);
}

#[test]
fn result_list_wrapper_returns_per_node_statuses() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13006]);
    let object_tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: guid(1),
        },
        ObjectTypeNode {
            level: 1,
            guid: guid(2),
        },
        ObjectTypeNode {
            level: 1,
            guid: guid(3),
        },
    ])
    .expect("tree should build");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        guid(3),
        &user,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let result: AccessCheckResultListState = access_check_result_list(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        &object_tree,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("result-list wrapper should evaluate");

    assert_eq!(result.granted_list, vec![0, 0, READ_CONTROL]);
    assert_eq!(
        result.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
        ]
    );
}
