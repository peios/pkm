use kacs_core::{
    access_check, access_check_core, access_check_result_list, AccessCheckMode, AccessCheckResult,
    AccessCheckResultListState, AccessCheckToken, AccessStatus, CaapDiagnosticKind, CaapPolicy,
    CaapPolicyEntry, CaapRule, CaapSaclPhase, ClaimAttribute, ClaimValue, ConditionalContext,
    ConfinementTokenContext, GenericMapping, ImpersonationLevel, IntegrityLevel, ObjectTypeList,
    ObjectTypeNode, PipContext, RestrictedTokenContext, SecurityDescriptor, Sid, SidAndAttributes,
    TokenPrivileges, TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
    AUDIT_POLICY_OBJECT_ACCESS_FAILURE, AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
    AUDIT_POLICY_PRIVILEGE_USE_FAILURE, BACKUP_INTENT, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
    GENERIC_READ, GENERIC_WRITE, READ_CONTROL, SE_BACKUP_PRIVILEGE, SE_DACL_PRESENT,
    SE_GROUP_USE_FOR_DENY_ONLY, SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE,
    SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC,
};

const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const INHERIT_ONLY_ACE: u8 = 0x08;
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

fn mandatory_label_ace(mask: u32, integrity_level: IntegrityLevel) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 16], &[integrity_level as u32]);
    basic_ace(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, mask, &sid)
}

fn process_trust_label_ace(mask: u32, pip_type: u32, pip_trust: u32) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 19], &[pip_type, pip_trust]);
    basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, mask, &sid)
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
fn scalar_access_check_ordered_golden_vector_composes_all_major_stages() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13050]);
    let restricted_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23050]);
    let confinement_sid = sid_bytes([0, 0, 0, 0, 0, 15], &[3, 13050]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 33050]);
    let desired = READ_CONTROL | WRITE_DAC | kacs_core::ACCESS_SYSTEM_SECURITY;
    let object_audit_context = b"scalar-golden-vector";
    let object_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        FAILED_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    );
    let object_alarm = basic_ace(SYSTEM_ALARM_ACE_TYPE, 0, WRITE_DAC, &user);
    let caap_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        FAILED_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    );
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &restricted_sid),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &confinement_sid),
    ]);
    let sacl = acl_bytes(&[
        mandatory_label_ace(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, IntegrityLevel::High),
        process_trust_label_ace(GENERIC_READ | GENERIC_WRITE, 1, 1),
        scoped_policy_ace(&policy_sid),
        object_audit.clone(),
        object_alarm,
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted_sid),
        attributes: 0,
    }];
    let mut token = primary_token(parse_sid(&user));
    token.privileges = TokenPrivileges {
        present: SE_SECURITY_PRIVILEGE,
        enabled: SE_SECURITY_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    token.audit_policy = AUDIT_POLICY_PRIVILEGE_USE_FAILURE | AUDIT_POLICY_OBJECT_ACCESS_FAILURE;
    token.restricted = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    token.confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&confinement_sid)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };
    let effective_dacl = dacl.clone();
    let staged_dacl = acl_bytes(&[]);
    let effective_sacl = acl_bytes(&[caap_audit.clone()]);
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: effective_dacl.as_slice(),
            effective_sacl: Some(effective_sacl.as_slice()),
            staged_dacl: Some(staged_dacl.as_slice()),
            staged_sacl: None,
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
        desired,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        Some(object_audit_context),
        0,
        &policies,
    )
    .expect("scalar golden vector should evaluate");

    assert_eq!(result.mapped_desired, desired);
    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.privilege_granted, 0);
    assert_eq!(
        result.pip_decided & kacs_core::ACCESS_SYSTEM_SECURITY,
        kacs_core::ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
    assert!(result.staging_mismatch);
    assert_eq!(result.caap_diagnostic_events.len(), 1);
    assert_eq!(
        result.caap_diagnostic_events[0].kind,
        CaapDiagnosticKind::StagingMismatch
    );
    assert_eq!(result.privilege_use_events.len(), 1);
    assert_eq!(
        result.privilege_use_events[0].privilege,
        SE_SECURITY_PRIVILEGE
    );
    assert_eq!(
        result.privilege_use_events[0].requested,
        kacs_core::ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        result.privilege_use_events[0].granted,
        kacs_core::ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(result.privilege_use_events[0].surviving_bits, 0);
    assert!(!result.privilege_use_events[0].success);
    assert_eq!(result.updated_privileges.used & SE_SECURITY_PRIVILEGE, 0);
    assert_eq!(result.audit_events.len(), 3);
    assert_eq!(
        result.audit_events[0].ace_bytes,
        Some(object_audit.as_slice())
    );
    assert_eq!(
        result.audit_events[1].ace_bytes,
        Some(caap_audit.as_slice())
    );
    assert!(result.audit_events[2].policy_forced);
    for event in &result.audit_events {
        assert_eq!(event.requested, desired);
        assert_eq!(event.granted, READ_CONTROL);
        assert!(!event.success);
        assert_eq!(
            event.object_audit_context.as_deref(),
            Some(object_audit_context.as_slice())
        );
    }
}

#[test]
fn result_list_access_check_ordered_golden_vector_narrows_per_node() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13051]);
    let restricted_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23051]);
    let confinement_sid = sid_bytes([0, 0, 0, 0, 0, 15], &[3, 13051]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 33051]);
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
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            guid(2),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            WRITE_DAC,
            ACE_OBJECT_TYPE_PRESENT,
            guid(3),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            guid(2),
            &restricted_sid,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            guid(2),
            &confinement_sid,
        ),
    ]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted_sid),
        attributes: 0,
    }];
    let mut token = primary_token(parse_sid(&user));
    token.restricted = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    token.confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&confinement_sid)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };
    let effective_dacl = dacl.clone();
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
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

    let result = access_check_result_list(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        &object_tree,
        &ConditionalContext::default(),
        None,
        0,
        &policies,
    )
    .expect("result-list golden vector should evaluate");

    assert_eq!(result.granted_list, vec![0, READ_CONTROL, 0]);
    assert_eq!(
        result.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
        ]
    );
    assert_eq!(result.continuous_audit_mask, 0);
    assert!(!result.staging_mismatch);
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
fn conditional_audit_false_suppresses_audit_and_alarm() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13014]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let false_condition = expr(&append_tokens(&[
        int64_literal(1),
        int64_literal(2),
        vec![0x80],
    ]));
    let sacl = acl_bytes(&[
        callback_ace(
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
            &false_condition,
        ),
        callback_ace(
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            0,
            WRITE_DAC,
            &user,
            &false_condition,
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
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("false callback audit should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert!(result.audit_events.is_empty());
    assert_eq!(result.continuous_audit_mask, 0);
}

#[test]
fn malformed_conditional_audit_emits_as_unknown_and_alarm_records() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13015]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let malformed_condition = b"nope";
    let audit_ace = callback_ace(
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
        malformed_condition,
    );
    let sacl = acl_bytes(&[
        audit_ace.clone(),
        callback_ace(
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            0,
            WRITE_DAC,
            &user,
            malformed_condition,
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
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("malformed callback audit should evaluate as unknown");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.audit_events.len(), 1);
    assert_eq!(result.audit_events[0].ace_bytes, Some(audit_ace.as_slice()));
    assert!(result.audit_events[0].success);
    assert_eq!(result.continuous_audit_mask, WRITE_DAC);
}

#[test]
fn inherit_only_audit_and_alarm_aces_are_ignored() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13016]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_AUDIT_ACE_TYPE,
            INHERIT_ONLY_ACE | SUCCESSFUL_ACCESS_ACE_FLAG,
            READ_CONTROL,
            &user,
        ),
        basic_ace(SYSTEM_ALARM_ACE_TYPE, INHERIT_ONLY_ACE, WRITE_DAC, &user),
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
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("inherit-only SACL entries should be skipped");

    assert_eq!(result.granted, READ_CONTROL);
    assert!(result.audit_events.is_empty());
    assert_eq!(result.continuous_audit_mask, 0);
}

#[test]
fn sacl_audit_sid_matching_uses_deny_polarity() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13012]);
    let deny_only_group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23012]);
    let disabled_group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 33012]);
    let dacl = acl_bytes(&[]);
    let user_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        FAILED_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    );
    let deny_only_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        FAILED_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &deny_only_group,
    );
    let disabled_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        FAILED_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &disabled_group,
    );
    let sacl = acl_bytes(&[user_audit.clone(), deny_only_audit.clone(), disabled_audit]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let groups = [
        SidAndAttributes {
            sid: parse_sid(&deny_only_group),
            attributes: SE_GROUP_USE_FOR_DENY_ONLY,
        },
        SidAndAttributes {
            sid: parse_sid(&disabled_group),
            attributes: 0,
        },
    ];
    let mut token = primary_token_with_groups(parse_sid(&user), &groups);
    token.subject.user_deny_only = true;

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
    .expect("deny-polarity SACL audit should evaluate");

    assert_eq!(result.granted, 0);
    assert_eq!(result.audit_events.len(), 2);
    assert_eq!(
        result.audit_events[0].ace_bytes,
        Some(user_audit.as_slice())
    );
    assert_eq!(
        result.audit_events[1].ace_bytes,
        Some(deny_only_audit.as_slice())
    );
    for event in &result.audit_events {
        assert_eq!(event.requested, READ_CONTROL);
        assert_eq!(event.granted, 0);
        assert!(!event.success);
        assert!(!event.policy_forced);
    }
}

#[test]
fn sacl_audit_special_sid_triggers_match_owner_rights_and_principal_self() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13013]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let principal_target = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23013]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &owner)]);
    let owner_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &owner_rights,
    );
    let principal_audit = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &principal_self,
    );
    let sacl = acl_bytes(&[owner_audit.clone(), principal_audit.clone()]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let groups = [SidAndAttributes {
        sid: parse_sid(&principal_target),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let token = primary_token_with_groups(parse_sid(&owner), &groups);
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&principal_target)),
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
    .expect("special SID SACL audit should evaluate");

    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
    assert_eq!(result.audit_events.len(), 2);
    assert_eq!(
        result.audit_events[0].ace_bytes,
        Some(owner_audit.as_slice())
    );
    assert_eq!(
        result.audit_events[1].ace_bytes,
        Some(principal_audit.as_slice())
    );

    let without_self = access_check_core(
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
    .expect("OWNER RIGHTS audit should not require PRINCIPAL SELF");

    assert_eq!(without_self.audit_events.len(), 1);
    assert_eq!(
        without_self.audit_events[0].ace_bytes,
        Some(owner_audit.as_slice())
    );
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
fn object_and_caap_effective_sacls_both_emit_audit_events() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13012]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23012]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let object_audit_ace = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    );
    let caap_audit_ace = basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        READ_CONTROL,
        &user,
    );
    let object_sacl = acl_bytes(&[scoped_policy_ace(&policy_sid), object_audit_ace.clone()]);
    let caap_effective_sacl = acl_bytes(&[caap_audit_ace.clone()]);
    let object_context = b"object-plus-caap-sacl";
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&object_sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
            effective_sacl: Some(caap_effective_sacl.as_slice()),
            staged_dacl: None,
            staged_sacl: None,
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
        Some(object_context),
        0,
        &policies,
    )
    .expect("object and caap sacls should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.audit_events.len(), 2);
    assert_eq!(
        result.audit_events[0].ace_bytes,
        Some(object_audit_ace.as_slice())
    );
    assert_eq!(
        result.audit_events[1].ace_bytes,
        Some(caap_audit_ace.as_slice())
    );
    for event in &result.audit_events {
        assert!(event.success);
        assert!(!event.policy_forced);
        assert_eq!(event.requested, READ_CONTROL);
        assert_eq!(event.granted, READ_CONTROL);
        assert_eq!(
            event.object_audit_context.as_deref(),
            Some(object_context.as_slice())
        );
    }
    assert_eq!(result.continuous_audit_mask, 0);
    assert!(!result.staging_mismatch);
    assert!(result.caap_diagnostic_events.is_empty());
}

#[test]
fn caap_sacl_error_emits_diagnostic_without_widening_access() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13009]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23009]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let malformed_sacl = [1u8, 2, 3];
    let staged_sacl = acl_bytes(&[]);
    let object_context = b"caap-object-context";
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
            effective_sacl: Some(malformed_sacl.as_slice()),
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
        Some(object_context),
        0,
        &policies,
    )
    .expect("invalid caap sacl should not abort access check");

    assert_eq!(result.granted, READ_CONTROL);
    assert!(result.audit_events.is_empty());
    assert!(!result.staging_mismatch);
    assert_eq!(result.caap_diagnostic_events.len(), 1);
    let diagnostic = &result.caap_diagnostic_events[0];
    assert_eq!(diagnostic.kind, CaapDiagnosticKind::SaclError);
    assert_eq!(diagnostic.phase, Some(CaapSaclPhase::Effective));
    assert_eq!(
        diagnostic.policy_sid.as_deref(),
        Some(policy_sid.as_slice())
    );
    assert_eq!(diagnostic.rule_index, Some(0));
    assert_eq!(diagnostic.reason, "invalid-caap-sacl");
    assert_eq!(diagnostic.requested, READ_CONTROL);
    assert_eq!(diagnostic.effective_granted, READ_CONTROL);
    assert_eq!(diagnostic.staged_granted, READ_CONTROL);
    assert!(!diagnostic.object_results_differ);
    assert_eq!(
        diagnostic.object_audit_context.as_deref(),
        Some(object_context.as_slice())
    );
}

#[test]
fn staged_scalar_grant_delta_sets_staging_mismatch() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13007]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23007]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let empty_dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
            effective_sacl: None,
            staged_dacl: Some(empty_dacl.as_slice()),
            staged_sacl: None,
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
    .expect("grant delta should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert!(result.staging_mismatch);
    assert_eq!(result.caap_diagnostic_events.len(), 1);
    let diagnostic = &result.caap_diagnostic_events[0];
    assert_eq!(diagnostic.kind, CaapDiagnosticKind::StagingMismatch);
    assert_eq!(diagnostic.phase, None);
    assert_eq!(diagnostic.policy_sid, None);
    assert_eq!(diagnostic.rule_index, None);
    assert_eq!(diagnostic.reason, "effective-staged-delta");
    assert_eq!(diagnostic.requested, READ_CONTROL);
    assert_eq!(diagnostic.effective_granted, READ_CONTROL);
    assert_eq!(diagnostic.staged_granted, 0);
    assert!(!diagnostic.object_results_differ);
}

#[test]
fn staged_object_grant_delta_sets_staging_mismatch() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13008]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23008]);
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
    let base_dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let effective_dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            WRITE_DAC,
            ACE_OBJECT_TYPE_PRESENT,
            guid(2),
            &user,
        ),
    ]);
    let staged_dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            WRITE_DAC,
            ACE_OBJECT_TYPE_PRESENT,
            guid(3),
            &user,
        ),
    ]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&base_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
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
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy,
    }];

    let result = access_check_core(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        AccessCheckMode::Scalar,
        Some(&object_tree),
        &ConditionalContext::default(),
        None,
        0,
        &policies,
    )
    .expect("per-node grant delta should evaluate");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(
        result.object_granted_list,
        Some(vec![READ_CONTROL, READ_CONTROL | WRITE_DAC, READ_CONTROL].into())
    );
    assert!(result.staging_mismatch);
}

#[test]
fn caap_narrowed_privilege_grants_are_not_reported_as_final() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13009]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 23009]);
    let dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let mut token = primary_token(parse_sid(&user));
    token.privileges = TokenPrivileges {
        present: SE_BACKUP_PRIVILEGE,
        enabled: SE_BACKUP_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    let policy = CaapPolicy {
        rules: vec![CaapRule {
            applies_to: None,
            effective_dacl: dacl.as_slice(),
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
        BACKUP_INTENT,
        &policies,
    )
    .expect("caap-narrowed backup grant should evaluate");

    assert_eq!(result.granted, 0);
    assert_eq!(result.privilege_granted, 0);
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
fn zero_desired_access_succeeds_without_granting_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13006]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let result: AccessCheckResult = access_check(
        Some(&sd),
        &token,
        default_pip(),
        0,
        &mapping(),
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("zero desired access should evaluate");

    assert!(result.allowed);
    assert_eq!(result.granted, 0);
    assert_eq!(result.continuous_audit_mask, 0);
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
