use kacs_core::{
    access_check_core, parse_caap_policy_spec, AccessCheckMode, AccessCheckToken, CaapPolicyCache,
    ConditionalContext, GenericMapping, ImpersonationLevel, IntegrityLevel, PipContext,
    SecurityDescriptor, Sid, TokenPrivileges, TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, READ_CONTROL,
    SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
};

const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const MAX_CAAP_SPEC_LEN: usize = 256 * 1024;
const MAX_CAAP_RULE_COUNT: u32 = 256;
const MAX_CAAP_FIELD_LEN: usize = 64 * 1024;

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

fn object_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 12 + sid.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn callback_ace(
    ace_type: u8,
    flags: u8,
    mask: u32,
    sid: &[u8],
    application_data: &[u8],
) -> Vec<u8> {
    let unpadded_size = 8 + sid.len() + application_data.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
    bytes
}

fn callback_object_ace(
    ace_type: u8,
    flags: u8,
    mask: u32,
    sid: &[u8],
    application_data: &[u8],
) -> Vec<u8> {
    let unpadded_size = 12 + sid.len() + application_data.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
    bytes
}

fn opaque_acl_with_len(len: usize) -> Vec<u8> {
    assert!(len >= 12);
    assert!(len <= u16::MAX as usize);
    let ace_size = len - 8;
    assert_eq!(ace_size % 4, 0);

    let mut bytes = Vec::with_capacity(len);
    bytes.push(4);
    bytes.push(0);
    bytes.extend_from_slice(&(len as u16).to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.push(0xff);
    bytes.push(0);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.resize(len, 0);
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

fn scoped_policy_ace(policy_sid: &[u8]) -> Vec<u8> {
    basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, policy_sid)
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

fn overflowing_expr() -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    for _ in 0..1025 {
        bytes.extend_from_slice(&int64_literal(1));
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

fn caap_spec(
    applies_to: Option<&[u8]>,
    effective_dacl: &[u8],
    effective_sacl: Option<&[u8]>,
    staged_dacl: Option<&[u8]>,
    staged_sacl: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x01);
    bytes.extend_from_slice(&1u32.to_le_bytes());

    let applies_to = applies_to.unwrap_or(&[]);
    let effective_sacl = effective_sacl.unwrap_or(&[]);
    let staged_dacl = staged_dacl.unwrap_or(&[]);
    let staged_sacl = staged_sacl.unwrap_or(&[]);

    for field in [
        applies_to,
        effective_dacl,
        effective_sacl,
        staged_dacl,
        staged_sacl,
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
        bytes.extend_from_slice(field);
    }

    bytes
}

fn caap_spec_with_rule_count(rule_count: u32, effective_dacl: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x01);
    bytes.extend_from_slice(&rule_count.to_le_bytes());

    for _ in 0..rule_count {
        for field in [&[][..], effective_dacl, &[][..], &[][..], &[][..]] {
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
    }

    bytes
}

fn caap_spec_with_rule_fields(rules: &[(&[u8], &[u8], &[u8], &[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x01);
    bytes.extend_from_slice(&(rules.len() as u32).to_le_bytes());

    for (applies_to, effective_dacl, effective_sacl, staged_dacl, staged_sacl) in rules {
        for field in [
            *applies_to,
            *effective_dacl,
            *effective_sacl,
            *staged_dacl,
            *staged_sacl,
        ] {
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
    }

    bytes
}

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: 0,
        execute: 0,
        all: READ_CONTROL,
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
        restricted: Default::default(),
        confinement: Default::default(),
    }
}

#[test]
fn zero_rule_policy_has_no_effect_when_referenced() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13006]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 208]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[scoped_policy_ace(&policy_sid)]);
    let sd = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd).expect("sd should parse");
    let token = primary_token(parse_sid(&user));
    let mut cache = CaapPolicyCache::default();
    let spec = caap_spec_with_rule_count(0, &dacl);
    cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect("zero-rule policy should parse");
    let borrowed = cache
        .borrowed_entries()
        .expect("borrowed entries should build");

    let result = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        borrowed.as_slice(),
    )
    .expect("access check should evaluate");

    assert_eq!(cache.entries()[0].policy.rules.len(), 0);
    assert_eq!(result.granted, READ_CONTROL);
    assert!(!result.staging_mismatch);
}

#[test]
fn caap_wire_format_rejects_unknown_version() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13007]);
    let mut spec = caap_spec(
        None,
        &acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]),
        None,
        None,
        None,
    );
    spec[0] = 0x02;

    let error = parse_caap_policy_spec(&spec).expect_err("unknown version should be rejected");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("unsupported caap version")
    );
}

#[test]
fn caap_wire_format_accepts_max_rule_count_and_rejects_overflow() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13008]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let max_spec = caap_spec_with_rule_count(MAX_CAAP_RULE_COUNT, &dacl);
    let parsed = parse_caap_policy_spec(&max_spec).expect("max rule count should parse");
    assert_eq!(parsed.rules.len(), MAX_CAAP_RULE_COUNT as usize);

    let mut over_spec = Vec::new();
    over_spec.push(0x01);
    over_spec.extend_from_slice(&(MAX_CAAP_RULE_COUNT + 1).to_le_bytes());

    let error =
        parse_caap_policy_spec(&over_spec).expect_err("over-limit rule count should reject");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("caap rule count exceeds maximum")
    );
}

#[test]
fn caap_wire_format_accepts_exact_spec_size_boundary() {
    let dacl = opaque_acl_with_len(65_508);
    let applies_to = expr(&append_tokens(&[
        int64_literal(1),
        int64_literal(1),
        vec![0x80],
    ]));
    let empty = &[][..];
    let rules = [
        (applies_to.as_slice(), dacl.as_slice(), empty, empty, empty),
        (empty, dacl.as_slice(), empty, empty, empty),
        (empty, dacl.as_slice(), empty, empty, empty),
        (empty, dacl.as_slice(), empty, empty, empty),
    ];
    let spec = caap_spec_with_rule_fields(&rules);

    assert_eq!(spec.len(), MAX_CAAP_SPEC_LEN);
    let parsed = parse_caap_policy_spec(&spec).expect("exact max spec should parse");

    assert_eq!(parsed.rules.len(), 4);
}

#[test]
fn caap_wire_format_accepts_largest_representable_acl_field() {
    let dacl = opaque_acl_with_len(65_532);
    let spec = caap_spec(None, dacl.as_slice(), None, None, None);

    let parsed = parse_caap_policy_spec(&spec).expect("large acl field should parse");

    assert_eq!(parsed.rules[0].effective_dacl.len(), 65_532);
}

#[test]
fn caap_wire_format_rejects_oversized_specs_and_fields() {
    let oversized_spec = vec![0u8; MAX_CAAP_SPEC_LEN + 1];
    let error = parse_caap_policy_spec(&oversized_spec).expect_err("oversized spec should reject");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("caap spec exceeds maximum size")
    );

    let mut oversized_applies_to = Vec::new();
    oversized_applies_to.push(0x01);
    oversized_applies_to.extend_from_slice(&1u32.to_le_bytes());
    oversized_applies_to.extend_from_slice(&((MAX_CAAP_FIELD_LEN + 1) as u32).to_le_bytes());
    let error = parse_caap_policy_spec(&oversized_applies_to)
        .expect_err("oversized applies_to field should reject");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("caap applies_to")
    );

    let mut oversized_effective_dacl = Vec::new();
    oversized_effective_dacl.push(0x01);
    oversized_effective_dacl.extend_from_slice(&1u32.to_le_bytes());
    oversized_effective_dacl.extend_from_slice(&0u32.to_le_bytes());
    oversized_effective_dacl.extend_from_slice(&((MAX_CAAP_FIELD_LEN + 1) as u32).to_le_bytes());
    let error = parse_caap_policy_spec(&oversized_effective_dacl)
        .expect_err("oversized effective_dacl field should reject");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("caap effective_dacl")
    );
}

#[test]
fn caap_wire_format_accepts_policy_acls_with_all_recognized_ace_families() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13010]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 209]);
    let high_il = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let trust_label = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let app_data = expr(&append_tokens(&[
        int64_literal(1),
        int64_literal(1),
        vec![0x80],
    ]));
    let ace_families = [
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(SYSTEM_AUDIT_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(SYSTEM_ALARM_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(ACCESS_DENIED_OBJECT_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(SYSTEM_AUDIT_OBJECT_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(SYSTEM_ALARM_OBJECT_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_ace(
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_object_ace(
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_object_ace(
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_ace(
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_ace(
            SYSTEM_ALARM_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_object_ace(
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        callback_object_ace(
            SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &app_data,
        ),
        basic_ace(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, 0x2, &high_il),
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        scoped_policy_ace(&policy_sid),
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, 0, &trust_label),
    ];
    let acl = acl_bytes(&ace_families);
    let spec = caap_spec(None, &acl, Some(&acl), Some(&acl), Some(&acl));

    let parsed = parse_caap_policy_spec(&spec).expect("recognized ace families should parse");

    assert_eq!(parsed.rules.len(), 1);
    assert_eq!(parsed.rules[0].effective_dacl, acl);
}

#[test]
fn caap_wire_format_rejects_trailing_bytes_and_truncation() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13009]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let mut trailing = caap_spec(None, &dacl, None, None, None);
    trailing.push(0);
    let error = parse_caap_policy_spec(&trailing).expect_err("trailing bytes should reject");
    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("trailing bytes in caap spec")
    );

    let short_header = [0x01, 0x01];
    let error = parse_caap_policy_spec(&short_header).expect_err("truncated header should reject");
    assert_eq!(error, kacs_core::KacsError::Truncated("caap spec"));

    let mut truncated_field = Vec::new();
    truncated_field.push(0x01);
    truncated_field.extend_from_slice(&1u32.to_le_bytes());
    truncated_field.extend_from_slice(&0u32.to_le_bytes());
    truncated_field.extend_from_slice(&(dacl.len() as u32).to_le_bytes());
    truncated_field.extend_from_slice(&dacl[..3]);
    let error =
        parse_caap_policy_spec(&truncated_field).expect_err("truncated field should reject");
    assert_eq!(
        error,
        kacs_core::KacsError::Truncated("caap effective_dacl")
    );
}

#[test]
fn parsed_policy_cache_feeds_existing_caap_evaluator() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13000]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 200]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Classification", 5)),
        scoped_policy_ace(&policy_sid),
    ]);
    let sd = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd).expect("sd should parse");
    let token = primary_token(parse_sid(&user));

    let applies = expr(&append_tokens(&[
        attr_ref(0xfa, "classification"),
        int64_literal(5),
        vec![0x80],
    ]));
    let effective_dacl = acl_bytes(&[]);
    let spec = caap_spec(Some(applies.as_slice()), &effective_dacl, None, None, None);

    let parsed = parse_caap_policy_spec(&spec).expect("spec should parse");
    let mut cache = CaapPolicyCache::default();
    cache
        .upsert_policy(&policy_sid, parsed)
        .expect("cache update should succeed");

    let resource_claims = [kacs_core::ClaimAttribute::new(
        "Classification",
        0,
        vec![kacs_core::ClaimValue::Int64(5)],
    )];
    let context = ConditionalContext {
        resource_claims: &resource_claims,
        ..ConditionalContext::default()
    };
    let borrowed = cache
        .borrowed_entries()
        .expect("borrowed entries should build");
    let result = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        READ_CONTROL,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &context,
        None,
        0,
        borrowed.as_slice(),
    )
    .expect("access check should evaluate");

    assert_eq!(cache.entries().len(), 1);
    assert_eq!(result.granted, 0);
    assert_eq!(result.mapped_desired, READ_CONTROL);
}

#[test]
fn set_policy_spec_replaces_and_removes_by_policy_sid() {
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 201]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13001]);
    let read_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let first = caap_spec(None, &read_dacl, None, None, None);
    let second = caap_spec(None, &acl_bytes(&[]), None, None, None);

    let mut cache = CaapPolicyCache::default();
    cache
        .set_policy_spec(&policy_sid, Some(&first))
        .expect("initial insert should succeed");
    cache
        .set_policy_spec(&policy_sid, Some(&second))
        .expect("replace should succeed");

    assert_eq!(cache.entries().len(), 1);
    assert_eq!(
        cache.entries()[0]
            .policy
            .rules
            .first()
            .expect("rule should exist")
            .effective_dacl,
        acl_bytes(&[])
    );

    cache
        .set_policy_spec(&policy_sid, None)
        .expect("remove should succeed");
    assert!(cache.entries().is_empty());
}

#[test]
fn invalid_policy_sid_is_rejected_without_mutating_cache() {
    let mut cache = CaapPolicyCache::default();
    let invalid_sid = [1u8, 2, 3];
    let spec = caap_spec(None, &acl_bytes(&[]), None, None, None);

    let error = cache
        .set_policy_spec(&invalid_sid, Some(&spec))
        .expect_err("invalid policy SID should be rejected");

    assert!(matches!(
        error,
        kacs_core::KacsError::Truncated(_)
            | kacs_core::KacsError::InvalidSidRevision(_)
            | kacs_core::KacsError::InvalidSidSubAuthorityCount(_)
            | kacs_core::KacsError::InvalidSidLength { .. }
    ));
    assert!(cache.entries().is_empty());
}

#[test]
fn zero_effective_dacl_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 202]);
    let spec = caap_spec(None, &[], None, None, None);

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("zero effective dacl should be rejected");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("caap effective_dacl must not be empty")
    );
    assert!(cache.entries().is_empty());
}

#[test]
fn malformed_applies_to_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 203]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13002]);
    let malformed_applies_to = [0xfau8, 1, 0, 0, 0];
    let spec = caap_spec(
        Some(&malformed_applies_to),
        &acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]),
        None,
        None,
        None,
    );

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("malformed applies_to should be rejected");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("malformed caap applies_to expression")
    );
    assert!(cache.entries().is_empty());
}

#[test]
fn empty_applies_to_expression_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 206]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13004]);
    let spec = caap_spec(
        Some(b"artx"),
        &acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]),
        None,
        None,
        None,
    );

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("empty applies_to should be rejected");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("malformed caap applies_to expression")
    );
    assert!(cache.entries().is_empty());
}

#[test]
fn stack_overflowing_applies_to_expression_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 207]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13005]);
    let overflowing_applies_to = overflowing_expr();
    let spec = caap_spec(
        Some(overflowing_applies_to.as_slice()),
        &acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]),
        None,
        None,
        None,
    );

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("stack-overflowing applies_to should be rejected");

    assert_eq!(
        error,
        kacs_core::KacsError::InvalidCaapSpec("malformed caap applies_to expression")
    );
    assert!(cache.entries().is_empty());
}

#[test]
fn invalid_acl_payload_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 204]);
    let malformed_acl = [1u8, 2, 3];
    let spec = caap_spec(None, &malformed_acl, None, None, None);

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("invalid acl payload should be rejected");

    assert!(matches!(error, kacs_core::KacsError::Truncated(_)));
    assert!(cache.entries().is_empty());
}

#[test]
fn invalid_staged_sacl_payload_is_rejected_without_mutation() {
    let mut cache = CaapPolicyCache::default();
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 205]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 13003]);
    let malformed_acl = [1u8, 2, 3];
    let spec = caap_spec(
        None,
        &acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]),
        None,
        None,
        Some(&malformed_acl),
    );

    let error = cache
        .set_policy_spec(&policy_sid, Some(&spec))
        .expect_err("invalid staged sacl should be rejected");

    assert!(matches!(error, kacs_core::KacsError::Truncated(_)));
    assert!(cache.entries().is_empty());
}
