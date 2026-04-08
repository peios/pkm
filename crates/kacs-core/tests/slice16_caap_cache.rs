use kacs_core::{
    access_check_core, parse_caap_policy_spec, AccessCheckMode, AccessCheckToken, CaapPolicyCache,
    ConditionalContext, GenericMapping, ImpersonationLevel, IntegrityLevel, PipContext,
    SecurityDescriptor, Sid, TokenPrivileges, TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE,
    READ_CONTROL, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
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
    let borrowed = cache.borrowed_entries().expect("borrowed entries should build");
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
