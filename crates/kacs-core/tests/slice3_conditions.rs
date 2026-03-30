use kacs_core::{
    evaluate_conditional_expression, ClaimAttribute, ClaimValue, ConditionalContext,
    ConditionalResult, GenericMapping, Sid, SidAndAttributes, TokenView,
    CLAIM_SECURITY_ATTRIBUTE_DISABLED, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
    SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
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

fn parse_sid(bytes: &[u8]) -> Sid<'_> {
    Sid::parse(bytes).expect("sid should parse")
}

fn token<'a>(user: &'a [u8], groups: &'a [SidAndAttributes<'a>]) -> TokenView<'a> {
    TokenView {
        user: parse_sid(user),
        user_deny_only: false,
        groups,
    }
}

fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
    bytes
}

fn int64_literal(value: i64) -> Vec<u8> {
    int64_literal_with_sign(value, if value < 0 { 0x02 } else { 0x01 })
}

fn int64_literal_with_sign(value: i64, sign: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(11);
    bytes.push(0x04);
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.push(sign);
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

fn composite(elements: &[Vec<u8>]) -> Vec<u8> {
    let total = elements.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::new();
    bytes.push(0x50);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    for element in elements {
        bytes.extend_from_slice(element);
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
        read: 0x0000_0001,
        write: 0x0000_0002,
        execute: 0x0000_0004,
        all: 0x0000_0007,
    }
}

#[test]
fn malformed_magic_returns_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4000]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();

    let result = evaluate_conditional_expression(b"nope", &token, &context, true);

    assert_eq!(result, ConditionalResult::Unknown);
}

#[test]
fn exists_resolves_user_claim_presence() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4001]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "clearance",
        0,
        vec![ClaimValue::UInt64(4)],
    )];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let program = expr(&append_tokens(&[attr_ref(0xf9, "clearance"), vec![0x87]]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::True);
}

#[test]
fn literal_origin_in_logical_operator_forces_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4002]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[
        int64_literal(1),
        int64_literal(1),
        vec![0xa0],
    ]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::Unknown);
}

#[test]
fn promotes_int64_and_uint64_for_relational_operators() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4003]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new("level", 0, vec![ClaimValue::UInt64(1)])];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let program = expr(&append_tokens(&[
        int64_literal(-1),
        attr_ref(0xf9, "level"),
        vec![0x82],
    ]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::True);
}

#[test]
fn contains_works_on_multivalued_string_claims() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4004]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "tags",
        0,
        vec![
            ClaimValue::String("red".into()),
            ClaimValue::String("blue".into()),
        ],
    )];
    let context = ConditionalContext {
        local_claims: &claims,
        ..ConditionalContext::default()
    };
    let rhs = composite(&[string_literal("red")]);
    let program = expr(&append_tokens(&[attr_ref(0xf8, "tags"), rhs, vec![0x86]]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::True);
}

#[test]
fn claim_flags_are_applied_at_lookup_time() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4005]);
    let token = token(&user, &[]);
    let claims = [
        ClaimAttribute::new(
            "disabled",
            CLAIM_SECURITY_ATTRIBUTE_DISABLED,
            vec![ClaimValue::UInt64(1)],
        ),
        ClaimAttribute::new(
            "deny_only",
            CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
            vec![ClaimValue::UInt64(1)],
        ),
    ];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let disabled_exists = expr(&append_tokens(&[attr_ref(0xf9, "disabled"), vec![0x87]]));
    let deny_only_exists = expr(&append_tokens(&[attr_ref(0xf9, "deny_only"), vec![0x87]]));

    let disabled = evaluate_conditional_expression(&disabled_exists, &token, &context, true);
    let allow_side = evaluate_conditional_expression(&deny_only_exists, &token, &context, true);
    let deny_side = evaluate_conditional_expression(&deny_only_exists, &token, &context, false);

    assert_eq!(disabled, ConditionalResult::False);
    assert_eq!(allow_side, ConditionalResult::False);
    assert_eq!(deny_side, ConditionalResult::True);
}

#[test]
fn member_of_sees_virtual_groups_and_polarity() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4006]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let deny_only_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 545]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&deny_only_group),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let token = token(&user, &groups);
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&user)),
        caller_is_owner: true,
        ..ConditionalContext::default()
    };
    let principal_self_program = expr(&append_tokens(&[sid_literal(&principal_self), vec![0x89]]));
    let owner_program = expr(&append_tokens(&[sid_literal(&owner_rights), vec![0x89]]));
    let deny_only_program = expr(&append_tokens(&[sid_literal(&deny_only_group), vec![0x89]]));

    let self_result =
        evaluate_conditional_expression(&principal_self_program, &token, &context, true);
    let owner_result = evaluate_conditional_expression(&owner_program, &token, &context, true);
    let allow_result = evaluate_conditional_expression(&deny_only_program, &token, &context, true);
    let deny_result = evaluate_conditional_expression(&deny_only_program, &token, &context, false);

    assert_eq!(self_result, ConditionalResult::True);
    assert_eq!(owner_result, ConditionalResult::True);
    assert_eq!(allow_result, ConditionalResult::False);
    assert_eq!(deny_result, ConditionalResult::True);
}

#[test]
fn principal_self_without_self_sid_is_false_not_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4009]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[sid_literal(&principal_self), vec![0x89]]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::False);
}

#[test]
fn device_member_of_uses_device_groups() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4007]);
    let device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 560]);
    let token = token(&user, &[]);
    let device_groups = [SidAndAttributes {
        sid: parse_sid(&device_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let context = ConditionalContext {
        device_groups: &device_groups,
        ..ConditionalContext::default()
    };
    let program = expr(&append_tokens(&[sid_literal(&device_group), vec![0x8a]]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::True);
}

#[test]
fn signless_negative_integer_literal_is_malformed_and_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4010]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[
        int64_literal_with_sign(-1, 0x03),
        int64_literal(0),
        vec![0x82],
    ]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::Unknown);
}

#[test]
fn non_boolean_final_stack_value_returns_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4008]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&int64_literal(7));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::Unknown);
}

#[test]
fn mapping_fixture_still_available_for_slice_three_tests() {
    let mapping = mapping();
    assert_eq!(mapping.all, 0x0000_0007);
}
