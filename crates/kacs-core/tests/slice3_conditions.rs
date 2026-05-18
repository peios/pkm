use kacs_core::{
    evaluate_conditional_expression, ClaimAttribute, ClaimValue, ConditionalContext,
    ConditionalResult, GenericMapping, Sid, SidAndAttributes, TokenView,
    CLAIM_SECURITY_ATTRIBUTE_DISABLED, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
    CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
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
    signed_literal(0x04, value, sign, 0x02)
}

fn signed_literal(token_type: u8, raw_value: i64, sign: u8, base: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(11);
    bytes.push(token_type);
    bytes.extend_from_slice(&raw_value.to_le_bytes());
    bytes.push(sign);
    bytes.push(base);
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

fn octet_literal(value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x18);
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value);
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

fn result_tokens(result: ConditionalResult) -> Vec<u8> {
    match result {
        ConditionalResult::True => append_tokens(&[int64_literal(1), int64_literal(1), vec![0x80]]),
        ConditionalResult::False => {
            append_tokens(&[int64_literal(1), int64_literal(2), vec![0x80]])
        }
        ConditionalResult::Unknown => {
            append_tokens(&[attr_ref(0xf9, "__missing"), int64_literal(1), vec![0x80]])
        }
    }
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
fn ms_dtyp_bytecode_golden_vectors_cover_token_families() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4035]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 544]);
    let device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 560]);
    let missing_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 561]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&group),
        attributes: SE_GROUP_ENABLED,
    }];
    let device_groups = [SidAndAttributes {
        sid: parse_sid(&device_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let token = token(&user, &groups);
    let local_claims = [ClaimAttribute::new(
        "LocalGate",
        0,
        vec![ClaimValue::Boolean(1)],
    )];
    let user_claims = [ClaimAttribute::new(
        "UserGate",
        0,
        vec![ClaimValue::UInt64(1)],
    )];
    let resource_claims = [ClaimAttribute::new(
        "ResourceGate",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let device_claims = [ClaimAttribute::new(
        "DeviceGate",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let context = ConditionalContext {
        device_groups: &device_groups,
        local_claims: &local_claims,
        user_claims: &user_claims,
        resource_claims: &resource_claims,
        device_claims: &device_claims,
        ..ConditionalContext::default()
    };
    let true_result = result_tokens(ConditionalResult::True);
    let false_result = result_tokens(ConditionalResult::False);
    let cases = vec![
        (
            "int8 literal",
            append_tokens(&[
                signed_literal(0x01, 0x7f, 0x01, 0x02),
                int64_literal(127),
                vec![0x80],
            ]),
            ConditionalResult::True,
        ),
        (
            "int16 literal",
            append_tokens(&[
                signed_literal(0x02, 0x7fff, 0x01, 0x02),
                int64_literal(32767),
                vec![0x80],
            ]),
            ConditionalResult::True,
        ),
        (
            "int32 literal",
            append_tokens(&[
                signed_literal(0x03, 0x7fff_ffff, 0x01, 0x02),
                int64_literal(2_147_483_647),
                vec![0x80],
            ]),
            ConditionalResult::True,
        ),
        (
            "int64 literal",
            append_tokens(&[
                signed_literal(0x04, -1, 0x02, 0x02),
                int64_literal(-1),
                vec![0x80],
            ]),
            ConditionalResult::True,
        ),
        (
            "unicode string literal",
            append_tokens(&[string_literal("Alpha"), string_literal("alpha"), vec![0x80]]),
            ConditionalResult::True,
        ),
        (
            "octet string literal",
            append_tokens(&[
                octet_literal(&[0xaa, 0xbb]),
                octet_literal(&[0xaa, 0xbb]),
                vec![0x80],
            ]),
            ConditionalResult::True,
        ),
        (
            "sid literal",
            append_tokens(&[sid_literal(&user), sid_literal(&user), vec![0x80]]),
            ConditionalResult::True,
        ),
        (
            "composite literal",
            append_tokens(&[
                composite(&[int64_literal(1), int64_literal(2)]),
                composite(&[int64_literal(2)]),
                vec![0x86],
            ]),
            ConditionalResult::True,
        ),
        (
            "eq",
            append_tokens(&[int64_literal(7), int64_literal(7), vec![0x80]]),
            ConditionalResult::True,
        ),
        (
            "ne",
            append_tokens(&[int64_literal(7), int64_literal(8), vec![0x81]]),
            ConditionalResult::True,
        ),
        (
            "lt",
            append_tokens(&[int64_literal(7), int64_literal(8), vec![0x82]]),
            ConditionalResult::True,
        ),
        (
            "le",
            append_tokens(&[int64_literal(7), int64_literal(7), vec![0x83]]),
            ConditionalResult::True,
        ),
        (
            "gt",
            append_tokens(&[int64_literal(8), int64_literal(7), vec![0x84]]),
            ConditionalResult::True,
        ),
        (
            "ge",
            append_tokens(&[int64_literal(7), int64_literal(7), vec![0x85]]),
            ConditionalResult::True,
        ),
        (
            "contains",
            append_tokens(&[
                composite(&[string_literal("red"), string_literal("blue")]),
                composite(&[string_literal("blue")]),
                vec![0x86],
            ]),
            ConditionalResult::True,
        ),
        (
            "any_of",
            append_tokens(&[
                string_literal("blue"),
                composite(&[string_literal("red"), string_literal("blue")]),
                vec![0x88],
            ]),
            ConditionalResult::True,
        ),
        (
            "not_contains",
            append_tokens(&[
                composite(&[string_literal("red")]),
                composite(&[string_literal("blue")]),
                vec![0x8e],
            ]),
            ConditionalResult::True,
        ),
        (
            "not_any_of",
            append_tokens(&[
                string_literal("green"),
                composite(&[string_literal("red"), string_literal("blue")]),
                vec![0x8f],
            ]),
            ConditionalResult::True,
        ),
        (
            "exists local",
            append_tokens(&[attr_ref(0xf8, "LocalGate"), vec![0x87]]),
            ConditionalResult::True,
        ),
        (
            "exists user",
            append_tokens(&[attr_ref(0xf9, "UserGate"), vec![0x87]]),
            ConditionalResult::True,
        ),
        (
            "exists resource",
            append_tokens(&[attr_ref(0xfa, "ResourceGate"), vec![0x87]]),
            ConditionalResult::True,
        ),
        (
            "exists device",
            append_tokens(&[attr_ref(0xfb, "DeviceGate"), vec![0x87]]),
            ConditionalResult::True,
        ),
        (
            "not exists",
            append_tokens(&[attr_ref(0xf8, "Missing"), vec![0x8d]]),
            ConditionalResult::True,
        ),
        (
            "member_of",
            append_tokens(&[sid_literal(&group), vec![0x89]]),
            ConditionalResult::True,
        ),
        (
            "device_member_of",
            append_tokens(&[sid_literal(&device_group), vec![0x8a]]),
            ConditionalResult::True,
        ),
        (
            "member_of_any",
            append_tokens(&[
                composite(&[sid_literal(&missing_group), sid_literal(&group)]),
                vec![0x8b],
            ]),
            ConditionalResult::True,
        ),
        (
            "device_member_of_any",
            append_tokens(&[
                composite(&[sid_literal(&missing_group), sid_literal(&device_group)]),
                vec![0x8c],
            ]),
            ConditionalResult::True,
        ),
        (
            "not_member_of",
            append_tokens(&[sid_literal(&missing_group), vec![0x90]]),
            ConditionalResult::True,
        ),
        (
            "not_device_member_of",
            append_tokens(&[sid_literal(&missing_group), vec![0x91]]),
            ConditionalResult::True,
        ),
        (
            "not_member_of_any",
            append_tokens(&[composite(&[sid_literal(&missing_group)]), vec![0x92]]),
            ConditionalResult::True,
        ),
        (
            "not_device_member_of_any",
            append_tokens(&[composite(&[sid_literal(&missing_group)]), vec![0x93]]),
            ConditionalResult::True,
        ),
        (
            "and",
            append_tokens(&[true_result.clone(), true_result.clone(), vec![0xa0]]),
            ConditionalResult::True,
        ),
        (
            "or",
            append_tokens(&[false_result.clone(), true_result.clone(), vec![0xa1]]),
            ConditionalResult::True,
        ),
        (
            "not",
            append_tokens(&[false_result, vec![0xa2]]),
            ConditionalResult::True,
        ),
        (
            "zero padding",
            append_tokens(&[true_result, vec![0x00, 0x00, 0x00]]),
            ConditionalResult::True,
        ),
    ];

    for (name, tokens, expected) in cases {
        assert_eq!(
            evaluate_conditional_expression(&expr(&tokens), &token, &context, true),
            expected,
            "{name}"
        );
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
fn malformed_bytecode_bounds_underflow_and_final_stack_fail_closed() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4024]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let mut stack_overflow = b"artx".to_vec();
    for _ in 0..1030 {
        stack_overflow.extend_from_slice(&int64_literal(1));
    }
    let cases = [
        (b"art".to_vec(), "short magic"),
        (expr(&[0x04, 0]), "truncated integer literal"),
        (
            expr(&[0x10, 0xff, 0xff, 0xff, 0xff]),
            "overlong string literal",
        ),
        (expr(&[0x10, 1, 0, 0, 0, 0]), "odd string length"),
        (expr(&[0x18, 4, 0, 0, 0, 1]), "truncated octet literal"),
        (expr(&[0x51, 8, 0, 0, 0, 1, 1, 0]), "truncated SID literal"),
        (
            expr(&[0x50, 4, 0, 0, 0, 0x04]),
            "truncated composite literal",
        ),
        (expr(&[0xf9, 1, 0, 0, 0, 0]), "odd attribute name"),
        (expr(&[0x87]), "unary operator underflow"),
        (
            expr(&append_tokens(&[int64_literal(1), vec![0x80]])),
            "binary operator underflow",
        ),
        (
            expr(&append_tokens(&[
                result_tokens(ConditionalResult::True),
                vec![0xa0],
            ])),
            "logical operator underflow",
        ),
        (expr(&[0xff]), "unknown opcode"),
        (expr(&[0x00]), "empty final stack"),
        (
            expr(&append_tokens(&[
                result_tokens(ConditionalResult::True),
                result_tokens(ConditionalResult::False),
            ])),
            "multiple final stack entries",
        ),
        (stack_overflow, "stack depth overflow"),
    ];

    for (program, name) in cases {
        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::Unknown,
            "{name}"
        );
    }
}

#[test]
fn padding_bytes_end_expression_and_must_be_zero() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4025]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let zero_padding = expr(&append_tokens(&[
        result_tokens(ConditionalResult::True),
        vec![0x00, 0x00, 0x00],
    ]));
    let nonzero_padding = expr(&append_tokens(&[
        result_tokens(ConditionalResult::True),
        vec![0x00, 0x01, 0x00],
    ]));

    assert_eq!(
        evaluate_conditional_expression(&zero_padding, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&nonzero_padding, &token, &context, true),
        ConditionalResult::Unknown
    );
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
fn not_exists_resolves_attribute_absence() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4017]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "present",
        0,
        vec![ClaimValue::UInt64(1)],
    )];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let cases = [
        (
            append_tokens(&[attr_ref(0xf9, "missing"), vec![0x8d]]),
            ConditionalResult::True,
            "missing attribute",
        ),
        (
            append_tokens(&[attr_ref(0xf9, "present"), vec![0x8d]]),
            ConditionalResult::False,
            "present attribute",
        ),
        (
            append_tokens(&[int64_literal(1), vec![0x8d]]),
            ConditionalResult::Unknown,
            "literal origin",
        ),
    ];

    for (tokens, expected, name) in cases {
        let program = expr(&tokens);

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "{name}"
        );
    }
}

#[test]
fn empty_attribute_values_normalize_to_absent() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4022]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new("empty", 0, Vec::<ClaimValue>::new())];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let cases = [
        (
            append_tokens(&[attr_ref(0xf9, "empty"), vec![0x87]]),
            ConditionalResult::False,
            "Exists(empty)",
        ),
        (
            append_tokens(&[attr_ref(0xf9, "empty"), vec![0x8d]]),
            ConditionalResult::True,
            "Not_Exists(empty)",
        ),
        (
            append_tokens(&[attr_ref(0xf9, "empty"), int64_literal(0), vec![0x80]]),
            ConditionalResult::Unknown,
            "empty == literal",
        ),
    ];

    for (tokens, expected, name) in cases {
        let program = expr(&tokens);

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "{name}"
        );
    }
}

#[test]
fn attribute_lookup_is_case_insensitive() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4013]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "Clearance",
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
fn attribute_lookup_is_unicode_case_insensitive() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4033]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "État",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let program = expr(&append_tokens(&[attr_ref(0xf9, "état"), vec![0x87]]));

    assert_eq!(
        evaluate_conditional_expression(&program, &token, &context, true),
        ConditionalResult::True
    );
}

#[test]
fn all_attribute_namespaces_are_recognized() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4034]);
    let token = token(&user, &[]);
    let local_claims = [ClaimAttribute::new(
        "local",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let user_claims = [ClaimAttribute::new(
        "user",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let resource_claims = [ClaimAttribute::new(
        "resource",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let device_claims = [ClaimAttribute::new(
        "device",
        0,
        vec![ClaimValue::String("present".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        user_claims: &user_claims,
        resource_claims: &resource_claims,
        device_claims: &device_claims,
        ..ConditionalContext::default()
    };
    let cases = [
        (0xf8, "local"),
        (0xf9, "user"),
        (0xfa, "resource"),
        (0xfb, "device"),
    ];

    for (opcode, name) in cases {
        let program = expr(&append_tokens(&[attr_ref(opcode, name), vec![0x87]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::True,
            "namespace opcode {opcode:#x}"
        );
    }
}

#[test]
fn literal_origin_in_logical_operator_forces_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4002]);
    let token = token(&user, &[]);
    let claims = [
        ClaimAttribute::new("false_flag", 0, vec![ClaimValue::UInt64(0)]),
        ClaimAttribute::new("true_flag", 0, vec![ClaimValue::UInt64(1)]),
    ];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let cases = [
        (
            append_tokens(&[int64_literal(1), int64_literal(1), vec![0xa0]]),
            "literal AND literal",
        ),
        (
            append_tokens(&[attr_ref(0xf9, "false_flag"), int64_literal(1), vec![0xa0]]),
            "false attribute AND literal",
        ),
        (
            append_tokens(&[attr_ref(0xf9, "true_flag"), int64_literal(0), vec![0xa1]]),
            "true attribute OR literal",
        ),
        (
            append_tokens(&[int64_literal(0), vec![0xa2]]),
            "NOT literal",
        ),
    ];

    for (tokens, name) in cases {
        let program = expr(&tokens);

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::Unknown,
            "{name}"
        );
    }
}

#[test]
fn logical_and_or_truth_tables_match_spec() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4019]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let and_cases = [
        (
            ConditionalResult::True,
            ConditionalResult::True,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::True,
            ConditionalResult::False,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::True,
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::True,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::False,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::Unknown,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::True,
            ConditionalResult::Unknown,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::False,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
        ),
    ];
    let or_cases = [
        (
            ConditionalResult::True,
            ConditionalResult::True,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::True,
            ConditionalResult::False,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::True,
            ConditionalResult::Unknown,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::True,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::False,
            ConditionalResult::False,
        ),
        (
            ConditionalResult::False,
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::True,
            ConditionalResult::True,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::False,
            ConditionalResult::Unknown,
        ),
        (
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
            ConditionalResult::Unknown,
        ),
    ];

    for (lhs, rhs, expected) in and_cases {
        let program = expr(&append_tokens(&[
            result_tokens(lhs),
            result_tokens(rhs),
            vec![0xa0],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "AND {lhs:?} {rhs:?}"
        );
    }

    for (lhs, rhs, expected) in or_cases {
        let program = expr(&append_tokens(&[
            result_tokens(lhs),
            result_tokens(rhs),
            vec![0xa1],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "OR {lhs:?} {rhs:?}"
        );
    }
}

#[test]
fn logical_not_truth_table_matches_spec() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4020]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let cases = [
        (ConditionalResult::True, ConditionalResult::False),
        (ConditionalResult::False, ConditionalResult::True),
        (ConditionalResult::Unknown, ConditionalResult::Unknown),
    ];

    for (value, expected) in cases {
        let program = expr(&append_tokens(&[result_tokens(value), vec![0xa2]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "NOT {value:?}"
        );
    }
}

#[test]
fn attribute_logical_coercion_matrix_matches_spec() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4021]);
    let token = token(&user, &[]);
    let claims = [
        ClaimAttribute::new("nonzero_int", 0, vec![ClaimValue::UInt64(7)]),
        ClaimAttribute::new("zero_int", 0, vec![ClaimValue::UInt64(0)]),
        ClaimAttribute::new("noncanonical_bool", 0, vec![ClaimValue::Boolean(2)]),
        ClaimAttribute::new("false_bool", 0, vec![ClaimValue::Boolean(0)]),
        ClaimAttribute::new(
            "nonempty_string",
            0,
            vec![ClaimValue::String("present".into())],
        ),
        ClaimAttribute::new("empty_string", 0, vec![ClaimValue::String("".into())]),
        ClaimAttribute::new("null", 0, Vec::<ClaimValue>::new()),
        ClaimAttribute::new("sid", 0, vec![ClaimValue::Sid(user.clone().into())]),
        ClaimAttribute::new("octet", 0, vec![ClaimValue::Octet(vec![0x51, 0x52].into())]),
        ClaimAttribute::new(
            "composite",
            0,
            vec![ClaimValue::Composite(vec![ClaimValue::UInt64(1)].into())],
        ),
    ];
    let context = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };
    let cases = [
        ("nonzero_int", ConditionalResult::True),
        ("zero_int", ConditionalResult::False),
        ("noncanonical_bool", ConditionalResult::True),
        ("false_bool", ConditionalResult::False),
        ("nonempty_string", ConditionalResult::True),
        ("empty_string", ConditionalResult::False),
        ("missing", ConditionalResult::Unknown),
        ("null", ConditionalResult::Unknown),
        ("sid", ConditionalResult::Unknown),
        ("octet", ConditionalResult::Unknown),
        ("composite", ConditionalResult::Unknown),
    ];

    for (name, expected) in cases {
        let program = expr(&append_tokens(&[
            attr_ref(0xf9, name),
            result_tokens(ConditionalResult::True),
            vec![0xa0],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "{name}"
        );
    }
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
fn relational_operators_cover_equality_and_ordering_matrix() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4015]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let cases = [
        (0x80, 3, 3, ConditionalResult::True),
        (0x80, 3, 4, ConditionalResult::False),
        (0x81, 3, 4, ConditionalResult::True),
        (0x81, 3, 3, ConditionalResult::False),
        (0x82, 3, 4, ConditionalResult::True),
        (0x82, 3, 3, ConditionalResult::False),
        (0x83, 3, 3, ConditionalResult::True),
        (0x83, 4, 3, ConditionalResult::False),
        (0x84, 4, 3, ConditionalResult::True),
        (0x84, 3, 3, ConditionalResult::False),
        (0x85, 3, 3, ConditionalResult::True),
        (0x85, 3, 4, ConditionalResult::False),
    ];

    for (opcode, lhs, rhs, expected) in cases {
        let program = expr(&append_tokens(&[
            int64_literal(lhs),
            int64_literal(rhs),
            vec![opcode],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "opcode {opcode:#x}, lhs {lhs}, rhs {rhs}"
        );
    }
}

#[test]
fn mixed_operand_types_except_int_promotion_return_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4031]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let mixed_cases = [
        (string_literal("7"), int64_literal(7), 0x80, "string == int"),
        (string_literal("7"), int64_literal(7), 0x81, "string != int"),
        (string_literal("7"), int64_literal(7), 0x82, "string < int"),
        (string_literal("7"), int64_literal(7), 0x83, "string <= int"),
        (string_literal("7"), int64_literal(7), 0x84, "string > int"),
        (string_literal("7"), int64_literal(7), 0x85, "string >= int"),
        (
            string_literal("7"),
            int64_literal(7),
            0x86,
            "string Contains int",
        ),
        (
            string_literal("7"),
            int64_literal(7),
            0x88,
            "string Any_of int",
        ),
        (
            string_literal("7"),
            int64_literal(7),
            0x8e,
            "string Not_Contains int",
        ),
        (
            string_literal("7"),
            int64_literal(7),
            0x8f,
            "string Not_Any_of int",
        ),
        (
            sid_literal(&user),
            octet_literal(&user),
            0x80,
            "sid == octet",
        ),
    ];
    let promoted_cases = [
        (
            int64_literal(-1),
            attr_ref(0xf9, "uint"),
            0x82,
            ConditionalResult::True,
            "negative int64 promotes below uint64",
        ),
        (
            int64_literal(7),
            attr_ref(0xf9, "uint"),
            0x80,
            ConditionalResult::True,
            "nonnegative int64 equals uint64",
        ),
    ];
    let claims = [ClaimAttribute::new("uint", 0, vec![ClaimValue::UInt64(7)])];
    let context_with_uint = ConditionalContext {
        user_claims: &claims,
        ..ConditionalContext::default()
    };

    for (lhs, rhs, opcode, name) in mixed_cases {
        let program = expr(&append_tokens(&[lhs, rhs, vec![opcode]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::Unknown,
            "{name}"
        );
    }

    for (lhs, rhs, opcode, expected, name) in promoted_cases {
        let program = expr(&append_tokens(&[lhs, rhs, vec![opcode]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context_with_uint, true),
            expected,
            "{name}"
        );
    }
}

#[test]
fn unknown_relational_operands_propagate_through_each_operator() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4032]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let opcodes = [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x88, 0x8e, 0x8f];

    for opcode in opcodes {
        let program = expr(&append_tokens(&[
            attr_ref(0xf9, "missing"),
            int64_literal(1),
            vec![opcode],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::Unknown,
            "opcode {opcode:#x}"
        );
    }
}

#[test]
fn signed_integer_literal_width_sign_and_base_match_bytecode_rules() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4026]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let true_cases = [
        (
            signed_literal(0x01, 127, 0x01, 0x02),
            int64_literal(127),
            "int8 max positive",
        ),
        (
            signed_literal(0x01, 128, 0x02, 0x02),
            int64_literal(-128),
            "int8 min through negative sign override",
        ),
        (
            signed_literal(0x02, 32767, 0x03, 0x02),
            int64_literal(32767),
            "int16 max no sign",
        ),
        (
            signed_literal(0x02, 32768, 0x02, 0x02),
            int64_literal(-32768),
            "int16 min through negative sign override",
        ),
        (
            signed_literal(0x03, 2_147_483_647, 0x01, 0x02),
            int64_literal(2_147_483_647),
            "int32 max positive",
        ),
        (
            signed_literal(0x03, 2_147_483_648, 0x02, 0x02),
            int64_literal(-2_147_483_648),
            "int32 min through negative sign override",
        ),
        (
            signed_literal(0x04, -1, 0x01, 0x02),
            int64_literal(1),
            "positive sign overrides raw negative",
        ),
        (
            signed_literal(0x04, -1, 0x03, 0x02),
            int64_literal(1),
            "no sign treats raw negative as positive",
        ),
        (
            signed_literal(0x04, 1, 0x02, 0x02),
            int64_literal(-1),
            "negative sign overrides raw positive",
        ),
        (
            signed_literal(0x04, 7, 0x01, 0x01),
            signed_literal(0x04, 7, 0x01, 0x03),
            "base is display-only",
        ),
    ];
    let unknown_cases = [
        (
            signed_literal(0x01, 128, 0x01, 0x02),
            "int8 positive overflow",
        ),
        (
            signed_literal(0x02, 32768, 0x03, 0x02),
            "int16 no-sign overflow",
        ),
        (
            signed_literal(0x03, 2_147_483_648, 0x01, 0x02),
            "int32 positive overflow",
        ),
        (signed_literal(0x04, 1, 0x04, 0x02), "invalid sign"),
        (signed_literal(0x04, 1, 0x01, 0x04), "invalid base"),
    ];

    for (lhs, rhs, name) in true_cases {
        let program = expr(&append_tokens(&[lhs, rhs, vec![0x80]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::True,
            "{name}"
        );
    }

    for (literal, name) in unknown_cases {
        let program = expr(&append_tokens(&[literal, int64_literal(0), vec![0x80]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            ConditionalResult::Unknown,
            "{name}"
        );
    }
}

#[test]
fn octet_literals_participate_in_condition_comparisons() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4018]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let cases = [
        (
            octet_literal(&[0xde, 0xad, 0xbe, 0xef]),
            octet_literal(&[0xde, 0xad, 0xbe, 0xef]),
            0x80,
            ConditionalResult::True,
        ),
        (
            octet_literal(&[0xde, 0xad, 0xbe, 0xef]),
            octet_literal(&[0xde, 0xad, 0xbe, 0xee]),
            0x81,
            ConditionalResult::True,
        ),
    ];

    for (lhs, rhs, opcode, expected) in cases {
        let program = expr(&append_tokens(&[lhs, rhs, vec![opcode]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected
        );
    }
}

#[test]
fn string_comparisons_are_bytewise_with_ascii_case_folding_only() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4027]);
    let token = token(&user, &[]);
    let claims = [ClaimAttribute::new(
        "case_sensitive",
        CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
        vec![ClaimValue::String("Alpha".into())],
    )];
    let context = ConditionalContext {
        local_claims: &claims,
        ..ConditionalContext::default()
    };
    let ascii_default = expr(&append_tokens(&[
        string_literal("Alpha"),
        string_literal("alpha"),
        vec![0x80],
    ]));
    let non_ascii_default = expr(&append_tokens(&[
        string_literal("É"),
        string_literal("é"),
        vec![0x80],
    ]));
    let flagged_case_sensitive = expr(&append_tokens(&[
        attr_ref(0xf8, "case_sensitive"),
        string_literal("alpha"),
        vec![0x80],
    ]));

    assert_eq!(
        evaluate_conditional_expression(&ascii_default, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&non_ascii_default, &token, &context, true),
        ConditionalResult::False
    );
    assert_eq!(
        evaluate_conditional_expression(&flagged_case_sensitive, &token, &context, true),
        ConditionalResult::False
    );
}

#[test]
fn malformed_utf16_string_literal_fails_closed() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4028]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let mut invalid_surrogate = vec![0x10];
    invalid_surrogate.extend_from_slice(&2u32.to_le_bytes());
    invalid_surrogate.extend_from_slice(&0xd800u16.to_le_bytes());
    let program = expr(&append_tokens(&[
        invalid_surrogate,
        string_literal("x"),
        vec![0x80],
    ]));

    assert_eq!(
        evaluate_conditional_expression(&program, &token, &context, true),
        ConditionalResult::Unknown
    );
}

#[test]
fn malformed_sid_literal_and_non_sid_membership_operands_fail_closed() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4030]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let invalid_sid_literal = {
        let mut bytes = vec![0x51];
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
        bytes
    };
    let invalid_sid_program = expr(&append_tokens(&[
        invalid_sid_literal,
        sid_literal(&user),
        vec![0x80],
    ]));
    let non_sid_membership_program =
        expr(&append_tokens(&[string_literal("not-a-sid"), vec![0x89]]));

    assert_eq!(
        evaluate_conditional_expression(&invalid_sid_program, &token, &context, true),
        ConditionalResult::Unknown
    );
    assert_eq!(
        evaluate_conditional_expression(&non_sid_membership_program, &token, &context, true),
        ConditionalResult::Unknown
    );
}

#[test]
fn heterogeneous_composite_literals_use_contiguous_element_encoding() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4029]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let lhs = composite(&[int64_literal(7), string_literal("blue")]);
    let rhs = composite(&[string_literal("blue")]);
    let program = expr(&append_tokens(&[lhs, rhs, vec![0x86]]));

    assert_eq!(
        evaluate_conditional_expression(&program, &token, &context, true),
        ConditionalResult::True
    );
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
fn set_operators_cover_contains_any_and_negated_forms() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4016]);
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
    let cases = [
        (0x86, vec!["red"], ConditionalResult::True),
        (0x86, vec!["red", "green"], ConditionalResult::False),
        (0x88, vec!["green", "blue"], ConditionalResult::True),
        (0x88, vec!["green"], ConditionalResult::False),
        (0x8e, vec!["red"], ConditionalResult::False),
        (0x8e, vec!["green"], ConditionalResult::True),
        (0x8f, vec!["green", "blue"], ConditionalResult::False),
        (0x8f, vec!["green"], ConditionalResult::True),
    ];

    for (opcode, rhs_values, expected) in cases {
        let rhs_literals = rhs_values
            .iter()
            .map(|value| string_literal(value))
            .collect::<Vec<_>>();
        let program = expr(&append_tokens(&[
            attr_ref(0xf8, "tags"),
            composite(&rhs_literals),
            vec![opcode],
        ]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "opcode {opcode:#x}, rhs {rhs_values:?}"
        );
    }
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
fn equality_of_two_absent_attributes_is_unknown() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4014]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[
        attr_ref(0xf9, "missing_user"),
        attr_ref(0xfb, "missing_device"),
        vec![0x80],
    ]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::Unknown);
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
fn inverted_membership_operators_respect_deny_only_group_polarity() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4011]);
    let deny_only_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 546]);
    let deny_only_device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 547]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&deny_only_group),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let device_groups = [SidAndAttributes {
        sid: parse_sid(&deny_only_device_group),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let token = token(&user, &groups);
    let context = ConditionalContext {
        device_groups: &device_groups,
        ..ConditionalContext::default()
    };

    let not_member = expr(&append_tokens(&[sid_literal(&deny_only_group), vec![0x90]]));
    let not_member_any = expr(&append_tokens(&[
        composite(&[sid_literal(&deny_only_group)]),
        vec![0x92],
    ]));
    let not_device_member = expr(&append_tokens(&[
        sid_literal(&deny_only_device_group),
        vec![0x91],
    ]));
    let not_device_member_any = expr(&append_tokens(&[
        composite(&[sid_literal(&deny_only_device_group)]),
        vec![0x93],
    ]));

    assert_eq!(
        evaluate_conditional_expression(&not_member, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&not_member, &token, &context, false),
        ConditionalResult::False
    );
    assert_eq!(
        evaluate_conditional_expression(&not_member_any, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&not_member_any, &token, &context, false),
        ConditionalResult::False
    );
    assert_eq!(
        evaluate_conditional_expression(&not_device_member, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&not_device_member, &token, &context, false),
        ConditionalResult::False
    );
    assert_eq!(
        evaluate_conditional_expression(&not_device_member_any, &token, &context, true),
        ConditionalResult::True
    );
    assert_eq!(
        evaluate_conditional_expression(&not_device_member_any, &token, &context, false),
        ConditionalResult::False
    );
}

#[test]
fn empty_sid_set_membership_uses_normal_set_semantics() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4023]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let empty_set = composite(&[]);
    let cases = [
        (0x89, ConditionalResult::True, "Member_of({})"),
        (0x8a, ConditionalResult::True, "Device_Member_of({})"),
        (0x8b, ConditionalResult::False, "Member_of_Any({})"),
        (0x8c, ConditionalResult::False, "Device_Member_of_Any({})"),
        (0x90, ConditionalResult::False, "Not_Member_of({})"),
        (0x91, ConditionalResult::False, "Not_Device_Member_of({})"),
        (0x92, ConditionalResult::True, "Not_Member_of_Any({})"),
        (
            0x93,
            ConditionalResult::True,
            "Not_Device_Member_of_Any({})",
        ),
    ];

    for (opcode, expected, name) in cases {
        let program = expr(&append_tokens(&[empty_set.clone(), vec![opcode]]));

        assert_eq!(
            evaluate_conditional_expression(&program, &token, &context, true),
            expected,
            "{name}"
        );
    }
}

#[test]
fn member_of_does_not_treat_user_sid_as_group_membership() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4012]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[sid_literal(&user), vec![0x89]]));

    let allow_result = evaluate_conditional_expression(&program, &token, &context, true);
    let deny_result = evaluate_conditional_expression(&program, &token, &context, false);

    assert_eq!(allow_result, ConditionalResult::False);
    assert_eq!(deny_result, ConditionalResult::False);
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
fn sign_byte_overrides_raw_integer_sign() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 4010]);
    let token = token(&user, &[]);
    let context = ConditionalContext::default();
    let program = expr(&append_tokens(&[
        int64_literal_with_sign(-1, 0x03),
        int64_literal(0),
        vec![0x84],
    ]));

    let result = evaluate_conditional_expression(&program, &token, &context, true);

    assert_eq!(result, ConditionalResult::True);
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
