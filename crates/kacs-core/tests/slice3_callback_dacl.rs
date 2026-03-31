use kacs_core::{
    evaluate_dacl_result_list_with_context, evaluate_dacl_with_context,
    evaluate_dacl_with_object_tree_and_context, AccessStatus, ClaimAttribute, ClaimValue,
    ConditionalContext, GenericMapping, ObjectTypeList, ObjectTypeNode, SecurityDescriptor, Sid,
    SidAndAttributes, TokenView, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACE_OBJECT_TYPE_PRESENT, CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY, READ_CONTROL,
    SE_DACL_PRESENT, SE_GROUP_ENABLED, SE_SELF_RELATIVE, WRITE_DAC,
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

fn callback_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8], app_data: &[u8]) -> Vec<u8> {
    let size = (8 + sid.len() + app_data.len() + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(app_data);
    while bytes.len() < size {
        bytes.push(0);
    }
    bytes
}

fn callback_object_ace(
    ace_type: u8,
    flags: u8,
    mask: u32,
    object_flags: u32,
    object_type: Option<[u8; 16]>,
    sid: &[u8],
    app_data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&object_flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    body.extend_from_slice(sid);
    body.extend_from_slice(app_data);

    let size = (4 + body.len() + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    while bytes.len() < size {
        bytes.push(0);
    }
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

fn sd_with_dacl(owner: &[u8], dacl: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(owner);
    let dacl_offset = bytes.len() as u32;
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes.extend_from_slice(dacl);
    bytes
}

fn object_tree() -> ObjectTypeList {
    ObjectTypeList::new(&[
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
    .expect("tree should parse")
}

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0,
        all: READ_CONTROL | WRITE_DAC,
    }
}

fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
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

#[test]
fn callback_allow_ace_grants_when_condition_is_true() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5000]);
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        &expr(&append_tokens(&[
            attr_ref(0xf8, "mode"),
            string_literal("yes"),
            vec![0x80],
        ])),
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [ClaimAttribute::new(
        "mode",
        0,
        vec![ClaimValue::String("yes".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn callback_attribute_lookup_is_case_insensitive() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5008]);
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        &expr(&append_tokens(&[
            attr_ref(0xf8, "mode"),
            string_literal("yes"),
            vec![0x80],
        ])),
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [ClaimAttribute::new(
        "Mode",
        0,
        vec![ClaimValue::String("yes".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn callback_allow_ace_skips_on_unknown_condition() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5001]);
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        b"bad!",
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl_with_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn callback_deny_ace_fires_on_unknown_condition() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5002]);
    let dacl = acl_bytes(&[
        callback_ace(
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            b"bad!",
        ),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &expr(&append_tokens(&[
                attr_ref(0xf8, "mode"),
                string_literal("yes"),
                vec![0x80],
            ])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [ClaimAttribute::new(
        "mode",
        0,
        vec![ClaimValue::String("yes".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn callback_object_ace_propagates_across_the_object_tree() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5003]);
    let tree = object_tree();
    let dacl = acl_bytes(&[callback_object_ace(
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some([0x10; 16]),
        &user,
        &expr(&append_tokens(&[
            attr_ref(0xf8, "mode"),
            string_literal("yes"),
            vec![0x80],
        ])),
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [ClaimAttribute::new(
        "mode",
        0,
        vec![ClaimValue::String("yes".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let root = evaluate_dacl_with_object_tree_and_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &tree,
        &context,
    )
    .expect("evaluation should succeed");
    let list = evaluate_dacl_result_list_with_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &tree,
        &context,
    )
    .expect("result list should succeed");

    assert!(root.success);
    assert_eq!(root.granted, READ_CONTROL);
    assert_eq!(
        list.status_list,
        vec![AccessStatus::Ok, AccessStatus::Ok, AccessStatus::Ok]
    );
    assert_eq!(
        list.granted_list,
        vec![READ_CONTROL, READ_CONTROL, READ_CONTROL]
    );
}

#[test]
fn callback_object_owner_rights_suppresses_implicit_owner_grant() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5005]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let dacl = acl_bytes(&[callback_object_ace(
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some([0x10; 16]),
        &owner_rights,
        &expr(&append_tokens(&[
            attr_ref(0xf8, "mode"),
            string_literal("yes"),
            vec![0x80],
        ])),
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&owner),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [ClaimAttribute::new(
        "mode",
        0,
        vec![ClaimValue::String("no".into())],
    )];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn callback_conditions_can_see_principal_self_and_device_membership() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5004]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 561]);
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        WRITE_DAC,
        &user,
        &expr(&append_tokens(&[
            {
                let mut bytes = Vec::new();
                bytes.push(0x51);
                bytes.extend_from_slice(&(principal_self.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&principal_self);
                bytes
            },
            vec![0x89],
            {
                let mut bytes = Vec::new();
                bytes.push(0x51);
                bytes.extend_from_slice(&(device_group.len() as u32).to_le_bytes());
                bytes.extend_from_slice(&device_group);
                bytes
            },
            vec![0x8a],
            vec![0xa0],
        ])),
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let device_groups = [SidAndAttributes {
        sid: parse_sid(&device_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&user)),
        device_groups: &device_groups,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, WRITE_DAC, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, WRITE_DAC);
}

#[test]
fn deny_only_local_claim_is_visible_to_callback_deny_ace() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5006]);
    let dacl = acl_bytes(&[
        callback_ace(
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &expr(&append_tokens(&[attr_ref(0xf8, "blocked"), vec![0x87]])),
        ),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &expr(&append_tokens(&[
                attr_ref(0xf8, "mode"),
                string_literal("yes"),
                vec![0x80],
            ])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let local_claims = [
        ClaimAttribute::new(
            "blocked",
            CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
            vec![ClaimValue::Boolean(true)],
        ),
        ClaimAttribute::new("mode", 0, vec![ClaimValue::String("yes".into())]),
    ];
    let context = ConditionalContext {
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn deny_only_resource_claim_is_visible_to_callback_deny_ace() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 5007]);
    let dacl = acl_bytes(&[
        callback_ace(
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &expr(&append_tokens(&[attr_ref(0xfa, "blocked"), vec![0x87]])),
        ),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &user,
            &expr(&append_tokens(&[
                attr_ref(0xf8, "mode"),
                string_literal("yes"),
                vec![0x80],
            ])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let resource_claims = [ClaimAttribute::new(
        "blocked",
        CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY,
        vec![ClaimValue::Boolean(true)],
    )];
    let local_claims = [ClaimAttribute::new(
        "mode",
        0,
        vec![ClaimValue::String("yes".into())],
    )];
    let context = ConditionalContext {
        resource_claims: &resource_claims,
        local_claims: &local_claims,
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_context(&sd, &token, READ_CONTROL, &mapping(), false, &context)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}
