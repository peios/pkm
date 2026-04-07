use kacs_core::{
    evaluate_dacl_result_list_with_confinement_context, evaluate_dacl_with_confinement_context,
    AccessStatus, ConditionalContext, ConfinementTokenContext, GenericMapping, ObjectTypeList,
    ObjectTypeNode, SecurityDescriptor, Sid, SidAndAttributes, TokenView, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT,
    READ_CONTROL, SE_DACL_PRESENT, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY, SE_SELF_RELATIVE,
    WRITE_DAC,
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
    object_type: Option<[u8; 16]>,
    sid: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&object_flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    body.extend_from_slice(sid);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
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

fn sd_with_dacl(owner: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | if dacl.is_some() { SE_DACL_PRESENT } else { 0 };
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(owner);
    if let Some(dacl) = dacl {
        let dacl_offset = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
        bytes.extend_from_slice(dacl);
    }
    bytes
}

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0,
        all: READ_CONTROL | WRITE_DAC,
    }
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

fn expr(tokens: &[u8]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    bytes.extend_from_slice(tokens);
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

#[test]
fn confinement_intersects_normal_grants() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9000]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 42]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &package),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn confinement_exempt_bypasses_confinement_merge() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9001]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 43]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: true,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn confinement_null_dacl_grants_all_valid_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9002]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 44]);
    let sd_bytes = sd_with_dacl(&owner, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn confinement_principal_self_is_scoped_to_confinement_identity() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9003]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 45]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&package)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &context,
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn confinement_principal_self_does_not_match_outside_confinement_set() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9007]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 49]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&user)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &context,
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn confinement_callback_membership_uses_full_token_groups() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9004]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 46]);
    let real_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 600]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&real_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &package,
            &expr(&append_tokens(&[sid_literal(&real_group), vec![0x89]])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &groups,
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn disabled_confinement_capability_still_matches_by_presence() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9010]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 60]);
    let capability = sid_bytes([0, 0, 0, 0, 0, 15], &[3, 60]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &capability),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let capability_entries = [SidAndAttributes {
        sid: parse_sid(&capability),
        attributes: 0,
    }];
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &capability_entries,
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn deny_only_confinement_capability_still_injects_principal_self() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9011]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 61]);
    let capability = sid_bytes([0, 0, 0, 0, 0, 15], &[3, 61]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let capability_entries = [SidAndAttributes {
        sid: parse_sid(&capability),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &capability_entries,
        confinement_exempt: false,
    };
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&capability)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &context,
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn confinement_owner_rights_membership_is_scoped_to_confinement_identity() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 47]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9005]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &owner,
            &expr(&append_tokens(&[sid_literal(&owner_rights), vec![0x89]])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&owner)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn confinement_owner_rights_does_not_match_when_owner_is_outside_confinement_set() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 50]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9008]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 51]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &package,
            &expr(&append_tokens(&[sid_literal(&owner_rights), vec![0x89]])),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn confinement_object_tree_intersection_is_per_node() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9006]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 48]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some([0x11; 16]),
            &package,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_dacl_result_list_with_confinement_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &object_tree(),
        &ConditionalContext::default(),
        &confinement,
    )
    .expect("evaluation should succeed");

    assert_eq!(
        result.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
            AccessStatus::AccessDenied,
        ]
    );
    assert_eq!(result.granted_list, vec![0, READ_CONTROL, 0]);
}
