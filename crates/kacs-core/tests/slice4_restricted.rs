use kacs_core::{
    evaluate_conditional_expression, evaluate_dacl_result_list_with_restricted_context,
    evaluate_dacl_with_restricted_context, AccessStatus, ConditionalContext, ConditionalResult,
    GenericMapping, KacsError, ObjectTypeList, ObjectTypeNode, RestrictedTokenContext,
    SecurityDescriptor, Sid, SidAndAttributes, TokenView, ACCESS_ALLOWED_ACE_TYPE,
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
fn restricted_pass_intersects_normal_grants() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7000]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8000]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &restricted),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn write_restricted_only_intersects_write_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7001]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7101]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8001]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &group,
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let group_entries = [SidAndAttributes {
        sid: parse_sid(&group),
        attributes: SE_GROUP_ENABLED,
    }];
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: true,
        groups: &group_entries,
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: true,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn privilege_granted_bits_are_restored_after_restricted_merge() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7002]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8002]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: WRITE_DAC,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        WRITE_DAC,
        &mapping(),
        true,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, WRITE_DAC);
}

#[test]
fn restricted_principal_self_is_injected_even_for_deny_only_restricting_sid() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7003]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8003]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let member_of_self = expr(&append_tokens(&[sid_literal(&principal_self), vec![0x89]]));
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &restricted,
            &member_of_self,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    let conditional_context = ConditionalContext {
        self_sid: Some(parse_sid(&restricted)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &conditional_context,
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_member_of_matches_disabled_restricting_sid_by_presence() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 70031]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 80031]);
    let member_of_restricted = expr(&append_tokens(&[sid_literal(&restricted), vec![0x89]]));
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &restricted,
            &member_of_restricted,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: 0,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_member_of_matches_deny_only_restricting_sid_by_presence() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 70032]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 80032]);
    let member_of_restricted = expr(&append_tokens(&[sid_literal(&restricted), vec![0x89]]));
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &restricted,
            &member_of_restricted,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_USE_FOR_DENY_ONLY,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_pass_grants_owner_implicit_rights_independently() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8003]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7003]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&owner),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn restricted_principal_self_matches_restricting_sid() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7004]);
    let self_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8004]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &principal_self),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&self_sid),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&self_sid)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &context,
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_conditional_principal_self_is_invisible_when_not_restricting() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7007]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8007]);
    let principal_self = sid_bytes([0, 0, 0, 0, 0, 5], &[10]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &restricted,
            &expr(&[sid_literal(&principal_self), vec![0x89]].concat()),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    let context = ConditionalContext {
        self_sid: Some(parse_sid(&user)),
        ..ConditionalContext::default()
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &context,
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn restricted_device_groups_drive_device_member_of_conditions() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7005]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8005]);
    let device_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 560]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        callback_ace(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            READ_CONTROL,
            &restricted,
            &expr(&[sid_literal(&device_group), vec![0x8a]].concat()),
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_device_groups = [SidAndAttributes {
        sid: parse_sid(&device_group),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &restricted_device_groups,
        write_restricted: false,
        privilege_granted: 0,
    };
    let expression = expr(&[sid_literal(&device_group), vec![0x8a]].concat());
    let condition_context = ConditionalContext {
        device_groups: &restricted_device_groups,
        ..ConditionalContext::default()
    };
    assert_eq!(
        evaluate_conditional_expression(&expression, &token, &condition_context, true),
        ConditionalResult::True
    );

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_merge_applies_per_node_in_result_list_mode() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7006]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8006]);
    let child_guid = [0x11; 16];
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(child_guid),
            &restricted,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_result_list_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &object_tree(),
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted_list, vec![0, READ_CONTROL, 0]);
    assert_eq!(
        result.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
            AccessStatus::AccessDenied,
        ]
    );
}

#[test]
fn write_restricted_does_not_leak_write_bits_from_restricted_only_grants() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7008]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7108]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8008]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &group),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &restricted),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let group_entries = [SidAndAttributes {
        sid: parse_sid(&group),
        attributes: SE_GROUP_ENABLED,
    }];
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: true,
        groups: &group_entries,
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: true,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn restricted_inner_pass_always_applies_owner_implicit_rights() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9001]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9002]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&owner),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        true,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn write_restricted_requires_user_deny_only_in_standalone_helper() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 9101]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&owner),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &[],
        restricted_device_groups: &[],
        write_restricted: true,
        privilege_granted: 0,
    };

    let err = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect_err("invalid restricted token invariant must fail");

    assert_eq!(
        err,
        KacsError::InvalidTokenInvariant("write_restricted requires user_deny_only")
    );
}

#[test]
fn maximum_allowed_runs_full_restricted_merge() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 7009]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 8009]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL | WRITE_DAC, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &restricted),
    ]);
    let sd_bytes = sd_with_dacl(&owner, &dacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };
    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let restricted_context = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };

    let result = evaluate_dacl_with_restricted_context(
        &sd,
        &token,
        kacs_core::MAXIMUM_ALLOWED,
        &mapping(),
        false,
        &ConditionalContext::default(),
        &restricted_context,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}
