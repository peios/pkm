use kacs_core::{
    evaluate_dacl, GenericMapping, SecurityDescriptor, Sid, SidAndAttributes, TokenView,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT, DELETE, GENERIC_READ, MAXIMUM_ALLOWED,
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
    let size = 8 + sid.len() + app_data.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(app_data);
    bytes
}

fn opaque_ace(ace_type: u8, ace_size: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; ace_size as usize];
    bytes[0] = ace_type;
    bytes[2..4].copy_from_slice(&ace_size.to_le_bytes());
    bytes
}

fn acl_bytes(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(2);
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
        read: READ_CONTROL | 0x0000_0001,
        write: WRITE_DAC | 0x0000_0002,
        execute: 0x0000_0004,
        all: DELETE | READ_CONTROL | WRITE_DAC | 0x0000_0007,
    }
}

#[test]
fn grants_access_for_matching_user_allow_ace() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1000]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn deny_only_user_does_not_match_allow_but_matches_deny() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1001]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: true,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn enabled_group_matches_allow_and_deny_only_group_matches_deny() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1002]);
    let enabled_group_bytes = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 544]);
    let deny_only_group_bytes = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 545]);
    let groups = [
        SidAndAttributes {
            sid: parse_sid(&enabled_group_bytes),
            attributes: SE_GROUP_ENABLED,
        },
        SidAndAttributes {
            sid: parse_sid(&deny_only_group_bytes),
            attributes: SE_GROUP_USE_FOR_DENY_ONLY,
        },
    ];
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, WRITE_DAC, &deny_only_group_bytes),
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            READ_CONTROL,
            &enabled_group_bytes,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &groups,
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn owner_group_receives_implicit_rights() {
    let owner_group_bytes = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 551]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1002, 7]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&owner_group_bytes),
        attributes: SE_GROUP_ENABLED,
    }];
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_with_dacl(&owner_group_bytes, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &groups,
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn disabled_group_matches_neither_allow_nor_deny() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1003]);
    let disabled_group_bytes = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 546]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&disabled_group_bytes),
        attributes: 0,
    }];
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, WRITE_DAC, &disabled_group_bytes),
        basic_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            READ_CONTROL,
            &disabled_group_bytes,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &groups,
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn empty_dacl_still_grants_owner_implicit_rights() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn skip_owner_implicit_disables_owner_bypass() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), true)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn owner_rights_ace_suppresses_implicit_owner_grant() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let owner_rights = sid_bytes([0, 0, 0, 0, 0, 3], &[4]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL,
        &owner_rights,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&owner),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL | WRITE_DAC, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn null_dacl_grants_all_valid_rights() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sd_bytes = sd_with_dacl(&user, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, MAXIMUM_ALLOWED, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(
        result.granted,
        DELETE | READ_CONTROL | WRITE_DAC | 0x0000_0007
    );
}

#[test]
fn inherit_only_ace_is_skipped() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2000]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0x08,
        READ_CONTROL,
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, GENERIC_READ, &mapping(), true)
        .expect("evaluation should succeed");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn malformed_callback_allow_ace_is_skipped_as_unknown() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2001]);
    let dacl = acl_bytes(&[callback_ace(
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        0,
        READ_CONTROL,
        &user,
        b"artx",
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("malformed callback ace should not error");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn object_ace_without_object_type_guid_behaves_like_basic_allow() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2002]);
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        0,
        None,
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn object_ace_with_object_type_guid_behaves_like_basic_allow_without_tree() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2003]);
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some([0x22; 16]),
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&user, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("guid-scoped object ace should behave globally without a tree");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn first_writer_wins_uses_received_dacl_order() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2004]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_DENIED_ACE_TYPE, 0, READ_CONTROL, &user),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn maximum_allowed_returns_full_granted_set_and_does_not_short_circuit() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2005]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &user),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(
        &sd,
        &token,
        MAXIMUM_ALLOWED | READ_CONTROL,
        &mapping(),
        false,
    )
    .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
}

#[test]
fn unknown_ace_types_are_skipped_during_evaluation() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2006]);
    let dacl = acl_bytes(&[
        opaque_ace(0x7f, 4),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl(&sd, &token, READ_CONTROL, &mapping(), false)
        .expect("evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}
