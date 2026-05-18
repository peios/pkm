use kacs_core::{
    evaluate_dacl, evaluate_dacl_result_list, evaluate_dacl_with_object_tree, AccessStatus,
    GenericMapping, KacsError, ObjectTypeList, ObjectTypeNode, SecurityDescriptor, Sid,
    SidAndAttributes, TokenView, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, DELETE, READ_CONTROL,
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

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(sid);

    let size = 4 + body.len();
    let mut bytes = Vec::with_capacity(size);
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

fn object_ace_with_inherited_type(
    ace_type: u8,
    flags: u8,
    mask: u32,
    object_flags: u32,
    object_type: Option<[u8; 16]>,
    inherited_object_type: Option<[u8; 16]>,
    sid: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&object_flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    if let Some(guid) = inherited_object_type {
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

fn guid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

#[test]
fn rejects_empty_object_type_list() {
    let err = ObjectTypeList::new(&[]).expect_err("empty list must fail");
    assert_eq!(err, KacsError::EmptyObjectTypeList);
}

#[test]
fn rejects_nonzero_root_level() {
    let nodes = [ObjectTypeNode {
        level: 1,
        guid: guid(1),
    }];

    let err = ObjectTypeList::new(&nodes).expect_err("root level must be zero");
    assert_eq!(err, KacsError::InvalidObjectTypeRootLevel(1));
}

#[test]
fn rejects_multiple_level_zero_nodes() {
    let nodes = [
        ObjectTypeNode {
            level: 0,
            guid: guid(1),
        },
        ObjectTypeNode {
            level: 0,
            guid: guid(2),
        },
    ];

    let err = ObjectTypeList::new(&nodes).expect_err("multiple roots must fail");
    assert_eq!(err, KacsError::MultipleObjectTypeRoots);
}

#[test]
fn rejects_level_gaps() {
    let nodes = [
        ObjectTypeNode {
            level: 0,
            guid: guid(1),
        },
        ObjectTypeNode {
            level: 2,
            guid: guid(2),
        },
    ];

    let err = ObjectTypeList::new(&nodes).expect_err("level gaps must fail");
    assert_eq!(
        err,
        KacsError::ObjectTypeLevelGap {
            previous: 0,
            current: 2,
        }
    );
}

#[test]
fn rejects_duplicate_guids() {
    let nodes = [
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
            guid: guid(2),
        },
    ];

    let err = ObjectTypeList::new(&nodes).expect_err("duplicate guids must fail");
    assert_eq!(err, KacsError::DuplicateObjectTypeGuid(guid(2)));
}

#[test]
fn guid_scoped_object_ace_without_tree_behaves_like_basic_ace() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2000]);
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some(guid(7)),
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
fn object_grants_to_all_siblings_propagate_to_root() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2001]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(3)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn deny_on_one_property_fails_root_but_not_other_property_results() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2002]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(3)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    assert!(!root.success);
    assert_eq!(root.granted, 0);

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(result_list.granted_list, vec![0, 0, READ_CONTROL]);
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
        ]
    );
}

#[test]
fn malformed_callback_object_ace_is_skipped_as_unknown() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2003]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[callback_object_ace(
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some(guid(2)),
        &user,
        &[0x01, 0x02, 0x03, 0x04],
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("malformed callback object ace should not error");

    assert!(!result.success);
    assert_eq!(result.granted, 0);
}

#[test]
fn group_match_still_applies_for_guid_scoped_object_aces() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2004]);
    let group_bytes = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 544]);
    let groups = [SidAndAttributes {
        sid: parse_sid(&group_bytes),
        attributes: SE_GROUP_ENABLED,
    }];
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some(guid(2)),
        &group_bytes,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &groups,
    };

    let result = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("group-guid evaluation should succeed");

    assert!(result.success);
    assert_eq!(result.granted, READ_CONTROL);
}

#[test]
fn unmatched_object_guid_does_not_apply_to_object_tree() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2005]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some(guid(9)),
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert!(!root.success);
    assert_eq!(root.granted, 0);
    assert_eq!(result_list.granted_list, vec![0, 0, 0]);
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
        ]
    );
}

#[test]
fn inherited_object_type_only_object_ace_applies_globally() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2006]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace_with_inherited_type(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_INHERITED_OBJECT_TYPE_PRESENT,
        None,
        Some(guid(9)),
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert!(root.success);
    assert_eq!(root.granted, READ_CONTROL);
    assert_eq!(
        result_list.granted_list,
        vec![READ_CONTROL, READ_CONTROL, READ_CONTROL]
    );
    assert_eq!(
        result_list.status_list,
        vec![AccessStatus::Ok, AccessStatus::Ok, AccessStatus::Ok]
    );
}

#[test]
fn ordinary_basic_ace_applies_globally_to_result_list() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2007]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(
        result_list.granted_list,
        vec![READ_CONTROL, READ_CONTROL, READ_CONTROL]
    );
    assert_eq!(
        result_list.status_list,
        vec![AccessStatus::Ok, AccessStatus::Ok, AccessStatus::Ok]
    );
}

#[test]
fn object_ace_without_object_type_applies_globally_to_result_list() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2008]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        0,
        None,
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(
        result_list.granted_list,
        vec![READ_CONTROL, READ_CONTROL, READ_CONTROL]
    );
    assert_eq!(
        result_list.status_list,
        vec![AccessStatus::Ok, AccessStatus::Ok, AccessStatus::Ok]
    );
}

#[test]
fn parent_grant_after_child_denial_preserves_child_denial() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2009]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(1)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(result_list.granted_list, vec![0, 0, READ_CONTROL]);
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
        ]
    );
}

#[test]
fn parent_denial_after_child_grant_preserves_child_grant() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2010]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
        object_ace(
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(1)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(result_list.granted_list, vec![0, READ_CONTROL, 0]);
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
            AccessStatus::AccessDenied,
        ]
    );
}

#[test]
fn upward_grant_propagates_only_shared_bits() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2011]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL | WRITE_DAC,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(3)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert_eq!(
        result_list.granted_list,
        vec![READ_CONTROL, READ_CONTROL | WRITE_DAC, READ_CONTROL]
    );
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
            AccessStatus::AccessDenied,
        ]
    );
}

#[test]
fn leaf_grants_propagate_through_deeper_tree() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2012]);
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
            level: 2,
            guid: guid(4),
        },
        ObjectTypeNode {
            level: 1,
            guid: guid(3),
        },
    ])
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(4)),
            &user,
        ),
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(3)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert!(root.success);
    assert_eq!(root.granted, READ_CONTROL);
    assert_eq!(
        result_list.granted_list,
        vec![READ_CONTROL, READ_CONTROL, READ_CONTROL, READ_CONTROL]
    );
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::Ok,
            AccessStatus::Ok,
            AccessStatus::Ok,
            AccessStatus::Ok,
        ]
    );
}

#[test]
fn scalar_object_tree_fails_when_child_is_ungranted_without_denial() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2013]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        Some(guid(2)),
        &user,
    )]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert!(!root.success);
    assert_eq!(root.granted, 0);
    assert_eq!(result_list.granted_list, vec![0, READ_CONTROL, 0]);
    assert_eq!(
        result_list.status_list,
        vec![
            AccessStatus::AccessDenied,
            AccessStatus::Ok,
            AccessStatus::AccessDenied,
        ]
    );
}

#[test]
fn later_child_deny_does_not_override_earlier_global_allow() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2005]);
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
    .expect("tree should parse");
    let dacl = acl_bytes(&[
        object_ace(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            0,
            None,
            &user,
        ),
        object_ace(
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            0,
            READ_CONTROL,
            ACE_OBJECT_TYPE_PRESENT,
            Some(guid(2)),
            &user,
        ),
    ]);
    let sd_bytes = sd_with_dacl(&owner, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = TokenView {
        user: parse_sid(&user),
        user_deny_only: false,
        groups: &[],
    };

    let root = evaluate_dacl_with_object_tree(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("tree evaluation should succeed");
    let result_list = evaluate_dacl_result_list(
        &sd,
        &token,
        READ_CONTROL,
        &mapping(),
        false,
        None,
        &object_tree,
    )
    .expect("result-list evaluation should succeed");

    assert!(root.success);
    assert_eq!(root.granted, READ_CONTROL);
    assert_eq!(result_list.granted_list, vec![READ_CONTROL, READ_CONTROL]);
    assert_eq!(
        result_list.status_list,
        vec![AccessStatus::Ok, AccessStatus::Ok]
    );
}
