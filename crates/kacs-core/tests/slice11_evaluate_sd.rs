use kacs_core::{
    evaluate_security_descriptor, AccessCheckToken, ConditionalContext, ConfinementTokenContext,
    GenericMapping, ImpersonationLevel, IntegrityLevel, KacsError, ObjectTypeList, ObjectTypeNode,
    PipContext, RestrictedTokenContext, SecurityDescriptor, Sid, SidAndAttributes, TokenPrivileges,
    TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_SYSTEM_SECURITY, ACE_OBJECT_TYPE_PRESENT, GENERIC_WRITE, READ_CONTROL, SE_DACL_PRESENT,
    SE_GROUP_ENABLED, SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE,
    SE_TAKE_OWNERSHIP_PRIVILEGE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC, WRITE_OWNER,
};

const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;

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

fn sid_attr<'a>(sid: Sid<'a>) -> SidAndAttributes<'a> {
    SidAndAttributes {
        sid,
        attributes: SE_GROUP_ENABLED,
    }
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

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC,
        execute: 0x0000_0020,
        all: READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_0020,
    }
}

fn primary_token<'a>(user: Sid<'a>, groups: &'a [SidAndAttributes<'a>]) -> AccessCheckToken<'a> {
    AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups,
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        audit_policy: 0,
        privileges: TokenPrivileges::default(),
        integrity_level: IntegrityLevel::Medium,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        restricted: RestrictedTokenContext::default(),
        confinement: ConfinementTokenContext::default(),
    }
}

fn default_pip() -> PipContext {
    PipContext::default()
}

#[test]
fn identification_level_impersonation_denies_before_other_validation() {
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1000]);
    let token = AccessCheckToken {
        token_type: TokenType::Impersonation,
        impersonation_level: ImpersonationLevel::Identification,
        ..primary_token(parse_sid(&user), &[])
    };

    let err = evaluate_security_descriptor(
        None,
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect_err("identification-level impersonation must deny immediately");

    assert_eq!(err, KacsError::AccessDenied);
}

#[test]
fn missing_group_is_accepted_but_missing_owner_is_rejected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1001]);
    let allow_read = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user)]);
    let token = primary_token(parse_sid(&user), &[]);

    let missing_group_bytes = sd_bytes(Some(&owner), None, None, Some(&allow_read));
    let missing_group = SecurityDescriptor::parse(&missing_group_bytes).expect("sd should parse");
    let missing_group_result = evaluate_security_descriptor(
        Some(&missing_group),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("missing group must still evaluate");
    assert_eq!(missing_group_result.granted, READ_CONTROL);

    let missing_owner_bytes = sd_bytes(None, Some(&group), None, None);
    let missing_owner = SecurityDescriptor::parse(&missing_owner_bytes).expect("sd should parse");
    let missing_owner_err = evaluate_security_descriptor(
        Some(&missing_owner),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect_err("missing owner must fail");
    assert_eq!(missing_owner_err, KacsError::MissingSecurityDescriptorOwner);
}

#[test]
fn malformed_object_tree_is_reused_as_a_fail_closed_dependency() {
    let err = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: [0x10; 16],
        },
        ObjectTypeNode {
            level: 2,
            guid: [0x11; 16],
        },
    ])
    .expect_err("invalid object-tree layout must fail");

    assert_eq!(
        err,
        KacsError::ObjectTypeLevelGap {
            previous: 0,
            current: 2,
        }
    );
}

#[test]
fn write_restricted_requires_user_deny_only_in_full_pipeline() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10015]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut token = primary_token(parse_sid(&user), &[]);
    token.restricted = RestrictedTokenContext {
        restricted_sids: &[],
        restricted_device_groups: &[],
        write_restricted: true,
        privilege_granted: 0,
    };

    let err = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect_err("invalid restricted token invariant must fail");

    assert_eq!(
        err,
        KacsError::InvalidTokenInvariant("write_restricted requires user_deny_only")
    );
}

#[test]
fn scalar_pipeline_composes_mapping_dacl_and_take_ownership_fallback() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1002]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &user)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut token = primary_token(parse_sid(&user), &[]);
    token.privileges = TokenPrivileges {
        present: SE_TAKE_OWNERSHIP_PRIVILEGE,
        enabled: SE_TAKE_OWNERSHIP_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        GENERIC_WRITE | WRITE_OWNER,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.mapped_desired, WRITE_DAC | WRITE_OWNER);
    assert!(!result.max_allowed_mode);
    assert_eq!(result.granted, WRITE_DAC | WRITE_OWNER);
    assert_eq!(result.privilege_granted, WRITE_OWNER);
}

#[test]
fn pip_revocation_is_not_restored_after_restricted_merge() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10020]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10021]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, 0, &trust)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let restricted_sids = [SidAndAttributes {
        sid: parse_sid(&restricted),
        attributes: SE_GROUP_ENABLED,
    }];
    let mut token = primary_token(parse_sid(&user), &[]);
    token.privileges = TokenPrivileges {
        present: kacs_core::SE_BACKUP_PRIVILEGE,
        enabled: kacs_core::SE_BACKUP_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    token.restricted = RestrictedTokenContext {
        restricted_sids: &restricted_sids,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    let pip = PipContext {
        pip_type: 512,
        pip_trust: 1024,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        pip,
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        kacs_core::BACKUP_INTENT,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.privilege_granted, 0);
    assert_eq!(result.mapped_desired, READ_CONTROL);
}

#[test]
fn pip_decided_bits_block_owner_implicit_and_dacl_grants() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10022]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 5]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL,
        &trust,
    )]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &owner,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&owner), &[]);
    let pip = PipContext {
        pip_type: 1,
        pip_trust: 1,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        pip,
        READ_CONTROL | WRITE_DAC,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.decided & WRITE_DAC, WRITE_DAC);
}

#[test]
fn mandatory_decided_blocks_take_ownership_fallback() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1003]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        &high,
    )]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let mut token = primary_token(parse_sid(&user), &[]);
    token.privileges = TokenPrivileges {
        present: SE_TAKE_OWNERSHIP_PRIVILEGE,
        enabled: SE_TAKE_OWNERSHIP_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        WRITE_OWNER,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, 0);
    assert_eq!(result.privilege_granted, 0);
    assert_eq!(result.decided & WRITE_OWNER, WRITE_OWNER);
}

#[test]
fn privilege_grants_survive_restricted_merge_but_not_confinement() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1004]);
    let restricted = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2001]);
    let confinement = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 77]);
    let dacl = acl_bytes(&[
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &user),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &restricted),
        basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, READ_CONTROL, &confinement),
    ]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let restricted_entries = [sid_attr(parse_sid(&restricted))];
    let mut token = primary_token(parse_sid(&user), &[]);
    token.privileges = TokenPrivileges {
        present: SE_SECURITY_PRIVILEGE,
        enabled: SE_SECURITY_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };
    token.restricted = RestrictedTokenContext {
        restricted_sids: &restricted_entries,
        restricted_device_groups: &[],
        write_restricted: false,
        privilege_granted: 0,
    };
    token.confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&confinement)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL | ACCESS_SYSTEM_SECURITY,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.privilege_granted, ACCESS_SYSTEM_SECURITY);
}

#[test]
fn object_tree_pipeline_preserves_root_and_per_node_grants() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1005]);
    let tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: [0x10; 16],
        },
        ObjectTypeNode {
            level: 1,
            guid: [0x11; 16],
        },
    ])
    .expect("tree should parse");
    let dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        [0x11; 16],
        &user,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user), &[]);

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        Some(&tree),
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(
        result.object_granted_list,
        Some(vec![READ_CONTROL, READ_CONTROL].into())
    );
}
