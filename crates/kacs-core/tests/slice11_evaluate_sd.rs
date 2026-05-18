use kacs_core::{
    evaluate_security_descriptor, AccessCheckToken, ConditionalContext, ConfinementTokenContext,
    GenericMapping, ImpersonationLevel, IntegrityLevel, KacsError, ObjectTypeList, ObjectTypeNode,
    PipContext, RestrictedTokenContext, SecurityDescriptor, Sid, SidAndAttributes, TokenPrivileges,
    TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_SYSTEM_SECURITY, ACE_OBJECT_TYPE_PRESENT, GENERIC_WRITE, READ_CONTROL, SE_DACL_PRESENT,
    SE_GROUP_ENABLED, SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE,
    SE_TAKE_OWNERSHIP_PRIVILEGE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP,
    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC, WRITE_OWNER,
};

const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;
const EXECUTE_RIGHT: u32 = 0x0000_0020;

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
fn missing_owner_is_rejected_but_missing_group_is_valid() {
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
    .expect("missing group is a valid security descriptor shape");
    assert_eq!(missing_group_result.granted, READ_CONTROL);

    let missing_owner_bytes = sd_bytes(None, Some(&group), None, Some(&allow_read));
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
fn security_descriptor_group_sid_does_not_grant_access() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let object_group = sid_bytes([0, 0, 0, 0, 0, 5], &[32, 545]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1001]);
    let empty_dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&object_group), None, Some(&empty_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token_groups = [sid_attr(parse_sid(&object_group))];
    let token = primary_token(parse_sid(&user), &token_groups);

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        READ_CONTROL,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("sd group should not make evaluation malformed");

    assert_eq!(result.granted, 0);
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
fn null_dacl_grants_only_rights_not_predecided_by_pip() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10023]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL,
        &trust,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user), &[]);
    let pip = PipContext {
        pip_type: 512,
        pip_trust: 1024,
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
    assert_eq!(result.pip_decided & WRITE_DAC, WRITE_DAC);
    assert_eq!(result.decided & WRITE_DAC, WRITE_DAC);
}

#[test]
fn absent_trust_label_does_not_restrict_nonzero_caller_pip() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10027]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC,
        &user,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user), &[]);
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

    assert_eq!(result.granted, READ_CONTROL | WRITE_DAC);
    assert_eq!(result.pip_decided, 0);
}

#[test]
fn pip_denials_apply_to_root_and_object_tree_nodes() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10028]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let tree = ObjectTypeList::new(&[
        ObjectTypeNode {
            level: 0,
            guid: [0x30; 16],
        },
        ObjectTypeNode {
            level: 1,
            guid: [0x31; 16],
        },
    ])
    .expect("tree should parse");
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
        &user,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = primary_token(parse_sid(&user), &[]);
    let pip = PipContext {
        pip_type: 512,
        pip_trust: 1024,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        pip,
        READ_CONTROL | WRITE_DAC,
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
    assert_eq!(result.pip_decided & WRITE_DAC, WRITE_DAC);
}

#[test]
fn pip_strips_privilege_granted_backup_restore_security_and_take_ownership() {
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10029]);
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let empty_dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, 0, &trust)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&empty_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let pip = PipContext {
        pip_type: 512,
        pip_trust: 1024,
    };
    let full_mapping = GenericMapping {
        all: mapping().all | kacs_core::DELETE,
        ..mapping()
    };
    let cases = [
        (
            READ_CONTROL,
            kacs_core::SE_BACKUP_PRIVILEGE,
            kacs_core::BACKUP_INTENT,
            READ_CONTROL,
            false,
            "backup",
        ),
        (
            WRITE_DAC,
            kacs_core::SE_RESTORE_PRIVILEGE,
            kacs_core::RESTORE_INTENT,
            WRITE_DAC,
            false,
            "restore",
        ),
        (
            ACCESS_SYSTEM_SECURITY,
            SE_SECURITY_PRIVILEGE,
            0,
            ACCESS_SYSTEM_SECURITY,
            false,
            "security",
        ),
        (
            WRITE_OWNER,
            SE_TAKE_OWNERSHIP_PRIVILEGE,
            0,
            WRITE_OWNER,
            true,
            "take ownership",
        ),
    ];

    for (desired, privilege, intent, denied_bit, fallback_path, name) in cases {
        let mut token = primary_token(parse_sid(&user), &[]);
        token.privileges = TokenPrivileges {
            present: privilege,
            enabled: privilege,
            enabled_by_default: 0,
            used: 0,
        };

        let result = evaluate_security_descriptor(
            Some(&sd),
            &token,
            pip,
            desired,
            &full_mapping,
            None,
            &ConditionalContext::default(),
            intent,
        )
        .expect("evaluation should succeed");

        assert_eq!(result.granted, 0, "{name}");
        assert_eq!(result.privilege_granted, 0, "{name}");
        assert_eq!(result.pip_decided & denied_bit, denied_bit, "{name}");
        if fallback_path {
            assert_eq!(result.provenance.take_ownership_granted, 0, "{name}");
        } else {
            assert_eq!(
                result.provenance.privilege_granted() & denied_bit,
                denied_bit,
                "{name}"
            );
        }
    }
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
    assert_eq!(result.privilege_granted, 0);
    assert_eq!(result.provenance.security_granted, ACCESS_SYSTEM_SECURITY);
}

#[test]
fn backup_restore_and_take_ownership_privileges_do_not_bypass_confinement() {
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10025]);
    let confinement = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 78]);
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let empty_dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&empty_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let cases = [
        (
            READ_CONTROL,
            kacs_core::SE_BACKUP_PRIVILEGE,
            kacs_core::BACKUP_INTENT,
            READ_CONTROL,
            "backup",
        ),
        (
            WRITE_DAC,
            kacs_core::SE_RESTORE_PRIVILEGE,
            kacs_core::RESTORE_INTENT,
            WRITE_DAC,
            "restore",
        ),
        (
            WRITE_OWNER,
            SE_TAKE_OWNERSHIP_PRIVILEGE,
            0,
            WRITE_OWNER,
            "take ownership",
        ),
    ];

    for (desired, privilege, intent, provenance_bit, name) in cases {
        let mut token = primary_token(parse_sid(&user), &[]);
        token.privileges = TokenPrivileges {
            present: privilege,
            enabled: privilege,
            enabled_by_default: 0,
            used: 0,
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
            desired,
            &mapping(),
            None,
            &ConditionalContext::default(),
            intent,
        )
        .expect("evaluation should succeed");

        assert_eq!(result.granted, 0, "{name}");
        assert_eq!(result.privilege_granted, 0, "{name}");
        assert_eq!(
            result.provenance.privilege_granted() & provenance_bit,
            provenance_bit,
            "{name}"
        );
    }
}

#[test]
fn low_and_untrusted_tokens_cannot_write_unlabeled_objects() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10024]);
    let dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_DAC, &user)]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    for integrity_level in [IntegrityLevel::Low, IntegrityLevel::Untrusted] {
        let mut token = primary_token(parse_sid(&user), &[]);
        token.integrity_level = integrity_level;

        let result = evaluate_security_descriptor(
            Some(&sd),
            &token,
            default_pip(),
            WRITE_DAC,
            &mapping(),
            None,
            &ConditionalContext::default(),
            0,
        )
        .expect("evaluation should succeed");

        assert_eq!(result.granted, 0);
        assert_eq!(result.decided & WRITE_DAC, WRITE_DAC);
    }
}

#[test]
fn mic_category_matrix_narrows_dacl_grants_for_below_label_callers() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10025]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let dacl = acl_bytes(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        READ_CONTROL | WRITE_DAC | EXECUTE_RIGHT,
        &user,
    )]);
    let cases = [
        (
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            READ_CONTROL | EXECUTE_RIGHT,
        ),
        (
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            EXECUTE_RIGHT,
        ),
        (
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            READ_CONTROL,
        ),
        (
            SYSTEM_MANDATORY_LABEL_NO_READ_UP
                | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
                | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            0,
        ),
    ];

    for (label_mask, expected_granted) in cases {
        let sacl = acl_bytes(&[basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            label_mask,
            &high,
        )]);
        let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
        let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
        let token = primary_token(parse_sid(&user), &[]);

        let result = evaluate_security_descriptor(
            Some(&sd),
            &token,
            default_pip(),
            READ_CONTROL | WRITE_DAC | EXECUTE_RIGHT,
            &mapping(),
            None,
            &ConditionalContext::default(),
            0,
        )
        .expect("evaluation should succeed");

        assert_eq!(result.granted, expected_granted);
    }
}

#[test]
fn se_security_privilege_survives_mic_without_pip_label() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 10026]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        &high,
    )]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let mut token = primary_token(parse_sid(&user), &[]);
    token.privileges = TokenPrivileges {
        present: SE_SECURITY_PRIVILEGE,
        enabled: SE_SECURITY_PRIVILEGE,
        enabled_by_default: 0,
        used: 0,
    };

    let result = evaluate_security_descriptor(
        Some(&sd),
        &token,
        default_pip(),
        ACCESS_SYSTEM_SECURITY,
        &mapping(),
        None,
        &ConditionalContext::default(),
        0,
    )
    .expect("evaluation should succeed");

    assert_eq!(result.granted, ACCESS_SYSTEM_SECURITY);
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
