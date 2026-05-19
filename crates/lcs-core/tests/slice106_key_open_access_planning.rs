use kacs_core::{
    ACCESS_ALLOWED_ACE_TYPE, AccessCheckToken, ConditionalContext, ImpersonationLevel,
    IntegrityLevel, PipContext, SE_DACL_PRESENT, SE_SELF_RELATIVE, SYSTEM_AUDIT_ACE_TYPE, Sid,
    TOKEN_MANDATORY_POLICY_NO_WRITE_UP, TokenPrivileges, TokenType, TokenView,
};
use lcs_core::{
    KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, LcsError, MAXIMUM_ALLOWED, READ_CONTROL,
    REG_OPEN_LINK, RegistryKeyOpenAccessInput, RegistryOpenAccessDecision,
    RegistryOpenAccessTarget, SYNCHRONIZE, plan_registry_key_open_access,
    select_registry_open_access_target,
};

const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

fn basic_ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let ace_size = 8 + sid.len();
    let mut bytes = Vec::new();
    bytes.push(ace_type);
    bytes.push(flags);
    bytes.extend_from_slice(&(ace_size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut bytes = Vec::new();
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

fn sd(owner: &[u8], group: &[u8], sacl: Option<&[u8]>, dacl: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    let owner_offset = bytes.len() as u32;
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes.extend_from_slice(group);
    let sacl_offset = if let Some(sacl) = sacl {
        let offset = bytes.len() as u32;
        bytes.extend_from_slice(sacl);
        offset
    } else {
        0
    };
    let dacl_offset = bytes.len() as u32;
    bytes.extend_from_slice(dacl);

    let mut control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
    if sacl.is_some() {
        control |= kacs_core::SE_SACL_PRESENT;
    }
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
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

fn input<'a>(
    sd: &'a [u8],
    token: &'a AccessCheckToken<'a>,
    desired_access: u32,
) -> RegistryKeyOpenAccessInput<'a> {
    RegistryKeyOpenAccessInput {
        key_sd: sd,
        token,
        desired_access,
        pip: PipContext::default(),
        conditional_context: ConditionalContext::default(),
        object_audit_context: Some(b"key-guid"),
        privilege_intent: 0,
        caap_policies: &[],
    }
}

#[test]
fn open_target_selection_handles_reg_open_link_and_reserved_flags() {
    assert_eq!(
        select_registry_open_access_target(false, 0),
        Ok(RegistryOpenAccessTarget::FinalKey)
    );
    assert_eq!(
        select_registry_open_access_target(true, 0),
        Ok(RegistryOpenAccessTarget::SymlinkTarget)
    );
    assert_eq!(
        select_registry_open_access_target(true, REG_OPEN_LINK),
        Ok(RegistryOpenAccessTarget::SymlinkKey)
    );
    assert_eq!(
        select_registry_open_access_target(false, REG_OPEN_LINK),
        Ok(RegistryOpenAccessTarget::FinalKey)
    );
    assert_eq!(
        select_registry_open_access_target(true, REG_OPEN_LINK | 0x80),
        Err(LcsError::UnknownOpenFlags {
            flags: REG_OPEN_LINK | 0x80,
            unknown: 0x80,
        })
    );
}

#[test]
fn key_open_access_delegates_to_kacs_and_stores_requested_mask() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, KEY_READ, &user)]);
    let sd = sd(&owner, &group, None, &dacl);
    let token = primary_token(Sid::parse(&user).unwrap());

    let plan = plan_registry_key_open_access(input(&sd, &token, KEY_READ)).unwrap();

    assert_eq!(plan.decision, RegistryOpenAccessDecision::Allowed);
    assert_eq!(plan.requested_access, KEY_READ);
    assert_eq!(plan.mapped_desired_access, KEY_READ);
    assert!(!plan.maximum_allowed);
    assert_eq!(plan.access_check_granted, KEY_READ);
    assert_eq!(plan.fd_granted_access, Some(KEY_READ));
    assert!(!plan.key_open_sacl_audit_required);
    assert!(!plan.audit_failure_blocks_completion);
}

#[test]
fn key_open_access_denial_never_publishes_partial_fd_grants() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(
        ACCESS_ALLOWED_ACE_TYPE,
        0,
        KEY_QUERY_VALUE,
        &user,
    )]);
    let sd = sd(&owner, &group, None, &dacl);
    let token = primary_token(Sid::parse(&user).unwrap());

    let plan =
        plan_registry_key_open_access(input(&sd, &token, KEY_QUERY_VALUE | KEY_SET_VALUE)).unwrap();

    assert_eq!(plan.decision, RegistryOpenAccessDecision::Denied);
    assert_eq!(plan.mapped_desired_access, KEY_QUERY_VALUE | KEY_SET_VALUE);
    assert_eq!(plan.access_check_granted, KEY_QUERY_VALUE);
    assert_eq!(plan.fd_granted_access, None);
}

#[test]
fn maximum_allowed_open_uses_kacs_computed_granted_mask() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let granted = KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL;
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, granted, &user)]);
    let sd = sd(&owner, &group, None, &dacl);
    let token = primary_token(Sid::parse(&user).unwrap());

    let plan = plan_registry_key_open_access(input(&sd, &token, MAXIMUM_ALLOWED)).unwrap();

    assert_eq!(plan.decision, RegistryOpenAccessDecision::Allowed);
    assert!(plan.maximum_allowed);
    assert_eq!(plan.mapped_desired_access, 0);
    assert_eq!(plan.access_check_granted, granted);
    assert_eq!(plan.fd_granted_access, Some(granted));
}

#[test]
fn key_open_sacl_audit_blocks_completion_until_kmes_emit_succeeds() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, KEY_READ, &user)]);
    let sacl = acl(&[basic_ace(
        SYSTEM_AUDIT_ACE_TYPE,
        SUCCESSFUL_ACCESS_ACE_FLAG,
        KEY_READ,
        &user,
    )]);
    let sd = sd(&owner, &group, Some(&sacl), &dacl);
    let token = primary_token(Sid::parse(&user).unwrap());

    let plan = plan_registry_key_open_access(input(&sd, &token, KEY_READ)).unwrap();

    assert_eq!(plan.decision, RegistryOpenAccessDecision::Allowed);
    assert_eq!(plan.fd_granted_access, Some(KEY_READ));
    assert!(plan.key_open_sacl_audit_required);
    assert!(plan.audit_failure_blocks_completion);
}

#[test]
fn key_open_rejects_source_sd_access_masks_outside_registry_rights() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, SYNCHRONIZE, &user)]);
    let sd = sd(&owner, &group, None, &dacl);
    let token = primary_token(Sid::parse(&user).unwrap());

    assert_eq!(
        plan_registry_key_open_access(input(&sd, &token, KEY_QUERY_VALUE)),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "registry_open.key_sd"
        })
    );
}

#[test]
fn key_open_denies_identification_level_impersonation_without_fd_publication() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, KEY_READ, &user)]);
    let sd = sd(&owner, &group, None, &dacl);
    let mut token = primary_token(Sid::parse(&user).unwrap());
    token.token_type = TokenType::Impersonation;
    token.impersonation_level = ImpersonationLevel::Identification;

    let plan = plan_registry_key_open_access(input(&sd, &token, KEY_READ)).unwrap();

    assert_eq!(plan.decision, RegistryOpenAccessDecision::Denied);
    assert_eq!(plan.access_check_granted, 0);
    assert_eq!(plan.fd_granted_access, None);
}
