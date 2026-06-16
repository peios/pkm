mod common;
use common::{acl_bytes, basic_ace, parse_sid, sid_bytes};
use kacs_core::{
    access_check_core, AccessCheckMode, AccessCheckToken, CaapPolicy, CaapPolicyEntry, CaapRule,
    ConditionalContext, ConfinementTokenContext, GenericMapping, ImpersonationLevel,
    IntegrityLevel, ObjectTypeList, ObjectTypeNode, PipContext, RestrictedTokenContext,
    SecurityDescriptor, Sid, TokenPrivileges, TokenType, TokenView, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_SYSTEM_SECURITY, ACE_OBJECT_TYPE_PRESENT,
    AUDIT_POLICY_PRIVILEGE_USE_FAILURE, AUDIT_POLICY_PRIVILEGE_USE_SUCCESS, BACKUP_INTENT,
    MAXIMUM_ALLOWED, READ_CONTROL, SE_BACKUP_PRIVILEGE, SE_DACL_PRESENT, SE_RELABEL_PRIVILEGE,
    SE_SACL_PRESENT, SE_SECURITY_PRIVILEGE, SE_SELF_RELATIVE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, TOKEN_MANDATORY_POLICY_NO_WRITE_UP, WRITE_DAC,
    WRITE_OWNER,
};

const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;




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

fn trust_label_sid(pip_type: u32, pip_trust: u32) -> Vec<u8> {
    sid_bytes([0, 0, 0, 0, 0, 19], &[pip_type, pip_trust])
}

fn integrity_sid(level: u32) -> Vec<u8> {
    sid_bytes([0, 0, 0, 0, 0, 16], &[level])
}

fn guid(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn mapping() -> GenericMapping {
    GenericMapping {
        read: READ_CONTROL,
        write: WRITE_DAC | WRITE_OWNER,
        execute: 0x0000_0020,
        all: READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_0020,
    }
}

fn token_with_privileges<'a>(
    user: Sid<'a>,
    integrity_level: IntegrityLevel,
    privileges: u64,
    audit_policy: u32,
) -> AccessCheckToken<'a> {
    AccessCheckToken {
        subject: TokenView {
            user,
            user_deny_only: false,
            groups: &[],
        },
        token_type: TokenType::Primary,
        impersonation_level: ImpersonationLevel::Impersonation,
        privileges: TokenPrivileges {
            present: privileges,
            enabled: privileges,
            enabled_by_default: 0,
            used: 0,
        },
        integrity_level,
        mandatory_policy: TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        restricted: RestrictedTokenContext::default(),
        confinement: Default::default(),
        audit_policy,
    }
}

#[test]
fn successful_privilege_use_marks_used_and_emits_events() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14000]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_SECURITY_PRIVILEGE | SE_BACKUP_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
    );

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        ACCESS_SYSTEM_SECURITY | kacs_core::GENERIC_READ,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        Some(b"/priv-success"),
        BACKUP_INTENT,
        &[],
    )
    .expect("privilege-use success should evaluate");

    assert_eq!(
        state.updated_privileges.used,
        SE_SECURITY_PRIVILEGE | SE_BACKUP_PRIVILEGE
    );
    assert_eq!(state.privilege_use_events.len(), 2);
    assert!(state.privilege_use_events.iter().all(|event| event.success));
    assert_eq!(
        state.privilege_use_events[0].privilege,
        SE_SECURITY_PRIVILEGE
    );
    assert_eq!(
        state.privilege_use_events[0].requested,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        state.privilege_use_events[0].granted,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        state.privilege_use_events[0].surviving_bits,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        state.privilege_use_events[0].object_audit_context,
        Some(b"/priv-success".to_vec().into())
    );
    assert_eq!(state.privilege_use_events[1].privilege, SE_BACKUP_PRIVILEGE);
    assert_eq!(state.privilege_use_events[1].requested, READ_CONTROL);
    assert_eq!(state.privilege_use_events[1].granted, READ_CONTROL);
    assert_eq!(state.privilege_use_events[1].surviving_bits, READ_CONTROL);
    assert_eq!(
        state.privilege_use_events[1].object_audit_context,
        Some(b"/priv-success".to_vec().into())
    );
}

#[test]
fn maximum_allowed_probing_skips_privilege_use_side_effects() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14001]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_SECURITY_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_SUCCESS | AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    );

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("maximum allowed privilege path should evaluate");

    assert_eq!(state.updated_privileges.used, 0);
    assert!(state.privilege_use_events.is_empty());
}

#[test]
fn pip_stripping_causes_failure_privilege_use_event_without_mark_used() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14002]);
    let trust_sid = trust_label_sid(512, 1);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        0,
        &trust_sid,
    )]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_SECURITY_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    );

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        ACCESS_SYSTEM_SECURITY,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("pip failure privilege path should evaluate");

    assert_eq!(state.granted & ACCESS_SYSTEM_SECURITY, 0);
    assert_eq!(state.updated_privileges.used, 0);
    assert_eq!(state.privilege_use_events.len(), 1);
    assert_eq!(
        state.privilege_use_events[0].privilege,
        SE_SECURITY_PRIVILEGE
    );
    assert_eq!(
        state.privilege_use_events[0].requested,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(
        state.privilege_use_events[0].granted,
        ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(state.privilege_use_events[0].surviving_bits, 0);
    assert!(!state.privilege_use_events[0].success);
}

#[test]
fn relabel_privilege_only_marks_used_when_write_owner_survives() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14003]);
    let label_sid = integrity_sid(12288);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        &label_sid,
    )]);

    let success_dacl = acl_bytes(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, 0, WRITE_OWNER, &user)]);
    let success_sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&success_dacl));
    let success_sd = SecurityDescriptor::parse(&success_sd_bytes).expect("sd should parse");
    let success_token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_RELABEL_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
    );

    let success = access_check_core(
        Some(&success_sd),
        &success_token,
        PipContext::default(),
        WRITE_OWNER,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("relabel success should evaluate");
    assert_eq!(success.updated_privileges.used, SE_RELABEL_PRIVILEGE);
    assert_eq!(success.privilege_use_events.len(), 1);
    assert!(success.privilege_use_events[0].success);

    let failure_dacl = acl_bytes(&[]);
    let failure_sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&failure_dacl));
    let failure_sd = SecurityDescriptor::parse(&failure_sd_bytes).expect("sd should parse");
    let failure_token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_RELABEL_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    );

    let failure = access_check_core(
        Some(&failure_sd),
        &failure_token,
        PipContext::default(),
        WRITE_OWNER,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        None,
        0,
        &[],
    )
    .expect("relabel failure should evaluate");
    assert_eq!(failure.updated_privileges.used, 0);
    assert_eq!(failure.privilege_use_events.len(), 1);
    assert_eq!(
        failure.privilege_use_events[0].privilege,
        SE_RELABEL_PRIVILEGE
    );
    assert!(!failure.privilege_use_events[0].success);
}

#[test]
fn result_list_mode_counts_survival_on_any_node_as_success() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14004]);
    let policy_sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 24004]);
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
    .expect("tree should build");

    let base_dacl = acl_bytes(&[]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
        0,
        0,
        &policy_sid,
    )]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), Some(&sacl), Some(&base_dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let rule_dacl = acl_bytes(&[object_ace(
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        0,
        READ_CONTROL,
        ACE_OBJECT_TYPE_PRESENT,
        guid(2),
        &user,
    )]);
    let policies = [CaapPolicyEntry {
        sid: parse_sid(&policy_sid),
        policy: CaapPolicy {
            rules: vec![CaapRule {
                applies_to: None,
                effective_dacl: rule_dacl.as_slice(),
                effective_sacl: None,
                staged_dacl: None,
                staged_sacl: None,
            }]
            .into(),
        },
    }];

    let token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_BACKUP_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_SUCCESS,
    );

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        kacs_core::GENERIC_READ,
        &mapping(),
        AccessCheckMode::ResultList,
        Some(&object_tree),
        &ConditionalContext::default(),
        None,
        BACKUP_INTENT,
        &policies,
    )
    .expect("result-list privilege-use path should evaluate");

    assert_eq!(state.granted, 0);
    assert_eq!(
        state.object_granted_list,
        Some(vec![0, READ_CONTROL, 0].into())
    );
    assert_eq!(state.updated_privileges.used, SE_BACKUP_PRIVILEGE);
    assert_eq!(state.privilege_use_events.len(), 1);
    assert_eq!(state.privilege_use_events[0].privilege, SE_BACKUP_PRIVILEGE);
    assert!(state.privilege_use_events[0].success);
    assert_eq!(state.privilege_use_events[0].requested, READ_CONTROL);
    assert_eq!(state.privilege_use_events[0].granted, READ_CONTROL);
    assert_eq!(state.privilege_use_events[0].surviving_bits, READ_CONTROL);
}

#[test]
fn confinement_stripping_causes_failure_privilege_use_event_without_mark_used() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14005]);
    let package = sid_bytes([0, 0, 0, 0, 0, 15], &[2, 14005]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let mut token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_BACKUP_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    );
    token.confinement = ConfinementTokenContext {
        confinement_sid: Some(parse_sid(&package)),
        confinement_capabilities: &[],
        confinement_exempt: false,
    };

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        kacs_core::GENERIC_READ,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        Some(b"/priv-confinement"),
        BACKUP_INTENT,
        &[],
    )
    .expect("confinement-narrowed privilege-use path should evaluate");

    assert_eq!(state.granted, 0);
    assert_eq!(state.updated_privileges.used, 0);
    assert_eq!(state.privilege_use_events.len(), 1);
    assert_eq!(state.privilege_use_events[0].privilege, SE_BACKUP_PRIVILEGE);
    assert_eq!(state.privilege_use_events[0].requested, READ_CONTROL);
    assert_eq!(state.privilege_use_events[0].granted, READ_CONTROL);
    assert_eq!(state.privilege_use_events[0].surviving_bits, 0);
    assert!(!state.privilege_use_events[0].success);
    assert_eq!(
        state.privilege_use_events[0].object_audit_context,
        Some(b"/priv-confinement".to_vec().into())
    );
}

#[test]
fn enabled_but_unrequested_privilege_emits_no_privilege_use_event() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let group = sid_bytes([0, 0, 0, 0, 0, 5], &[32]);
    let user = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 14006]);
    let dacl = acl_bytes(&[]);
    let sd_bytes = sd_bytes(Some(&owner), Some(&group), None, Some(&dacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let token = token_with_privileges(
        parse_sid(&user),
        IntegrityLevel::Medium,
        SE_BACKUP_PRIVILEGE,
        AUDIT_POLICY_PRIVILEGE_USE_SUCCESS | AUDIT_POLICY_PRIVILEGE_USE_FAILURE,
    );

    let state = access_check_core(
        Some(&sd),
        &token,
        PipContext::default(),
        WRITE_DAC,
        &mapping(),
        AccessCheckMode::Scalar,
        None,
        &ConditionalContext::default(),
        Some(b"/priv-unrequested"),
        BACKUP_INTENT,
        &[],
    )
    .expect("unrequested privilege path should evaluate");

    assert_eq!(state.granted, READ_CONTROL);
    assert_eq!(state.updated_privileges.used, 0);
    assert!(state.privilege_use_events.is_empty());
}
