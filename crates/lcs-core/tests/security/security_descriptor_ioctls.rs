use crate::common::sid;
use kacs_core::{
    ACCESS_ALLOWED_ACE_TYPE, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE, SecurityDescriptor,
};
use lcs_core::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, KEY_READ, KEY_SET_VALUE, LcsError,
    OWNER_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SYNCHRONIZE, plan_registry_get_security,
    plan_registry_set_security,
};

fn basic_ace(ace_type: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + sid.len());
    bytes.push(ace_type);
    bytes.push(0);
    bytes.extend_from_slice(&(8 + sid.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
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

fn sd(
    owner: Option<&[u8]>,
    group: Option<&[u8]>,
    sacl: Option<&[u8]>,
    dacl: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    let mut control = SE_SELF_RELATIVE;

    let owner_offset = append_optional_component(&mut bytes, owner);
    let group_offset = append_optional_component(&mut bytes, group);
    let sacl_offset = append_optional_component(&mut bytes, sacl);
    let dacl_offset = append_optional_component(&mut bytes, dacl);

    if sacl.is_some() {
        control |= SE_SACL_PRESENT;
    }
    if dacl.is_some() {
        control |= SE_DACL_PRESENT;
    }

    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
    bytes[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    bytes
}

fn append_optional_component(bytes: &mut Vec<u8>, component: Option<&[u8]>) -> u32 {
    let Some(component) = component else {
        return 0;
    };
    let offset = bytes.len() as u32;
    bytes.extend_from_slice(component);
    offset
}

fn with_control(mut bytes: Vec<u8>, flags: u16) -> Vec<u8> {
    let control = u16::from_le_bytes([bytes[2], bytes[3]]) | flags;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes
}

const NULL_DACL_FLAGS: u16 = kacs_core::SE_DACL_PROTECTED
    | kacs_core::SE_DACL_AUTO_INHERITED
    | kacs_core::SE_DACL_AUTO_INHERIT_REQ
    | kacs_core::SE_DACL_DEFAULTED;
const NULL_SACL_FLAGS: u16 = kacs_core::SE_SACL_PROTECTED
    | kacs_core::SE_SACL_AUTO_INHERITED
    | kacs_core::SE_SACL_AUTO_INHERIT_REQ
    | kacs_core::SE_SACL_DEFAULTED;

#[test]
fn null_acl_queries_preserve_only_selected_control_flags() {
    let owner = sid(5, &[18]);
    let existing = with_control(
        sd(Some(&owner), None, None, None),
        NULL_DACL_FLAGS | NULL_SACL_FLAGS,
    );
    for (info, expected) in [
        (DACL_SECURITY_INFORMATION, NULL_DACL_FLAGS),
        (SACL_SECURITY_INFORMATION, NULL_SACL_FLAGS),
        (
            DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
            NULL_DACL_FLAGS | NULL_SACL_FLAGS,
        ),
    ] {
        let plan = plan_registry_get_security(&existing, info).unwrap();
        let output = SecurityDescriptor::parse(plan.output_sd.as_slice()).unwrap();
        assert_eq!(output.control(), SE_SELF_RELATIVE | expected);
        assert!(output.dacl().is_none() && output.sacl().is_none());
    }
}

#[test]
fn null_acl_flags_survive_owner_and_group_updates() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let existing = with_control(
        sd(Some(&owner), None, None, None),
        NULL_DACL_FLAGS | NULL_SACL_FLAGS,
    );
    for info in [OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION] {
        let input = sd(Some(&owner), Some(&group), None, None);
        let plan = plan_registry_set_security(&existing, &input, info).unwrap();
        let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
        assert_eq!(
            output.control(),
            SE_SELF_RELATIVE | NULL_DACL_FLAGS | NULL_SACL_FLAGS
        );
        assert!(output.dacl().is_none() && output.sacl().is_none());
    }
}

#[test]
fn null_acl_replacement_uses_input_flags_and_preserves_the_other_acl() {
    let owner = sid(5, &[18]);
    let empty = acl(&[]);
    let existing = with_control(
        sd(Some(&owner), None, Some(&empty), Some(&empty)),
        NULL_DACL_FLAGS | NULL_SACL_FLAGS,
    );
    for (info, retained, selected) in [
        (
            DACL_SECURITY_INFORMATION,
            NULL_SACL_FLAGS | SE_SACL_PRESENT,
            kacs_core::SE_DACL_PROTECTED,
        ),
        (
            SACL_SECURITY_INFORMATION,
            NULL_DACL_FLAGS | SE_DACL_PRESENT,
            kacs_core::SE_SACL_PROTECTED,
        ),
    ] {
        // NULL input has no bytes, but its selected flags still replace the
        // corresponding old flags. Unselected input flags are ignored.
        let input = with_control(sd(None, None, None, None), selected);
        let plan = plan_registry_set_security(&existing, &input, info).unwrap();
        let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
        assert_eq!(output.control(), SE_SELF_RELATIVE | retained | selected);
        assert_eq!(output.dacl().is_none(), info == DACL_SECURITY_INFORMATION);
        assert_eq!(output.sacl().is_none(), info == SACL_SECURITY_INFORMATION);
    }
}

#[test]
fn null_acl_flags_do_not_collapse_a_selected_empty_acl() {
    let owner = sid(5, &[18]);
    let empty = acl(&[]);
    let existing = sd(Some(&owner), None, None, None);
    let input = with_control(
        sd(None, None, Some(&empty), Some(&empty)),
        NULL_DACL_FLAGS | NULL_SACL_FLAGS,
    );
    let info = DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    let plan = plan_registry_set_security(&existing, &input, info).unwrap();
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert_eq!(
        output.control(),
        SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_SACL_PRESENT | NULL_DACL_FLAGS | NULL_SACL_FLAGS
    );
    assert_eq!(output.dacl().unwrap().bytes(), empty);
    assert_eq!(output.sacl().unwrap().bytes(), empty);
    let query = plan_registry_get_security(plan.merged_sd.as_slice(), info).unwrap();
    assert_eq!(
        SecurityDescriptor::parse(query.output_sd.as_slice())
            .unwrap()
            .control(),
        output.control()
    );
}

#[test]
fn null_acl_flags_with_label_and_dacl_selection_take_only_dacl_flags_from_input() {
    let owner = sid(5, &[18]);
    let existing = with_control(
        sd(Some(&owner), None, None, None),
        NULL_DACL_FLAGS | NULL_SACL_FLAGS,
    );
    let label = acl(&[label_ace(0x2000)]);
    let input = with_control(
        sd(None, None, Some(&label), None),
        kacs_core::SE_DACL_PROTECTED,
    );
    let plan =
        plan_registry_set_security(&existing, &input, LABEL_INFO | DACL_SECURITY_INFORMATION)
            .unwrap();
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert_eq!(
        output.control(),
        SE_SELF_RELATIVE | SE_SACL_PRESENT | kacs_core::SE_DACL_PROTECTED | NULL_SACL_FLAGS
    );
    assert!(output.dacl().is_none());
    assert_eq!(output.sacl().unwrap().bytes(), label);
}

#[test]
fn null_acl_merge_also_preserves_defaulted_null_group_state() {
    let owner = sid(5, &[18]);
    let existing = with_control(
        sd(Some(&owner), None, None, None),
        kacs_core::SE_GROUP_DEFAULTED | NULL_DACL_FLAGS,
    );
    let input = sd(Some(&owner), None, None, None);
    let plan = plan_registry_set_security(&existing, &input, OWNER_SECURITY_INFORMATION).unwrap();
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert!(output.group().is_none());
    assert_eq!(
        output.control(),
        SE_SELF_RELATIVE | kacs_core::SE_GROUP_DEFAULTED | NULL_DACL_FLAGS
    );
}

// The existing KACS wire selector is also the registry LABEL selector.
const LABEL_INFO: u32 = peios_uapi::KACS_SECINFO_LABEL;

fn label_ace(level: u32) -> Vec<u8> {
    basic_ace(
        kacs_core::SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        1,
        &sid(16, &[level]),
    )
}

fn audit_ace() -> Vec<u8> {
    let mut ace = basic_ace(kacs_core::SYSTEM_AUDIT_ACE_TYPE, KEY_READ, &sid(5, &[18]));
    ace[1] = 0x40; // successful-access audit flag
    ace
}

#[test]
fn label_query_returns_only_the_effective_label() {
    let owner = sid(5, &[18]);
    let mut inherit_only = label_ace(0x1000);
    inherit_only[1] = kacs_core::INHERIT_ONLY_ACE;
    let label = label_ace(0x2000);
    let sacl = acl(&[audit_ace(), inherit_only, label.clone()]);
    let existing = sd(Some(&owner), None, Some(&sacl), None);
    let plan = plan_registry_get_security(&existing, LABEL_INFO).expect("label query");
    let output = SecurityDescriptor::parse(plan.output_sd.as_slice()).unwrap();
    assert!(output.owner().is_none());
    assert!(output.group().is_none());
    assert!(output.dacl().is_none());
    assert_eq!(output.sacl().unwrap().bytes(), acl(&[label]));
}

#[test]
fn label_write_preserves_audit_aces_and_unselected_descriptor_state() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let audit = audit_ace();
    let old_sacl = acl(&[audit.clone(), label_ace(0x1000)]);
    let new_label = label_ace(0x2000);
    let input_sacl = acl(&[new_label.clone()]);
    let mut existing = sd(Some(&owner), Some(&group), Some(&old_sacl), None);
    let flags = kacs_core::SE_DACL_PROTECTED
        | kacs_core::SE_DACL_AUTO_INHERITED
        | kacs_core::SE_SACL_PROTECTED
        | kacs_core::SE_SACL_AUTO_INHERIT_REQ;
    let control = u16::from_le_bytes([existing[2], existing[3]]) | flags;
    existing[2..4].copy_from_slice(&control.to_le_bytes());
    let input = sd(None, None, Some(&input_sacl), None);
    let plan = plan_registry_set_security(&existing, &input, LABEL_INFO).expect("label write");
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert_eq!(output.owner().unwrap().as_bytes(), owner);
    assert_eq!(output.group().unwrap().as_bytes(), group);
    assert!(output.dacl().is_none());
    assert_eq!(output.control() & flags, flags);
    assert_eq!(output.sacl().unwrap().bytes(), acl(&[new_label, audit]));
}

#[test]
fn label_clear_removes_labels_but_keeps_audit_entries() {
    let owner = sid(5, &[18]);
    let audit = audit_ace();
    let mut inherit_only = label_ace(0x1000);
    inherit_only[1] = kacs_core::INHERIT_ONLY_ACE;
    let old_sacl = acl(&[label_ace(0x2000), audit.clone(), inherit_only]);
    let existing = sd(Some(&owner), None, Some(&old_sacl), None);
    let input = sd(None, None, None, None);
    let plan = plan_registry_set_security(&existing, &input, LABEL_INFO).expect("label clear");
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert_eq!(output.sacl().unwrap().bytes(), acl(&[audit]));
}

#[test]
fn label_clear_preserves_sacl_flags_when_the_last_ace_is_removed() {
    let owner = sid(5, &[18]);
    let old_sacl = acl(&[label_ace(0x2000)]);
    let mut existing = sd(Some(&owner), None, Some(&old_sacl), None);
    let control = u16::from_le_bytes([existing[2], existing[3]]) | kacs_core::SE_SACL_PROTECTED;
    existing[2..4].copy_from_slice(&control.to_le_bytes());
    let input = sd(None, None, None, None);
    let plan = plan_registry_set_security(&existing, &input, LABEL_INFO).expect("last label clear");
    let output = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert!(output.sacl().is_none());
    assert_ne!(output.control() & kacs_core::SE_SACL_PROTECTED, 0);
    assert_eq!(output.control() & SE_SACL_PRESENT, 0);
}

#[test]
fn label_selector_rejects_audit_payloads_empty_acls_and_inherit_only_labels() {
    let owner = sid(5, &[18]);
    let existing = sd(Some(&owner), None, None, None);
    let mut inherited = label_ace(0x2000);
    inherited[1] = kacs_core::INHERIT_ONLY_ACE;
    for sacl in [
        acl(&[]),
        acl(&[audit_ace()]),
        acl(&[inherited]),
        acl(&[label_ace(0x1000), label_ace(0x2000)]),
    ] {
        let input = sd(None, None, Some(&sacl), None);
        assert!(plan_registry_set_security(&existing, &input, LABEL_INFO).is_err());
    }
}

#[test]
fn label_selector_uses_read_control_and_write_owner() {
    use lcs_core::{RegistrySecurityOperation as Op, registry_security_info_required_access};
    assert_eq!(
        registry_security_info_required_access(Op::Get, LABEL_INFO).unwrap(),
        lcs_core::READ_CONTROL
    );
    assert_eq!(
        registry_security_info_required_access(Op::Set, LABEL_INFO).unwrap(),
        lcs_core::WRITE_OWNER
    );
    assert_eq!(
        registry_security_info_required_access(Op::Set, LABEL_INFO | DACL_SECURITY_INFORMATION)
            .unwrap(),
        lcs_core::WRITE_OWNER | lcs_core::WRITE_DAC
    );
    assert!(
        registry_security_info_required_access(Op::Get, LABEL_INFO | SACL_SECURITY_INFORMATION)
            .is_err()
    );
    assert!(
        registry_security_info_required_access(Op::Set, LABEL_INFO | SACL_SECURITY_INFORMATION)
            .is_err()
    );
}

#[test]
fn get_security_returns_only_requested_components() {
    let owner = sid(5, &[18]);
    let group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let system = sid(5, &[18]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let sacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_SET_VALUE, &system)]);
    let existing = sd(Some(&owner), Some(&group), Some(&sacl), Some(&dacl));

    let plan = plan_registry_get_security(
        &existing,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .expect("subset should be produced");

    assert_eq!(plan.required_len, plan.output_sd.len());
    let output = SecurityDescriptor::parse(plan.output_sd.as_slice()).unwrap();
    assert_eq!(output.owner().unwrap().as_bytes(), owner.as_slice());
    assert!(output.group().is_none());
    assert!(output.sacl().is_none());
    assert_eq!(output.dacl().unwrap().bytes(), dacl.as_slice());

    let sacl_plan =
        plan_registry_get_security(&existing, SACL_SECURITY_INFORMATION).expect("sacl subset");
    let sacl_output = SecurityDescriptor::parse(sacl_plan.output_sd.as_slice()).unwrap();
    assert!(sacl_output.owner().is_none());
    assert!(sacl_output.group().is_none());
    assert_eq!(sacl_output.sacl().unwrap().bytes(), sacl.as_slice());
    assert!(sacl_output.dacl().is_none());
}

#[test]
fn set_security_merges_indicated_components_and_ignores_unindicated_input() {
    let old_owner = sid(5, &[18]);
    let old_group = sid(5, &[32, 544]);
    let new_owner = sid(5, &[21, 2000]);
    let ignored_group = sid(5, &[21, 3000]);
    let user = sid(5, &[21, 1000]);
    let old_dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let new_dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_SET_VALUE, &user)]);
    let ignored_sacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let existing = sd(Some(&old_owner), Some(&old_group), None, Some(&old_dacl));
    let input = sd(
        Some(&new_owner),
        Some(&ignored_group),
        Some(&ignored_sacl),
        Some(&new_dacl),
    );

    let plan = plan_registry_set_security(
        &existing,
        &input,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )
    .expect("selected owner and dacl should merge");

    assert!(plan.direct_key_mutation);
    assert!(!plan.layer_qualified);
    assert!(plan.updates_last_write_time);
    assert!(!plan.affects_existing_fd_grants);
    assert!(plan.affects_future_opens);

    let merged = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();
    assert_eq!(merged.owner().unwrap().as_bytes(), new_owner.as_slice());
    assert_eq!(merged.group().unwrap().as_bytes(), old_group.as_slice());
    assert!(merged.sacl().is_none());
    assert_eq!(merged.dacl().unwrap().bytes(), new_dacl.as_slice());
}

#[test]
fn set_security_can_replace_sacl_without_touching_dacl() {
    let owner = sid(5, &[18]);
    let user = sid(5, &[21, 1000]);
    let old_dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let old_sacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let new_sacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_SET_VALUE, &user)]);
    let existing = sd(Some(&owner), None, Some(&old_sacl), Some(&old_dacl));
    let input = sd(None, None, Some(&new_sacl), None);

    let plan = plan_registry_set_security(&existing, &input, SACL_SECURITY_INFORMATION)
        .expect("selected sacl should merge");
    let merged = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();

    assert_eq!(merged.owner().unwrap().as_bytes(), owner.as_slice());
    assert_eq!(merged.sacl().unwrap().bytes(), new_sacl.as_slice());
    assert_eq!(merged.dacl().unwrap().bytes(), old_dacl.as_slice());
}

#[test]
fn set_security_allows_null_group_without_clearing_owner() {
    let owner = sid(5, &[18]);
    let old_group = sid(5, &[32, 544]);
    let user = sid(5, &[21, 1000]);
    let dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, KEY_READ, &user)]);
    let existing = sd(Some(&owner), Some(&old_group), None, Some(&dacl));
    let input = sd(None, None, None, None);

    let plan = plan_registry_set_security(&existing, &input, GROUP_SECURITY_INFORMATION)
        .expect("null group is valid");
    let merged = SecurityDescriptor::parse(plan.merged_sd.as_slice()).unwrap();

    assert_eq!(merged.owner().unwrap().as_bytes(), owner.as_slice());
    assert!(merged.group().is_none());
    assert_eq!(merged.dacl().unwrap().bytes(), dacl.as_slice());
}

#[test]
fn set_security_rejects_owner_clearing_merge() {
    let owner = sid(5, &[18]);
    let existing = sd(Some(&owner), None, None, None);
    let input = sd(None, None, None, None);

    assert_eq!(
        plan_registry_set_security(&existing, &input, OWNER_SECURITY_INFORMATION),
        Err(LcsError::SecurityDescriptorMergeMissingOwner {
            field: "reg_set_security.input_sd"
        })
    );
}

#[test]
fn set_security_validates_only_indicated_input_acl_components() {
    let owner = sid(5, &[18]);
    let user = sid(5, &[21, 1000]);
    let existing = sd(Some(&owner), None, None, None);
    let invalid_dacl = acl(&[basic_ace(ACCESS_ALLOWED_ACE_TYPE, SYNCHRONIZE, &user)]);
    let input = sd(Some(&owner), None, None, Some(&invalid_dacl));

    plan_registry_set_security(&existing, &input, OWNER_SECURITY_INFORMATION)
        .expect("unindicated dacl is ignored");
    assert_eq!(
        plan_registry_set_security(&existing, &input, DACL_SECURITY_INFORMATION),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "reg_set_security.input_sd"
        })
    );
}

#[test]
fn security_descriptor_payload_plans_fail_closed_on_invalid_inputs() {
    let owner = sid(5, &[18]);
    let existing = sd(Some(&owner), None, None, None);
    let malformed = [1, 0, 0];

    assert_eq!(
        plan_registry_get_security(&existing, 0),
        Err(LcsError::ZeroSecurityInfo)
    );
    assert_eq!(
        plan_registry_set_security(&existing, &malformed, OWNER_SECURITY_INFORMATION),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "reg_set_security.input_sd"
        })
    );
    assert_eq!(
        plan_registry_get_security(&malformed, OWNER_SECURITY_INFORMATION),
        Err(LcsError::MalformedSecurityDescriptor {
            field: "reg_get_security.existing_sd"
        })
    );
}
