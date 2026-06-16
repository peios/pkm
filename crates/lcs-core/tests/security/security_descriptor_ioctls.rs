use crate::common::{sid};
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
