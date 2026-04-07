use kacs_core::{
    apply_mic, resolve_mandatory_label, GenericMapping, IntegrityLevel, KacsError,
    MicEnforcementState, PrivilegeProvenance, SecurityDescriptor, READ_CONTROL,
    SE_RELABEL_PRIVILEGE, SE_SACL_PRESENT, SE_SELF_RELATIVE, WRITE_DAC, WRITE_OWNER,
};

const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const INHERIT_ONLY_ACE: u8 = 0x08;
const SYSTEM_MANDATORY_LABEL_NO_READ_UP: u32 = 0x0000_0001;
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;
const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: u32 = 0x0000_0004;
const TOKEN_MANDATORY_POLICY_NO_WRITE_UP: u32 = 0x0000_0001;

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

fn sd_with_sacl(owner: &[u8], sacl: Option<&[u8]>) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | if sacl.is_some() { SE_SACL_PRESENT } else { 0 };
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    if let Some(sacl) = sacl {
        let sacl_offset = bytes.len() as u32;
        bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
        bytes.extend_from_slice(sacl);
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

#[test]
fn missing_label_uses_default_medium_no_write_up() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sd_bytes = sd_with_sacl(&owner, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");

    assert_eq!(label.integrity_level, IntegrityLevel::Medium);
    assert_eq!(label.mask, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
    assert!(!label.explicit);
}

#[test]
fn first_mandatory_label_is_used() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let low = sid_bytes([0, 0, 0, 0, 0, 16], &[4096]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &low,
        ),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &high,
        ),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");

    assert_eq!(label.integrity_level, IntegrityLevel::Low);
    assert_eq!(label.mask, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
    assert!(label.explicit);
}

#[test]
fn inherit_only_mandatory_label_is_ignored() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let low = sid_bytes([0, 0, 0, 0, 0, 16], &[4096]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            INHERIT_ONLY_ACE,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &high,
        ),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &low,
        ),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");

    assert_eq!(label.integrity_level, IntegrityLevel::Low);
    assert_eq!(label.mask, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
}

#[test]
fn invalid_label_sid_is_rejected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let invalid = sid_bytes([0, 0, 0, 0, 0, 16], &[12345]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        &invalid,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let err = resolve_mandatory_label(&sd).expect_err("invalid label sid must fail");
    assert_eq!(err, KacsError::InvalidMandatoryLabelSid);
}

#[test]
fn dominant_callers_receive_no_mic_predecisions() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        &high,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");
    let mut decided = 0u32;
    let mut provenance = PrivilegeProvenance::default();

    let mic = apply_mic(
        label,
        IntegrityLevel::System,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        0,
        &mapping(),
        &mut decided,
        &mut provenance,
    )
    .expect("mic should succeed");

    assert_eq!(decided, 0);
    assert_eq!(mic, MicEnforcementState::default());
    assert_eq!(provenance.relabel_granted, 0);
}

#[test]
fn non_dominant_masking_blocks_requested_categories() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_READ_UP
            | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
            | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
        &high,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");
    let mut decided = 0u32;
    let mut provenance = PrivilegeProvenance::default();

    let mic = apply_mic(
        label,
        IntegrityLevel::Medium,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        0,
        &mapping(),
        &mut decided,
        &mut provenance,
    )
    .expect("mic should succeed");

    assert_eq!(
        decided,
        READ_CONTROL | WRITE_DAC | WRITE_OWNER | 0x0000_0020
    );
    assert_eq!(mic.mandatory_decided, decided);
    assert_eq!(provenance.relabel_granted, 0);
}

#[test]
fn mandatory_policy_can_disable_mic() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        &high,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");
    let mut decided = 0u32;
    let mut provenance = PrivilegeProvenance::default();

    let mic = apply_mic(
        label,
        IntegrityLevel::Low,
        0,
        0,
        &mapping(),
        &mut decided,
        &mut provenance,
    )
    .expect("mic should succeed");

    assert_eq!(decided, 0);
    assert_eq!(mic.mandatory_decided, 0);
    assert_eq!(provenance.relabel_granted, 0);
}

#[test]
fn relabel_privilege_punches_write_owner_through_mic() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
        0,
        SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
        &high,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let label = resolve_mandatory_label(&sd).expect("label resolution should succeed");
    let mut decided = 0u32;
    let mut provenance = PrivilegeProvenance::default();

    let mic = apply_mic(
        label,
        IntegrityLevel::Medium,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        SE_RELABEL_PRIVILEGE,
        &mapping(),
        &mut decided,
        &mut provenance,
    )
    .expect("mic should succeed");

    assert_eq!(decided & WRITE_OWNER, 0);
    assert_eq!(mic.mandatory_decided & WRITE_OWNER, 0);
    assert_eq!(provenance.relabel_granted, WRITE_OWNER);
}
