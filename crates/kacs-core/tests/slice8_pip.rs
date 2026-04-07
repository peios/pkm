use kacs_core::{
    apply_pip, resolve_process_trust_label, GenericMapping, KacsError, PipEnforcementState,
    ProcessTrustLabel, SecurityDescriptor, ACCESS_SYSTEM_SECURITY, READ_CONTROL, SE_SACL_PRESENT,
    SE_SELF_RELATIVE, WRITE_DAC, WRITE_OWNER,
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
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&20u32.to_le_bytes());
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
fn missing_trust_label_is_a_noop() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sd_bytes = sd_with_sacl(&owner, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd).expect("trust label resolution should succeed");

    assert_eq!(label, None);
}

#[test]
fn first_trust_label_is_used() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let lower = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 1024]);
    let higher = sid_bytes([0, 0, 0, 0, 0, 19], &[1024, 8192]);
    let sacl = acl_bytes(&[
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, READ_CONTROL, &lower),
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, WRITE_DAC, &higher),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("trust label resolution should succeed")
        .expect("first trust label should exist");

    assert_eq!(
        label,
        ProcessTrustLabel {
            pip_type: 512,
            pip_trust: 1024,
            mask: READ_CONTROL,
        }
    );
}

#[test]
fn malformed_trust_label_shape_is_rejected() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let invalid = sid_bytes([0, 0, 0, 0, 0, 19], &[512]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL,
        &invalid,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let err = resolve_process_trust_label(&sd).expect_err("malformed trust label sid must fail");
    assert_eq!(err, KacsError::InvalidProcessTrustLabelSid);
}

#[test]
fn dominant_callers_receive_no_pip_predecisions() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 1024,
        mask: READ_CONTROL,
    };
    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC;
    let mut privilege_granted = ACCESS_SYSTEM_SECURITY;

    let pip = apply_pip(
        label,
        1024,
        8192,
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(decided, 0);
    assert_eq!(granted, READ_CONTROL | WRITE_DAC);
    assert_eq!(privilege_granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(pip, PipEnforcementState::default());
}

#[test]
fn non_dominant_pip_revokes_privilege_granted_bits() {
    let label = ProcessTrustLabel {
        pip_type: 512,
        pip_trust: 4096,
        mask: READ_CONTROL,
    };
    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
    let mut privilege_granted = WRITE_OWNER | ACCESS_SYSTEM_SECURITY;

    let pip = apply_pip(
        label,
        512,
        1024,
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(
        decided,
        WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(granted, READ_CONTROL);
    assert_eq!(privilege_granted, 0);
    assert_eq!(pip.mandatory_decided, decided);
}

#[test]
fn nonstandard_numeric_type_values_are_valid() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let nonstandard = sid_bytes([0, 0, 0, 0, 0, 19], &[1536, 6000]);
    let sacl = acl_bytes(&[basic_ace(
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
        0,
        READ_CONTROL | 0x0000_0020,
        &nonstandard,
    )]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let label = resolve_process_trust_label(&sd)
        .expect("trust label resolution should succeed")
        .expect("trust label should exist");

    assert_eq!(label.pip_type, 1536);
    assert_eq!(label.pip_trust, 6000);

    let mut decided = 0u32;
    let mut granted = READ_CONTROL | WRITE_DAC | 0x0000_0020;
    let mut privilege_granted = 0;
    let pip = apply_pip(
        label,
        1024,
        6000,
        &mapping(),
        &mut decided,
        &mut granted,
        &mut privilege_granted,
    )
    .expect("pip should succeed");

    assert_eq!(granted, READ_CONTROL | 0x0000_0020);
    assert_eq!(decided, WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY);
    assert_eq!(pip.mandatory_decided, decided);
}
